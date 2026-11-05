# 調査報告：ClamAV / clamav-engine-scan

> 担当：clamav-engine-scan / 調査日：2026-11-05 / 調査結果：部分完了（コード・テスト・依存関係・ライセンス一次資料を確認。Windows実機での実行・性能計測・法務判断は未実施）

## 0. 結論（3〜5行）

- **AegisGuardに取り入れる価値：高いが、補助的なオンデマンド検査に限定して評価。** ClamAVはシグネチャ照合だけでなくPE、ZIP、Office、PDF、メールなどの多層パーサーを備える。一方、静的MVPに常駐AVを加える必要はない。
- **最優先候補：** `clamscan.exe` を低権限の隔離ワーカーから明示的に起動し、個別ファイルの追加確認と詳細な「未検査/一部未検査」状態を返す方式（導入前にライセンス・署名DB利用条件・実機負荷を確認）。
- **次点：** サイズ/時間/再帰/ファイル件数制限と更新世代を含む結果キャッシュ、Office/PDF/ZIPの検査カバレッジ拡張。ClamAVの「OK」はファイル全内容の解析完了を保証しない。
- **見送り：** MVPへの`libclamav`直接リンク、恒常的な`clamd`同梱常駐、ClamAVパーサーのRustへの丸ごとコピー。
- **最大の制約：** GPLv2とUnRAR等の別ライセンス、攻撃者入力を処理するネイティブパーサーの脆弱性、署名更新/RSS/二重I/O。**法的評価未完了**、性能値は未実測。

## 1. 対象の固定と調査方法

| 要素 | 値 / 根拠 |
|---|---|
| 公式リポジトリ・commit固定URL | [Cisco-Talos/clamav の対象commit](https://github.com/Cisco-Talos/clamav/tree/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d)。GitHub API上のデフォルトブランチは `main`。 |
| 調査コミットSHA・タグ | `dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d`（2026-10-22の`main`）。調査時点の最新公開リリースは[`clamav-1.5.4`](https://github.com/Cisco-Talos/clamav/releases/tag/clamav-1.5.4)（2026-08-07）。リリースタグが指すコミットは `fa59fca15872bb8a914ba4c68188bcc8a502cbdf`。**調査コードはタグではなく上記main SHAに固定**したため、配布物との厳密な同一性は未検証。 |
| AegisGuardの比較先SHA | [`83fcf0d150e8d760baff5f971c106deb09c1f8e4`](https://github.com/choko510/AegisGuard/tree/83fcf0d150e8d760baff5f971c106deb09c1f8e4)（2026-11-05取得時の`main`）。 |
| ライセンスファイルと対象範囲 | [COPYING.txt](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/COPYING.txt#L1-L8)＝GPL v2原文、[`libclamav/pe.c`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/pe.c#L1-L37)＝GPLv2明示＋一部Apache-2.0、[UnRAR](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/COPYING/COPYING.unrar#L1-L34)＝独自制約、[YARA由来](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/COPYING/COPYING.YARA#L1-L8)＝Apache-2.0。 |
| ソース/ドキュメント確認範囲 | 公開API、`others.c`、`scanners.c`、`unzip.c`、`pe.c`、`pdf.c`、`ole2_extract.c`、`cache.c`、`clamd`、`clamscan`、`freshclam`、`libclamav_rust`、CMake/Cargo、Windowsサンプル設定、ZIP/PDF/OLE2/daemon/隔離競合テスト、公式マニュアルとリリース記録。AegisGuard側はREADME/SECURITY/ARCHITECTURE/Cargo/全`src`モジュールの静的構成を確認。 |
| 実機・ビルド・テスト | **未実施**。外部C/C++/Rust依存物の取得・ビルド・実行、Windows 11、Defender併用ベンチマークを行っていない。既存テスト**コードの調査**と、テスト**実行**を混同しない。 |
| 日付・未検証制限 | 2026-11-05。公開タグ最新性は調査日現在。DBファイルの契約、実配布パッケージのDLL一覧、実際の検査率と誤検知率、署名検証チェーンは未確認。 |

### 比較先の現状（実装済みと構想の区別）

- **実装済み：** [`src/scan.rs#L9-L75`](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/scan.rs#L9-L75) は拡張子ベースのPE/スクリプト分類、PE 64MiB・スクリプト4MiBの入力制限、SHA-256計算と単一ファイル読み込み。[`src/pe.rs#L32-L118`](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/pe.rs#L32-L118) はPEヘッダー・セクション範囲・W+X・高エントロピーの根拠付け。[`src/script.rs#L501-L561`](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/script.rs#L501-L561) は文字列復元の深度/層/バイト数制限。JSONL報告は[`src/model.rs#L27-L114`](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/model.rs#L27-L114) の`status`・`risk`・`analysis_complete`・`incomplete_reasons`を使用。
- **実装済みだが要注意：** [`src/scan.rs#L30-L67`](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/scan.rs#L30-L67) は初期シンボリックリンクを拒否するものの、`metadata`確認と`open`の間の差し替え競合を解決していない。[`SECURITY.md#L7-L13`](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md#L7-L13) も明記。
- **未実装/構想：** YARA-X実行、Authenticode検証、Windowsサービス、Sysmon/ETW、AMSI、Firewall/WFP遮断、継続監視。[`docs/ARCHITECTURE.md#L9-L34`](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L9-L34)、[`SECURITY.md#L15-L22`](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md#L15-L22)。したがって「ClamAVとYARA-Xが現在二重稼働」は事実ではなく、**将来の競合可能性**である。
- **ライセンス：** AegisGuardは[`README.md#L80-L82`](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md#L80-L82) で**自コードのライセンス未設定**を明示。GPLリンク可能な配布形態は未決。

## 2. 実装アーキテクチャとソース調査

| 機能 | 主要なファイル/シンボルと役割 | commit SHA固定の一次情報 | 確認状態 |
|---|---|---|---|
| C API /エンジンライフサイクル | `cl_init`、`cl_engine_new`、`cl_load`、`cl_engine_compile`、`cl_engine_set_num`、`cl_engine_free`。署名DB読込・コンパイルが検査前提。 | [clamav.h L290–337](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/clamav.h#L290-L337)、[L374–481](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/clamav.h#L374-L481)、[L1705–1714](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/clamav.h#L1705-L1714)、[manager.c L1608–1663](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/clamscan/manager.c#L1608-L1663) | 実装確認 |
| 現行APIの戻り値と判定 | `cl_scanfile_ex`/`cl_scandesc_ex`/`cl_scanmap_ex`では処理エラー（`cl_error_t`）と検出判定（`cl_verdict_t`）を別出力。`CL_SUCCESS`でも`CL_VERDICT_NOTHING_FOUND`と`TRUSTED`は別。古い`cl_scanfile`系と混同禁止。 | [clamav.h L84–139](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/clamav.h#L84-L139)、[L1457–1495](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/clamav.h#L1457-L1495)、[L1558–1596](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/clamav.h#L1558-L1596)、[manager.c L865–898](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/clamscan/manager.c#L865-L898) | 実装確認 |
| PE、スクリプト、Office、PDF、アーカイブ | 解析フラグ`CL_SCAN_PARSE_PE/PDF/OLE2/ARCHIVE`、`CL_SCAN_HEURISTIC_ENCRYPTED_*`。`scanners.c`のファイル形式ディスパッチから`pe.c`、`pdf.c`、`ole2_extract.c`、`unzip.c`等へ。`cli_scanscript`はスクリプト正規化も行う。 | [clamav.h L175–222](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/clamav.h#L175-L222)、[scanners.c L2644–2752](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/scanners.c#L2644-L2752)、[L4780–4998](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/scanners.c#L4780-L4998)、[pdf.c L76–107](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/pdf.c#L76-L107)、[ole2_extract.c L1–58](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/ole2_extract.c#L1-L58) | 実装確認。検出率の優劣は未実測 |
| ZIPの取り扱い | ZIP中央ディレクトリに依存せずローカルヘッダー索引も追加、重複エントリを処理し、暗号化・展開サイズを評価。解凍処理の安全性は脆弱性修正履歴を要確認。 | [unzip.c L57–96](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/unzip.c#L57-L96)、[L155–175](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/unzip.c#L155-L175)、[L1857–1895](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/unzip.c#L1857-L1895) | 実装確認 |
| 多層・容量・時間制限 | `CL_ENGINE_MAX_SCANSIZE/MAX_FILESIZE/MAX_RECURSION/MAX_FILES/MAX_SCANTIME`。`cli_checklimits`は内部対象のスキップと通知、`cli_checktimelimit`は中断、`cli_recursion_stack_push`は再帰上限で一部未検査としてキャッシュ抑止。 | [clamav.h L307–340](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/clamav.h#L307-L340)、[others.c L1131–1257](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/others.c#L1131-L1257)、[L1697–1728](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/others.c#L1697-L1728) | 実装確認 |
| **超過したのにOKになり得る** | ZIP内の4KiBファイルに対し`--max-filesize=1K`と`--alert-exceeds-max=no`を指定した公式テストは終了コード0/`OK`を期待。`yes`なら`Heuristics.Limits.Exceeded.MaxFileSize`。**OK≠完全解析**。 | [zip_test.py L20–72](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/unit_tests/clamscan/zip_test.py#L20-L72) | テスト**仕様**を確認、実行は未実施 |
| 暗号化/壊れた文書・ヒューリスティック | OLE2暗号化ファイルへのアラートとJSON metadata、破損PNGを含むZIPでヒューリスティック優先度を検証。暗号化自体はマルウェア確定ではない。 | [ole2_encryption_test.py L37–74](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/unit_tests/clamscan/ole2_encryption_test.py#L37-L74)、[heuristics_test.py L24–105](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/unit_tests/clamscan/heuristics_test.py#L24-L105) | テストコード確認 |
| PDF構造/メタ情報 | `pdf.c`はJS、埋込ファイル、OpenAction、Launch等を解析。PDF統計テストが`JavaScriptObjectCount`、`EmbeddedFileCount`などを期待。 | [pdf.c L76–107](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/pdf.c#L76-L107)、[pdf_stats_test.py L37–72](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/unit_tests/clamscan/pdf_stats_test.py#L37-L72) | 実装とテスト仕様を確認 |
| cleanキャッシュ | `clean_cache_add`でSHA-256、サイズ、再帰階層を使い、metadata収集/未完走/アラートありではキャッシュを避ける。ClamAV内部のエンジン内キャッシュであり、AegisGuardの永続結果キャッシュとは別。 | [cache.c L652–716](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/cache.c#L652-L716)、[others.c L1714–1727](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/others.c#L1714-L1727) | 実装確認 |
| `clamscan` | `cl_engine_new`→`cl_load`→`cl_engine_compile`→`cl_scanfile_ex`。CLI単発でDB読込/初期化が発生し得るため起動コストは要実測。 | [manager.c L1390–1415](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/clamscan/manager.c#L1390-L1415)、[L1608–1663](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/clamscan/manager.c#L1608-L1663)、[L865–898](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/clamscan/manager.c#L865-L898) | 実装確認 |
| `clamd`/通信 | `clamd`のサーバー/セッション/スキャン実装が分離。WindowsはTCPポートを使う構成がテストに含まれ、TCPは認証付き安全なRPCではない。`INSTREAM`には`StreamMaxLength`等の上限。 | [clamd/scanner.c L488–652](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/clamd/scanner.c#L488-L652)、[unit_tests/clamd_test.py L77–105](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/unit_tests/clamd_test.py#L77-L105)、[Windows clamd.conf L95–109](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/win32/conf_examples/clamd.conf.sample#L95-L109)、[L145–152](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/win32/conf_examples/clamd.conf.sample#L145-L152) | 実装・設定確認 |
| Rustの位置づけ | `libclamav_rust`の`Cargo.toml`は`crate-type = ["staticlib"]`でCビルドに組み込む内部Rust実装。公開された「AegisGuardが直接依存可能な純Rust AV crate」ではない。 | [libclamav_rust/Cargo.toml L1–45](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav_rust/Cargo.toml#L1-L45)、[src/lib.rs L1–40](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav_rust/src/lib.rs#L1-L40)、[CMakeLists.txt L132–160](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/CMakeLists.txt#L132-L160) | 実装確認 |
| テスト・回帰保護 | Pythonベースの`clamscan` ZIP/PDF/OLE2/隔離ディレクトリ競合テスト、`clamd`統合テスト、Cユニットテストを保持。Windows`clamd`テストはloopback TCPを設定。 | [zip_test.py L1–104](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/unit_tests/clamscan/zip_test.py#L1-L104)、[quarantine_toctou_test.py L1–110](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/unit_tests/clamscan/quarantine_toctou_test.py#L1-L110)、[clamd_test.py L42–113](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/unit_tests/clamd_test.py#L42-L113)、[unit_tests/CMakeLists.txt](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/unit_tests/CMakeLists.txt) | テスト資産確認。再実行していない |

**注意すべき検査漏れ**：`CL_SCAN_HEURISTIC_EXCEEDS_MAX`を有効化しても、検出した「一部未検査」事象を**悪性確定**に変換してはいけない。パーサーの仕様により途中省略がトップレベルの`OK`に集約される経路があるため、AegisGuardは`scan_complete`を独自の三値（`complete`/`partial`/`unknown`）で保持する。暗号化/破損/未対応圧縮形式も`partial`または`unknown`。CLI表示だけで全内部オブジェクトの完全性は証明できない。

## 3. 具体的な取り込み候補と選択肢

| 候補機能 | 利用方法（crate/API・外部CLI・独自実装・参考・見送り） | AegisGuard接続先 | 優先度 | 工数目安 S/M/L | ライセンス・技術上の阻害要因 |
|---|---|---|---|---|---|
| **① ファイル単発追加スキャン** | **外部CLI（第一候補）**、`clamscan.exe`を明示的なユーザー操作で起動 | 将来の`scanner_adapter`/JSONL `Report` | P0 | M | ClamAVの配布・DB条件未決、CLI出力非構造化、起動/DB読込I/O、Windows ACL |
| **② incomplete/制限理由の正規化** | **AegisGuard独自実装**。ClamAVのstatus・警告・exit codeを保守的に統合 | `src/model.rs`、`src/scan.rs`に将来接続 | P0 | S | `OK`から完全性が推定できない、partialの機械可観測性に限界 |
| **③ ハッシュ/DB世代連動キャッシュ** | **AegisGuard独自実装**（`cache.c`は設計参考） | 将来の局所キャッシュ/ジョブ制御 | P1 | M | 元ファイル差し替え、内部clean cacheとの差、署名DB更新時の失効 |
| ZIP/Office/PDF追加検査 | **外部CLI**の対象を段階的に増やす | ファイル種別判定/`Report` | P1 | M | 脆弱なパーサー面の増加、暗号化・展開不完全の判定 |
| `clamd`＋`INSTREAM` | **外部サービス**（将来の代替案のみ） | 専用isolated worker | P2 | L | 常駐RAM/DBリロード、Windows無認証TCP、接続・権限分離 |
| `libclamav` FFI/直接リンク | **crate/API直接利用は当面見送り** | Rust内FFI仮構想のみ | P3 | L | GPLv2組合せ、unsafe FFI、ネイティブクラッシュがメインプロセスへ波及 |
| ZIPパーサー/PEアンパッカーをコピー | **不採用** | 該当なし | — | L | GPL/UnRAR/YARA等の複合ライセンス、修正追従/脆弱性負債 |
| 再帰・制限・キャッシュ抑止設計 | **設計参考のみ** | 独自解析のlimitsと`analysis_complete` | P1 | S | パーサーを移植せず概念だけ採用 |
| ClamAVのYARA派生matcher | **不採用/参考のみ**。YARA-Xとは別製品 | 将来のYARA-X担当へ引継ぎ | P3 | M | 実装・シグネチャ言語・GPLとの混同、機能重複 |

### 採用候補ごとのI/O、API/設定、失敗時の扱い

**① 単発CLIアダプター（P0）**：入力は`{snapshot_path, sha256, size, declared_type, request_id, profile}`。Rustからシェルを介さず固定パスの署名確認済み`clamscan.exe`へ`Command`と固定引数で渡す。対象パスをアプリ管理下の読み取り専用スナップショットにし、引用符・改行・Unicode・絶対パスをテストする。出力は`{engine_version, database_version, exit_code, detection_names, stderr, scan_status, duration, warnings}`。0=検出なし、1=検出あり、2=エラーというCLI終了コードは**対象バージョン・実機で再検証する前提**で設計し、未知のコード・解析不能行・タイムアウトは`not_assessed`/`unknown`にする。`--remove`/`--move`/`--copy`等の自動アクションは禁止。`--alert-exceeds-max`をPoC時有効にしても、検出と不完全性を区別する。公式[Scanningマニュアル](https://docs.clamav.net/manual/Usage/Scanning.html)を参照。

**② 状態正規化（P0）**：入力はCLI戻り値、警告種別、途中終了、対象SHA、スキャナー起動の成否。出力は既存`Report`と矛盾しない拡張`engine_findings[]`および`scan_complete`、`incomplete_reasons[]`。`malware`/`PUA`/`encrypted`/`broken`/`limit_reached`/`engine_error`を一緒くたに「感染」としない。特に[ZIP制限テスト](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/unit_tests/clamscan/zip_test.py#L51-L72)が示す非完全`OK`を低リスク証明としてキャッシュしない。正規化できない場合は監査ログだけ残し`unknown`。

**③ キャッシュ（P1）**：入力キー＝`SHA-256(読み取ったスナップショット内容) + ファイル長 + ClamAV engine build/version + 公式/追加DBの検証済み世代 + scan option/limit hash + adapter schema version`。出力は同一バイト列の**既知の再検査結果**のみ。`partial`・`unknown`・エラー・スキャナー異常終了・DB有効性不明はネガティブキャッシュしない。DB更新・設定変更・AVバージョン変更で世代を変える。元のパス/mtime**だけ**をキーにしない。適切な保持期限、ACL、消去動作を設定する。ClamAV自身のclean cacheは[`cache.c`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/cache.c#L652-L716) の通りエンジン内の別機構。

**④ コンテナ追加解析（P1）**：対象の第一弾はユーザー指定のZIP/Office/PDF、次にPEの比較。CLI経由で`scan_profile=documents`のように範囲を明示し、結果に「ClamAVが解析できた種類」と「未確認の内部オブジェクト」を可能な範囲で添える。悪意ある文書を開かず、プレビュー/マクロ実行/添付展開の手動実行はしない。構造サマリが必要ならPoC限定で`--gen-json`を調べるが、一時ファイルに機微情報が残る可能性があるため本番既定は無効。

**`clamd`代替案（P2）**：再スキャンが高頻度になった場合のみ`INSTREAM`でバイト列を送る実験。`clamd`自体のDB更新世代、接続失敗、`StreamMaxLength`、`MaxThreads`、キュー/タイムアウトを検査。Windowsは[無保護TCPである旨の公式サンプル](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/win32/conf_examples/clamd.conf.sample#L95-L109)から**127.0.0.1限定であっても同一端末上の他プロセスによる接続リスク**が残る。プロセス権限分離や接続元制御を設計するまで本番採用しない。[プロトコル資料](https://docs.clamav.net/manual/Usage/ClamdProtocol.html)。

## 4. ライセンス・再配布・依存関係

| 対象 | 一次資料と確認事項 | AegisGuardへの含意 |
|---|---|---|
| **`libclamav`/中核Cコード** | [`pe.c`著作権冒頭](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/pe.c#L1-L22)、[GPLv2全文](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/COPYING.txt#L59-L121)、[ClamAV公式libclamavマニュアル「License」](https://docs.clamav.net/manual/Development/libclamav.html)。公式はlibclamavのGPL v2、商用クローズドソースとのリンク不可と明記。 | 静的/動的リンクをRust FFIで行えばGPL適合性の検討が必要。AegisGuardは現状[ライセンス未設定](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md#L80-L82)。独立してビルドできるから無条件で許諾されるという意味ではない。**法的評価未完了。** |
| **ClamAV内Rustモジュール** | [`libclamav_rust/src/lib.rs`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav_rust/src/lib.rs#L1-L20) はGPL v2を明記。`Cargo.toml`は[`staticlib`とgit依存](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav_rust/Cargo.toml#L7-L45)。 | 「Rustで書かれた部分なら自由に流用可」は誤り。直接Rust依存はネイティブ実装を消せずライセンス面も解消しない。 |
| **混在する由来コード/圧縮エンジン** | [UnRAR利用/再配布制限](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/COPYING/COPYING.unrar#L1-L34)、[YARA由来のApache-2.0](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/COPYING/COPYING.YARA#L1-L8)、[LGPL原文](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/COPYING/COPYING.LGPL#L1-L22)、`COPYING`下のzlib/bzip2/lzma/curl/pcre等の個別原文。 | コピーする場合は**ファイル/部品単位**の権利確認が必要。特にUnRARソースのRAR圧縮再実装禁止を見落とさない。これはClamAV全体がLGPLという意味ではない。 |
| **CLI外部プロセス利用** | `clamscan`自体はClamAV実装・GPL条件の対象。ライブラリリンクとプロセス分離では法的評価の論点が異なるが、同梱・変更物配布・ソース提供・通知等の義務は消えない。 | **CLIなら常にGPLから自由、とは断定しない。** 初期PoCではユーザーが別途導入した公式配布物を利用し、製品同梱しない。自動入手/インストール/同梱は法務確認後。 |
| **公式署名データ（CVD/CLD/CDIFF）** | [更新と公式DBの説明](https://docs.clamav.net/manual/Usage/SignatureManagement.html)、[署名データのCVD形式/署名](https://docs.clamav.net/manual/Development/libclamav.html)、[配布とアクセスの制限](https://docs.clamav.net/faq/faq-eol.html)。 | **データ単体の再配布ライセンス/商用同梱条件は未確定**。GPLv2がDB全体に当然適用されるとは扱わない。検証済み`freshclam`による正規更新を候補とし、DBバイナリをAegisGuard repo/配布物に埋め込まない。 |
| **非公式・追加ルール、YARA等** | ClamAVは[カスタム署名フォーマット](https://docs.clamav.net/manual/Signatures.html)を受け付けるが、作成者・第三者の著作権/配布許諾は署名ごとに別。`.crb`、bytecodeの特性も読み込みDBに依存。 | 一般のYARAルールとClamAV独自シグネチャを同一視しない。署名/追加ルールの出自と許諾台帳、ハッシュ、配布条件を分離して保持。 |

**Windows配布・依存関係：** 調査日時点で公式[1.5.4 Windows x64 MSI/ZIPと.sig](https://www.clamav.net/downloads)が存在。自前ビルドは[`CMakeLists.txt#L132-L160`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/CMakeLists.txt#L132-L160) のBison/Flex/Rust、[`#L500-L538`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/CMakeLists.txt#L500-L538) のOpenSSL・zlib・bzip2・libxml2・PCRE2・JSON-C、[`libclamav/CMakeLists.txt#L1-L51`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/CMakeLists.txt#L1-L51) のWindows互換層やリンク、[`libclamav_rust/Cargo.toml#L7-L34`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav_rust/Cargo.toml#L7-L34) のRust crates/git依存を伴う。**単一crateを`Cargo.toml`へ1行追加する統合ではない**。配布ZIPのバイナリ署名/.sig検証方法と再配布条項は別途PoCで確定する。

## 5. Defender共存・Windows制約・権限境界

- **役割分担：** Defenderは既存のリアルタイム保護・AMSI連携などの主防御。ClamAVはユーザーが明示したファイルの第二意見として扱う。ClamAVをWindows登録AVとして主防御に切り替えず、Defender除外・保護停止・ASR無効化・Firewall変更をしない。[AegisGuard設計](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L19-L35)、[ClamAV使用形態](https://docs.clamav.net/manual/Usage.html)。
- **WFP/ETW/Sysmon/AMSI：** libclamavのパーサー/CLIはこれらのWindows観測イベントを取得する代替ではない。現状のAegisGuardでも未実装。将来Windowsセンサーが得た`file_hash/path/process_guid`と追加スキャン結果を**相関**させるべきで、パケット/プロセスフックをClamAVから移植しない。
- **必要権限：** PoCは一般ユーザーとしてアクセス可能なスナップショットだけを走査。管理者/サービス/SYSTEMでユーザーファイルを無条件に開かない。機密文書をスキャンする際のパス・メタデータ・一時ファイル・ログにユーザー情報が残り得る。ACL、非公開ログ、短期消去、ネットワーク無送信を検証。
- **Windows固有：** [`win32/conf_examples/clamd.conf.sample#L95-L109`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/win32/conf_examples/clamd.conf.sample#L95-L109) はWindowsのclamdソケットが**無保護TCPのみ**と明記。設定例では`TCPAddr localhost`。同一ホスト上の任意ユーザーからの利用や`SHUTDOWN/RELOAD`コマンド許可設定も要吟味。サービス化はPoCに不要。
- **再解析の競合：** AegisGuard・ClamAV・Defenderが同じファイルを順に読むと重複I/Oが増える。クラウド同期/ダウンロードフォルダーでTOCTOU、ACL、ファイルロック、reparse pointに注意。スナップショットを先に確定し、3エンジンで同一ハッシュを共有したことを検証する。
- **失敗/ロールバック：** 外部スキャナー起動不可・DB不在/期限切れ・権限エラー時はAegisGuard本体の静的解析を継続し、ClamAV結果を`not_assessed`として記録。既存のDefender状態を変更せず、ワーカー停止で元に戻せる構成に限定する。

## 6. 性能・堅牢性・誤検知

**実測値：なし。** 公式[必要要件](https://docs.clamav.net/)はWindows 10/11でメモリ3GiB以上・空きストレージ5GiB等を推奨するが、これは**AegisGuardへの追加搭載時の実測消費量ではない**。`clamscan`は毎起動でDBロードし得る。`clamd`は初回ロードを共有できる反面、常駐メモリ・DBリロード中の追加メモリ・サービス攻撃面を持つ。[CMake/CLI初期化](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/clamscan/manager.c#L1390-L1415)、[DB compile](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/clamscan/manager.c#L1608-L1663)、[設定の同時リロード警告](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/win32/conf_examples/clamd.conf.sample#L221-L230)。

**上限の意味**：展開後ファイルの`MaxFileSize`、容器内合計`MaxScanSize`、`MaxFiles`、再帰深度、`MaxScanTime`は相互に異なる。[`cli_checklimits`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/others.c#L1149-L1205)。制限でスキップが発生しても[ZIPテスト](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/unit_tests/clamscan/zip_test.py#L51-L72)のようにアラートを無効にすれば`OK`に見える。強制的に上限を上げるのでなく、**解析漏れの記録**と安全な上限調整を先に行う。タイムアウトをライブラリ内の`CL_ENGINE_MAX_SCANTIME`だけに委ねず、親プロセスのwall-clock/CPU/メモリ/ジョブ数/総I/Oにも制限を設け、プロセスをKill可能にする。

**攻撃者入力の具体的危険**：公式[1.5.4リリース](https://github.com/Cisco-Talos/clamav/releases/tag/clamav-1.5.4)はZIP索引ヒープ破壊（CVE-2026-20337）、ZIP無効free（20338）、PESpin展開整数オーバーフロー（20339）、PDF解析整数アンダーフロー（20346）、XAR異常確保（20348）、UnRARのWindowsパス関連問題（CVE-2025-8088）などを修正。**外部エンジンは安全なデータ処理器だと仮定しない**。1.5.3以下は検証候補から外し、最新のセキュリティ更新を継続監視。リリース版1.5.4の修正をmainの特定ビルドへ適用済みと勝手に断言しない。

**誤検知/検査漏れ**：暗号化ZIP/Office、破損PDF/PE、重複/重なりZIP、未対応の圧縮形式、既定の深度制限、正規の社内マクロ、ダウンロードアーカイブのOSメタデータ、FP署名・信頼された電子署名などを区別。ClamAVの`TRUSTED`はAegisGuard全体の「安全」と同義でない。Defender/YARA-Xの将来判定を上書きせず、`engine=clamav`の根拠と走査範囲を保存する。

**測定計画：** 同一スナップショット集合（空/小PE/大PE/PowerShell/ZIP多層/Office/PDF/暗号化/壊れた無害ファイル）を、AegisGuard単独、ClamAV単発、両方で比較。ウォーム/コールド起動、DB読込時間、各ファイルの経過時間、CPU時間、peak RSS/Private Bytes、読み取り/書き込みバイト、生成一時ファイル、検知/誤検知、`partial`理由を記録。測定前に「何%高速」等を主張しない。

## 7. 推奨する小さなPoCと成功基準

- **前提：** Windows 11 x64＋Defender有効の隔離テスト環境。実環境設定変更なし。ユーザーが別途インストールした公式ClamAV 1.5.4以上の確認済みバイナリ、公式DBを正規経路から取得。PoC専用ディレクトリ・一般ユーザー権限・ループバック以外のclamd通信なし・任意コード実行なし。
- **安全なサンプル/検証方法：** テキスト、独自に生成した無害PEスタブ、マクロなしOffice/PDF、ZIP内複数ダミーファイル、意図的に壊した文書、暗号化文書（テスト用）、ZIPの深度/サイズ制限境界。マルウェア検体は使わず、試験用の独自`.ndb`署名で既知の**無害文字列**をヒットさせる。Defenderが検出し得る既知のテストマルウェア文字列の使用も初期PoCでは避ける。
- **段階① 無効：** 呼び出しインターフェイスの設計を検査するだけ。通常AegisGuardスキャンに変化なし、設定flagは既定OFF。
- **段階② 監査/可視化：** 明示的な単発操作でのみ起動、固定許可リスト/単一ジョブ、スナップショットのハッシュ照合、timeout・exit code・stdout/stderrを上限付きで取得。アラート/警告をJSONLへ紐付けるが自動削除・隔離・ブロックは**しない**。
- **段階③ 限定有効化：** テスト用フォルダーの一部対象拡張子へ実行範囲を広げ、負荷とデータ量を測定。Defenderや他のWindows設定を変更しない。
- **成功条件と性能測定方法：** (1) データの一致＝走査したスナップショットSHAが起動前後で一致。(2) 署名命中、非命中、プロセスエラー、DB欠落、制限超過、暗号化/破損、強制終了を**混同しない**。(3) [ZIP公式テスト](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/unit_tests/clamscan/zip_test.py#L51-L72)相当の上限境界では`OK`でも`complete`と断定しない。(4) タイムアウト/強制終了時に子プロセスが残存しない。(5) 検査中にDefender保護が有効のままで、対象/メタデータ/ログが外部送信されない。(6) 繰り返し測定したCPU時間・RSS・I/O・レイテンシの統計と95パーセンタイルを**数値を捏造せず**報告する。
- **失敗時の扱い・ロールバック：** エンジン異常・scan partial・タイムアウトは`not_assessed`/`unknown`としてAegisGuard本体の結果と分離。feature flag OFFとワーカー停止でロールバック。すべての一時スナップショット/ルール/DBの権限と削除タイミングを確認。
- **中止条件：** ClamAVに未修正の対象入力RCE/メモリ破壊の疑義、未検証配布物、DBライセンス不明な同梱、Defenderの変更要求、プロセス分離不能、機微情報が無断送信される構成、異常メモリ/CPU/ディスク増加。実機で安全なPoCを完走するまで**正式採用決定ではない**。

### 導入候補上位3件

| 順位 | 候補 | 優先度/規模 | ブロッカー |
|---|---|---|---|
| 1 | 単発`clamscan`隔離ワーカー | P0 / M | Windows公式配布物の検証、DB取得・利用条件、CLI出力/timeout、Defender共存実測 |
| 2 | 結果の`partial/unknown`正規化＋上限理由の保持 | P0 / S | ClamAV CLIが内部スキップの完全な機械可読情報を常に出すとは限らない |
| 3 | SHA・DB世代・オプション連動キャッシュ | P1 / M | 更新世代の正確な取得、TOCTOU解消、機密ファイルのACL |

## 8. 採用しない設計と理由

1. **MVPに`libclamav`を直接リンクし全ファイルを自動常駐スキャン**：GPLv2との結合・未定のAegisGuardライセンス、FFIによるC/Rust境界とネイティブクラッシュ伝播、DBの常駐負荷が先行する。センサーなしの現在の製品には常駐が必要ない。
2. **ClamAVのZIP/PE/Office/PDFの実装を丸ごとRustへコピー・翻訳**：依存・著作権由来が混在する大量のコードを保守することになり、脆弱性修正追従と独自fuzzingが困難。GPL等のライセンス義務は翻訳で消えない。
3. **Windowsで`clamd`をデフォルトの公開TCPサービスとして起動**：Windows実装のソケットが[無保護TCP](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/win32/conf_examples/clamd.conf.sample#L95-L109)。外部露出・ローカル悪用・常駐RAM・更新負荷に対してMVPでの便益が小さい。
4. **ClamAV検出名を即座にFirewall遮断/削除へ直結**：誤検知と解析不完全により回復不能な影響を生む。Defenderの責務にも重なるため観測・照合止まりとする。

## 9. 他担当との境界・引継ぎ

- **YARA-X担当：** ClamAV内部のYARA由来matcherとYARA-Xのルール互換性/ライセンスは別に確認。YARA-Xの重複スキャンは実装後に計測する。共通の`engine_findings`スキーマ設計だけ引継ぎ。
- **PE/難読化担当：** [AegisGuard PE](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/pe.rs#L32-L118) の構造・エントロピーとClamAV PEアンパッカーの違い、[難読化](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/script.rs#L501-L561) に対する正規化の相互補完を後日検証。既存の`incomplete`を後退させない。
- **Windowsセンサー/相関担当：** スナップショット識別子・ハッシュ・`ProcessGuid`・スキャン世代を橋渡し。Sysmon/ETW/WFP/AMSI機能をClamAVが持つという前提では設計しない。
- **更新/供給網担当：** `freshclam` DBバージョン、署名真正性、製品同梱条件、SBOM、バイナリ署名検証、更新失敗時のフォールバックを別の更新系設計へ引継ぎ。
- **利用規約/法務担当：** `GPLv2`、`UnRAR`、個別由来コード、CVD/CLDデータ、CLI同梱の適合性確認が必要。調査者は法的許諾を断定しない。

## 10. 未確認事項・追加調査項目

1. **最重要：法的評価未完了。** AegisGuardの配布方針/ライセンス未決。libclamavへのリンク・ClamAV CLI同梱・標準DB配布/改変・非公式ルール同梱それぞれについて権利者/専門家確認が必要。
2. **最重要：Windows 11実測未実施。** 1.5.4 x64配布物の真正性確認、実DLL/サービス構成、UAC/ACL、低権限での起動、Defender併用時のコスト/ロック/隔離を確認していない。
3. **高：CLI出力の完全性。** `--alert-exceeds-max`を有効にしてもすべての展開省略が機械可読に出る保証は未確認。ログ解析を「完全検査の証明」には使えない。
4. **高：隔離強度。** Windows Job Object・トークン/ACL・プロセスの権限制限・子プロセス追跡・タイムアウト・一時ディレクトリの削除を設計/検証していない。Defenderを弱める例外設定は不可。
5. **高：形式別の検出可能性。** ZIP内の重複/暗号化/壊れたヘッダー、PDF JS/埋込Office/Officeマクロ、packed PE、ClamAV bytecode DB依存機能に対する再現テスト未実施。
6. **中：ClamAV 1.5.4の長期サポート終了・脆弱性修正状況の将来変化。** 新リリース公開時に再評価する。`main`と署名付きタグ・Windows配布実体の差分も未確認。
7. **中：DB更新・データ保護。** DB世代の信頼できる読み出し、ダウンロードの正規頻度/レート制限、標準DBの再配布条件、追加ルールのライセンス台帳、ログ・一時ファイルの残留を検証していない。
8. **中：再現テスト未実行。** 公式既存テストの失敗/成功を本調査では主張しない。非悪性テストデータでWindows環境の回帰スイートを後日構築する。

## 11. 一次情報一覧

すべて2026-11-05確認。下記のコードリンクは調査対象コミット`dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d`または比較先`83fcf0d150e8d760baff5f971c106deb09c1f8e4`に固定した。

1. [`libclamav/clamav.h#L84-L139`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/clamav.h#L84-L139)・[`#L175-L222`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/clamav.h#L175-L222)・[`#L1457-L1495`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/clamav.h#L1457-L1495)：判定とエラーの分離、パーサーフラグ、現行スキャンAPI。
2. [`libclamav/others.c#L1131-L1257`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/others.c#L1131-L1257)・[`#L1697-L1728`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/others.c#L1697-L1728)：制限/タイムアウト/再帰上限と未解析扱い。
3. [`libclamav/unzip.c#L155-L175`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/unzip.c#L155-L175)・[`#L1857-L1895`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/unzip.c#L1857-L1895)：ZIP展開とローカルヘッダー、サイズ制限。
4. [`unit_tests/clamscan/zip_test.py#L51-L72`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/unit_tests/clamscan/zip_test.py#L51-L72)：上限超過で`OK`になる具体的回帰期待値。
5. [`unit_tests/clamscan/ole2_encryption_test.py#L37-L74`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/unit_tests/clamscan/ole2_encryption_test.py#L37-L74)・[`pdf_stats_test.py#L37-L72`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/unit_tests/clamscan/pdf_stats_test.py#L37-L72)：Office暗号化とPDF構造メタデータ。
6. [`libclamav/cache.c#L652-L716`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/cache.c#L652-L716)：cleanキャッシュの禁止条件/キー。
7. [`clamscan/manager.c#L865-L898`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/clamscan/manager.c#L865-L898)・[`#L1608-L1663`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/clamscan/manager.c#L1608-L1663)：CLIのAPI利用/DBロード・コンパイル。
8. [`win32/conf_examples/clamd.conf.sample#L95-L109`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/win32/conf_examples/clamd.conf.sample#L95-L109)・[`unit_tests/clamd_test.py#L77-L105`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/unit_tests/clamd_test.py#L77-L105)：Windows TCPリスクとテスト構成。
9. [`libclamav_rust/Cargo.toml#L1-L45`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav_rust/Cargo.toml#L1-L45)・[`lib.rs#L1-L20`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav_rust/src/lib.rs#L1-L20)・[`CMakeLists.txt#L500-L538`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/CMakeLists.txt#L500-L538)：Rustの`staticlib`特性とビルド依存。
10. [`libclamav/pe.c#L1-L37`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/pe.c#L1-L37)・[`COPYING.unrar#L1-L34`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/COPYING/COPYING.unrar#L1-L34)・[`COPYING.YARA#L1-L8`](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/COPYING/COPYING.YARA#L1-L8)：GPL・UnRAR・YARA由来の個別ライセンス。
11. [AegisGuard `scan.rs#L9-L75`](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/scan.rs#L9-L75)・[`model.rs#L27-L114`](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/model.rs#L27-L114)・[`ARCHITECTURE.md#L9-L44`](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L9-L44)：現行機能、結果モデル、未実装機能。
12. 公式ドキュメント：[libclamav API/ライセンス](https://docs.clamav.net/manual/Development/libclamav.html)、[Scanning](https://docs.clamav.net/manual/Usage/Scanning.html)、[ClamD Protocol](https://docs.clamav.net/manual/Usage/ClamdProtocol.html)、[署名DB更新](https://docs.clamav.net/manual/Usage/SignatureManagement.html)、[ClamAV 1.5.4セキュリティ修正一覧](https://github.com/Cisco-Talos/clamav/releases/tag/clamav-1.5.4)。
