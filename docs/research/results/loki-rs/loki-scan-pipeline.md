# 調査報告：Loki-RS / loki-scan-pipeline

> 担当：`loki-scan-pipeline` / 調査日：2026-11-05（JST） / 調査結果：**静的コード調査完了・実機検証未実施** / 対象：Windows 11 x64、Rust、Defender併用

## 0. 結論（3〜5行）

- **取り入れる価値は高いが、Loki-RS本体の移植は推奨しない。** 特にファイル種別選別、ファイル名・ハッシュIOC、YARA-X一致理由、構造化JSONLの設計が有用。
- **最優先はAegisGuard独自の「検査結果／検査不能」のモデル維持と強化。** Loki-RSは一部のYARAエラーやスキップを通常の検出件数から分離しており、「検出なし」の解釈に注意が必要。
- ZIPは単一エントリの展開バイト上限を実装するが、アーカイブ単位の総展開バイト数・件数・時間予算の明示的な制御がなく、安全な再設計が必要。
- **GPL-3.0コードをコピーせず、BSD-3-Clause宣言のYARA-Xを別途評価し、走査・IOC・報告モデルを独立実装する。** ルール/IOCデータの権利は別審査。AegisGuard本体のライセンスも未設定で、法的評価未完了。

## 1. 対象の固定と調査方法

| 要素 | 値 / 根拠 |
|---|---|
| 公式リポジトリ・固定URL | [Neo23x0/Loki-RS @ 0866b3d0e32d82f8b5776f61c67b655a34a55b4a](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/README.md)（デフォルト`master`、調査時） |
| 調査コミット・タグ | **`0866b3d0e32d82f8b5776f61c67b655a34a55b4a`**。`Cargo.toml`は`2.13.1`、GitHub release `v2.13.1` 公開日 2026-09-27（[releases](https://github.com/Neo23x0/Loki-RS/releases/tag/v2.13.1)）。releaseタグと調査コミットの一致は未照合 |
| AegisGuard比較先 | **`83fcf0d150e8d760baff5f971c106deb09c1f8e4`**（`main`の調査時HEAD）。[README](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md)・[SECURITY](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md)・[ARCHITECTURE](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md)・[scan.rs](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/scan.rs#L1-L155)・[model.rs](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/model.rs#L1-L120) |
| ライセンス | [Loki-RS LICENSE](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/LICENSE#L1-L20) GPL v3、[Cargo manifest](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/Cargo.toml#L1-L75)・[vendored YARA-X manifest](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/vendor/yara-x/Cargo.toml#L13-L41) |
| 確認ソース | `src/main.rs`、`src/modules/filesystem_scan.rs`、`src/modules/process_check.rs`、`src/helpers/{score,throttler,yara,unified_logger,html_report}.rs`、`src/loki_util/main.rs`、`Cargo.toml`、テスト、`.github/workflows/test.yml`。AegisGuard側`src/main.rs`・`scan.rs`・`model.rs`・`Cargo.toml` |
| ビルド・実機・テスト | **未実施**。GitHub上の固定コミットのRust実装・テストコード・ワークフローを読んだ静的レビュー。Windows Defender有効の実測、cargo test結果、実際の検出率は確認していない |
| 確認日・限界 | 2026-11-05。ルール配布物、最新脅威フィード、ZIP悪性検体の動的検証なし。他プロジェクト・バイナリの実行なし |

**現行AegisGuardとの相違**：`scan.rs::classify`は拡張子で対象を限定、`scan_file`はシンボリックリンク検査・ファイル長上限・SHA-256・PE/スクリプト解析、`run`は`WalkDir`直列走査と標準出力/任意JSONL。`model.rs::Report`には`analysis_complete`、`incomplete_reasons`、`not_assessed`が既にある（[scan](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/scan.rs#L10-L130)、[model](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/model.rs#L20-L110)）。C2は手動フィード更新とIP照合であり、`src/main.rs`にはリアルタイム監視やYARAスキャンのCLIがない（[main](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/main.rs#L1-L80)、[Cargo](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/Cargo.toml#L1-L28)）。

## 2. 実装アーキテクチャとソース調査

### 2.1 機能マップ（コード根拠）

| 機能 | 主要ファイル・シンボル / 実態 | 一次情報 | 状態 |
|---|---|---|---|
| 起動/スキャン構成 | `Cli`：フォルダー、プロセス無効化、ファイル全種、アーカイブ無効化、64,000,000 byteデフォルト、YARA 10秒、`--threads=-2`、`--cpu-limit=100`、出力/閾値 | [main.rs L21–180](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L21-L180) | 実装確認 |
| 並列走査 | `main`でRayonグローバルプール作成。`scan_path`は`WalkDir::follow_links(false).par_bridge().map().reduce()`。**優先度付きキューや永続ジョブキューはコード上確認できない** | [main.rs L1197–1220](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L1197-L1220)、[L1320–1340](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L1320-L1340)、[filesystem_scan.rs L503–610](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/filesystem_scan.rs#L503-L610) | 実装確認／優先順位は未実装と判断 |
| CPU制限 | スレッドローカル`CpuThrottler`が作業時間後にsleep。`ScanState`経由で設定変更可能。**全プロセスのCPU使用率を測定して厳格制御する仕組みではない** | [throttler.rs L1–100](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/helpers/throttler.rs#L1-L100)、[filesystem_scan.rs L563–580](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/filesystem_scan.rs#L563-L580) | 実装確認 |
| 例外/リンク/媒体 | symlink・reparse-point検出をwalk時に除外、実行ファイル自身のディレクトリ・設定正規表現・クラウド系パスを除外。Windowsは`GetDriveTypeW`でネットワークドライブを判定 | [filesystem_scan.rs L126–212](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/filesystem_scan.rs#L126-L212)、[L630–806](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/filesystem_scan.rs#L630-L806) | 実装確認／TOCTOU耐性未確認 |
| magic/拡張子 | `file_format::FileFormat::from_file`と`REL_EXTS`・`FILE_TYPES`、`--scan-all-files`。種別推定失敗や偽装によりスキップの可能性 | [filesystem_scan.rs L51–68](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/filesystem_scan.rs#L51-L68)、[L812–856](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/filesystem_scan.rs#L812-L856) | 実装確認 |
| ファイル読取 | `read_bounded`で上限+追加1 byte相当を検出し、`Vec<u8>`所有のスナップショットへ読む。スキャン前のsize判定に加え読取中増加も検知 | [filesystem_scan.rs L611–629](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/filesystem_scan.rs#L611-L629)、[L856–896](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/filesystem_scan.rs#L856-L896) | 実装確認 |
| ZIP | `ZipArchive`で各エントリをメモリ展開し`scan_memory_buffer`へ渡す。エントリ単位でサイズ事前確認＋実読取上限。**全件数/総展開量/総CPU時間上限、再帰ZIP解析、圧縮率制限は明示的にない** | [filesystem_scan.rs L925–1028](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/filesystem_scan.rs#L925-L1028)、[L1482–1509](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/filesystem_scan.rs#L1482-L1509) | 実装確認／総量耐性未確認 |
| ファイル名IOC | `initialize_filename_iocs`で`;`区切りパターン/score/false-positive regexを取り込み、走査時にパスまたはファイル名と照合 | [main.rs L736–876](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L736-L876)、[filesystem_scan.rs L1066–1108](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/filesystem_scan.rs#L1066-L1108) | 実装確認 |
| ハッシュIOC | MD5/SHA1/SHA256を型別配列にソートし二分探索。2列/3列IOC対応。ファイル名IOCの**後**にFPハッシュを確認し、一致するとそれまでの一致も含め結果を捨てる | [main.rs L288–568](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L288-L568)、[filesystem_scan.rs L1109–1170](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/filesystem_scan.rs#L1109-L1170) | 実装確認 |
| YARA-X | `initialize_yara_rules`は`signatures/yara`直下の`.yar`を個別コンパイル→文字列結合し再コンパイル。`scan_file`がScannerを毎回作りtimeout・外部変数を設定 | [main.rs L886–1003](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L886-L1003)、[filesystem_scan.rs L1312–1428](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/filesystem_scan.rs#L1312-L1428) | 実装確認 |
| スコア/重複 | `GenMatch`を`ArrayVec<_,100>`に先着順格納。重み付き積`100 × (1 − Π(1 − score_i/100/2^i))`で並べ替え後計算、閾値デフォルト80/60/40。**全理由の一意化処理はない** | [filesystem_scan.rs L1060–1275](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/filesystem_scan.rs#L1060-L1275)、[score.rs L14–38](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/helpers/score.rs#L14-L38) | 実装確認 |
| レポート | `LogEvent`にファイル属性、理由、ハッシュ、プロセス情報を構造化。MutexでJSONL追記・flush。`generate_report`がJSONLを再読込しHTML生成 | [unified_logger.rs L56–145](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/helpers/unified_logger.rs#L56-L145)、[L447–485](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/helpers/unified_logger.rs#L447-L485)、[html_report.rs L67–158](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/helpers/html_report.rs#L67-L158) | 実装確認 |
| C2照合 | `check_c2_match`はIP厳密一致、ドメイン末尾一致（CIDRはTODO）。`process_check::get_process_network_info`は`netstat2`経由のプロセスに関連付く**TCP**ソケットを使用。ファイル走査の`scan_memory_buffer`へC2は渡されない | [main.rs L696–735](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L696-L735)、[process_check.rs L724–798](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L724-L798) | 実装確認 |
| 監視の範囲 | `main`が1回の`ProcessCheck`→`FileScan`を順番に実行し、終了サマリーとexit code 0/2。イベント購読による常駐・ファイルオープン前の遮断ではない | [main.rs L1603–1821](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L1603-L1821) | オンデマンド実装確認 |
| 署名更新 | `loki-util update`がYARA Forge core ZIPを取得→段階展開→コンパイル検査→置換し、失敗時に復旧を試行。走査中のホットリロードはなし | [loki_util/main.rs L243–317](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/loki_util/main.rs#L243-L317)、[L333–487](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/loki_util/main.rs#L333-L487) | 実装確認 |

### 2.2 実際の処理順・失敗・検出漏れ

`scan_memory_buffer`は **(1)ファイル名regex → (2)MD5/SHA1/SHA256生成、FPハッシュ照合・悪性ハッシュ照合 → (3)YARA-X → (4)重み付きスコアと閾値 → (5)ログ** の順（[L1033–1287](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/filesystem_scan.rs#L1033-L1287)）。最大100件の`sample_matches`は先着順で、`max_reasons`の表示も`take(n)`で先頭だけ選ぶ（[L1202–1277](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/filesystem_scan.rs#L1202-L1277)）。強い一致が後から出ると表示理由・スコアから欠落し得る。MD5/SHA1/SHA256が同一内容の複数IOCとして独立加点されることもあり、**ルール・同一根拠の重複排除とスコア校正が必要**。

`log_yara_scan_error`ではtimeoutを`logger.file_error`（`event_type=error`）に記録するが、`parse_jsonl_reader`のHTML findingsは`file_match`/`file_scan_warning`/`process_match`のみ対象（[yara.rs L13–61](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/helpers/yara.rs#L13-L61)、[html_report.rs L115–151](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/helpers/html_report.rs#L115-L151)）。したがって「検出0件」と「タイムアウトで未評価」をHTML一覧だけで区別できない事例がある。コード内テストもこの区別を明示（[html_report.rs L2439–2469](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/helpers/html_report.rs#L2439-L2469)）。AegisGuardでは既存`Report.analysis_complete=false`/`not_assessed`を**破壊しない**。

`read_bounded`は単一読み込みの展開サイズを制限するが、ZIP内の多数エントリには繰り返し確保・展開を行う。タイムアウトは**YARA-Xの1回のスキャンのみ**でありZIP展開全体の時間予算ではない。ファイル内ZIPの二重入れ子を深掘りするループも確認できない。「ZIPに対応」≠「任意の入れ子/圧縮爆弾に耐える」。サイズ超過・I/O拒否が`0`件として返り得るため、処理済み・スキップ・失敗を別カウンタで保全すべき。

`check_c2_match`のドメイン末尾一致はラベル境界（`.example.org`）を検査せず、単純な`ends_with`なので意図しない名称にも一致し得る。ただし現行`get_process_network_info`はソケットのIP文字列を使い、DNS照合を標準で行っていない（[main.rs L696–735](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L696-L735)、[process_check.rs L758–798](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L758-L798)）。**ファイルスキャンへC2検出を組み込んだと誤認しないこと。**

### 2.3 テスト・CIの実際

- Rust単体テスト：`read_bounded`の読み込み上限・ファイル切詰め後の所有データ・ZIPヘッダー過少申告（[filesystem_scan.rs L1436–1510](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/filesystem_scan.rs#L1436-L1510)）、スコア（[score.rs L43–104](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/helpers/score.rs#L43-L104)）、hash FP・C2・filename FPなど（[main.rs L1828–2745](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L1828-L2745)）、署名更新の失敗時復元（[loki_util/main.rs L899–1084](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/loki_util/main.rs#L899-L1084)）は**テストコードの存在を確認**した。実行結果は未確認。
- Shellスモークテスト：[YARA](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/tests/detection_tests/test_yara_rule.sh#L1-L110)は「YARA/match」の語が出たかという緩い条件で、実際のルールヒットを必須としない。[Filename IOC](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/tests/detection_tests/test_filename_ioc.sh#L1-L85)もマッチ不在時に警告のみの分岐がある。検出性能の保証とは扱わない。
- [CI workflow](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/.github/workflows/test.yml#L1-L240)のLinux/macOSは`cargo test`・`cargo build`・shell suiteを実行する設計。Windowsは`cargo test`とビルドに続き、バイナリ存在・help・versionの基本確認が中心。**Windows上のZIP/偽装拡張子/IOC/タイムアウト/Defender併用の結合テスト結果は未確認**。
- [`docs/parity_matrix.md`](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/docs/parity_matrix.md#L1-L60)は「Last Updated 2026-01-04」「2.0.1-alpha」の古い自己申告を含むため、2.13.1の真の実装確認はソース優先。 [`docs/score_calculation.md`](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/docs/score_calculation.md#L1-L85)の一部サンプル値と単体テストの期待値に不一致があるため、定量的スコアは実装・再計算で評価する。

## 3. 具体的な取り込み候補と選択肢

| 候補機能 | 利用方法 | AegisGuard接続先 | 優先度 | 工数 S/M/L | 阻害要因/判断 |
|---|---|---|---|---|---|
| スキップ・不完全・異常の明示的な監査モデル | **独自実装**（Lokiの失敗を反面教師に） | `src/model.rs`・`src/scan.rs` | **P0** | **S** | 現行`analysis_complete`を温存、I/O不可・ZIP上限・YARA timeoutを各項目別に区別 |
| ファイル名IOC・SHA-256照合と証拠の正規化 | **独自実装**（ソート索引/regexは設計参考） | `src/scan.rs`・`src/model.rs`、将来のrule loader | **P0** | **M** | 署名出所/バージョン/expiry、許可リストは全検出の抑止でなく理由付き例外にする |
| ZIP検査と制限予算 | **独自実装**、zip crate等は個別審査 | `src/scan.rs` | **P1** | **M** | 総展開量、展開数、深度、比率、時間、ファイル名、失敗記録・回収が必要 |
| 拡張子＋magic判定 | **独自実装**（file-formatのAPIを独立評価可能） | `src/scan.rs` | **P1** | **S–M** | 実際の種別が曖昧な場合はnot_assessedでなくpolicyに沿って再分類。全ファイルスキャンは高負荷 |
| YARA-X実行 | **Rust crate/API直接利用を別途評価** | `src/scan.rs` / 将来のYARA adapter | **P1** | **M–L** | 独立crates.io版を前提。Lokiの`vendor`パッチを自動採用しない。Rust MSRV/ライセンス/タイムアウトは別担当の検証待ち |
| JSONLイベント・HTML可視化 | **AegisGuard独自JSONL維持＋設計参考** | `src/model.rs`・`src/scan.rs` / 将来UI | **P2** | **S–M** | PIIパス・ログflush・HTML escape/XSS・ディスク制限。GPLテンプレートコピー不可 |
| ワーカー数とバックプレッシャー | **独自実装**、Rayon API評価 | `src/scan.rs` | **P2** | **M** | Lokiの`par_bridge`だけでは優先順位、メモリ予算、I/O予算、無制限キューを保証しない |
| Loki-RS外部CLIスキャン連携 | **外部CLI/プロセスとして限定PoCのみ** | 独立アダプタ（現時点で実装しない） | P3 | M | GPL配布形態の法的評価、ユーザー明示同意、結果取り込み、独立実行・権限、exit 2の解釈 |
| Loki-RSソース直接コピー/内包 | **不採用** | なし | — | — | GPL-3.0、現在のAegisGuardライセンス未設定、更新追従コスト |

**入力/出力・失敗の最小契約：**

- **監査モデル**：`ScanRequest {path, policy_id, rule_set_version, limits}` → `ScanOutcome {file_identity?, sha256?, reasons[], status: analyzed|incomplete|not_assessed, reasons_for_incomplete[], started_at, completed_at}`を概念型として提案。I/Oエラー、再解析中の変更、YARA timeout、ZIP予算超過はいずれも`not_assessed/incomplete`にマップし、低リスクに落とさない。PoCは既存`Report`からこの項目へマッピングだけ試す。
- **IOC**：ローカルで検証済みの`HashIndicator {algorithm, value, source, version, expires_at, score}` / `PathIndicator {regex, source, score, fp_regex?}`を受け、`Signal {rule_id, evidence_source, score, provenance}`を出す。重複した原因は同一`rule_id＋artifact_sha256`等でまとめ、**FPは理由を残し調査者承認で抑止**。不正ハッシュ・不正regex・期限切れルールはスキップとエラーの両方を出す。PoCは合法の合成IOCで一致・非一致・誤形式を試す。
- **ZIP**：アーカイブbytes＋上限ポリシー→子`ScanOutcome`とアーカイブ単位の集計。個別上限・総展開バイト数・エントリ件数・再帰深度・時間上限を定義。予算到達は必ず`incomplete`、展開ファイルはディスクに書かずメモリで扱う。PoCは無害な高圧縮テキスト/壊れたZIPを使う。
- **YARA-X**：別担当のAPI仕様が確定後、ローカルの検証済みルール＋バイト配列→ルールID/一致オフセット/メタ情報または構造化エラー。compile failureとscan timeoutを別状態へ。**検出率と安全性をLokiのスコアから直接引き継がない**。
- **レポート**：`Report`の既存JSONLに`engine_version`/`ruleset_sha256`/`coverage`/`error_count`などを追加する設計候補。追記時のアクセス制御、ファイルローテーション、JSONエスケープ、出力先が入力パスと同一にならないことを検証。PoCでは`analysis_complete=false`がHTML等でも見失われないことを確認。
- **ワーカー**：`(PathBuf, priority, budget, cancellation)`入力、順序保証なし`ScanOutcome`出力。cancelや容量超過はイベントに記録し、結果欠落は明示する。PoCは1/2ワーカーの決定的合成ファイル群で比較。

## 4. ライセンス・再配布・依存関係

1. **Loki-RS本体**：[`LICENSE`](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/LICENSE#L1-L20)はGPL Version 3。AegisGuardへのソースコピペ・静的リンク・改変版同梱はGPLの条件とAegisGuardの採用ライセンスを法的に評価するまで保留。APIや設計概念だけを参考に独立した実装を書く。
2. **外部CLI**：独立した実行ファイルとして利用する構成は、直接リンクと異なる選択肢だが「CLI経由なら常にGPL義務がない」と断定しない。組合せの実体・同梱方法・通信方式・配布物の権利表示・ソース提供義務を法務確認。**法的評価未完了**。
3. **YARA-X**：Lokiの[`Cargo.toml`](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/Cargo.toml#L1-L77)は`yara-x = "1.17.0"`を宣言しつつ`[patch.crates-io] yara-x={path="vendor/yara-x"}`でベンダー版へ差替え。[ベンダーmanifest](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/vendor/yara-x/Cargo.toml#L13-L41)には`license="BSD-3-Clause"`、`rust-version="1.91.0"`と記載。**AegisGuardはRust 1.85**（[Cargo](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/Cargo.toml#L1-L28)）。単なる依存追加ではMSRVが足りない可能性が高い。ベンダー差分・同梱ソース中の独立ライセンス・再現ビルドを担当`yara-rust-api`へ引継ぎ。
4. **YARAルール**：`loki-util`が[YARA Forge coreを取得](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/loki_util/main.rs#L12-L17)する。[YARA Forge](https://github.com/YARAHQ/yara-forge)は複数の第三者ルールを集約する。Forgeツール自体の`LICENSE`はGPL v3だが、**配布される各YARAルール/IOC/サードパーティシグネチャに同一ライセンスが自動で適用されるとは断定できない**。ルールごとの出所・配布条件・派生物・商用使用・帰属表示を未確認扱いとする。ルールを本リポジトリに同梱していない。
5. **IOCデータ**：`hash-iocs.txt`、`filename-iocs.txt`、`c2`を読み込む仕組みはコードで確認したが、**IOC集合の原著作者・ルール別ライセンス・再配布条件は未確認**。AegisGuard既存のFeodo/C2IntelFeedsもデータの権利を別途審査する。
6. **Rust依存関係**：主な直接依存は`rayon 1.11`、`walkdir 2.5`、`file-format 0.28`、`zip 7`（aes-crypto/bzip2/deflate64/deflate/ppmd/zstd等）、`regex 1.12`、`csv 1.4`、`md5/sha1/sha2`、`serde/serde_json`、`netstat2 0.11`、`windows 0.62`、`sysinfo 0.38`、`ureq 3.2`、`yara-x 1.17`等（[Cargo](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/Cargo.toml#L14-L75)、[lockfile](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/Cargo.lock)）。これら**全依存のSPDXとWindowsバイナリのサプライチェーン監査は未完了**。crateごとに個別評価。Lokiの`LICENSE`が全データ/依存を一律に再ライセンスするわけではない。

## 5. Defender共存・Windows制約・権限境界

- **Windows 11 x64**：ファイル走査・JSONLは標準権限で読める範囲のみ。Lokiは非昇格時に警告を出す（[main.rs L1310–1327](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L1310-L1327)）。保護ディレクトリ/他プロセスメモリ/ネットワークドライブにはアクセス制約がある。`OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ)`で読める範囲だけ取得し、400MBの内部上限がある（[process_check.rs L801–865](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L801-L865)）。管理者昇格を常時必須とはしない。
- **Defenderと二重走査**：オンデマンドの読み出しでディスクI/O・CPU・電池使用量が重複し得る。Defenderリアルタイム保護、AMSI、ASR、Exploit protectionを停止/例外追加してはならない。PoCはDefender有効のまま、ユーザー所有の無害なフォルダーに限定する。
- **WFP/ETW/Sysmon/AMSI**：Lokiの当該ファイルスキャンはこれらを購読・操作していない。`netstat2`を使うプロセスのTCPスナップショットはSysmon Event 3やETWの時間的相関を代替しない。WFPブロック機能もない。AegisGuard側の計画は[ARCHITECTURE](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L12-L65)を参照。常駐/遮断・Windowsイベント対応は本担当の範囲外。
- **リンクとTOCTOU**：`entry.path_is_symlink()`/`symlink_metadata`と`File::open(path)`は別タイミングで実行される。置換競合、Windows reparse point、ハードリンク、UNCパス、マウント変更はハンドルベースの同一性確認を検討。AegisGuard[SECURITY](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md#L5-L15)も同様のraceを公認。
- **ネットワーク/機密性**：通常ファイルスキャンでは検体を外部送信しない一方、Lokiには任意`--remote`出力があり、JSONLにはローカルパス・ホスト名・プロセス・一致文字列が入る（[main.rs L80–94](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L80-L94)、[unified_logger.rs L89–145](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/helpers/unified_logger.rs#L89-L145)）。AegisGuardのデフォルト外部送信禁止方針を保持し、ログACL・機密情報除去・opt-inを必須とする。

## 6. 性能・堅牢性・誤検知

| 論点 | コードで確認できたこと | 統合時の注意・測定 |
|---|---|---|
| CPU | Rayon並列＋作業後sleepの`CpuThrottler`。`--threads=-2`のCPU数−2（下限1） | 実負荷率の上限保証なし。実機でCPU、I/O、P95/P99処理時間、電池消費を計測 |
| メモリ | 各ワーカーが最大`max_file_size`の`Vec<u8>`、ZIPのエントリも個別に展開 | ワーカー数×バッファ、同時ZIPの一時割当、上限到達時挙動、OOMを測る |
| アーカイブ | エントリごとの展開量上限はテストあり、総量/件数/経過時間の全体上限はなし | 高圧縮ファイル、多数エントリ、壊れたZIP、入れ子ZIPを無害な合成データで確認 |
| 誤検知 | FP filename regexとFP hash、可変スコア、重み付き合成 | FPハッシュで全シグナルが抑止される副作用。検出理由のプロビナンス保存、単一IOCでの断定を避ける |
| 検査漏れ | magicに合わない種類、サイズ超過、アクセス拒否、100件上限、YARA error、未展開nested ZIP | `analyzed / incomplete / not_assessed`＋スキップ理由別カウントを受け入れ条件へ |
| ログ | JSONLで各イベントを`flush`。HTMLはJSONLを再読込み・メモリ内に集計 | 多数イベント時のI/O/メモリ、rotation、JSONL肥大、HTML生成失敗を測定 |
| 署名更新 | `loki-util`には一時ディレクトリ、compile検証、rollbackテストがある | 更新成功時は`ruleset_sha256`/世代番号を更新し、**旧結果キャッシュを世代単位で無効化**。Lokiに永続スキャンキャッシュ/自動無効化は確認できない |
| Win11 CI | Windows jobは起動基本確認が中心 | Windows固有reparse/UNC、ファイルロック、Defender競合、非昇格を実機で検証 |

数値はコードに明示された**設定既定値・上限**のみを記載した。スループット、検出率、実際のCPU上限達成率、誤検知率の実測値は**なし**。

## 7. 推奨する小さなPoCと成功基準

### 導入候補上位3件

1. **P0 / S — 状態遷移・カバレッジの忠実な報告**：既存`Report`を保持し、サイズ超過・I/O拒否・ルール構文エラー・YARA timeout・ZIP総量超過を区別。**ブロッカー**：エラー分類とUI/JSONLの互換スキーマ。
2. **P0 / M — SHA-256＋ファイル名IOCの独立照合**：模擬ルールのみから開始。重複統合、ルール出所、FP例外の監査証跡を持つ。**ブロッカー**：フィード権利・署名更新の世代とスコア校正。
3. **P1 / M — 上限付きZIP・ファイル種別選別**：メモリ/展開数/合計byte/深度/時間を合わせた予算。**ブロッカー**：ZIPライブラリの検証・TOCTOU/途中失敗の報告。

### 安全な最小PoC（実装前の受け入れ基準）

- **前提**：無害な合成`.exe`風ファイル、文字列だけの`.ps1`、通常テキスト、予め作った短いYARAルール、壊れたZIP、少数の高圧縮テキストのみ。Windows 11 x64、標準ユーザー/昇格の両方を別テスト。Defender有効でオフライン。悪性サンプルや自動遮断を使わない。
- **再現手順**：①基準CLIの`scan`出力を保存、②同じ合成ファイルを新ポリシーで走査、③1/2ワーカーを比較、④FPと悪性IOCを同一ファイルに故意に付与、⑤サイズ/件数/時間/深度上限をそれぞれ独立して発火、⑥ZIP変更/ルール更新/中断/再実行、⑦生成JSONLを解析して結果件数・エラー数と一致させる。
- **機能成功**：一致理由と出所が再現可能。上限到達・アクセス拒否・YARA失敗時は`analysis_complete=false`または`not_assessed`になり「clean」「安全」と解釈されない。総ZIP予算の越境は発生せず、無限展開/停止不能なし。走査結果での許可リストは理由付きで監査可能。同じルール世代の再実行は論理的に同じ判定。
- **性能測定**：ファイル数/総bytes/ZIP展開bytes/処理時間/ピークRSS/CPU負荷/I/O/ログbytesを取得。ベースライン比と上限逸脱を記録するが、**未測定の速度向上率を合格基準として捏造しない**。PoCで事前設定した資源予算を超えた時は中断し、理由をJSONLへ出す。
- **失敗時/ロールバック**：機能フラグ無効にして既存`src/scan.rs`の単一パスへ戻せる設計。破損ルール更新は旧版を保持して使用、キャッシュ世代一致を要求。ログはローカルのみ、ACLを維持する。
- **中止条件**：Defenderの無効化が必要、第三者に検体/ログを送る必要がある、外部GPLコードのコピーを求められる、メモリ/展開上限を保証できない、不完全状態を正常完了へ変換してしまう場合。

## 8. 採用しない設計と理由

1. **Loki-RS本体をAegisGuardへコピペ/静的統合**：GPL-3.0の再配布条件、依存更新、AegisGuard未ライセンス、Rust MSRV差異を抱える。現在の機能の大半は独立実装/独立crate評価で代替可能。法的評価未完了。
2. **FPハッシュ一致による全検査結果の即時抹消**：Lokiの`scan_memory_buffer`が`return (1,0,0,0,0)`する形は、別の強いヒューリスティック/YARA一致を見逃す。許可リストは検出根拠を消さず、重み付き可視化/人の承認に限定。
3. **LokiのCPU sleep方式を「厳格なCPU上限」として採用**：ワーカー個別のsleepは全体負荷制御やI/O競合を保証しない。別途リソース計測とバックプレッシャーを設計。
4. **Lokiの既定スコア/閾値・HTMLを無変更で持ち込む**：複数検出原因の相関・重複、未評価と非検出の混同、GPL由来HTMLの流用問題がある。既存AegisGuardの`review/high`は独自の証拠強度として維持。

## 9. 他担当との境界・引継ぎ

- **`yara-rust-api`担当**：YARA-X最新版、Rust 1.85とのMSRV、`vendor/yara-x`差分、APIのタイムアウト/コンパイル/メタ情報/一致オフセット/偽装ルール耐性の詳細。ここでは呼出し順とレポートへの接続だけを判定。
- **署名・更新担当**：YARA Forge各ルールのライセンス/帰属、HTTPS取得物の真正性と改ざん検証、検証失敗時のatomic rollback、世代番号・キャッシュ失効、差分/巻き戻し。Loki更新実装の存在は確認したがAegisGuard統合の決定はしない。
- **Windowsイベント/ネットワーク担当**：LokiのC2はプロセスソケットのオンデマンドスナップショットであり、ETW/Sysmonによる時系列・WFPによる遮断ではない。プロセスIDだけの関連付けやドメインIOCの扱いはそちらで検証。
- **AegisGuardコア設計者**：`Report`スキーマ、スコア校正、誤検知監査、標準ユーザー権限、Defenderと共存したポリシーを統括。ほかの担当ファイルは変更しない。

## 10. 未確認事項・追加調査項目

| 重大度 | 未確認/要実測 | 次の確認 |
|---|---|---|
| **高** | ZIPの大量エントリ、CRC不整合、巨大メタデータ、nested ZIP、展開タイムアウトとメモリ上限の実機挙動 | 合成テスト・プロファイル |
| **高** | Windows reparse-point/UNC/ハードリンク/ファイル置換race、AVロック時の読み取り | Defenderを有効にしたWin11テスト |
| **高** | GPL-3.0とAegisGuard配布形態の関係、YARA Forge配布ルール・IOC・ベンダーコードの個別ライセンス | SPDX/SBOM/法務確認 |
| **高** | LokiのYARA-X `vendor`パッチとcrates.io版の差分、Rust MSRV 1.91問題、依存の脆弱性 | `yara-rust-api`担当・Cargo.lock監査 |
| 中 | Win11の検出ロジック結合テスト、FP率・FN率、利用しない種別の検査漏れ | 誤検知用の無害なコーパス |
| 中 | 入力を変更した場合のルール世代別結果キャッシュ・ホットリロード/無効化 | AegisGuard独自設計。Lokiでは永続キャッシュ未確認 |
| 中 | C2 domain suffixのラベル境界・IPv6・UDP・DNS関連付け | ネットワーク担当 |
| 中 | システム負荷率、I/O・電池消費、Rayon queueのバックプレッシャー、HTML大量ログ・ログ漏洩 | ローカル性能計測 |
| 低 | `v2.13.1`のリリースタグと調査master SHAの厳密な対応 | Gitタグcommit比較 |

## 11. 一次情報一覧

**すべて2026-11-05に閲覧。コードリンクはLoki-RS `0866b3d0e32d82f8b5776f61c67b655a34a55b4a` またはAegisGuard `83fcf0d150e8d760baff5f971c106deb09c1f8e4` に固定。** 少なくとも以下の実装箇所を突き合わせた。

1. [Loki走査設定・CLI](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L21-L180) — スキャン対象、サイズ、threads、CPU、YARA timeoutの既定値。
2. [Loki起動・スレッド・モジュール順](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L1171-L1340)、[モジュール実行](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L1603-L1821) — オンデマンド実行と終了コード。
3. [Lokiファイル列挙/並列](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/filesystem_scan.rs#L503-L629) — WalkDir+Rayon、read_bounded。
4. [対象ファイルと除外](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/filesystem_scan.rs#L630-L928) — symlink、cloud/ネットワーク、size、magic。
5. [ZIP子ファイル](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/filesystem_scan.rs#L925-L1032)、[ZIP過少申告テスト](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/filesystem_scan.rs#L1482-L1509)。
6. [ファイル名・FPハッシュ・hash照合](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/filesystem_scan.rs#L1033-L1175)、[IOC初期化](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L288-L568)。
7. [YARA-X/スコア/理由の先頭打ち切り](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/filesystem_scan.rs#L1175-L1428)、[重み付きスコアテスト](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/helpers/score.rs#L1-L104)。
8. [プロセスC2/ネットワーク情報](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L724-L801)、[C2照合](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L696-L735)。
9. [JSONLイベント/ライタ](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/helpers/unified_logger.rs#L56-L145)、[L447–485](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/helpers/unified_logger.rs#L447-L485)、[HTML読み込み](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/helpers/html_report.rs#L67-L158)。
10. [YARAエラー](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/helpers/yara.rs#L13-L61)、[HTML検査失敗テスト](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/helpers/html_report.rs#L2439-L2469)。
11. [署名ダウンロード/コンパイル/巻き戻し](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/loki_util/main.rs#L243-L488)、[失敗時テスト](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/loki_util/main.rs#L899-L1084)。
12. [LokiのGPL-3.0原文](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/LICENSE#L1-L20)、[直接依存/ベンダーパッチ](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/Cargo.toml#L1-L75)、[YARA-XのBSD-3-Clause/MSRV宣言](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/vendor/yara-x/Cargo.toml#L13-L41)。
13. [外部テスト](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/tests/detection_tests/test_yara_rule.sh#L1-L110)、[CI](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/.github/workflows/test.yml#L1-L240)。
14. [AegisGuard現行ファイルスキャン](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/scan.rs#L1-L155)、[モデル](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/model.rs#L1-L110)、[安全方針](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md#L1-L55)、[設計](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L1-L75)。

**結論**：Loki-RSはオンデマンドのスキャン設計を比較するための有力な一次資料だが、コピーして常駐AV化するのではない。AegisGuardの強みである「検査不能を安全と呼ばない」モデルを核に、ライセンスが明確なAPIと予算制御された独自パイプラインへ段階的に拡張するのが安全である。
