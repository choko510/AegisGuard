# 調査報告：ClamAV / clamav-signature-update

> 担当：clamav-signature-update / 調査日：2026-11-05 / 調査結果：ソース・テスト・依存関係の静的調査完了（実行検証は未実施）

## 0. 結論（3〜5行）

- **取り入れる価値：高い。ただし設計パターンとして。** CVD/CDIFF更新は「取得→真正性確認→展開/適用→ロード試験→切替」を具体的に実装する。ただしWindowsでの切替には削除先行経路があり、トランザクションをそのまま模倣できない。
- **最優先候補：AegisGuard独自の署名付き更新マニフェスト、ソース別のバージョン/失効管理、二世代保持を伴う安全な切替。** C2 IPフィードと将来のYARA-X双方に適用する。
- **見送り：ClamAVのGPLv2実装をRustアプリに直接コピー/リンクすること、公式CVD/第三者ルールの無条件同梱とYARA-Xへの形式流用。**
- **最大の制約：配布データの権利関係・供給者の信頼・署名鍵管理・Defenderとの負荷競合。** 本体ソフトウェアのGPLv2を「公式署名DBや第三者署名の自由な製品再配布許可」と読み替えない。**法的評価未完了。**
- **注意：** ClamAVの差分更新は一部欠落を許容する場合があるが、AegisGuardの自動遮断用IOCでは同じ緩和を初期採用しない。

## 1. 対象の固定と調査方法

| 要素 | 値 / 根拠 |
|---|---|
| 公式リポジトリ・commit固定URL | [Cisco-Talos/clamav](https://github.com/Cisco-Talos/clamav/tree/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d)。GitHub上のデフォルトブランチは main |
| 調査コミットSHA・タグ | **dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d**（main、2026-10-22のマージコミット）。同時点の [CMakeLists.txt L18-L25](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/CMakeLists.txt#L18-L25) は開発版 1.6.0。GitHub Releases の latest 表示は **clamav-1.5.4（2026-08-07公開）**。調査対象のmainと安定版を混同しない |
| AegisGuard比較先 | **83fcf0d150e8d760baff5f971c106deb09c1f8e4**、[main固定](https://github.com/choko510/AegisGuard/tree/83fcf0d150e8d760baff5f971c106deb09c1f8e4) |
| ライセンス | [ClamAV COPYING.txt](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/COPYING.txt) はGPLv2（OpenSSLリンクの例外記載あり）。[README L103-L139](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/README.md#L103-L139) は組込み第三者コードの別ライセンスを明記。公式署名DBの同梱・再頒布の独立許諾は確認できず |
| AegisGuard確認 | [README](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md)、[SECURITY.md](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md)、[設計文書](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md)、[Cargo.toml](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/Cargo.toml)、src/c2.rs・src/main.rsを確認 |
| 外部ソース確認 | libfreshclam/*.c、freshclam/*.c、libclamav/cvd.c、libclamav_rust/src/{cvd,cdiff,codesign}.rs、Cargo.toml、設定man、unit_tests/freshclam_test.py、unit_tests/clamscan/fp_check_test.py、unit_tests/CMakeLists.txt、COPYING類 |
| ビルド・テスト | **未実施**。安全性を損なう実サンプル実行なし。テストコードと期待値を静的に精査したのであって、Windows上で動作・性能を確認したわけではない |
| 情報確認日・制限 | 2026-11-05。公開ソース、公式マニュアルと現在のリポジトリ状態の確認。実際のCVD内部のCOPYING、CDNの配布契約、商用同梱許諾、実デバイス負荷は未確認 |

### AegisGuardの実態

現在のMVPは静的ファイル/スクリプト解析と**明示的に実行するC2更新/照合**が中心。src/c2.rsはダウンロード上限8 MiB、ソースごと最大50,000 IP、48時間のTTL、IPリテラル検証を持つ（[L17-L30](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L17-L30)、[L198-L238](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L198-L238)）。一部の取得だけ失敗した場合、そのフィードの旧内容と成功時刻を維持し、期限切れの一致は有効一致から除外する（[L260-L329](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L260-L329)、[L378-L409](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L378-L409)）。一時ファイル・.bakを使う更新はあるものの、強制終了/電源断をまたぐ自動回復、署名付き供給元証明、署名付きルール更新は未実装（[L286-L354](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L286-L354)、[SECURITY.md](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md)）。YARA-X、常駐センサー、AMSI/WFP/Sysmon連携も**計画のみ**。

## 2. 実装アーキテクチャとソース調査

| 機能 | 主要ファイル・シンボルと実際の挙動 | commit固定の一次情報 | 確認状態 |
|---|---|---|---|
| 更新の起点 | freshclamはlibfreshclamを呼び、データベース更新後にコールバックでロードテストできる。テストはcl_loadとbytecode準備まで試みる | [freshclam.c L264-L438](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/freshclam/freshclam.c#L264-L438)、[libfreshclam.c L469-L533](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libfreshclam/libfreshclam.c#L469-L533) | 実装確認 |
| バージョン確認 | query_remote_database_versionはDNS TXT、HTTPのCVD/CLDヘッダを用い、失敗時は代替取得経路を試す | [libfreshclam_internal.c L2044-L2220](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libfreshclam/libfreshclam_internal.c#L2044-L2220) | 実装確認 |
| CVD正当性検証 | getcvdはダウンロードした一時CVDのヘッダを検査し、バージョン対応の .cvd.sign を取得可能なら取得し cli_cvdverifyを実行。欠落した.signは旧形式の内部RSA署名での検証を試みる | [libfreshclam_internal.c L1457-L1599](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libfreshclam/libfreshclam_internal.c#L1457-L1599) | 実装確認 |
| 署名検証ポリシー | cvd.rsのverifyは外部署名の**不正**を検知するとエラーにし、検証不可の場合だけ旧内部RSA署名へフォールバックする。FIPS制限時は旧MD5経路を許さない | [cvd.rs L325-L479](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav_rust/src/cvd.rs#L325-L479) | 実装確認 |
| 証明書による外部署名 | codesign.rsのVerifierは設定された証明書ストアでPKCS#7署名を検証する。信頼する証明書の運用は別途必要 | [codesign.rs L608-L696](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav_rust/src/codesign.rs#L608-L696) | 実装確認 |
| CDIFFパッチ | downloadPatchAndApplyはバージョン別 .cdiff と任意の .cdiff.sign を一時作業領域へ取得。Rustのcdiff_applyは外部署名/旧RSA署名の検証を行ってから差分命令を適用する | [libfreshclam_internal.c L1699-L1832](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libfreshclam/libfreshclam_internal.c#L1699-L1832)、[cdiff.rs L641-L749](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav_rust/src/cdiff.rs#L641-L749) | 実装確認 |
| CDIFF失敗・部分更新 | updatedbはパッチ取得失敗時に再試行し、空パッチ/適用失敗等では完全CVDへ切替。一部だけパッチ適用できた場合、欠落数と条件によって**部分更新のCLDを採用**する | [libfreshclam_internal.c L2489-L2634](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libfreshclam/libfreshclam_internal.c#L2489-L2634) | 実装確認 |
| CLDの性質 | パッチ後にbuildcldでCLDを生成する。コードは「CLDは署名できないためsignファイルをコピーしない」と明記。更新チェーンの信頼は取得したパッチの検証に依存する | [libfreshclam_internal.c L1879-L2041](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libfreshclam/libfreshclam_internal.c#L1879-L2041)、[L2615-L2641](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libfreshclam/libfreshclam_internal.c#L2615-L2641) | 実装確認 |
| 切替と旧DB保持 | ロードテスト成功後にrename。**Windowsでは置換先が存在すると先にunlinkする実装**。同名の旧DBを永続バックアップする保証はない。失敗時に常に旧DBが残ると断定できない | [libfreshclam_internal.c L2640-L2730](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libfreshclam/libfreshclam_internal.c#L2640-L2730) | 実装確認・重大な移植上の注意 |
| アップデートレート制限 | HTTP 403で少なくとも24時間、429でRetry-Afterがなければ少なくとも4時間の再試行停止情報をfreshclam.datに保持 | [libfreshclam_internal.c L1362-L1414](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libfreshclam/libfreshclam_internal.c#L1362-L1414)、[L172-L381](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libfreshclam/libfreshclam_internal.c#L172-L381) | 実装確認 |
| 独自/第三者データ取得 | updatecustomdbはfile://やURLの独自DBを別経路で取り込む。ロードテスト後置換するが、一般テキストDBにCVD公式署名同等の真正性保証が自動付与されるわけではない | [libfreshclam_internal.c L2783-L2975](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libfreshclam/libfreshclam_internal.c#L2783-L2975) | 実装確認 |
| 誤検知抑制 | ClamAVは.fp/.sfpでファイル許可、.ign2で検出名を除外。ign2は署名エントリのMD5を指定して更新時に例外を無効化できる | [公式Allow Lists](https://docs.clamav.net/manual/Signatures/AllowLists.html)、[fp_check_test.py L97-L164](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/unit_tests/clamscan/fp_check_test.py#L97-L164) | 機能は実装/テスト・仕様は公式文書 |
| clamdへの反映 | freshclam.confのNotifyClamdでDB更新後にclamdへリロード通知。デーモンの導入が必須というわけではない | [freshclam.conf.5.in L180-L195](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/docs/man/freshclam.conf.5.in#L180-L195)、[notify.c L155-L188](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/freshclam/notify.c#L155-L188) | 実装確認 |

### 更新の状態遷移と失敗モード

1. ローカルCVD/CLDとリモート版を照合。ローカルがリモートより新しければ即座に古い版へ戻すのではなく現行版を扱う（[updatedb L2423-L2475](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libfreshclam/libfreshclam_internal.c#L2423-L2475)）。**署名付きの最小許容バージョンを永続的に保持するアンチロールバック機構がある、とは確認できない。**
2. 初回/差分無効ならCVD全体。差分可能なら連続したCDIFFを取得・署名検証し、一時ディレクトリへ適用。CDIFFから再生成したCLDは、配布済みの署名付きCVDと同じ署名付データではない。
3. CDIFFが空、更新失敗、サーバー上に適切な差分がない場合は全部取得への退避、または一定条件で途中の版のCLDを採用。[テスト L444-L529](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/unit_tests/freshclam_test.py#L444-L529) は「3件中2件適用」を成功扱い。**遮断用データには欠落したルールの意味を判定できないので、この基準を流用しない。**
4. ロード試験が失敗すれば本番置換前に中断する一方、Windowsで旧ファイルを削除した後のrename失敗やプロセスクラッシュは、旧版を必ず復元できる設計ではない。AegisGuardは二世代保持・検証済みディレクトリの切替・起動時復旧を独自に要する。
5. 署名真正性は「正規配信者が出した内容か」の検証であり、「検出率が十分か」「誤検知がないか」の保証ではない。Allow Listsと保留/監査モードを別に必要とする。

### テストを実際に読んだ範囲

- [freshclam_test.py L180-L311](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/unit_tests/freshclam_test.py#L180-L311)：モックHTTPで403/429、再試行抑止の期待文字列を確認する**テスト定義**。
- [L312-L376](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/unit_tests/freshclam_test.py#L312-L376)：CVD 1からCDIFF 2〜6でCLDへの更新を想定。
- [L444-L612](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/unit_tests/freshclam_test.py#L444-L612)：パッチ欠落時の部分更新。
- [L613-L734](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/unit_tests/freshclam_test.py#L613-L734)：ゼロバイトパッチと、広告された版より古いCVDを返すミラーからの段階的回復。
- [cdiff.rs L1380-L1759](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav_rust/src/cdiff.rs#L1380-L1759)：差分コマンドMOVE/DELETE/EXCHANGEなどの成功・不正入力・境界条件のRustユニットテスト。
- [fp_check_test.py L97-L267](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/unit_tests/clamscan/fp_check_test.py#L97-L267)：誤検知許可の挙動とFIPS時にMD5/SHA1ベースのFPルールが動かない条件を試すテスト。
- [unit_tests/CMakeLists.txt L352-L405](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/unit_tests/CMakeLists.txt#L352-L405)：上記テストをCTestに登録。**本調査では実際にCTestを実行していない。**

## 3. 具体的な取り込み候補と選択肢

| 候補機能 | 利用方法 | AegisGuard接続先 | 優先度 | 工数目安 | 前提・阻害要因 |
|---|---|---|---|---|---|
| **1. 署名付きマニフェスト/版・発行元検証** | **独自Rust実装**（ClamAV設計参考） | 新規ルール更新層→C2・YARA-X | **P0** | **M** | 署名鍵配布・ローテーション・失効/期限・最小バージョン管理。ClamAVのGPLコードは転用しない |
| **2. ステージング→検査→二世代切替** | **独自Rust実装** | C2キャッシュ保存、将来のルールストア | **P0** | **M** | NTFSの置換失敗、ファイルロック、ACL、クラッシュ時回復、原子的参照切替の設計 |
| **3. 例外/失効/ソース来歴と監査** | **独自Rust実装**（ign2等を参考） | IOC判定、アラート、将来のYARA-X | **P1** | **S〜M** | 署名IDと内容ハッシュ、例外期限、誤検知監査、元フィードのライセンス |
| CDIFF風差分更新 | **設計参考→独自実装を条件付き検討** | 将来の大きなルール配信 | P2 | L | 完全版SHA-256との照合、差分の完全性、サイズ上限、全量更新へのフォールバック。現行小規模C2では複雑性が勝りやすい |
| ClamAVの署名を別製品として検査 | **外部CLI/サービス**（利用者が別途導入） | 将来の任意検査アダプタ | P2 | M | 再配布法務・CLI実行制限・スキャン二重化・常駐負荷。現在の担当範囲は署名更新中心、実検査設計は別担当 |
| libfreshclam/libclamavのRust/C API直利用 | **見送り** | なし | 不採用 | L | 現在のRust部分は[staticlib＋C連携](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav_rust/Cargo.toml#L39-L45)で、独立した許諾済みアップデータcrateではない。GPLv2とABI/配布管理が障壁 |
| CVDをYARA-Xルールとして直接ロード | **見送り** | なし | 不採用 | L | CVDはClamAV固有の複数形式・バイトコード等を含むコンテナ。YARA-Xがそのまま解釈できる根拠なし |

### 採用候補ごとの契約と最小PoC

**P0-1 署名付き更新の入力/出力：** 入力は取得先ID、ローカルの信頼公開鍵/鍵ID、署名付きmanifest（schema_version、feed_id、sequence、created_at、expires_at、payload SHA-256、byte_length、署名、必要エンジン版、削除/失効リスト）。出力は検証済み候補または拒否理由（署名不正、期限切れ、単調増加版違反、サイズ・JSON構造・供給者不一致）。原則HTTPSに加え、**TLSと独立のコンテンツ署名**、key pinning/失効と検証済み最小sequenceの永続管理が必要。失敗は旧データと旧成功時刻を保持し、期限切れデータの利用は警告または監査限定。PoCはローカルの生成テスト鍵・模擬manifestで正常/改ざん/リプレイ/鍵失効を検証する。元のClamAVの証明書/CVD署名コードをコピーしない。

**P0-2 安全な切替：** 入力は上記の検証済み候補と直前の有効generation。出力は不変generationディレクトリ、検証済みcurrent参照、前generation、更新イベント（旧/新ハッシュ・版・成功/失敗）。展開は私有ACLの作業ディレクトリに限定し、上限検査→完全パース/コンパイル→必要なら読み込み成功を試す→新generationを永続化→current参照を切替。単一ファイルのrenameだけで**電源断耐性やWindows原子的置換を保証しない**。失敗時は旧generationを有効にし、起動時に未完了マーカーとハッシュを検証して復旧。PoCは書込中断・参照切替直前・切替直後・ファイル使用中・容量不足を模擬する。src/c2.rsの既存.bak処理と整合させる。

**P1-3 誤検知/失効：** 入力は（source, rule_id, content_hash, first_seen, expires, verdict, rationale）とユーザーの例外登録。出力は「照合・監査のみ・失効・例外適用・更新未検証」の区別されたイベント。フィードがIPを削除した場合、期限切れや再割当の場合、また署名改版で例外の対象が変わった場合を扱う。ClamAVの.ign2が内容ハッシュと紐付けられる点を参考とし、**広域の永久ホワイトリストを初期値にしない**。PoCは架空IPと無害なローカルルールで、悪性扱いの自動遮断なしに差分更新・失効・ルール改版を検証する。

**外部CLI分離：** もしユーザーがClamAVを別途インストールする場合のみ、許可した実行パスからfreshclam/clamdを起動・状態参照する候補。入力はユーザー選択、明示されたDB保存先/タイムアウト、出力は終了ステータスとDB版/更新時刻。文字列連結シェルは禁止し、任意引数・任意URLを受け付けない。アップデート不能/ライセンス不明時はAegisGuardのC2/YARA-X更新に連鎖させず、独立したオプションとして保留。

### 製品へ同梱するか、利用者に取得させるか

| 方法 | 便益 | コスト/失敗モード/契約 |
|---|---|---|
| **第三者ルール/公式CVDを製品同梱** | オフラインの初回使用、初回通信が不要 | インストーラ肥大、古い署名、再配布・改変・帰属表示・商用利用条件の個別確認が必須。公式署名DBの再頒布許諾は本調査では**未確認** |
| **利用者が提供元から別途ダウンロード** | 同梱に関する負担を減らし、更新元を明確化できる | ネット接続・配布先変更・レート制限・サポート切れ・初回DL失敗・PII/環境情報の送信の確認が必要。取得したデータの利用条件は依然確認が必要 |
| **ユーザー管理の私設ミラー** | LAN内の帯域削減、分断ネットワーク対応 | [公式Private Mirror文書](https://docs.clamav.net/appendix/CvdPrivateMirror.html) がFreshClam/CVDUpdateでの**私的利用向け構成**を説明。一般向け製品のバンドル/第三者への公開配信権まで示すものではない。HTTP Range非対応では全量転送が起こり得る |
| **AegisGuard独自IOC/ルール** | 再現可能な検証パイプラインと公開鍵運用を一元化 | 作成ルールと元データの権利は別。出典、再配布可否、改変可否、利用目的、削除要請を明示的に記録 |

## 4. ライセンス・再配布・依存関係

| 対象 | 一次根拠 | 利用上の評価 |
|---|---|---|
| ClamAV本体 C/Rust ソース（freshclam/libfreshclam/libclamav） | [COPYING.txt](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/COPYING.txt)、[README](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/README.md#L103-L139) | GPLv2。コードコピー/直接リンクには頒布時義務や派生物評価が生じる可能性。AegisGuard本体は現時点でライセンス未設定であり、安易に取り込めない。外部プロセス連携でも頒布形態・一体性の評価は**未完了** |
| ClamAV内の第三者コード | [README L114-L139](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/README.md#L114-L139)、[COPYING/COPYING.YARA](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/COPYING/COPYING.YARA)、[libclamunrar/license.txt](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamunrar/license.txt) | YARA由来コードはApache-2.0告知、UnRARは再実装制限がある独自ライセンスで、READMEはランタイムロード扱いと説明。システム全体を単一のGPLラベルで評価しない |
| **Cisco Talos公式CVD/CLD/CDIFF** | [署名説明](https://docs.clamav.net/manual/Signatures.html)、[private mirror](https://docs.clamav.net/appendix/CvdPrivateMirror.html)、[EOL方針](https://docs.clamav.net/faq/faq-eol.html) | **配布ファイル自体のライセンス原文と第三者向け製品同梱許諾を確認できない**。GPLv2はソースの許諾として確認できたが、署名データ一式の権利と同一とは証明されない。法的評価未完了 |
| 第三者の.ndb/.ldb/.yar/.fp等 | [公式フォーマット一覧](https://docs.clamav.net/manual/Signatures.html) | フォーマットがオープンでもルール本文の著作権/利用条件は**供給者ごと**。必須のライセンス/著作者/再配布/改変/二次利用のメタデータなしに製品へ同梱しない |
| C2フィード（Feodo/C2IntelFeeds） | [AegisGuard README](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md) | 現状は各サイトからの利用者側取得で再配布はしない。フィードの原本利用条件は今回別途包括監査しておらず、**署名化して再配布する前に個別確認** |
| 独自署名更新処理 | ClamAVのソースを**技術の参考**として読むのみ | 新規Rust実装・独自テストデータ/マニフェストを用い、ClamAVコード/署名をコピーしない選択が法務・依存管理の両面で低リスク。ただし暗号実装はレビューと鍵運用が必要 |

依存の実体：ClamAVはCMake/CとRustを混在させ、C側はlibcurl等のHTTP/TLS、zlib、libclamav、OSのファイルAPIに依存する。[libclamav_rust/Cargo.toml L1-L45](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav_rust/Cargo.toml#L1-L45) はopenssl 0.10.70、sha2、sha1、md5、flate2、tar、glob、tempfile、clam-sigutil（Git tag 1.2.4）およびGitブランチを参照するonenote_parser等を宣言。crate-type は staticlib。**単独のRust署名更新ライブラリとして簡単に埋め込める構成ではない**。上流バージョン更新・外部Git依存固定・SBOM/CVE監査も必要。

## 5. Defender共存・Windows制約・権限境界

- **現行のAegisGuardにはリアルタイムスキャナがない**。署名更新機能単体はSysmon/ETW/WFP/AMSIを必要とせず、ユーザー領域のキャッシュとHTTPS取得で足りる。既存のDefenderを停止・除外登録しない。
- 別途ClamAVのclamd/オンデマンドスキャンを有効化すると、Defenderとの二重ファイル読み出し、CPU/メモリ/ディスクI/O、スキャン対象のロック・遅延が発生し得る。ClamAVがDefenderを置換するとの評価や、Windows上の同時実行互換性は**未実測**。当初は更新＋監査のみ、後日限定的なオンデマンド検査を検討。
- Windowsでは更新先ディレクトリの書込み/置換・ACL・UAC・ファイルの使用中ロックに注意。ユーザープロファイル下のAegisGuard専用ディレクトリなら通常のユーザー権限でPoC可能。Program FilesやサービスのDBディレクトリはACLにより追加権限が必要な場合がある。**管理者権限やWFPの権限を自動取得できるという主張はしない**。
- [freshclam内部 L2649-L2672](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libfreshclam/libfreshclam_internal.c#L2649-L2672) のWindows unlink→renameは途中失敗で空白期間を生む。AegisGuardの現行 [c2.rs L286-L324](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L286-L324) にもバックアップからの復帰失敗や電源断時の復旧方針を追加検証する余地がある（今回は実装修正しない）。
- **プライバシー上の発見：** freshclamはfreshclam.datにUUIDを作成・保持し、デフォルトUser-Agentへ**OS・アーキテクチャ・CPU・UUID**を埋め込んで送信する（[libfreshclam_internal.c L358-L381](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libfreshclam/libfreshclam_internal.c#L358-L381)、[L611-L638](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libfreshclam/libfreshclam_internal.c#L611-L638)）。**外部送信なしとは言えない**。AegisGuardが模倣する場合、永続識別子を送らない方針・通知・プライバシー最小化を採用する。検体アップロードは別機能のclamsubmit/報告フォームであり、更新要求と同一視しない。[公式報告FAQ](https://docs.clamav.net/faq/faq-malware-fp-reports.html)はユーザー投稿の保持・共有範囲を説明する。
- フィードが破壊されてもWFP遮断ルールやDefender設定を自動で変更しない。将来の遮断導入時は期限切れ・過剰ヒット・署名失効・時刻異常で fail-openの観察状態へ降格し、ユーザー承認/復旧手段を別途設計する。

## 6. 性能・堅牢性・誤検知

**定量値の扱い：本調査は実測なし。** 公式の「数百万件の検出」のような説明、CVDヘッダのsignature count、ローカルルール件数は**AegisGuardやWindows 11での検出率・処理速度・常駐メモリの実測値ではない**。検出率を数値化しない。差分更新はネットワーク節約になり得る一方、パッチ展開とロードテストのCPU/ディスクピークが増えることもある。少数のIPルールにCDIFF風機構は不要である可能性が高い。

- **負荷上限と検査漏れ：** [clamd.conf.sample L620-L658](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/etc/clamd.conf.sample#L620-L658) にMaxScanSize/MaxFileSize/MaxRecursion/MaxFiles、[L720-L752](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/etc/clamd.conf.sample#L720-L752) にPCREMatchLimit/PCRERecMatchLimit/PCREMaxFileSizeがある。制限により検出されないケースを陰性と混同しない。これはClamAVの**設定例の値**で、AegisGuardのベンチマークではない。
- **フォーマットと攻撃者入力：** CVDの512バイトヘッダ、tar/gzip、CDIFFのコマンドパーサを扱うため、署名が正当でもバグ・パストラバーサル・展開爆弾・不正な数値/行長・リソース枯渇を検討。ClamAVはCVD展開時に危険なパスを拒否するコードを持つ（[libclamav/cvd.c L79-L289](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/cvd.c#L79-L289)）。AegisGuardはネットワーク入力/新ルールを必要最低限のスキーマ・上限で扱い、署名検証の前に攻撃者制御スクリプトを実行しない。
- **信頼境界：** CVD/差分の真正性検証と、公式/第三者ルールの内容の妥当性、アップデータ自身の安全性は別。TLSだけで署名付き供給元と誤検知防止を代替しない。失効や漏えい鍵で「正しく署名された悪質なルール」が届く場合を想定し、緊急kill-switchと段階適用を設計する。
- **部分更新/欠落：** [freshclamテスト](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/unit_tests/freshclam_test.py#L444-L529)では欠落許容が仕様だが、C2遮断でルール失効分だけ未反映となると危険。AegisGuardは**同一feedの更新を全件一貫して受理/拒否**し、複数feed間のみ独立の部分成功を許す方針を推奨。
- **誤検知/見逃し：** .fp/.sfp/.ign2は抑制手段であり、広範囲の例外は見逃しを増やす。検出名だけでなくルールhash、版、例外理由と期限を記録。公式の[誤検知報告FAQ](https://docs.clamav.net/faq/faq-scan-alerts.html)も検出を直ちに削除判断にしないよう注意している。実測には無害な正常ファイル群と自作合成入力を用い、FP率・FN相当・不完全分析を個別報告する。
- **取得不能：** [HTTP 403/429処理](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libfreshclam/libfreshclam_internal.c#L1377-L1414)と[公式FAQ](https://docs.clamav.net/faq/faq-freshclam.html)から、公式CDNは無制限の直接curl等を想定しない。公式DBを取得するなら**サポート対象のfreshclam/cvdupdate**を使う。リトライ連打、署名を持たない独自クローラによる取得、CDN回避は採用しない。
- **測定計画：** 初回/通常/失敗時それぞれの転送バイト数、更新所要時間、ピークRSS、CPU時間、書込量、キャッシュ世代数、DBリロード時間、誤検知・期限切れ・失効判定、ログ量をWindows 11+Defender有効で取得。現時点はすべて**要実測**。

## 7. 推奨する小さなPoCと成功基準

- **前提：** 実装タスクは本調査PRの範囲外。テスト専用の未公開署名鍵、架空のC2 IP/無害なYARA-X相当のテキスト規則、ローカルHTTPモック、専用一時ディレクトリのみ。Defender有効・ネットワーク遮断/自動隔離なし。
- **安全な順序：** ①アップデータ無効/テストデータのみでmanifestと証明書/公開鍵の検証 ②更新イベントと失効の**監査モード** ③限定的な手動有効化（検出ログのみ）。C2遮断機能は対象外。
- **受け入れ基準（機能）：** 正常署名・正しいhash・単調増加版でだけ候補が有効化。署名不正、署名対象の改変、未知鍵、期限切れ、リプレイ/旧version、サイズ超過、JSON不正、空レスポンス、合成パーサ異常はすべて拒否。どの場合も旧検証済みgenerationを失わず、成功時刻を偽更新しない。
- **受け入れ基準（復旧）：** 取得途中/検証直後/永続化中/切替前後の障害注入、Windowsファイルロック、容量不足、再起動を模擬し、次回起動時のcurrentとpreviousがそれぞれ完全に検証可能。**一瞬でも旧版も新版も参照不能になるケースは失敗**。ロールバックは署名・単調増加の例外ルールを設けて手動・監査可能にする（過去の攻撃者版への黙示的巻戻しは認めない）。
- **受け入れ基準（C2/YARA-X）：** フィードAが成功、Bが失敗してもBのlast_success_atは不変。期限切れBは一致=有効判定に用いない。ルール更新は事前に構文/コンパイル検証し、ロード失敗で本番世代に反映されない。署名の内容変更時に該当例外の再評価を要求。
- **性能基準：** 数値を事前に捏造しない。ベースラインと候補の転送量・メモリピーク・CPU・ディスク・更新待機時間を同一条件で記録し、結果に基づいて閾値を決定。負荷でDefenderスキャンや通常利用を著しく妨げればPoC中止。
- **中止条件：** 署名/鍵管理が曖昧、Windowsで旧DBが消える、供給元の同梱利用許諾が不明、誤検知で自動遮断が起きる、検証用データが実際の悪性実行を要求する、予期しない外部送信が起きる場合。
- **切戻し：** ネット取得を停止し、最終の検証済みgenerationへ戻して監査記録を保存。Windows Defender・システムFW・既存サービス設定は触らない。

## 8. 採用しない設計と理由

1. **ClamAVのlibfreshclam/libclamav_rustの直接組み込みやCコード移植。** GPLv2・別ライセンス第三者コンポーネント・OpenSSLとC ABI・Rust staticlib・上流更新保守を抱え、署名管理だけを実現するAegisGuardの小さなMVPには不均衡。独自実装は**アイデアのみを参照**し、ソースはコピーしない。
2. **ClamAV公式DBと第三者署名を無条件で同梱、またはCVDをYARA-Xとして直接扱う。** データライセンスが未確認、CVDは複数のClamAV専用形式とバイトコードを内包し、単純な互換性はない。フォーマットの可読性を再配布許可や解析互換と混同しない。
3. **欠落CDIFFの部分反映を、遮断ルールにも採用。** ClamAV自体には許容パスとテストがあるが、AegisGuardのC2フィードで失効/追加の一部欠落は誤遮断と見逃しに直結する。同一feedは全件整合性を要求する。
4. **Windowsのunlink→renameをそのまま模倣し、単一コピーしか持たない構成。** 旧DBの消失リスクとクラッシュ復旧不全。二世代方式でPoC後に判断。

## 9. 他担当との境界・引継ぎ

- **ClamAVエンジン/スキャン担当：** clamd/clamdscanの検出API、実際の検出範囲と実行負荷、Defender併用時の測定、Windowsスキャン統合の判断は当担当では確定しない。署名更新部分が有望でもエンジン採用の根拠にはならない。
- **YARA-X担当：** ルール構文・コンパイル境界・安全な実行リソース制限・ライセンス・アプリ統合、ClamAVのYARAサポートとの相互運用可否を別途検証。ClamAV固有コンテナは前提としない。
- **C2/ルール配信担当：** フィードごとのProvenance/TTL/expiry、認証付きmanifest、例外/失効、署名キーを共通化。現行C2の「失敗したソースの成功時刻を変えない」仕様は維持。フィード提供者ごとの再配布許諾を確認。
- **Windowsセンサー/対応担当：** 署名更新は防御回避も自動遮断も要しない。WFPやFirewallの権限、誤遮断時の復旧、Defender競合を別途安全に設計。
- **法務/プライバシー担当：** CiscoのCVD再配布・改変許諾の一次資料、第三者ルールの利用規約、UUID送出/保存と利用者への通知、GPL製品配布時義務を確認するまで同梱判断は凍結。

## 10. 未確認事項・追加調査項目

| 重要度 | 未確認事項 | 解消に必要な作業 |
|---|---|---|
| **Blocker** | Cisco Talos公式CVD/CLD/CDIFFの**製品同梱・再配布・派生加工**の利用条件 | 実際の配布アーカイブ内COPYINGと公式契約/供給元回答を確認。法律上の判断は専門家へ |
| **Blocker** | 利用予定の第三者署名・C2ルールの再配布/改変/商用利用条件 | ルール提供元別の原本LICENSE、利用規約、配布権限の台帳化 |
| **High** | Windows 11でfreshclamの置換失敗/旧データ保持の再現、AegisGuardの.bak復旧 | Defender有効の隔離されたテスト環境で障害注入。プロダクション設定は変更しない |
| **High** | 将来の署名付きAegisGuard更新鍵の配布、ローテーション、漏えい/失効、強制ロールバック防止 | 脅威モデル策定、署名鍵HSM/保管手順、期限・公開鍵更新プロトコル、レビューテスト |
| **High** | ClamAVのstable release（1.5系）で同じ更新コードとFIPS/.sign挙動が成り立つか | 調査固定mainとの差分をstableタグで検証し、互換性を評価 |
| Medium | 署名DB増大に伴うRSS/CPU、差分の費用対効果、スキャン漏れ/検出率 | Windows 11 x64実機で無害な固定ワークロード・対照群を実測 |
| Medium | private mirror・HTTP Range・403/429・オフライン復旧の実運用と更新許可 | 利用規約を確認したうえでローカルミラー/モック試験。公式CDNへ自動負荷をかけない |
| Medium | UUID等のUser-Agent情報の保存/送信、DNS/HTTP時のログと第三者への情報提供 | ソースベースのリスクを利用者向け告知/環境別パケット確認で検証 |
| Medium | 誤検知の実データ分布・.ign2例外のルール変更時挙動・更新後の失効反映 | 無害な正常サンプルに限定して検証。報告窓口への検体送付はユーザーの明示同意が必要 |

## 11. 一次情報一覧

**すべて2026-11-05参照。外部ClamAVのリンクは指定SHAで固定。以下は主要な5件を超える実装判断の根拠であり、公式マニュアルは補助資料。**

1. [libfreshclam/libfreshclam_internal.c L1457-L1599：CVD取得と署名検証](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libfreshclam/libfreshclam_internal.c#L1457-L1599)
2. [libclamav_rust/src/cvd.rs L325-L479：detached署名と旧RSAへのフォールバック条件](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav_rust/src/cvd.rs#L325-L479)
3. [libclamav_rust/src/codesign.rs L608-L696：PKCS#7検証](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav_rust/src/codesign.rs#L608-L696)
4. [libclamav_rust/src/cdiff.rs L641-L749：CDIFF署名検証と適用](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav_rust/src/cdiff.rs#L641-L749)
5. [libfreshclam/libfreshclam_internal.c L2489-L2730：全量へのフォールバック・部分成功・ロードテスト後置換](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libfreshclam/libfreshclam_internal.c#L2489-L2730)
6. [unit_tests/freshclam_test.py L312-L734：差分更新・部分更新・古いミラー・空ファイルの検証ケース](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/unit_tests/freshclam_test.py#L312-L734)
7. [libfreshclam/libfreshclam_internal.c L1362-L1414：403/429とRetry-After](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libfreshclam/libfreshclam_internal.c#L1362-L1414)
8. [libfreshclam/libfreshclam_internal.c L611-L638：OS/CPU/UUID入りUser-Agent](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libfreshclam/libfreshclam_internal.c#L611-L638)
9. [libclamav/cvd.c L291-L474：CVDヘッダとverify関数](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav/cvd.c#L291-L474)
10. [unit_tests/clamscan/fp_check_test.py L97-L267：.fp誤検知抑制テスト](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/unit_tests/clamscan/fp_check_test.py#L97-L267)
11. [libclamav_rust/Cargo.toml：Rust依存・staticlib](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/libclamav_rust/Cargo.toml)
12. [README L103-L139・COPYING.txt：本体GPLv2、第三者ライセンス](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/README.md#L103-L139)
13. [AegisGuard src/c2.rs L260-L409：フィード毎の更新失敗時刻・キャッシュ切替・期限切れ](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L260-L409)
14. [公式FreshClam FAQ：CDNで許可される取得方法と403/429](https://docs.clamav.net/faq/faq-freshclam.html)
15. [公式Private Mirror：CVD/CDIFFとCLDのミラー構成・Range](https://docs.clamav.net/appendix/CvdPrivateMirror.html)
16. [公式Allow Lists：.fp/.sfp/.ign2と例外のハッシュ結合](https://docs.clamav.net/manual/Signatures/AllowLists.html)
17. [公式EOL方針：署名DBダウンロードと誤検知検査対象バージョン](https://docs.clamav.net/faq/faq-eol.html)

**判定の限界：** 本書はソース・テスト・公式文書の静的分析であり、ビルド成功、全テスト成功、完全なライセンスチェーン、実際の誤検知率・検出率、Windowsでの安定性を実証するものではない。実装・検体実行・PRマージは行わない。
