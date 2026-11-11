# 調査＋実装担当A：Windows永続化監査

あなたは **choko510/AegisGuard の独立Rustモジュール開発担当** です。外部仕様の調査・技術選定・コード実装・テスト・日本語PRまで**この作業で完遂**してください。P5〜P10と同時進行中なので、対象外の既存実装は変更しないでください。

**担当ID：** persistence-audit
**リポジトリ：** https://github.com/choko510/AegisGuard
**編集可能なパス：** `standalone/persistence-audit/` **以下だけ**
**作業ブランチ：** `standalone/persistence-audit`（最新mainから作成。衝突する場合は一意な別名）
**提出PRタイトル：** `調査・実装: Windows永続化監査`
**作業条件：** **PRを作成するがマージしない**。他の6担当のディレクトリにも触れない。

## 0. まず読み込む

**`docs/parallel-agents/PROTOCOL.md` の全文**、このプロンプトの全文、最新のルート`README.md`/`SECURITY.md`/`docs/ARCHITECTURE.md`、現在のオープンPRと担当パスの重なり。共通プロトコルの書込禁止・read-only・安全テスト・PRルールは絶対条件です。プロンプトを読み飛ばしたまま実装しないこと。

## 1. 目標

Windowsの代表的な自動起動・永続化エントリを読み取り専用で棚卸しし、実行先の信頼性・理由付きの優先度を表示する。P6のブラウザ固有のCOM監視やP8の常駐サービスとは別実装。

## 2. 調査で突き止めること

- 公式根拠：Microsoft [Task Scheduler 2.0](https://learn.microsoft.com/en-us/windows/win32/taskschd/about-the-task-scheduler)、Windows Registry API、WMI permanent event subscriptionsの公式仕様。タスク列挙で古いTask Scheduler 1.0を採用しない。
- Run/RunOnce（HKCU/HKLMの32/64bitビュー）、Startupフォルダー、Task Scheduler 2.0、WMI __EventFilter / CommandLineEventConsumer / __FilterToConsumerBindingの**列挙可能範囲・権限・欠損**を比較。サービス/ドライバーの詳細は担当Dに譲る。
- 正規Windowsタスク、正規アップデーター、ユーザー設定と悪性永続化は**パス/配置だけで断定できない**。信頼性/偽陽性、署名検査の負荷、収集してはいけないユーザー名・生引数を検討。

各技術選択について、Microsoft等の**一次情報URL、確認日、採用したAPI/関数/型と制約、代替案と不採用理由**を`standalone/persistence-audit/RESEARCH.md`に残してください。Windowsで実行していないものは「実機未確認」とすること。

## 3. 実装を完了する内容

- CLI：`persistence-audit scan --format json [--include-wmi] [--limit N]`、`persistence-audit inspect-fixture <file>`。実環境走査はWindowsのみ。最小MVPはRun/RunOnce＋Startup＋Task Scheduler、WMIは権限/環境上難しければ独立モジュールとして不完全を明示する。
- 型`PersistenceEntry {kind,scope,location_redacted,target_path,signature_status?,evidence,assessment}`。コマンドラインの秘密値は収集せず、実行先パスが不明なものを安全扱いしない。正常値/未知値/異常値を区別。
- サービス/ドライバーの棚卸し、ブラウザCLSIDの個別追跡、常駐監視、レジストリ編集、タスク削除や自動修復は**しない**。

**リポジトリの既存モジュールをimportしてコンパイルさせない。** 単独`Cargo.toml`で構築し、`README.md`にCLI使用例とJSON出力例、権限、非対応、統合先となる将来の型を記載。少なくとも動作するMVPと安全なfixture経路を完成させること。広範囲な機能で全件が実装できなければ、どこまでが実装済みか明示し、未完了を成功扱いしない。

## 4. テストすべき条件

- HKCU/HKLM、WOW64、未定義ターゲット、引用符と環境変数、権限拒否、遅いWMI、消えたタスク、Unicodeパス、過長値、重複、ゼロ件、合成の正規アップデーター。
- RegistryとTask Schedulerへの操作はread-only。テストのためにPCに永続化を書かない。合成fixtureとモックでカバーする。

安全なfixtureとWindows/APIのモックを用意し、入力異常・時間/件数/ファイルサイズ上限・権限拒否・誤判定を明示的に検証。Linux上でWindows APIの実機成功を捏造しない。`cargo fmt --all -- --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test` を専用フォルダーから実行し、失敗は直す。

## 5. 提出条件

- 追加/編集：`standalone/persistence-audit/` 内の`src/`・`tests/`・`Cargo.toml`・`Cargo.lock`・`README.md`・`RESEARCH.md`などのみ。
- 出力はversion付きJSON。診断不能/権限なし/部分成功と空・安全を区別。危険入力、誤検知、秘密の漏出を見逃さない。
- **最新mainからPR**、日本語タイトル/説明。PR本文には使った公式仕様/ライセンス、達成した機能、未実装、テスト実績、Windows実機有無、リスク、将来のP5 typed APIへの接続案を記載。
- PR前に`git diff --name-only origin/main...HEAD`を確認して**自分の専用フォルダー外の変更ゼロ**を保証。
- **PRはマージしない**。最後にPR URL・成果物・重要な技術判断・テスト結果・残課題を報告。コネクタが書けない場合はその事実を述べ、作成したファイルを引き渡す。

**調査報告だけで作業を終えないこと。実装と検証まで責任を持って進めること。**
