# 調査＋実装担当D：Windowsドライバー・サービス棚卸し

あなたは **choko510/AegisGuard の独立Rustモジュール開発担当** です。外部仕様の調査・技術選定・コード実装・テスト・日本語PRまで**この作業で完遂**してください。P5〜P10と同時進行中なので、対象外の既存実装は変更しないでください。

**担当ID：** driver-inventory
**リポジトリ：** https://github.com/choko510/AegisGuard
**編集可能なパス：** `standalone/driver-inventory/` **以下だけ**
**作業ブランチ：** `standalone/driver-inventory`（最新mainから作成。衝突する場合は一意な別名）
**提出PRタイトル：** `調査・実装: Windowsドライバー・サービス棚卸し`
**作業条件：** **PRを作成するがマージしない**。他の6担当のディレクトリにも触れない。

## 0. まず読み込む

**`docs/parallel-agents/PROTOCOL.md` の全文**、このプロンプトの全文、最新のルート`README.md`/`SECURITY.md`/`docs/ARCHITECTURE.md`、現在のオープンPRと担当パスの重なり。共通プロトコルの書込禁止・read-only・安全テスト・PRルールは絶対条件です。プロンプトを読み飛ばしたまま実装しないこと。

## 1. 目標

ロード済み・登録済みのカーネルドライバーとWindowsサービスのメタデータを収集し、登録先、署名、起動方式などの不審点を根拠付きで示す。

## 2. 調査で突き止めること

- Microsoft Service Control Managerの`EnumServicesStatusEx`、`QueryServiceConfig`、`QueryServiceConfig2`、Driver Service Type、SetupAPI等の公式仕様を調査。Windowsドライバーと普通のサービス、起動種別を分ける。
- ファイルパスの`\SystemRoot`・環境変数・引数、32/64bit、実行ファイルの署名（WinVerifyTrust等）、ファイルが見つからない/保護された領域の例外、管理者権限がない場合の可視性を調査。
- 名前・パス・署名だけでは悪性を断定できない。永続化担当AはRun/Task/WMIであり、**ここはSCM登録サービス・ドライバーだけ**を扱う。

各技術選択について、Microsoft等の**一次情報URL、確認日、採用したAPI/関数/型と制約、代替案と不採用理由**を`standalone/driver-inventory/RESEARCH.md`に残してください。Windowsで実行していないものは「実機未確認」とすること。

## 3. 実装を完了する内容

- CLI：`driver-inventory list [--drivers-only] --format json`、`driver-inventory inspect-fixture <file>`。種別、状態、開始方法、サービス名（最小化）、実行ファイルの正規化パス/存在/署名状態（不明可）、出所、エラーを列挙。
- 時間と件数の上限あり。署名検証は必要に応じたオプションでコスト制御。OSに新しいドライバーを入れない。
- ドライバーの開始/停止・サービス設定変更・アクセス拒否回避・kernelメモリ読取り・BYOVD実行は禁止。

**リポジトリの既存モジュールをimportしてコンパイルさせない。** 単独`Cargo.toml`で構築し、`README.md`にCLI使用例とJSON出力例、権限、非対応、統合先となる将来の型を記載。少なくとも動作するMVPと安全なfixture経路を完成させること。広範囲な機能で全件が実装できなければ、どこまでが実装済みか明示し、未完了を成功扱いしない。

## 4. テストすべき条件

- カーネル/ユーザー型サービス、停⽌中/実⾏中、仮想ドライバー、署名未確認、長大/空パス、ファイル欠落、権限不足、SCM列挙の再試行条件、マルチSZ/Unicode。
- 無害なfixtureで差分を検証し、実環境でサービスを停止・作成しない。

安全なfixtureとWindows/APIのモックを用意し、入力異常・時間/件数/ファイルサイズ上限・権限拒否・誤判定を明示的に検証。Linux上でWindows APIの実機成功を捏造しない。`cargo fmt --all -- --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test` を専用フォルダーから実行し、失敗は直す。

## 5. 提出条件

- 追加/編集：`standalone/driver-inventory/` 内の`src/`・`tests/`・`Cargo.toml`・`Cargo.lock`・`README.md`・`RESEARCH.md`などのみ。
- 出力はversion付きJSON。診断不能/権限なし/部分成功と空・安全を区別。危険入力、誤検知、秘密の漏出を見逃さない。
- **最新mainからPR**、日本語タイトル/説明。PR本文には使った公式仕様/ライセンス、達成した機能、未実装、テスト実績、Windows実機有無、リスク、将来のP5 typed APIへの接続案を記載。
- PR前に`git diff --name-only origin/main...HEAD`を確認して**自分の専用フォルダー外の変更ゼロ**を保証。
- **PRはマージしない**。最後にPR URL・成果物・重要な技術判断・テスト結果・残課題を報告。コネクタが書けない場合はその事実を述べ、作成したファイルを引き渡す。

**調査報告だけで作業を終えないこと。実装と検証まで責任を持って進めること。**
