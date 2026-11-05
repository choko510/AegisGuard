# 調査＋実装担当E：インストール済みソフト・脆弱性調査

あなたは **choko510/AegisGuard の独立Rustモジュール開発担当** です。外部仕様の調査・技術選定・コード実装・テスト・日本語PRまで**この作業で完遂**してください。P5〜P10と同時進行中なので、対象外の既存実装は変更しないでください。

**担当ID：** software-audit
**リポジトリ：** https://github.com/choko510/AegisGuard
**編集可能なパス：** `standalone/software-audit/` **以下だけ**
**作業ブランチ：** `standalone/software-audit`（最新mainから作成。衝突する場合は一意な別名）
**提出PRタイトル：** `調査・実装: インストール済みソフト・脆弱性調査`
**作業条件：** **PRを作成するがマージしない**。他の6担当のディレクトリにも触れない。

## 0. まず読み込む

**`docs/parallel-agents/PROTOCOL.md` の全文**、このプロンプトの全文、最新のルート`README.md`/`SECURITY.md`/`docs/ARCHITECTURE.md`、現在のオープンPRと担当パスの重なり。共通プロトコルの書込禁止・read-only・安全テスト・PRルールは絶対条件です。プロンプトを読み飛ばしたまま実装しないこと。

## 1. 目標

Windowsに登録されたアプリとバージョンを安全に棚卸しし、明確な根拠がある場合に限り公開アドバイザリと一致候補を提示する。

## 2. 調査で突き止めること

- インストール情報はUninstallレジストリキー（HKLM/HKCU、WOW64）、MSIX/PackageManager等の合法な照会APIを比較。`Win32_Product`クエリは再構成・修復等の副作用懸念があるため**使わない**。
- NVDの[CPE Match Criteria](https://nvd.nist.gov/general/faq-sections/cpe-faqs)とCVEの製品/版適用条件、ベンダー公式アドバイザリ、CPEの曖昧性、"製品名が一致"と"その製品のそのビルドが脆弱"の違いを調査。
- API rate limit、更新日/キャッシュ、オフライン時の遅延、不明バージョン、ESU/バックポート/修正ビルドの扱い、外部送信するインストール済アプリ一覧のプライバシーを検討。

各技術選択について、Microsoft等の**一次情報URL、確認日、採用したAPI/関数/型と制約、代替案と不採用理由**を`standalone/software-audit/RESEARCH.md`に残してください。Windowsで実行していないものは「実機未確認」とすること。

## 3. 実装を完了する内容

- CLI：`software-audit inventory --format json`、`software-audit match --inventory <json> --advisories <local.json>`（**デフォルトはオフライン**）、`software-audit inspect-fixture <file>`。
- バージョン付き`SoftwareEntry`/`AdvisoryMatch`/`evidence`/`confidence`/`source_checked_at`を出力。厳密にマップできない場合は`candidate/unknown`、脆弱性確定ではない。
- ネットワーク更新機能を追加するなら明示オプトイン・取得上限・タイムアウト・正当性検証・ローカルキャッシュ・規約遵守。勝手にインストール済みソフトの情報を送らない。
- インストール/更新/アンインストール/ベンダーツール実行、危険な脆弱性PoCの実行は禁止。

**リポジトリの既存モジュールをimportしてコンパイルさせない。** 単独`Cargo.toml`で構築し、`README.md`にCLI使用例とJSON出力例、権限、非対応、統合先となる将来の型を記載。少なくとも動作するMVPと安全なfixture経路を完成させること。広範囲な機能で全件が実装できなければ、どこまでが実装済みか明示し、未完了を成功扱いしない。

## 4. テストすべき条件

- 似た名称の別製品、製品名異名、バージョン比較（`1.9` vs `1.10`）、範囲境界、arch/edition、ベンダー修正ビルド、unknown版、偽CPE一致、同一製品重複、悪意ある長大advisory JSON、取得データ古い。
- 合成したアプリ台帳・アドバイザリで精度を測り、False Positiveを隠さない。

安全なfixtureとWindows/APIのモックを用意し、入力異常・時間/件数/ファイルサイズ上限・権限拒否・誤判定を明示的に検証。Linux上でWindows APIの実機成功を捏造しない。`cargo fmt --all -- --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test` を専用フォルダーから実行し、失敗は直す。

## 5. 提出条件

- 追加/編集：`standalone/software-audit/` 内の`src/`・`tests/`・`Cargo.toml`・`Cargo.lock`・`README.md`・`RESEARCH.md`などのみ。
- 出力はversion付きJSON。診断不能/権限なし/部分成功と空・安全を区別。危険入力、誤検知、秘密の漏出を見逃さない。
- **最新mainからPR**、日本語タイトル/説明。PR本文には使った公式仕様/ライセンス、達成した機能、未実装、テスト実績、Windows実機有無、リスク、将来のP5 typed APIへの接続案を記載。
- PR前に`git diff --name-only origin/main...HEAD`を確認して**自分の専用フォルダー外の変更ゼロ**を保証。
- **PRはマージしない**。最後にPR URL・成果物・重要な技術判断・テスト結果・残課題を報告。コネクタが書けない場合はその事実を述べ、作成したファイルを引き渡す。

**調査報告だけで作業を終えないこと。実装と検証まで責任を持って進めること。**
