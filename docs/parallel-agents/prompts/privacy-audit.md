# 調査＋実装担当G：ログ・レポートの機密情報QA

あなたは **choko510/AegisGuard の独立Rustモジュール開発担当** です。外部仕様の調査・技術選定・コード実装・テスト・日本語PRまで**この作業で完遂**してください。P5〜P10と同時進行中なので、対象外の既存実装は変更しないでください。

**担当ID：** privacy-audit
**リポジトリ：** https://github.com/choko510/AegisGuard
**編集可能なパス：** `standalone/privacy-audit/` **以下だけ**
**作業ブランチ：** `standalone/privacy-audit`（最新mainから作成。衝突する場合は一意な別名）
**提出PRタイトル：** `調査・実装: ログ・レポートの機密情報QA`
**作業条件：** **PRを作成するがマージしない**。他の6担当のディレクトリにも触れない。

## 0. まず読み込む

**`docs/parallel-agents/PROTOCOL.md` の全文**、このプロンプトの全文、最新のルート`README.md`/`SECURITY.md`/`docs/ARCHITECTURE.md`、現在のオープンPRと担当パスの重なり。共通プロトコルの書込禁止・read-only・安全テスト・PRルールは絶対条件です。プロンプトを読み飛ばしたまま実装しないこと。

## 1. 目標

AegisGuardが将来出力するJSONL・エラー・監視イベントのデータから、秘密/個人情報の誤混入を検出する独立した検証器と合成テスト群を作る。

## 2. 調査で突き止めること

- 現行`src/model.rs`、`src/events/mod.rs`、`src/report.rs`、`src/defender.rs`、`src/jsonl.rs`の**出力の型とマスキング方針のみを読む**。本体ソースは改変せず、テスト可能なドキュメント化された出力契約を提案。
- Cookie、Authorization Bearer、ブラウザ認証情報、APIキー、JWT、PowerShellコマンドライン、URLクエリ、ホームパス、BitLocker回復キーなどの誤混入例を安全な**人工値**で模擬。
- 検知表現のFalse Positive、シークレットの完全なログへの露出、SHA256とsalt無きハッシュのプライバシー限界、エスケープ/HTML表示/Unicode正規化を調査。

各技術選択について、Microsoft等の**一次情報URL、確認日、採用したAPI/関数/型と制約、代替案と不採用理由**を`standalone/privacy-audit/RESEARCH.md`に残してください。Windowsで実行していないものは「実機未確認」とすること。

## 3. 実装を完了する内容

- CLI：`privacy-audit check --input <jsonl-or-log> --format json`、`privacy-audit self-test`。**明示されたファイルのみ**扱い、既定ではホームディレクトリや実ブラウザDBを横断スキャンしない。
- ルールは合成fixtureで確認し、`LeakFinding {category, severity, line_no, rule_id, redacted_excerpt_or_hash}`を返す。**検出した秘密の生値をstdout/stderr/保存ファイルへ複製しない**。終了コードは漏えい検出で非0、解析不能では別の非0。
- `serde_json`構造を理解する検査と平文ログ行の検査を分け、ファイル上限/行長/巨大トークン/入力破損に対応。ログ自体を勝手に書換えたり削除しない。

**リポジトリの既存モジュールをimportしてコンパイルさせない。** 単独`Cargo.toml`で構築し、`README.md`にCLI使用例とJSON出力例、権限、非対応、統合先となる将来の型を記載。少なくとも動作するMVPと安全なfixture経路を完成させること。広範囲な機能で全件が実装できなければ、どこまでが実装済みか明示し、未完了を成功扱いしない。

## 4. テストすべき条件

- 人工JWT/Authorization、長いURLに含む`token=`、Cookie風値、ユーザー名を含むWindowsパス、偽の回復キー、適切にマスクされた値、誤検知しやすい正常文字列、base64風データ、無効UTF-8、巨大行。
- 絶対に実際の秘密をテストデータに使わない。見つけた値をレポートへ出さないこと自体をテストする。

安全なfixtureとWindows/APIのモックを用意し、入力異常・時間/件数/ファイルサイズ上限・権限拒否・誤判定を明示的に検証。Linux上でWindows APIの実機成功を捏造しない。`cargo fmt --all -- --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test` を専用フォルダーから実行し、失敗は直す。

## 5. 提出条件

- 追加/編集：`standalone/privacy-audit/` 内の`src/`・`tests/`・`Cargo.toml`・`Cargo.lock`・`README.md`・`RESEARCH.md`などのみ。
- 出力はversion付きJSON。診断不能/権限なし/部分成功と空・安全を区別。危険入力、誤検知、秘密の漏出を見逃さない。
- **最新mainからPR**、日本語タイトル/説明。PR本文には使った公式仕様/ライセンス、達成した機能、未実装、テスト実績、Windows実機有無、リスク、将来のP5 typed APIへの接続案を記載。
- PR前に`git diff --name-only origin/main...HEAD`を確認して**自分の専用フォルダー外の変更ゼロ**を保証。
- **PRはマージしない**。最後にPR URL・成果物・重要な技術判断・テスト結果・残課題を報告。コネクタが書けない場合はその事実を述べ、作成したファイルを引き渡す。

**調査報告だけで作業を終えないこと。実装と検証まで責任を持って進めること。**
