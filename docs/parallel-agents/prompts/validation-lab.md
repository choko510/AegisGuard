# 調査＋実装担当F：安全な合成イベント・スキャナー検証ラボ

あなたは **choko510/AegisGuard の独立Rustモジュール開発担当** です。外部仕様の調査・技術選定・コード実装・テスト・日本語PRまで**この作業で完遂**してください。P5〜P10と同時進行中なので、対象外の既存実装は変更しないでください。

**担当ID：** validation-lab
**リポジトリ：** https://github.com/choko510/AegisGuard
**編集可能なパス：** `standalone/validation-lab/` **以下だけ**
**作業ブランチ：** `standalone/validation-lab`（最新mainから作成。衝突する場合は一意な別名）
**提出PRタイトル：** `調査・実装: 安全な合成イベント・スキャナー検証ラボ`
**作業条件：** **PRを作成するがマージしない**。他の6担当のディレクトリにも触れない。

## 0. まず読み込む

**`docs/parallel-agents/PROTOCOL.md` の全文**、このプロンプトの全文、最新のルート`README.md`/`SECURITY.md`/`docs/ARCHITECTURE.md`、現在のオープンPRと担当パスの重なり。共通プロトコルの書込禁止・read-only・安全テスト・PRルールは絶対条件です。プロンプトを読み飛ばしたまま実装しないこと。

## 1. 目標

P5〜P10の検出精度、イベント欠損・誤検知、耐久性を将来検証するため、マルウェア実行なしで再現可能な合成コーパスとテストツールを独立開発する。

## 2. 調査で突き止めること

- 現行`examples/bench_corpus.rs`、`docs/BASELINE.md`、`src/events/mod.rs`、`tests/fixtures`を**読むだけ**で、既存JSONL/イベントの型、ID1/7/11/12-14/22、Report v2スキーマを確認。
- 決定的な乱数seed、ケースID、期待される観測/欠損/部分結果、fixture更新の互換性、ハッシュによるデータ正当性、Windows/Linux同一出力を調査。
- 外部EICAR/マルウェア検体の使用条件、コード実行と静的検査の違いを整理。**不審コードや登録DLLを実際に動かさず**、イベントXML・ダミーファイル・JSONだけを生成する。

各技術選択について、Microsoft等の**一次情報URL、確認日、採用したAPI/関数/型と制約、代替案と不採用理由**を`standalone/validation-lab/RESEARCH.md`に残してください。Windowsで実行していないものは「実機未確認」とすること。

## 3. 実装を完了する内容

- CLI：`validation-lab generate --out <dir> --seed 42 --profile all`、`validation-lab verify --dir <dir>`、`validation-lab summarize --expected <manifest> --actual <report.jsonl>`。既存AegisGuard CLIの呼び出しは**オプション・無害な作成fixtureに対してのみ**で、本体変更なし。
- 合成イベントのシナリオ：正常なブラウザ更新、無害なCOM登録、DLL設置＋COM変更＋読み込みを表す架空のK2F型イベント、ログ欠損、PID再利用、遅延、重複、文字列が似た別パス、失効したIOC、通常管理スクリプト。
- 期待値の書式：case_id、入力ハッシュ、期待するrule/evidence（存在するルールだけ）、不明/未対応の明示。将来未実装ルールは`planned`として分ける。

**リポジトリの既存モジュールをimportしてコンパイルさせない。** 単独`Cargo.toml`で構築し、`README.md`にCLI使用例とJSON出力例、権限、非対応、統合先となる将来の型を記載。少なくとも動作するMVPと安全なfixture経路を完成させること。広範囲な機能で全件が実装できなければ、どこまでが実装済みか明示し、未完了を成功扱いしない。

## 4. テストすべき条件

- 同seedでbyte-for-byte再現、別seedで安全な変動、全manifestの整合、未知版、壊れたJSONL、改ざん検出、遅い大量入力、report未完成の扱い、Windows/Linuxの改行とパス差。
- CI/ベンチマークへの統合は行わず独立ツールとしてテストする。真の侵入テストや検出率を示したと偽らない。

安全なfixtureとWindows/APIのモックを用意し、入力異常・時間/件数/ファイルサイズ上限・権限拒否・誤判定を明示的に検証。Linux上でWindows APIの実機成功を捏造しない。`cargo fmt --all -- --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test` を専用フォルダーから実行し、失敗は直す。

## 5. 提出条件

- 追加/編集：`standalone/validation-lab/` 内の`src/`・`tests/`・`Cargo.toml`・`Cargo.lock`・`README.md`・`RESEARCH.md`などのみ。
- 出力はversion付きJSON。診断不能/権限なし/部分成功と空・安全を区別。危険入力、誤検知、秘密の漏出を見逃さない。
- **最新mainからPR**、日本語タイトル/説明。PR本文には使った公式仕様/ライセンス、達成した機能、未実装、テスト実績、Windows実機有無、リスク、将来のP5 typed APIへの接続案を記載。
- PR前に`git diff --name-only origin/main...HEAD`を確認して**自分の専用フォルダー外の変更ゼロ**を保証。
- **PRはマージしない**。最後にPR URL・成果物・重要な技術判断・テスト結果・残課題を報告。コネクタが書けない場合はその事実を述べ、作成したファイルを引き渡す。

**調査報告だけで作業を終えないこと。実装と検証まで責任を持って進めること。**
