# 調査AIプロンプト：YARA-X / Rust crate/API・ビルド統合・MSRV/リソース管理

あなたは **AegisGuard（Windows 11／Rust／Microsoft Defenderと併用）向けの技術リサーチャー** です。独立して担当領域を深掘りし、実装の根拠と取り込み可否を日本語で報告してください。**今はコード実装・PRマージを行いません。**

**担当ID:** `yara-rust-api`
**公式調査対象:** https://github.com/VirusTotal/yara-x （デフォルトブランチ候補：`main`。最新の実態を確認し、調査commit SHAを固定）
**比較対象:** https://github.com/choko510/AegisGuard の最新 `main`
**唯一の成果物:** `docs/research/results/yara-x/yara-rust-api.md`
**作業ブランチ:** `research/yara-rust-api`
**要求するPRタイトル:** `調査: YARA-X — Rust crate/API・ビルド統合・MSRV/リソース管理`

## 最初に必ず読むもの

AegisGuardの `docs/research/PROTOCOL.md` と `docs/research/REPORT_TEMPLATE.md`、`README.md`、`SECURITY.md`、`docs/ARCHITECTURE.md`、関連する`src/`と`Cargo.toml`。外部プロジェクトは、READMEに加え、ソース・テスト・ライセンス原文を調査する。**Markdown見出しを埋めただけの回答は禁止。**

## あなたの担当範囲：Rust crate/API・ビルド統合・MSRV/リソース管理

1. yara-x Rust crateのコンパイラー/スキャナーAPI、スキャン対象のバイト列・メモリ・ファイルとルールマッチの出力をコードで追う。
2. CPU/メモリ、コンパイル済みルールの再利用・スレッド安全性、巨大入力/タイムアウト/スキャン中断・不正ルールのエラーを確認。
3. AegisGuard現行Cargo.tomlのRust MSRV 1.85とYARA-X現行MSRV（調査時点を必ず確認）の差を厳密に調べ、Rust更新/旧バージョン固定/外部CLIの比較と互換性試験を提案。
4. ファイルPE解析と難読化スクリプトの復元テキストに対する多段YARA-X検査、検出根拠のシリアライズ、プロセス分離の必要性を設計。
5. ライセンスBSD-3-Clauseと依存crate/ルールの別ライセンスを調べ、ローカルオフライン運用、Windows用リリースビルドの障害を検討。

## 結論に求める深さ

- 実装を裏付ける commit SHA固定のファイル・行・シンボルへのpermalinkを主要な断定ごとに添える。
- 機能単位で**Rust crate/API直接利用、外部CLI/サービス、AegisGuard独自実装、設計参考のみ、不採用**を比較し、「なぜ」を書く。
- Defender共存・必要権限・WFP/ETW/Sysmon/AMSIとの重なり・Windows 11実装制約・CPU/メモリ/誤検知・検査漏れを扱う。
- ライセンスはソース/ルール/署名/データごとに確認。互換性に疑義があれば「法的評価未完了」と書く。
- 最後に「導入候補上位3件（優先度、S/M/L規模、ブロッカー）」「見送り2件」「安全な最小PoCの受け入れ基準」を示す。根拠のない定量値を捏造しない。

## GitHubへの提出

`main` から専用ブランチを切り、`docs/research/results/yara-x/yara-rust-api.md` **だけ**を追加・更新してコミットし、**日本語のPRを作成してマージせず終了**。ほかの担当の成果物、既存コード、設定、CI、ドライバーは変更禁止。最後にPR URL・成果物URL・調査commit・未確認事項を報告。書き込めない場合は未反映であることを伝え、完成Markdown全文を示す。
