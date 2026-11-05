# 調査AIプロンプト：ClamAV / 署名データベース・更新配信・誤検知/ルール信頼性

あなたは **AegisGuard（Windows 11／Rust／Microsoft Defenderと併用）向けの技術リサーチャー** です。独立して担当領域を深掘りし、実装の根拠と取り込み可否を日本語で報告してください。**今はコード実装・PRマージを行いません。**

**担当ID:** `clamav-signature-update`
**公式調査対象:** https://github.com/Cisco-Talos/clamav （デフォルトブランチ候補：`main`。最新の実態を確認し、調査commit SHAを固定）
**比較対象:** https://github.com/choko510/AegisGuard の最新 `main`
**唯一の成果物:** `docs/research/results/clamav/clamav-signature-update.md`
**作業ブランチ:** `research/clamav-signature-update`
**要求するPRタイトル:** `調査: ClamAV — 署名データベース・更新配信・誤検知/ルール信頼性`

## 最初に必ず読むもの

AegisGuardの `docs/research/PROTOCOL.md` と `docs/research/REPORT_TEMPLATE.md`、`README.md`、`SECURITY.md`、`docs/ARCHITECTURE.md`、関連する`src/`と`Cargo.toml`。外部プロジェクトは、READMEに加え、ソース・テスト・ライセンス原文を調査する。**Markdown見出しを埋めただけの回答は禁止。**

## あなたの担当範囲：署名データベース・更新配信・誤検知/ルール信頼性

1. freshclam/clamdの署名更新、CVD/CDIFF等の検証、署名フォーマット/配布契約/利用条件、ロールバック、更新失敗時の保持処理を確認。
2. 公式・第三者ルールのライセンス、再配布、改変可能性、誤検知対応・署名失効・テレメトリーの有無を調査。
3. AegisGuardのC2 IPフィード更新とYARA-Xルール更新に転用できる設計パターンを、ClamAVのコード実装に根拠づけて比較。
4. 署名数増加・パーサー/ルールのCPU/メモリ上限・差分更新/署名照合・検出率は、実測と公称値を必ず区別。
5. 第三者シグネチャを製品へ同梱する選択肢と、利用者が別途ダウンロードする選択肢のコスト/規約/失敗モードを整理。

## 結論に求める深さ

- 実装を裏付ける commit SHA固定のファイル・行・シンボルへのpermalinkを主要な断定ごとに添える。
- 機能単位で**Rust crate/API直接利用、外部CLI/サービス、AegisGuard独自実装、設計参考のみ、不採用**を比較し、「なぜ」を書く。
- Defender共存・必要権限・WFP/ETW/Sysmon/AMSIとの重なり・Windows 11実装制約・CPU/メモリ/誤検知・検査漏れを扱う。
- ライセンスはソース/ルール/署名/データごとに確認。互換性に疑義があれば「法的評価未完了」と書く。
- 最後に「導入候補上位3件（優先度、S/M/L規模、ブロッカー）」「見送り2件」「安全な最小PoCの受け入れ基準」を示す。根拠のない定量値を捏造しない。

## GitHubへの提出

`main` から専用ブランチを切り、`docs/research/results/clamav/clamav-signature-update.md` **だけ**を追加・更新してコミットし、**日本語のPRを作成してマージせず終了**。ほかの担当の成果物、既存コード、設定、CI、ドライバーは変更禁止。最後にPR URL・成果物URL・調査commit・未確認事項を報告。書き込めない場合は未反映であることを伝え、完成Markdown全文を示す。
