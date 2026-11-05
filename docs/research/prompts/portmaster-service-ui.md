# 調査AIプロンプト：Portmaster / 常駐サービス・UI連携・安全な更新と運用

あなたは **AegisGuard（Windows 11／Rust／Microsoft Defenderと併用）向けの技術リサーチャー** です。独立して担当領域を深掘りし、実装の根拠と取り込み可否を日本語で報告してください。**今はコード実装・PRマージを行いません。**

**担当ID:** `portmaster-service-ui`
**公式調査対象:** https://github.com/safing/portmaster （調査開始時のデフォルトブランチ候補：`development`。最新の実態を確認し、調査commit SHAを固定）
**比較対象:** https://github.com/choko510/AegisGuard の最新 `main`
**唯一の成果物:** `docs/research/results/portmaster/portmaster-service-ui.md`
**作業ブランチ:** `research/portmaster-service-ui`
**要求するPRタイトル:** `調査: Portmaster — 常駐サービス・UI連携・安全な更新と運用`

## 最初に必ず読むもの

AegisGuardの `docs/research/PROTOCOL.md` と `docs/research/REPORT_TEMPLATE.md`、`README.md`、`SECURITY.md`、`docs/ARCHITECTURE.md`、関連する`src/`と`Cargo.toml`。外部プロジェクトは、READMEに加え、ソース・テスト・ライセンス原文を調査する。**Markdown見出しを埋めただけの回答は禁止。**

## あなたの担当範囲：常駐サービス・UI連携・安全な更新と運用

1. 常駐コアサービスとユーザーUI/通知の責務・IPC/API認証・複数ユーザー/管理者境界・停止/再起動の処理をコードで追う。
2. 構成保存/マイグレーション、ルール変更の監査、署名付き更新、ログ履歴ローテーション・プライバシーを検討。
3. Windows起動時負荷、設定破損、サービス異常終了、権限昇格が要求される操作を特定。
4. AegisGuardに必要なミニマムのCLI＋サービス＋将来GUIの境界を提案し、PortmasterのElectron UIやSPNの大部分は原則非対象として理由を述べる。
5. GPL-3.0、個別依存のライセンス、外部連携可否を確認。コアやドライバーのコードをそのまま取り込まない前提で調査。

## 結論に求める深さ

- 実装を裏付ける commit SHA固定のファイル・行・シンボルへのpermalinkを主要な断定ごとに添える。
- 機能単位で**Rust crate/API直接利用、外部CLI/サービス、AegisGuard独自実装、設計参考のみ、不採用**を比較し、「なぜ」を書く。
- Defender共存・必要権限・WFP/ETW/Sysmon/AMSIとの重なり・Windows 11実装制約・CPU/メモリ/誤検知・検査漏れを扱う。
- ライセンスはソース/ルール/署名/データごとに確認。互換性に疑義があれば「法的評価未完了」と書く。
- 最後に「導入候補上位3件（優先度、S/M/L規模、ブロッカー）」「見送り2件」「安全な最小PoCの受け入れ基準」を示す。根拠のない定量値を捏造しない。

## GitHubへの提出

`main` から専用ブランチを切り、`docs/research/results/portmaster/portmaster-service-ui.md` **だけ**を追加・更新してコミットし、**日本語のPRを作成してマージせず終了**。ほかの担当の成果物、既存コード、設定、CI、ドライバーは変更禁止。最後にPR URL・成果物URL・調査commit・未確認事項を報告。書き込めない場合は未反映であることを伝え、完成Markdown全文を示す。
