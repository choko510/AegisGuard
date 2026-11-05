# 調査AIプロンプト：Portmaster / Windows WFP・カーネルドライバー・通信元の帰属

あなたは **AegisGuard（Windows 11／Rust／Microsoft Defenderと併用）向けの技術リサーチャー** です。独立して担当領域を深掘りし、実装の根拠と取り込み可否を日本語で報告してください。**今はコード実装・PRマージを行いません。**

**担当ID:** `portmaster-wfp-driver`
**公式調査対象:** https://github.com/safing/portmaster （調査開始時のデフォルトブランチ候補：`development`。最新の実態を確認し、調査commit SHAを固定）
**比較対象:** https://github.com/choko510/AegisGuard の最新 `main`
**唯一の成果物:** `docs/research/results/portmaster/portmaster-wfp-driver.md`
**作業ブランチ:** `research/portmaster-wfp-driver`
**要求するPRタイトル:** `調査: Portmaster — Windows WFP・カーネルドライバー・通信元の帰属`

## 最初に必ず読むもの

AegisGuardの `docs/research/PROTOCOL.md` と `docs/research/REPORT_TEMPLATE.md`、`README.md`、`SECURITY.md`、`docs/ARCHITECTURE.md`、関連する`src/`と`Cargo.toml`。外部プロジェクトは、READMEに加え、ソース・テスト・ライセンス原文を調査する。**Markdown見出しを埋めただけの回答は禁止。**

## あなたの担当範囲：Windows WFP・カーネルドライバー・通信元の帰属

1. Windowsのパケット傍受とプロセスID/サービスへの帰属を実装コードから辿り、WFPサブレイヤ/フィルター管理と独自ドライバーの責務を分離する。
2. Windowsドライバー署名、ロード/アンロード、インストール/更新、停止時デフォルト動作、WFP優先順位とDefender Firewall/他社製品との共存を評価。
3. ユーザーモードのWFP管理APIだけで実現可能な機能と、カーネルcallout/ドライバーがないと難しい機能を列挙。
4. AegisGuardの第1段階ではOS標準Windows Firewallルール/イベント監視へ寄せた場合の機能差と権限・メモリ・運用負担を比較。
5. アプリ別IP/ドメインブロックと「未知の接続の通知」を分離し、安全なrollbackとfail-open/fail-closed判断材料を提供。

## 結論に求める深さ

- 実装を裏付ける commit SHA固定のファイル・行・シンボルへのpermalinkを主要な断定ごとに添える。
- 機能単位で**Rust crate/API直接利用、外部CLI/サービス、AegisGuard独自実装、設計参考のみ、不採用**を比較し、「なぜ」を書く。
- Defender共存・必要権限・WFP/ETW/Sysmon/AMSIとの重なり・Windows 11実装制約・CPU/メモリ/誤検知・検査漏れを扱う。
- ライセンスはソース/ルール/署名/データごとに確認。互換性に疑義があれば「法的評価未完了」と書く。
- 最後に「導入候補上位3件（優先度、S/M/L規模、ブロッカー）」「見送り2件」「安全な最小PoCの受け入れ基準」を示す。根拠のない定量値を捏造しない。

## GitHubへの提出

`main` から専用ブランチを切り、`docs/research/results/portmaster/portmaster-wfp-driver.md` **だけ**を追加・更新してコミットし、**日本語のPRを作成してマージせず終了**。ほかの担当の成果物、既存コード、設定、CI、ドライバーは変更禁止。最後にPR URL・成果物URL・調査commit・未確認事項を報告。書き込めない場合は未反映であることを伝え、完成Markdown全文を示す。
