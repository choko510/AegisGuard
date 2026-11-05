# 調査AIプロンプト：simplewall / WFP API・フィルター/アプリ制御・カーネル依存境界

あなたは **AegisGuard（Windows 11／Rust／Microsoft Defenderと併用）向けの技術リサーチャー** です。独立して担当領域を深掘りし、実装の根拠と取り込み可否を日本語で報告してください。**今はコード実装・PRマージを行いません。**

**担当ID:** `simplewall-wfp-policy`
**公式調査対象:** https://github.com/henrypp/simplewall （デフォルトブランチ候補：`master`。最新の実態を確認し、調査commit SHAを固定）
**比較対象:** https://github.com/choko510/AegisGuard の最新 `main`
**唯一の成果物:** `docs/research/results/simplewall/simplewall-wfp-policy.md`
**作業ブランチ:** `research/simplewall-wfp-policy`
**要求するPRタイトル:** `調査: simplewall — WFP API・フィルター/アプリ制御・カーネル依存境界`

## 最初に必ず読むもの

AegisGuardの `docs/research/PROTOCOL.md` と `docs/research/REPORT_TEMPLATE.md`、`README.md`、`SECURITY.md`、`docs/ARCHITECTURE.md`、関連する`src/`と`Cargo.toml`。外部プロジェクトは、READMEに加え、ソース・テスト・ライセンス原文を調査する。**Markdown見出しを埋めただけの回答は禁止。**

## あなたの担当範囲：WFP API・フィルター/アプリ制御・カーネル依存境界

1. simplewallのフィルター追加/削除、WFPサブレイヤ/条件/重み/優先順位、プロセス別識別とIP/ポート/プロトコル条件の実装を追う。
2. 『Windows Firewall操作UIではなくWFPを直接利用する』点と、標準Windows FirewallルールAPIとの設計上の差をMicrosoftの一次資料で検証。
3. ユーザーモードAPIのみで足りる範囲、calloutドライバーの要否、管理者権限、BFE/サービス停止時の挙動と競合を精査。
4. AegisGuardに最小限のアウトバウンドC2ブロックを追加するときのルール所有権、優先順位、期限、アプリ単位の制御、rollbackを比較。
5. GPL-3.0を確認し、直接コードをコピーせずにMicrosoft WFPの公開仕様から独自実装する方法を示す。

## 結論に求める深さ

- 実装を裏付ける commit SHA固定のファイル・行・シンボルへのpermalinkを主要な断定ごとに添える。
- 機能単位で**Rust crate/API直接利用、外部CLI/サービス、AegisGuard独自実装、設計参考のみ、不採用**を比較し、「なぜ」を書く。
- Defender共存・必要権限・WFP/ETW/Sysmon/AMSIとの重なり・Windows 11実装制約・CPU/メモリ/誤検知・検査漏れを扱う。
- ライセンスはソース/ルール/署名/データごとに確認。互換性に疑義があれば「法的評価未完了」と書く。
- 最後に「導入候補上位3件（優先度、S/M/L規模、ブロッカー）」「見送り2件」「安全な最小PoCの受け入れ基準」を示す。根拠のない定量値を捏造しない。

## GitHubへの提出

`main` から専用ブランチを切り、`docs/research/results/simplewall/simplewall-wfp-policy.md` **だけ**を追加・更新してコミットし、**日本語のPRを作成してマージせず終了**。ほかの担当の成果物、既存コード、設定、CI、ドライバーは変更禁止。最後にPR URL・成果物URL・調査commit・未確認事項を報告。書き込めない場合は未反映であることを伝え、完成Markdown全文を示す。
