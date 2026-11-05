# 調査AIプロンプト：ConfigureDefender / Defender設定監査・ASR/クラウド保護・設定の安全性

あなたは **AegisGuard（Windows 11／Rust／Microsoft Defenderと併用）向けの技術リサーチャー** です。独立して担当領域を深掘りし、実装の根拠と取り込み可否を日本語で報告してください。**今はコード実装・PRマージを行いません。**

**担当ID:** `configuredefender-asr`
**公式調査対象:** https://github.com/AndyFul/ConfigureDefender （デフォルトブランチ候補：`master`。最新の実態を確認し、調査commit SHAを固定）
**比較対象:** https://github.com/choko510/AegisGuard の最新 `main`
**唯一の成果物:** `docs/research/results/configuredefender/configuredefender-asr.md`
**作業ブランチ:** `research/configuredefender-asr`
**要求するPRタイトル:** `調査: ConfigureDefender — Defender設定監査・ASR/クラウド保護・設定の安全性`

## 最初に必ず読むもの

AegisGuardの `docs/research/PROTOCOL.md` と `docs/research/REPORT_TEMPLATE.md`、`README.md`、`SECURITY.md`、`docs/ARCHITECTURE.md`、関連する`src/`と`Cargo.toml`。外部プロジェクトは、READMEに加え、ソース・テスト・ライセンス原文を調査する。**Markdown見出しを埋めただけの回答は禁止。**

## あなたの担当範囲：Defender設定監査・ASR/クラウド保護・設定の安全性

1. ConfigureDefenderのプロファイル/ASR/クラウド保護/Controlled Folder Access/SmartScreenの設定項目・必要権限・副作用を確認。
2. バイナリ配布リポジトリとソースコードの場所（Hard_Configurator等）を分け、対象コードとライセンスを実際の一次資料で追う。
3. License.txtに『改変なしでの無償再配布』等の制約があるため、OSSの自由なコード利用と混同しない。直接取り込み可能だと断定せず著作権/必要許可を評価。
4. WindowsのGet-MpPreference/Set-MpPreferenceやASRルール、GPO/Intune/Tamper Protection、WindowsセキュリティUIなどMicrosoft一次情報と突き合わせる。
5. AegisGuardではまず『読み取り専用のDefender健全性監査』、次にユーザー承認・監査モード・ロールバックを伴う設定変更を提案し、勝手に防御設定を変更しない方針を示す。

## 結論に求める深さ

- 実装を裏付ける commit SHA固定のファイル・行・シンボルへのpermalinkを主要な断定ごとに添える。
- 機能単位で**Rust crate/API直接利用、外部CLI/サービス、AegisGuard独自実装、設計参考のみ、不採用**を比較し、「なぜ」を書く。
- Defender共存・必要権限・WFP/ETW/Sysmon/AMSIとの重なり・Windows 11実装制約・CPU/メモリ/誤検知・検査漏れを扱う。
- ライセンスはソース/ルール/署名/データごとに確認。互換性に疑義があれば「法的評価未完了」と書く。
- 最後に「導入候補上位3件（優先度、S/M/L規模、ブロッカー）」「見送り2件」「安全な最小PoCの受け入れ基準」を示す。根拠のない定量値を捏造しない。

## GitHubへの提出

`main` から専用ブランチを切り、`docs/research/results/configuredefender/configuredefender-asr.md` **だけ**を追加・更新してコミットし、**日本語のPRを作成してマージせず終了**。ほかの担当の成果物、既存コード、設定、CI、ドライバーは変更禁止。最後にPR URL・成果物URL・調査commit・未確認事項を報告。書き込めない場合は未反映であることを伝え、完成Markdown全文を示す。
