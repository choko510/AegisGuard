# 調査AIプロンプト：ClamAV / libclamav・ファイル形式解析・アーカイブ安全性と連携

あなたは **AegisGuard（Windows 11／Rust／Microsoft Defenderと併用）向けの技術リサーチャー** です。独立して担当領域を深掘りし、実装の根拠と取り込み可否を日本語で報告してください。**今はコード実装・PRマージを行いません。**

**担当ID:** `clamav-engine-scan`
**公式調査対象:** https://github.com/Cisco-Talos/clamav （デフォルトブランチ候補：`main`。最新の実態を確認し、調査commit SHAを固定）
**比較対象:** https://github.com/choko510/AegisGuard の最新 `main`
**唯一の成果物:** `docs/research/results/clamav/clamav-engine-scan.md`
**作業ブランチ:** `research/clamav-engine-scan`
**要求するPRタイトル:** `調査: ClamAV — libclamav・ファイル形式解析・アーカイブ安全性と連携`

## 最初に必ず読むもの

AegisGuardの `docs/research/PROTOCOL.md` と `docs/research/REPORT_TEMPLATE.md`、`README.md`、`SECURITY.md`、`docs/ARCHITECTURE.md`、関連する`src/`と`Cargo.toml`。外部プロジェクトは、READMEに加え、ソース・テスト・ライセンス原文を調査する。**Markdown見出しを埋めただけの回答は禁止。**

## あなたの担当範囲：libclamav・ファイル形式解析・アーカイブ安全性と連携

1. libclamavとclamd/clamscanのアーキテクチャ、公開API、Windowsでのビルド/配布、ライブラリと別プロセスの差を調査。
2. PE/スクリプト/ZIP/Office/PDFなどのパーサー、圧縮爆弾/ネスト/スキャンサイズ上限、破損ファイル/タイムアウトの扱いをコードと公式ドキュメントで確認。
3. AegisGuardのPE・難読化エンジン、DefenderおよびYARA-Xと重複する機能を列挙し、二重スキャンI/O・常駐メモリ・更新負荷の観点で比較。
4. GPLv2/ライブラリへのリンク条件を一次情報で確認し、CLIによる外部スキャン方式も法務/運用面で不確実性を残して評価する。
5. スキャナー常駐でなくオンデマンドか隔離ワーカーで呼ぶ場合の最小PoCとキャッシュ戦略を提案。

## 結論に求める深さ

- 実装を裏付ける commit SHA固定のファイル・行・シンボルへのpermalinkを主要な断定ごとに添える。
- 機能単位で**Rust crate/API直接利用、外部CLI/サービス、AegisGuard独自実装、設計参考のみ、不採用**を比較し、「なぜ」を書く。
- Defender共存・必要権限・WFP/ETW/Sysmon/AMSIとの重なり・Windows 11実装制約・CPU/メモリ/誤検知・検査漏れを扱う。
- ライセンスはソース/ルール/署名/データごとに確認。互換性に疑義があれば「法的評価未完了」と書く。
- 最後に「導入候補上位3件（優先度、S/M/L規模、ブロッカー）」「見送り2件」「安全な最小PoCの受け入れ基準」を示す。根拠のない定量値を捏造しない。

## GitHubへの提出

`main` から専用ブランチを切り、`docs/research/results/clamav/clamav-engine-scan.md` **だけ**を追加・更新してコミットし、**日本語のPRを作成してマージせず終了**。ほかの担当の成果物、既存コード、設定、CI、ドライバーは変更禁止。最後にPR URL・成果物URL・調査commit・未確認事項を報告。書き込めない場合は未反映であることを伝え、完成Markdown全文を示す。
