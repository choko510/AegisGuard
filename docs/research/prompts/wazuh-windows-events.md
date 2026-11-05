# 調査AIプロンプト：Wazuh / Windows Agent・Sysmon/イベントログ収集・取りこぼし対策

あなたは **AegisGuard（Windows 11／Rust／Microsoft Defenderと併用）向けの技術リサーチャー** です。独立して担当領域を深掘りし、実装の根拠と取り込み可否を日本語で報告してください。**今はコード実装・PRマージを行いません。**

**担当ID:** `wazuh-windows-events`
**公式調査対象:** https://github.com/wazuh/wazuh （デフォルトブランチ候補：`main`。最新の実態を確認し、調査commit SHAを固定）
**比較対象:** https://github.com/choko510/AegisGuard の最新 `main`
**唯一の成果物:** `docs/research/results/wazuh/wazuh-windows-events.md`
**作業ブランチ:** `research/wazuh-windows-events`
**要求するPRタイトル:** `調査: Wazuh — Windows Agent・Sysmon/イベントログ収集・取りこぼし対策`

## 最初に必ず読むもの

AegisGuardの `docs/research/PROTOCOL.md` と `docs/research/REPORT_TEMPLATE.md`、`README.md`、`SECURITY.md`、`docs/ARCHITECTURE.md`、関連する`src/`と`Cargo.toml`。外部プロジェクトは、READMEに加え、ソース・テスト・ライセンス原文を調査する。**Markdown見出しを埋めただけの回答は禁止。**

## あなたの担当範囲：Windows Agent・Sysmon/イベントログ収集・取りこぼし対策

1. Windowsエージェントでのイベントチャネル購読、Event Log API/Sysmon統合、フィルタ、ブックマーク、再起動後の再開処理を実際のソースで調べる。
2. プロセス生成/通信/DLLロード/プロセスアクセスのイベントIDと、SysmonのProcessGuid/PID、親子関係、時間ずれの扱いを調べる。Wazuh固有機能とSysmon自体の機能を明確に区別。
3. 大量イベント時のキュー容量、フロー制御、ロス検知、接続断時のスプール、ログローテーション、プライバシーと権限を確認。
4. サーバー送信が前提の部分と、AegisGuardがローカル完結で模倣できる部分を区別し、Windows単体サービスMVPとしての最小イベント収集アーキテクチャを提案。
5. 導入/削除/権限/運用負荷に加え、WazuhのGPL-2/AGPL部分別ライセンスを実際のファイルに紐づけて評価。

## 結論に求める深さ

- 実装を裏付ける commit SHA固定のファイル・行・シンボルへのpermalinkを主要な断定ごとに添える。
- 機能単位で**Rust crate/API直接利用、外部CLI/サービス、AegisGuard独自実装、設計参考のみ、不採用**を比較し、「なぜ」を書く。
- Defender共存・必要権限・WFP/ETW/Sysmon/AMSIとの重なり・Windows 11実装制約・CPU/メモリ/誤検知・検査漏れを扱う。
- ライセンスはソース/ルール/署名/データごとに確認。互換性に疑義があれば「法的評価未完了」と書く。
- 最後に「導入候補上位3件（優先度、S/M/L規模、ブロッカー）」「見送り2件」「安全な最小PoCの受け入れ基準」を示す。根拠のない定量値を捏造しない。

## GitHubへの提出

`main` から専用ブランチを切り、`docs/research/results/wazuh/wazuh-windows-events.md` **だけ**を追加・更新してコミットし、**日本語のPRを作成してマージせず終了**。ほかの担当の成果物、既存コード、設定、CI、ドライバーは変更禁止。最後にPR URL・成果物URL・調査commit・未確認事項を報告。書き込めない場合は未反映であることを伝え、完成Markdown全文を示す。
