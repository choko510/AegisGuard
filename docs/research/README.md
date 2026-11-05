# AegisGuard 外部プロジェクト導入調査 — 15担当＋統合1担当

このディレクトリには **AIにそのまま渡せる調査プロンプト** と、調査結果の保存契約を収録しています。現段階は**調査設計**であり、取り込み可否の最終結論や実装を意味しません。

- **共通ルール**: [PROTOCOL.md](PROTOCOL.md)
- **成果物テンプレート**: [REPORT_TEMPLATE.md](REPORT_TEMPLATE.md)
- **結果格納先**: [results/README.md](results/README.md)
- **全体統合用プロンプト（最後に実行）**: [prompts/SYNTHESIS.md](prompts/SYNTHESIS.md)

## 担当一覧：15本の独立調査

| プロジェクト | 担当AIに渡すプロンプト | 調査範囲 | 結果Markdown |
|---|---|---|---|
| Loki-RS | [01 loki-scan-pipeline](prompts/loki-scan-pipeline.md) | ファイル/IOC/YARA/並列走査 | `results/loki-rs/loki-scan-pipeline.md` |
| Loki-RS | [02 loki-memory-ioc](prompts/loki-memory-ioc.md) | メモリ/Windowsプロセス/IOC | `results/loki-rs/loki-memory-ioc.md` |
| Portmaster | [03 portmaster-wfp-driver](prompts/portmaster-wfp-driver.md) | WFP/ドライバー/プロセス帰属 | `results/portmaster/portmaster-wfp-driver.md` |
| Portmaster | [04 portmaster-policy-dns](prompts/portmaster-policy-dns.md) | DNS/通信制御/ルール/フィード | `results/portmaster/portmaster-policy-dns.md` |
| Portmaster | [05 portmaster-service-ui](prompts/portmaster-service-ui.md) | サービス/UI/更新/権限/負荷 | `results/portmaster/portmaster-service-ui.md` |
| Wazuh | [06 wazuh-windows-events](prompts/wazuh-windows-events.md) | Windows Agent/Sysmon/イベント欠損 | `results/wazuh/wazuh-windows-events.md` |
| Wazuh | [07 wazuh-fim-persistence](prompts/wazuh-fim-persistence.md) | FIM/レジストリ/永続化 | `results/wazuh/wazuh-fim-persistence.md` |
| Wazuh | [08 wazuh-rules-correlation](prompts/wazuh-rules-correlation.md) | デコーダ/ルール/相関分析 | `results/wazuh/wazuh-rules-correlation.md` |
| ClamAV | [09 clamav-engine-scan](prompts/clamav-engine-scan.md) | エンジン/パーサー/安全性 | `results/clamav/clamav-engine-scan.md` |
| ClamAV | [10 clamav-signature-update](prompts/clamav-signature-update.md) | 署名DB/更新/ライセンス | `results/clamav/clamav-signature-update.md` |
| YARA-X | [11 yara-rust-api](prompts/yara-rust-api.md) | Rust API/MSRV/リソース | `results/yara-x/yara-rust-api.md` |
| YARA-X | [12 yara-rules-maintenance](prompts/yara-rules-maintenance.md) | ルール互換/配布/精度 | `results/yara-x/yara-rules-maintenance.md` |
| simplewall | [13 simplewall-wfp-policy](prompts/simplewall-wfp-policy.md) | WFP/フィルター/権限 | `results/simplewall/simplewall-wfp-policy.md` |
| simplewall | [14 simplewall-operational](prompts/simplewall-operational.md) | 永続化/運用/例外/復旧 | `results/simplewall/simplewall-operational.md` |
| ConfigureDefender | [15 configuredefender-asr](prompts/configuredefender-asr.md) | Defender監査/ASR/配布制約 | `results/configuredefender/configuredefender-asr.md` |

## AIへの渡し方

1. **先にこの調査プロンプト一式を `main` にマージ**し、すべての担当が同じ`PROTOCOL.md`を読めるようにする。
2. AIを15個の別スレッド/作業セッションで起動する。**各AIには対応する1つのプロンプトMarkdownの全文を渡す。** 接続されたGitHubにアクセス可能なら、ファイルURLを指定して内容を読ませてもよい。
3. 15担当は並列で調査し、担当固有のブランチと成果物ファイルで**別PR**を提出する。**AI側でマージしない**。
4. 出揃ったら人間がPRの証拠リンク・誤認・ライセンス・対象コミットをレビューし、必要なら各AIへ追加調査を指示する。問題なければ報告書PRをマージする。
5. **最後に** [SYNTHESIS.md](prompts/SYNTHESIS.md) を別の統合担当AIへ渡す。統合担当は2つの意思決定用MarkdownをPRにする。必要なら人間が検証し、その後ようやく実装PRを計画する。

## 二重調査を避ける境界

- **Loki-RSとYARA-X**：前者はスキャナーとしての使い方/IOC/メモリ、後者はcrate/APIとルール互換性・配布が主担当。
- **Portmasterとsimplewall**：前者は製品全体とDNS/ドライバー、後者はWFPルールの実装と安全な運用。
- **WazuhとSysmon**：Sysmonそのものの仕組みとWazuhのイベント読み取り・相関処理を分ける。
- **ClamAVとYARA-X/Defender**：検出エンジンを二重常駐させる前提にはせず、付加価値と負荷・ライセンスを比較する。
- **ConfigureDefender**：安全なDefender設定監査を主目的にし、ユーザーの防御設定を勝手に変更しない。

## 重要な初期調査仮説（**未確定の採用判断**）

- YARA-XはRustと親和性が高いが、AegisGuardのMSRVとYARA-Xの必要Rust版に差がある可能性。現行Cargoを確認する。
- Loki-RS/Portmaster/simplewallはGPLv3、ClamAVはGPLv2、Wazuhは部位別にGPLv2/AGPL系のため、*コードをコピーすることと設計を参考にすることは違う*。
- ConfigureDefenderの配布条件は一般的なOSS利用許諾とは別に確認が必要。
- PortmasterのWindows通信制御はWFPドライバーを含む可能性がある。Windows標準機能での再現範囲を調べる。

最終的な採用判断は**一次情報・権限・ライセンス・Defender共存・性能測定結果**を揃えてから行います。
