# AegisGuard 外部調査・採用判断マトリクス

> 判定日: 2026-11-05（JST） / 対象: Windows 11 x64・Rust-first・Defender共存 / 対象AegisGuard `main`: [83fcf0d150e8d760baff5f971c106deb09c1f8e4](https://github.com/choko510/AegisGuard/tree/83fcf0d150e8d760baff5f971c106deb09c1f8e4)  
> 判定種別: **設計段階の暫定意思決定**。コード実装・Windows実機・負荷・誤検知・法務判断の完了を意味しない。詳細実行順序は [IMPLEMENTATION_ROADMAP.md](IMPLEMENTATION_ROADMAP.md)。

## 1. 入力の完全性・レビュー状態

[調査契約PR #2](https://github.com/choko510/AegisGuard/pull/2) の `docs/research/README.md`・`PROTOCOL.md`・`REPORT_TEMPLATE.md` を読み、15件すべての成果物と各head SHAを照合した。**15/15件の報告書PR #3〜#17、および基盤PR #2は2026-11-05に`main`へsquashマージ済み**。報告書は全て指定の1ファイルを変更し、テンプレート12節が存在することを確認。提出者`choko510`アカウントから#2〜#17へ**16件の技術COMMENTレビューを提出**したが、これは独立レビュアーの**APPROVEではない**。部分完了・実機未検証等の報告は、そのまま制約を残して採用判定した。基盤マージコミットは [4198f8e95acdaadbb7f67ebaca5c5a55ec486d52](https://github.com/choko510/AegisGuard/commit/4198f8e95acdaadbb7f67ebaca5c5a55ec486d52) 。各報告書のマージコミットは下表。**マージは技術妥当性・製品安全性・法務承認を自動的に証明しない**。

| 担当/成果物（すべてcommit固定） | 調査PR | 入力head SHA（40文字） | マージコミット/審査状態 |
|---|---|---|---|
| [loki-memory-ioc](https://github.com/choko510/AegisGuard/blob/8899a71d318542a838feeaf12ee7bfbad3535550/docs/research/results/loki-rs/loki-memory-ioc.md) | [#3](https://github.com/choko510/AegisGuard/pull/3) | `8899a71d318542a838feeaf12ee7bfbad3535550` | [merged `58b28f3f39b4`](https://github.com/choko510/AegisGuard/commit/58b28f3f39b42d5e888cee588e89549537303007) / COMMENT済（Approveなし） |
| [loki-scan-pipeline](https://github.com/choko510/AegisGuard/blob/7889d700a72ca962c6a248bbc4044555e02fca0d/docs/research/results/loki-rs/loki-scan-pipeline.md) | [#4](https://github.com/choko510/AegisGuard/pull/4) | `7889d700a72ca962c6a248bbc4044555e02fca0d` | [merged `e29cfef6b8aa`](https://github.com/choko510/AegisGuard/commit/e29cfef6b8aadd5214ae81d47e1f059872e8649f) / COMMENT済（Approveなし） |
| [clamav-engine-scan](https://github.com/choko510/AegisGuard/blob/71617ec18d8d51a00495db4e66dca41d30c7ea65/docs/research/results/clamav/clamav-engine-scan.md) | [#5](https://github.com/choko510/AegisGuard/pull/5) | `71617ec18d8d51a00495db4e66dca41d30c7ea65` | [merged `615ae096055d`](https://github.com/choko510/AegisGuard/commit/615ae096055de910b99c5e44db167827332a0192) / COMMENT済（Approveなし） |
| [configuredefender-asr](https://github.com/choko510/AegisGuard/blob/ff60fa2ac08d1d388ae27ede3755cd6e36e996da/docs/research/results/configuredefender/configuredefender-asr.md) | [#6](https://github.com/choko510/AegisGuard/pull/6) | `ff60fa2ac08d1d388ae27ede3755cd6e36e996da` | [merged `db6969eff8be`](https://github.com/choko510/AegisGuard/commit/db6969eff8beb3837d979df5f1a56af433085e61) / COMMENT済（Approveなし） |
| [clamav-signature-update](https://github.com/choko510/AegisGuard/blob/89be80cc28cc53792018e1f183ff475a00fa34e1/docs/research/results/clamav/clamav-signature-update.md) | [#7](https://github.com/choko510/AegisGuard/pull/7) | `89be80cc28cc53792018e1f183ff475a00fa34e1` | [merged `9ec2ccc98694`](https://github.com/choko510/AegisGuard/commit/9ec2ccc98694b67f5a9817aefa49eaf8f30c1d05) / COMMENT済（Approveなし） |
| [portmaster-policy-dns](https://github.com/choko510/AegisGuard/blob/1fcb5b850692018c0889796c7dbb2f561f1098e0/docs/research/results/portmaster/portmaster-policy-dns.md) | [#8](https://github.com/choko510/AegisGuard/pull/8) | `1fcb5b850692018c0889796c7dbb2f561f1098e0` | [merged `de2467b64702`](https://github.com/choko510/AegisGuard/commit/de2467b64702c201319fdeaa9b155667acedb7a6) / COMMENT済（Approveなし） |
| [portmaster-wfp-driver](https://github.com/choko510/AegisGuard/blob/c06bd5d7c552d410f8cc5072f0dce49d4c31dc3e/docs/research/results/portmaster/portmaster-wfp-driver.md) | [#9](https://github.com/choko510/AegisGuard/pull/9) | `c06bd5d7c552d410f8cc5072f0dce49d4c31dc3e` | [merged `77698711dd11`](https://github.com/choko510/AegisGuard/commit/77698711dd113558254b5faaa341811aec012f5b) / COMMENT済（Approveなし） |
| [portmaster-service-ui](https://github.com/choko510/AegisGuard/blob/c1083b6199077977cc1642e76ed2a5e2b05a4774/docs/research/results/portmaster/portmaster-service-ui.md) | [#10](https://github.com/choko510/AegisGuard/pull/10) | `c1083b6199077977cc1642e76ed2a5e2b05a4774` | [merged `57fd156c19d5`](https://github.com/choko510/AegisGuard/commit/57fd156c19d5d8cb98b49b9930a953993fae6114) / COMMENT済（Approveなし） |
| [simplewall-wfp-policy](https://github.com/choko510/AegisGuard/blob/f6d8f43f46803a8111dea16d1d3351f4edc6c054/docs/research/results/simplewall/simplewall-wfp-policy.md) | [#11](https://github.com/choko510/AegisGuard/pull/11) | `f6d8f43f46803a8111dea16d1d3351f4edc6c054` | [merged `2d842e7752b4`](https://github.com/choko510/AegisGuard/commit/2d842e7752b4ec9844af1f0007d45018d5fd8f81) / COMMENT済（Approveなし） |
| [simplewall-operational](https://github.com/choko510/AegisGuard/blob/be6d8383372d5e704cf2cc41964db5eecc6564b2/docs/research/results/simplewall/simplewall-operational.md) | [#12](https://github.com/choko510/AegisGuard/pull/12) | `be6d8383372d5e704cf2cc41964db5eecc6564b2` | [merged `023e3469f5b8`](https://github.com/choko510/AegisGuard/commit/023e3469f5b842a8403faeadb7ab3072e6a3b864) / COMMENT済（Approveなし） |
| [wazuh-fim-persistence](https://github.com/choko510/AegisGuard/blob/f81b49261e8690a7801e5f1792de0435bb886257/docs/research/results/wazuh/wazuh-fim-persistence.md) | [#13](https://github.com/choko510/AegisGuard/pull/13) | `f81b49261e8690a7801e5f1792de0435bb886257` | [merged `e3de7c706965`](https://github.com/choko510/AegisGuard/commit/e3de7c706965605158cb325af0ab95241c3a050f) / COMMENT済（Approveなし） |
| [yara-rust-api](https://github.com/choko510/AegisGuard/blob/ebc66402a990ccc02c124afa6cf35b99297c9c0f/docs/research/results/yara-x/yara-rust-api.md) | [#14](https://github.com/choko510/AegisGuard/pull/14) | `ebc66402a990ccc02c124afa6cf35b99297c9c0f` | [merged `119dd5f2789a`](https://github.com/choko510/AegisGuard/commit/119dd5f2789a0cee527fe37c54b0fc01ce7a846b) / COMMENT済（Approveなし） |
| [wazuh-windows-events](https://github.com/choko510/AegisGuard/blob/0287f43689cb88762de9834a3ce8b137680cc5e4/docs/research/results/wazuh/wazuh-windows-events.md) | [#15](https://github.com/choko510/AegisGuard/pull/15) | `0287f43689cb88762de9834a3ce8b137680cc5e4` | [merged `bf23d9437bf7`](https://github.com/choko510/AegisGuard/commit/bf23d9437bf70ef3183f80f88625aa74f581121d) / COMMENT済（Approveなし） |
| [yara-rules-maintenance](https://github.com/choko510/AegisGuard/blob/2d5ac3aa33f83833be4244ee304b06ec027a6f2d/docs/research/results/yara-x/yara-rules-maintenance.md) | [#16](https://github.com/choko510/AegisGuard/pull/16) | `2d5ac3aa33f83833be4244ee304b06ec027a6f2d` | [merged `4281c89e87fb`](https://github.com/choko510/AegisGuard/commit/4281c89e87fbb021d934dff36e31abccf4b4c41d) / COMMENT済（Approveなし） |
| [wazuh-rules-correlation](https://github.com/choko510/AegisGuard/blob/1198a5117b2aeae6d70499b937332a299d2cc358/docs/research/results/wazuh/wazuh-rules-correlation.md) | [#17](https://github.com/choko510/AegisGuard/pull/17) | `1198a5117b2aeae6d70499b937332a299d2cc358` | [merged `90aa2b77617c`](https://github.com/choko510/AegisGuard/commit/90aa2b77617ca6210095c502e3916a5896e22ded) / COMMENT済（Approveなし） |

**追跡と確認範囲**: 各元報告のhead SHAとGitHubが返したsquash merge commitを併記した。今回のレビューはPR単位のファイル/構造/主要一次情報の監査であり、外部リンク全件到達性・原典全行の網羅試験・独立承認を意味しない。元報告が今後修正されたときは、別の訂正PRを作って本マトリクスにも反映する。

## 2. 結論・優先順位

### 最優先3件（採用するのは実装方針。実装着手にはPhaseゲートが必要）
1. **P0：安全・証拠・失敗モデルの強化**。現行`Report.analysis_complete`を維持し、I/O不可・再解析ポイント競合・デコード打切り・ログ欠損・ルールエラーを区別。入力/展開/キュー/ディスク上限と復旧を先に実装する。現行[model.rs](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/model.rs#L24-L107)・[scan.rs](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/scan.rs#L27-L90)・[SECURITY.md](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md)が起点。
2. **P1〜P2：Windows Event Logの読み取り専用収集＋小さな相関器**。標準Event Log APIをRustから使用し、まずSysmon Event ID 1/5、次に3/7/22・Defenderログを必要に応じ有効化。ProcessGuidとログ欠損を共に保持。Wazuhの収集コードは転用しない。
3. **P0〜P1：検証可能なIOC/ルール供給網**。現行C2のソース別TTLを保持し、出所・利用許諾・失効・バージョン・署名・二世代ロールバックを定義。外部データの同梱や自動遮断を承認した意味ではない。[現行更新](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L277-L338)は一時ファイル→旧版.bak→新ファイルの複数操作であり、電源断での無停止を証明していない。

### 条件付き採用3件
1. **YARA-X（P1）**：BSD-3-Clauseの公式Rust crateを第一候補に**固定ルール・監査モードでPoC**。Rust 1.85→上流1.95のMSRV差、依存ライセンス、タイムアウト、Windows実機、個別ルールの権利がブロッカー。CLI別プロセスはMSRVを維持する代替評価。[公式Cargo](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/Cargo.toml#L1-L19)。
2. **限定FIM/レジストリ差分（P2〜P4）**：重要な少数パスだけの読み取り専用ベースライン＋欠損時再走査。FIMは**ブラウザ認証情報DBの単純な読み取りを検出しない**。監視対象・権限・ログ量・TOCTOU・誤検知の実測後に範囲拡大。
3. **アプリ単位の限定アウトバウンド遮断（P3）**：まず**ポリシー計画とdry-runだけ**。Windows Firewall公開APIからAegisGuard所有ルールを明示承認で追加する案を隔離VMで評価。所有・期限・復旧・IPv4/IPv6・他製品共存を実証するまで実際の遮断は禁止。[Microsoft INetFwRule](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule)。

### 明確に見送る代表3件
1. **Portmasterのカーネルドライバー/Goコアの組込み**：GPL-3.0、WDK・ドライバー署名・OS停止リスク、Defender競合、過大な初期運用費。直接呼び込みと「Rust製だから流用容易」は不適切。[driver panic処理](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/lib.rs#L40-L81)。
2. **Wazuh Manager/Engine/Indexerやルール一式の移植・同梱**：4.x Cの相関と5.x C++ Engineを同一視できず、GPLv2/AGPL系の境界、重い依存、Windowsローカル目的との不整合。[Wazuh LICENSE](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/LICENSE#L1-L65)。
3. **ClamAV libclamav＋署名DBの二重常駐統合**：GPLv2・C/Rust FFI、アーカイブ解析面の複雑性、Defender重複負荷、公式/第三者DB再配布許諾の不足。手動の別プロセス比較は法務審査後の任意調査に限定。[COPYING](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/COPYING.txt)。

## 3. 重み付きスコアと不可欠なゲート

0〜5点は **5=今回のAegisGuardの設計目標に強く適合、0=明確に不適合**（実機検証の合格を意味しない）。軸順を D（検出・防御効果、重み25）、R（Rust統合20）、W（Windows/Defender共存20）、L（権利・再配布15）、P（性能・電池10）、M（保守10）とする。暫定合計は `Σ(軸の0〜5点 × 重み / 5)`、上限100点。性能未測定は有利に推定せず保守的に配点し、検証中は確度が低い。

| **候補方式** | D/R/W/L/P/M | 合計/100 | ゲート / 決定 | 主な根拠・条件 |
|---|---|---:|---|---|
| 失敗・上限・証拠の独自モデル | 5/5/5/5/5/5 | **100** | 方針採用 P0 | 既存Reportを拡張。実測で評価継続 |
| Windows APIによるイベント収集＋独自相関 | 5/4/5/5/3/4 | **90** | 方針採用 P1/2 | Sysmon別途有効化、永続cursor、権限、gap可視化 |
| 独自の署名・世代付き更新器 | 4/5/5/4/4/4 | **88** | 方針採用 P0/1、配布は保留 | 鍵保護・供給者許諾・切替の障害注入必須 |
| Microsoft APIでのDefender読み取り専用監査 | 3/5/5/5/4/4 | **86** | 方針採用 P4 | 有効な監査権限・GPO/ポリシー優先を区別 |
| YARA-X公式Rust crateによる検査 | 5/3/5/4/3/4 | **83** | **条件付き・PoCのみ** | MSRV 1.95、依存通知・ルール権利・負荷 |
| 独自のDNS/IPの確度付き証拠相関 | 4/4/5/5/3/3 | **83** | 方針採用 P2/3 | DoH/VPN等は不可視、DNS名≠接続先の証明 |
| 限定FIM＋レジストリ差分 | 4/4/5/5/3/3 | **83** | **条件付き・読取PoC** | 欠損時再走査・低負荷・誤検知評価 |
| Windows Firewall所有ルールの限定適用 | 4/4/3/5/4/3 | **77** | **保留：復旧ゲート未成立** | 明示承認・自動期限切れ・復旧CLI必須 |
| ユーザー同意による限定プロセスメモリ検査 | 3/3/3/5/2/2 | **62** | **保留：権限・機密ゲート** | PPL拒否を尊重・領域別coverage・全PID巡回禁止 |
| ClamAV libclamav/DB直統合 | — | **採点不可** | **見送り：法務・配布ゲート** | GPLv2とDBの権利・二重常駐の価値未実証 |
| Portmaster WFPカーネル/Goコア直統合 | — | **採点不可** | **見送り：法務・ドライバーゲート** | GPLv3、署名、panic/復旧設計なし |
| Wazuh Manager/Engine/ルール直統合 | — | **採点不可** | **見送り：法務・運用ゲート** | GPLv2/AGPL、C++、大規模サーバー構成 |
| simplewall GPLコード/CLI直接内蔵 | — | **採点不可** | **見送り：法務・共存ゲート** | Firewall無効化経路や広域ポリシーを継承しない |
| ConfigureDefender EXEの起動/改変同梱 | — | **採点不可** | **見送り：許諾・副作用ゲート** | 無改変・非販売配布条項は組込改変許諾ではない |
| YARA Forge全量ルールの自動同梱 | — | **採点不可** | **保留：ルール単位の許諾・互換ゲート** | 集約ツールGPLv3≠個々のルールのライセンス |

**スコアを覆すゲート**：①実際に利用・頒布するコード/ルール/データの法的許諾不明、②必要な独自ドライバーの署名・更新・rollback・OS停止対策なし、③DefenderまたはWindows Firewallを無効化、④未知入力の無制限展開・無制限バッファ、⑤自動遮断に期限・利用者承認・復旧・所有範囲なし。該当案は高得点でも不可。スコアを実際の検出率・互換率と呼ばない。直接転用を見送っても、**Microsoft公開APIを使ってゼロから独立実装する案の点数は別**である。

## 4. 横断機能マップと推奨接続方式

| 機能・観測契約 | 推奨方式と接続先 | 主な参考調査 | コスト/依存・失敗安全性 |
|---|---|---|---|
| 静的PE・スクリプト検査 | **既存Rustを強化**：`scan.rs/pe.rs/script.rs/model.rs` | Loki-RS #4、ClamAV #5 | S〜M / P0。サイズ超過・破損は`not_assessed`、復号打切りは`incomplete`。Reparse/TOCTOUの修正 |
| YARA検出（raw/復号層） | **YARA-X公式crate/API**、MSRV不一致時だけ**別CLIで隔離PoC** | YARA-X #14/#16、Loki #4 | M / Phase1。ルールcompile failure・timeoutを不完全として表現。マッチで自動措置しない |
| IOC更新・署名/来歴 | **AegisGuard独自実装**、ClamAV/Portmasterの設計参考 | ClamAV #7、Portmaster #8/#10 | M / P0〜1。旧検証済み世代保持、期限切れは有効一致としない |
| ファイル名・ハッシュIOC | **独自実装**、YARA/IOCを同じ証拠ID体系へ | Loki #3/#4 | M / P1。ハッシュとファイルidentityを照合、誤検知例外は期限付 |
| イベント監視（Process/Network/DLL） | **Windows Event Log API直接**＋**独自Rustセンサー** | Wazuh #15、Portmaster #9 | M / P2。Sysmon外部依存・ID3/7負荷、落ちたイベントを明示 |
| 時間窓ルール・スコア | **独自実装**。Wazuh 4.xの概念を参考 | Wazuh #17 | M / P2。ProcessGuid、重複・逆順・再起動/欠損。既存riskスコアと確率を混同しない |
| FIM・変更通知・永続化 | **Windows API直接＋独自差分DB** | Wazuh #13 | M〜L / P2〜4。対象限定、再走査で不足埋め、SACLは触らない |
| C2ドメイン/DNS/通信 | **独自相関器**：IP/ドメイン/プロセスごとに証拠と確度 | Portmaster #8、Loki #3 | M / P3。CDN・DoH・VPN・名前解決遅延はunknown、誤遮断禁止 |
| ファイアウォール応答 | **Windows Firewall API直接**の自分のルールのみ。WFP user-mode APIは**比較PoC** | simplewall #11/#12、Portmaster #9 | M〜L / P3。dry-run→承認→限定適用→検証→rollback。独自driverは不要と推定、ただし要求による再評価 |
| Defender/ASR状態 | **Microsoft公開API/PowerShell読み取りのみ**。ConfigureDefenderは**設計参考** | ConfigureDefender #6 | S〜M / P4。管理主体と実効値を区別、設定書換えをしない |
| 認証情報窃取兆候 | **自作の相関ルール**：プロセスアクセス/ファイル操作/外部通信/Defenderイベント | Wazuh #13/#17、Loki #3、#6 | L / P4。単一指標で悪性確定しない。資格情報・ブラウザDB/メモリは既定で読まない |
| プロセスメモリ | **限定Windows API読取＋YARA-X**は将来の明示同意PoCのみ | Loki #3 | L / P4以降。権限拒否・部分読取を観測、バイト内容はログへ保存しない |
| 常駐サービス/IPC/GUI | **独自Rustサービス・ACL付きNamed Pipe・別権限GUI** | Portmaster #10 | M〜L / P2以降。まずCLIの観察、特権命令は昇格サービスのみ。未実装 |

## 5. 重複機能の調停・根拠を伴う差異

### Loki-RS vs YARA-X
Loki-RSはファイル列挙・IOC・プロセスメモリ読取等を**束ねるアプリケーション**であり、YARA-Xはパターン照合の**エンジン**。Loki-RSのGPL-3.0コードを使わず、BSD-3-Clauseの上流YARA-X crateを直接評価する。Lokiのメモリ領域連結は境界を跨いだ偽一致と未読領域の隠蔽があり、領域単位・部分結果を契約とする。[Lokiのread/連結実装](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L800-L865)。上流YARA-Xは[第三者が操作可能なRulesのdeserializeを警告](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/rules.rs#L295-L305)。失敗は「検出なし」にしない。ルール品質は未実測。

### Portmaster vs simplewall
PortmasterはGoサービス＋Rust WFPカーネルcallout、DNS介入とアプリ帰属を含む総合製品。simplewallはWindowsユーザーモードWFP管理APIからprovider/filterを管理する別方式。**どちらのGPL-3.0コードもコピーしない**。AegisGuard初期要件は**アプリ限定・期限付き送信遮断**であり、Microsoftの[INetFwRule](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule)を先に検証し、[WFP user-mode filter management](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/wfp-user-mode-management-functions)は同じテストケースで比較。シンプルなフィルタのための独自callout driverを初期要件としない。simplewallには[Windows Firewallを無効化する実装](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L2059-L2085)があり、明示的に不採用。「temporary」はアプリ終了と同時に必ず消えるdynamic sessionではない（[#12](https://github.com/choko510/AegisGuard/pull/12)）。WFP優先順位・既存VPN/WSL/Defenderとの競合は実機未検証。

### Wazuh vs Windows Event Log/Sysmon
Sysmonは[ProcessGuid付きイベントを生成するMicrosoftの別ソフト](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)、Wazuhはその**Windows Event Log読取・転送・相関**が参考となる。Sysmon Event 3/7は既定OFF・高負荷になり得るので段階導入。Wazuhの[SendMSGが失敗してもbookmark更新](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/read_win_event_channel.c#L357-L370)、[bookmark再購読失敗時にfuture-onlyへ切替](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/read_win_event_channel.c#L489-L513)は「欠損ゼロ」保証ではない。AegisGuardは**イベントのdurable保存に成功した後**にカーソル進行、不可逆欠損はhealthとJSONLに記録する。さらにWazuhの4.x `analysisd`と5.x alphaのEngineの時間窓相関は同一と認定しない（[#17](https://github.com/choko510/AegisGuard/pull/17)）。

### ClamAV vs Defender＋YARA-X
ClamAVはC中心のフルAVエンジン/多形式パーサと独自署名DBを持ち、その検出範囲はYARAと同一ではない。ただしAegisGuardの**追加エンジン常駐の必要性・誤検知減少・負荷**は未実証。Defenderを一次防御、AegisGuardの静的ルールを理由付き調査に限定する。ClamAVのCVD/CDIFF設計から**完全性検証→ステージング→ロード確認→復旧**だけ学ぶ。GPLv2本体と[署名フォーマット/DB](https://docs.clamav.net/manual/Signatures.html)の配布権を混同しない。アーカイブ走査は圧縮比だけでなく総展開量・階層・件数・CPU時間の予算が揃うまで追加しない。

## 6. 法務・安全・コストの共通ゲート

| 対象/一次資料（固定） | 現時点の理解 | 次の承認条件 |
|---|---|---|
| [AegisGuard README](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md) | **ライセンス未設定**。GitHub公開は第三者へのコード再利用・頒布許諾を意味しない | **当面は文書の統合のみ**。OSSライセンス選択・バイナリの再配布は所有者の意思決定事項。第三者のGPL/AGPLコードはコピーしない |
| [YARA-X LICENSE](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/LICENSE)・[Cargo](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/Cargo.toml) | BSD-3-Clause、MSRV=1.95.0。同梱依存のライセンスは別 | SPDX/SBOM、著作権/免責notice、Windowsテスト、ルール個別台帳 |
| [YARA Forge LICENSE](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/LICENSE) | 集約ツールGPLv3、第三者ルール各々の許諾と互換性は未確認 | ルール単位の作者・出典・使用/再配布可否・版とテスト |
| [Loki-RS LICENSE](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/LICENSE)、[Portmaster LICENSE](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/LICENSE)、[simplewall LICENSE](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/LICENSE) | 各本体GPLv3。**外部CLIなら法的に常に安全とはいえない** | コード直訳/コピー/リンク/バイナリ同梱をしない。将来連携するなら法務審査 |
| [Wazuh LICENSE](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/LICENSE) | Engine AGPL-3.0-or-later、共通モジュールはGPL-2.0-only OR AGPL-3.0-or-later、その他は原則GPLv2 | ファイル単位・配布形態の法務評価が無いので設計参考まで |
| [ClamAV COPYING](https://github.com/Cisco-Talos/clamav/blob/dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d/COPYING.txt) | 本体GPLv2。UnRAR等第三者部品、CVD、第三者DBは別 | 直接統合せずDB再配布の許諾は未確認と表示 |
| [ConfigureDefender License](https://github.com/AndyFul/ConfigureDefender/blob/04163467957211587914f993f0799681e98d9b57/License.txt) | 無改変・無販売での再配布文言。MIT等の広汎な転用許諾ではない | EXEやソースを移植せず[Microsoft Defender公式](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-windows-events)の読取APIを独自実装 |
| [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)・[Sysinternals利用条件](https://learn.microsoft.com/en-us/sysinternals/license-terms)・[WFP API](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/wfp-user-mode-management-functions) | 公開Windows Event Log/WFP APIの参照と、Sysmon実行ファイルの第三者再配布許可は別。Microsoftの許諾は自由再配布を認めない | **SysmonをAegisGuardに同梱せず、ユーザーがMicrosoft公式から別途入手・導入する形式**に固定 |

**数値は今後測る**：S=単一モデル/薄いアダプタ、M=新サブシステム＋テスト、L=特権・OS相互運用/再起動復旧。開発工数の実時間見積りではない。CPU/RSS/電池/ディスク/イベント欠損率、誤検知率、ユーザー操作への影響はベースラインと同じ機材・fixtureで測り、閾値はその結果から決める。

## 6A. 追加の一次情報確認と残件のクローズ方法（2026-11-05）

| 論点 | 追加で確認した根拠 | 採用/見送りの結論 |
|---|---|---|
| Feodo Tracker | [abuse.ch利用規約 2026-10-21改定 3.4](https://abuse.ch/terms-of-use/) はFeodo TrackerデータをCC0原則で商用/非商用利用可と記載。[Feodo公式FAQ](https://feodotracker.abuse.ch/faq/)によると現在の対象botnetデータが空の場合がある | 出典・取得時刻・有効期限を記録して照合のみ。空フィードは安全判定ではない。利用規約や配布元の変更は都度確認する |
| C2IntelFeeds | [公式README固定commit](https://github.com/drb-ra/C2IntelFeeds/blob/eda1465f49e07fea4df4246a310fc94dd78873ed/README.md) は **CC BY-NC-SA 4.0** と明記（帰属・非商用・継承）。単独LICENSEファイルは確認できなかった | **商用/再配布向けの既定フィードに採用しない**。明示的な非商用ユーザー選択と出所/許諾記録が整うまで、将来配布版の標準更新対象から除外する。現行MVPの参照URL削除は別途コードPRで必要 |
| Sysmon | [Microsoft Sysinternalsライセンス](https://learn.microsoft.com/en-us/sysinternals/license-terms) と [再配布FAQ](https://learn.microsoft.com/en-us/sysinternals/license-faq) | 実行ファイルは無断同梱/改変/再配布しない。ユーザーが公式から導入したSysmonのイベントだけを読む。標準Windowsイベント経路は別実装 |
| YARA-Xとルール | [YARA-X BSD-3-Clause](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/LICENSE)、[v1.22.1 CargoのMSRV](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/Cargo.toml)、[YARA Forge GPLv3](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/LICENSE) | **最小PoCは自作ルールだけ**。第三者ルール全量同梱を見送り、上流crateの著作権NOTICE・依存SBOMは実際の配布前に監査。MSRV差は技術ゲートとして継続 |
| ConfigureDefender | [公式利用条件固定SHA](https://github.com/AndyFul/ConfigureDefender/blob/04163467957211587914f993f0799681e98d9b57/License.txt) は無改変・非販売配布と記載 | EXE/AutoIt/ミラーのコード転用や同梱を禁止。Microsoft公開APIで独自の読取り専用監査を設計 |
| AegisGuardの配布許諾 | [README](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md)は本体ライセンス未設定 | **所有者の決定を代行しない**。調査ドキュメントのマージは許諾決定でない。外部コード・データの許諾不明は「使わない」で閉じる |
| Windows 11実機性能/誤検知/復旧 | 利用者が今回の追加調査から**明示的にスキップ**を指定 | **未実施・合格とは主張しない**。研究資料の統合・マージは可能だが、実行時遮断/常駐などの本番出荷判定には別途安全性確認が必要 |

**調査資料の統合完了条件**：15件のMarkdown存在・12節構成・head SHAとsquash commit・16件のCOMMENTレビュー・主要な上流一次情報を確認した。未許諾の外部資産は**採用しない**と決定しており、法務判断が無い状態でのバイナリ同梱を行わない。実機検証を含まない本調査の成果は**設計決定資料**であり、独立レビューのAPPROVEや完成した防御機能を意味しない。

## 7. 第三の検証が必要な事項・ネガティブ判断

- **R-01 / YARA互換・供給網**：既存YARAルールの旧YARAとYARA-Xのcompile差・検出差、各ルールのライセンスとwarnings、タイムアウト上限の強制性。第三者が操作したserialized Rulesを読み込まない。**確認責任**: ルール担当＋セキュリティレビュー。
- **R-02 / Windowsイベント継続性**：SysmonのEvent 3/7の明示有効化・CPU/RSS、bookmarks破損、ログ上書き、EventID別schema、バックプレッシャー、再起動時の「重複は可・無言の損失は不可」の検証。**責任**: Windows実機検証者。
- **R-03 / WFP・Firewall競合**：Windows Firewall COMと直接WFP user-mode管理で同じアプリ/宛先限定条件が作れるか。ポリシー優先順位、BFE停止、VPN/WSL2/IPv6、ロールバックと期限切れ。**責任**: 隔離VM管理者。成立まで実通信遮断は保留。
- **R-04 / ポリシーと法務**：AegisGuard配布ライセンス、YARAルール/Feed/署名DB各権利、管理者権限の採用、Sysmon利用条件、コード/外部CLIを同梱する場合の義務。**責任**: 所有者＋必要に応じ法務担当。
- **R-05 / 資格情報窃取**：FIMはread exfilを検出しない。Sysmon Event 10等のプロセスアクセス、Defender ASR、通信との相関で何を観測できるか、誤検知・個人情報の処理を合成テストで検証。生パス・コマンドラインは最小収集、Cookie/パスワードを採取しない。
- **R-06 / Portmaster更新署名**：バイナリ更新とintel更新の検証設定は別経路。Portmasterの署名保証をそのままAegisGuardへ移植しない。**代替決定**: 自作マニフェストに認証とリプレイ防止を必須とする。
- **R-07 / ClamAV追加価値**：Defender有効のままの検出改善がfalse-positive/性能コストを上回るか実測できない限り常駐エンジン追加を行わない。
- **R-08 / 4.x/5.x Wazuh相関の同一視**：5.x alphaの機能互換が未確認。AegisGuardは4.xルールを直接実行せず、独自小規模仕様と再生テストを先に用意する。

**やらないこと（確定した禁止設計）**：Defender/Firewall無効化、無許可のドライバー導入・DLL注入、TLS復号やDNS一律横取り、全PID定期メモリ収集、無制限アーカイブ展開、外部検体や生ログの自動アップロード、資格情報DBの内容収集、自動ファイル削除、1件のYARA/IOC一致だけでの遮断、他製品ルールの削除、根拠のない「完全保護」表示。管理者または組織ポリシーを迂回して設定変更しない。

**完了/未完了の区別**：調査基盤・15件のレポートはmainにマージ済み、COMMENTベースの技術検査も実施済み。**独立第三者Approveはなし**。利用者指定によりWindows 11/Defender実機性能・誤検知・復旧の検証は**スキップ（成功ではない）**。本体ライセンス選択、将来の再配布、実運用遮断の承認は保留したまま、外部資産を無断利用しない設計として研究統合を完了する。
