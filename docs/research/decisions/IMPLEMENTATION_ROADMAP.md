# AegisGuard 実装ロードマップ（調査結果からの開発計画）

> 作成日: 2026-11-05（JST） / 比較対象 `main`: [83fcf0d150e8d760baff5f971c106deb09c1f8e4](https://github.com/choko510/AegisGuard/tree/83fcf0d150e8d760baff5f971c106deb09c1f8e4)  
> 関連：[ADOPTION_MATRIX.md](ADOPTION_MATRIX.md)（15件のcommit固定PR・重み付き比較・法務/安全ゲート）。**本書は実装命令の分割と検証基準であり、いずれのフェーズも未実装・未完了**。調査PR #3〜#17は未レビュー・未マージ。調査基盤PR [#2](https://github.com/choko510/AegisGuard/pull/2)も未マージ。

## 0. 現行の開始点と実装原則

AegisGuard 0.1.0は**Rust CLIの静的PE/スクリプト調査・手動C2 IP更新/オフライン照合のみ**。`src/main.rs`は`scan`・`c2 update/check/status`だけを提供し、実行時ブロック、サービス、イベント収集、YARA-X、署名検証、GUIは未実装。[現行CLI](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/main.rs#L1-L78)・[現行設計](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md)・[SECURITY.md](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md)を出発点とする。

- **保護を弱めない**：Defender・Firewall・ASRを無効にしない、ポリシーやGPO/Tamper Protectionを回避しない。OS設定の書込みはPhase 3で**ユーザー明示承認**と安全復旧の後だけ。
- **観測→監査→限定適用**：検査不能/欠損/遅延/不明な帰属は「陰性」や「防御成功」と表示しない。誤検知は説明・例外・監査で扱い、検出だけで自動削除・隔離しない。
- **Rust-first、境界は分離**：ローカルのcore/model、read-only sensor、rules/IOC updater、privileged response、一般ユーザーUIを明示的に分割。最初からすべてを別crateにせず、APIの境界だけ先行定義する。
- **外部ソースをコピーしない**：Wazuh GPL/AGPL、ClamAV GPLv2、Portmaster/simplewall/Loki-RS GPLv3、ConfigureDefender独自条件。Windows公開APIと独自設計を採用。YARA-X公式BSD-3-ClauseはMSRV/依存ライセンスを検証後に候補。
- **初期は未知サンプルを実行しない**：合成した無害なPE/スクリプト/イベント/IOC、専用テストルール、Mock HTTP/Windows 11隔離VMだけを使う。資格情報やブラウザDB、生のプロセスメモリをログ・クラウドへ送らない。
- **依存の開始ゲート**：15調査PRの人間レビュー、未マージheadの再照合、AegisGuard配布ライセンスの方針確認。実装PR着手時にはその時点の`main`/Cargo/CIを再確認する。

## 共通評価方法（全フェーズ共通）

**テスト台帳**を各PRに付ける。Windows 11 x64の隔離VM（ビルド番号、Defender状態・シグネチャ版、Sysmon導入有無/設定hash、CPU/メモリ・電源条件を記録）とCIのLinux/Windowsの両方で、変更前`main`と変更後を同じfixture・同じ繰り返し条件で比較。調査報告の「テスト所在確認」は**テスト実行済みを意味しない**。GitHub Actionsの設定・実行ログを各PRで確認し、Linux成功だけでWindows合格としない。

| 計測対象 | 測り方（成果物） | 停止・保留の考え方 |
|---|---|---|
| 検出と誤検知 | 無害な合成positive/negative、代表的な正常な管理スクリプト、署名済み正規PEを出所・hash・期待理由で固定。TP/FP/FN、ルール単位の誤警告・重複数・coverageを集計 | リグレッションや強い偽陽性は該当ルールを無効に戻す。陰性を「安全」と主張しない |
| 完全性・欠損 | 入力個数/バイト、検査完了/部分/不能、イベント取得数/永続化数、bookmark、ギャップ・取りこぼし件数、理由付きエラーを照合 | 損失が発生し表示されない、または不完全が低リスク扱いなら失敗 |
| CPU・メモリ・電池 | 同じデータセットのcold/warm実行を複数回行い、wall time、CPU time/平均・最大CPU%、peak private bytes/working set、I/O bytes、稼働時間とアイドル時消費を記録。電池はAC/バッテリー条件とWindows電源レポート/ETW値を分ける | 合格閾値はPhase 0で実機ベースラインから**事前宣言**。推定値で目標達成を主張しない |
| イベント処理 | 生成時刻→観測/保存/検出時刻のp50/p95/p99、events/s、キュー最大深さ、ディスク使用量、停止/再起動復旧時間、欠損/重複・逆順を測る | 上限到達時はdegradedとして警告し、メモリが無限に増えない |
| 更新・遮断・復旧 | 署名エラー、長さ超過、回線断、容量不足、ファイルロック、再起動、プロセスkill、権限拒否、同時操作、IPv4/IPv6/VPN/WSLを隔離VMで再生 | 旧検証済み世代/自己ルールだけの復元を実証できない場合、書込/遮断機能は有効化しない |
| プライバシー | JSONL/クラッシュログ/診断テレメトリでパス、ユーザー名、コマンドライン、資格情報風文字列、生メモリの混入をfixtureで検査。ACLと保存期限/ローテーションを監査 | 秘密・内容の漏出、外部送信、アクセス権過剰なら中止 |

**性能目標の決め方**：初回ベースライン計測→対象ハードウェア別（標準的ノートPCと低負荷機を含む）の許容予算を文書化→PRのCI/実機で回帰比較→閾値を満たさない機能を既定OFF。**今は具体的なms/MB/%の達成値は設定できない**。ただし無制限メモリ・無制限展開・静かなイベント欠損・復旧不能な遮断は測定を待たずに不合格。

## Phase 0 — 現行MVPの品質ゲート（最初に必須）

**依存**：現行`main`。外部エンジン/管理者権限/サービスは必要ない。**目的**：後続の機能が安全失敗契約を破れない基盤を作る。

1. **P0-01 安全モデル・JSONL vNext（S）**  
   入力：既存`Report`および各スキャナーの結果。出力：`analyzed / incomplete / not_assessed`、理由コード、エンジン/ルール/fixture版、coverage、時刻、ファイルidentity。検出理由と「到達できなかった範囲」を別軸にする。**DoD**：既存JSONL読者との互換テスト、0検出でも部分/不能が陰性に変換されない単体テスト、PII出力最小化のgolden fixture。既存[model.rs](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/model.rs#L24-L111)の意味を保つ。
2. **P0-02 ファイルidentity/TOCTOU対策（M）**  
   入力：ローカルファイル/フォルダ。Windowsでreparse point拒否を含むハンドルベースのポリシーと、読取前後のidentity整合。**DoD**：symlink/ジャンクション/再parse差替え/削除/成長/権限拒否のfixtureで安全に中断し、別ファイルを誤って検査済みにしない。Linuxは現行挙動維持。[現行既知リスク](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md#L6-L13)。
3. **P0-03 有界資源・fuzz・異常入力（M）**  
   既存`scan.rs`のPE 64MiB/スクリプト4MiB上限、`script.rs`の復号層/深度/累積量を保ち、時間・同時実行/ログ容量/キャンセルを予算化。新規ZIP/アーカイブ解凍は**この段階では導入しない**。**DoD**：壊れたPE/難読化入力/巨大Base64/zip-bomb相当の合成データでpanic・OOM・無制限CPUなし。限界到達は理由付き`incomplete`。PE/scriptパーサはfuzz + プロパティテスト。
4. **P0-04 C2キャッシュ/ログ耐障害（M）**  
   `src/c2.rs`のフィード別48時間TTL、空/不正/古いデータの非一致を維持。`.tmp → .bak → 本体` のWindows rename/電源断の中間状態を洗い、起動時の復元と保存先ACL、JSONLのサイズ/世代ローテーションを追加。**DoD**：成功A/失敗BでBの最終成功日時が変わらず、短い読み込み/書込/クラッシュで旧検証済み情報が破損なく復旧。新旧2世代の原子性は障害注入で実証するまで未達。
5. **P0-05 CI/依存監査・基準値（S〜M）**  
   Linux/Windowsの`fmt / clippy -D warnings / test`、固定安全fixture、Cargo.lock固定、ライセンス一覧/SBOM、依存脆弱性検査、ワークフローAction SHA固定、無害なbenchmarkを整理。**DoD**：Windows Runnerで定期再現可能、セキュリティ検査の失敗を隠さない、CPU/RSS/ディスク/誤検知の初期レポートが残る。CI編集は**将来の実装PR**で行い本統合PRでは変更しない。

**Phase 0出口**：WindowsとLinuxの既存テスト・異常入力・情報保護・クラッシュ復旧が合格し、ハードウェア別性能予算が決定済み。不明な検査を陰性に分類しない。**復旧**：後続機能フラグOFF、検査/更新を停止し前回有効なC2キャッシュ/JSONL形式に戻す。Defender/Firewallは一切変更しない。

## Phase 1 — YARA-X等の最小PoC（監査のみ）

**依存**：Phase 0、ルール出所台帳/所有者判断、[公式YARA-X Cargo](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/Cargo.toml#L1-L19)のMSRV整合。現行AegisGuardはRust **1.85**、固定されたYARA-X **1.22.1は1.95.0**を要求。最新の推奨版と依存のMSRVは実装直前に再確認。根拠なしにCargoを更新しない。

**I/O契約（新設案、未実装）**
- `YaraScanInput v1 = {artifact_sha256, layer_id: raw|decoded/<index>, bytes, ruleset_id, ruleset_sha256, max_input_bytes, deadline, policy_id}`
- `YaraScanOutput v1 = {engine_version, ruleset_sha256, matched_rule_ids[], evidence_offsets_redacted[], analysis_complete, incomplete_reasons[], duration_ms}`。**生の復元本文や秘密のマッチ文字列を保存しない**。エラーは `compile_failed / unsupported_module / timeout / truncated / cancelled / unavailable` を区別。
- `RuleManifest v1 = {issuer, key_id, schema, sequence, issued_at, expires_at, payload_sha256, payload_bytes, engine_requirement, origin_license_registry, signature}`。任意の外部compiled Rulesのdeserializeは禁止。[上流の危険警告](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/rules.rs#L295-L305)。

**小さな実装PR単位**
1. **P1-01 MSRV/ライセンス/二方式のビルドPoC（S〜M）**：現在の1.85維持の独立YARA-X CLI（プロセス分離、引数固定/起動timeout/Job Object可否）と、1.95へ引き上げた公式crate利用の両方を検証。**DoD**：Windows x64で再現ビルド、Cargo.lock・依存SBOM・ライセンスnotice、結果スキーマ、CPU/RSS/バイナリサイズ差、旧CIとの互換性を記録。**選択基準**：安全なcrate統合が成立すれば第一候補、成立しない場合CLI PoCに留め、旧版の安易な固定をしない。
2. **P1-02 少数の自作ルール＋compile/warningsゲート（M）**：信頼できるテキストYARAだけ受理、include・importとコンパイル警告/無視ルールを明示。外部ルールは使用・改変・再配布許諾が1件ずつ確認された場合のみ追加。**DoD**：正常/不正構文/未知module/競合ID/タイムアウト/無害な期待一致と非一致をテストし、errors/warningsで検証済み世代に切替えない。[Forge本体](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/LICENSE)のGPLとルール毎の許諾は分ける。
3. **P1-03 静的raw/復号層スキャンアダプタ（M）**：既存`scan.rs`と`script.rs`が得た上限付きバイト列を二重コピーしないよう渡し、結果を`Report`へ証拠IDで統合。**DoD**：raw/層別の一致・層破損・一部層打切り・YARAタイムアウト・キャンセルが完了状態に正しく伝播し、検出なしを安全判定にしない。正規ファイルの誤検知をgolden-setで比較。
4. **P1-04 署名付き更新と二世代ロールバックPoC（M）**：まずローカル合成署名とMock配信でmanifest検証、旧版保全、署名鍵/sequenceによるリプレイ拒否、Windowsファイルロック時の回復。**DoD**：改竄、期限切れ、長さ超過、空DB、不正URL、停電相当、コンパイル不合格は旧版継続。成功時刻を偽更新しない。**第三者ルール/フィードの再配布は権利確認まで禁止**。

**Phase 1出口**：監査のみで期待する合成一致を検出、非一致・不完全を分離。MSRV方式が確定し、許諾・SBOM・負荷予算・ルール戻しが合格。**復旧**：YARA検査フラグをOFF、直前検証済みルール世代へ戻し、既存静的スキャンは継続。自動遮断なし。定量的検出精度はこの段階では主張しない。

## Phase 2 — Windowsイベント収集・ProcessGuid相関・限定FIM

**依存**：Phase 0の情報保護・永続化、Phase 1の証拠モデル（YARAエンジン自体が未完成でもイベントPoCを分離実施可能）。Windows 11・Sysmonを**利用者/検証者が別途準備**。EventLog読み取りを最初の基準とし、独自ドライバー・SACL監査ポリシー変更を導入しない。

**I/O契約（未実装）**
- `EventEnvelope v1 = {event_uid, source, source_record_id, event_id, schema_version, occurred_at, observed_at, boot_id?, process_guid?, pid?, process_start?, parent_guid?, artifact_hash?, ip?, port?, dns_name?, payload_redacted, cursor, completeness}`
- `CorrelationFinding v1 = {rule_id, rule_version, process_key, event_refs[], window_start, window_end, confidence, missing_sources[], suppressed_reason?, verdict: observed|review|unknown}`。PID単独では同一プロセスとしない。イベント時間の逆転と重複を許容した有界window。
- `SensorHealth = {source, channel_available, bookmark, durable_cursor, queue_depth, drops, gap_detected, last_success_at, access_error}`。保存完了前にcursorを進めない。

**小さな実装PR単位**
1. **P2-01 Event Log購読＋bookmark/永続キュー（M）**：Windows EvtSubscribe/EvtRender等の公開APIへ直接接続するRustセンサー。まず自作EVTX/XML fixtureと既存イベントを読み取りのみで取得。**DoD**：イベント保存成功後にカーソル進行、再起動/購読失敗/アクセス拒否/ログ上書きの際にgap/degradedを明示。Wazuhで確認された[送信失敗後bookmark更新](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/read_win_event_channel.c#L357-L370)と[future-only fallback](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/read_win_event_channel.c#L489-L513)を再現して拒否テスト。
2. **P2-02 Sysmon正規化＋ProcessGuidプロセス寿命（M）**：まずID 1/5、次に隔離VMでID 3/7/22を**明示的に**設定して評価。**DoD**：PID再利用、複数process、clock skew、プロセス終了、バージョン不一致、イベント0件を区別。SysmonのEvent 3（ネットワーク）と7（image load）は[既定で無効](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)であり、取得ゼロを「通信なし」と解釈しない。実験後Sysmon設定を戻す。
3. **P2-03 ルール・イベント相関のオフライン再生（M）**：Wazuh 4.xの周波数/時間窓の考え方のみ参考。複数イベントで得た根拠と欠損、ルール版・説明を保持し、一致だけで悪性確定しない。**DoD**：並び替え、重複、欠損、未知PID、複数ログ源、再起動後の状態消失を再生テスト。5.x alpha Engineの同等機能は未確認として扱う。[調査PR #17](https://github.com/choko510/AegisGuard/pull/17)。
4. **P2-04 限定FIMベースラインPoC（M）**：少数の明示したテストパスのファイルhash/メタデータとWindows変更通知、ログ欠損時の再走査。任意の認証情報DBは検査対象外。**DoD**：作成/更新/rename/削除/不一致/監視停止/読み取り不能を個別に報告、正規更新の偽陽性とI/O負荷を集計。[Wazuh FIM調査 #13](https://github.com/choko510/AegisGuard/pull/13)。
5. **P2-05 IPC/サービスの最小権限境界（M）**：常駐が必要になった場合のみSCMサービス、一般ユーザーCLI/GUIからのNamed Pipe+ACL/SID検証・read-only APIを段階導入。**DoD**：不正ローカルクライアント/セッション越境/IPC再接続が権限昇格にならない、サービス停止後に特権設定が残らない。現行CLIは維持。

**Phase 2出口**：長時間収集と停止/再起動の復元、Event 1/5の正しい相関、Event 3/7の負荷/欠損計測、偽陽性・PIIを評価。高負荷のイベント源は既定OFF。**復旧**：センサー購読/サービスを停止し、bookmark/観測データを保護したまま無効化。既存のDefender/Sysmon設定は変更前に戻し、AegisGuardは他製品所有の設定を無断で削除しない。

## Phase 3 — C2検出強化と段階的なアプリ別アウトバウンド遮断

**依存**：Phase 0/1のIOC来歴・期限/更新、Phase 2のprocess identity・イベント欠損監査、ユーザーに確認するポリシーUI/CLI、昇格サービス・復旧経路。**段階の前半は観測/計画のみ**。Firewall実適用は別PRかつ別承認。

**I/O契約（未実装）**
- `IocEvidence v1 = {indicator_type: ip|domain|hash, normalized_value, source_id, license_ref, observed_at, expires_at, version, confidence, stale, allowlist_reason?}`。期限切れのhitは活性の高いC2一致にしない。DNS名はIPの断定根拠ではない。
- `PolicyPlan v1 = {plan_id, process_identity: path|signature|package?, destination_ip, destination_port?, protocol, ioc_evidence_ids[], expiry, dry_run, owner_namespace, expected_diff[], rollback_id, admin_approval}`。**未帰属/共有IP/不確実なDNS/期限切れの場合は適用候補から除外**。
- `PolicyApplyResult = {requested, applied_ids[], rejected[], observed_os_state[], rollback_state, audit_id}`。ルール追加が失敗・不整合のときは無効化または所有ルールだけ巻き戻す。

**小さな実装PR単位**
1. **P3-01 IOC source registry・DNS/IP・process相関（M）**：既存C2 IP手動照合を壊さず、出所/取得時刻/ドメインのラベル境界一致、DNS/IP:port/ProcessGuidの確度を構造化。**DoD**：架空IP、CDN共有、DoH/DoT/NRPT/VPN、DNSキャッシュ不整合、source再割当、期限切れ、ユーザー例外を再生し、判定理由とunknownを記録。パケットの完全な可視性は主張しない。
2. **P3-02 ポリシーdry-runと承認監査（M）**：ルール生成・重複/上限、期限、実効対象（アプリpathとリモートIP/port）、許可リスト、プレビューとシミュレータを作る。**DoD**：実Windows Firewallを変更せず、適用差分を一覧化。許可なし、expired、不確かな帰属、システム共用サービスは拒否。自動削除や無条件default-denyなし。
3. **P3-03 安全なWindows Firewallバックエンド（M〜L、**明示承認まで保留**）**：Microsoft [INetFwRule](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule)のApplicationName/RemoteAddresses/Direction/Actionを検証。AegisGuard専用名前空間/ID・管理者操作の独立境界・適用journal・期限タイマー・所有ルールのみ削除・GUIが使えないときの復旧CLIを設計。**DoD**：Windows 11隔離VM、Defender/Firewallは有効のまま、IPv4/IPv6/WSL/VPN、同時管理、プロセス再起動、電源断/サービスクラッシュ、管理者拒否、ルール不反映を注入して必ず復旧可能。利用者の通常ネットワークには適用しない。実機で復元できるまで機能フラグOFF。
4. **P3-04 WFP user-mode直接APIとの比較**（L、隔離VMのみ・必要時）：Windows Firewallでは要件達成不能の証拠が出た場合に、[WFP管理API](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/wfp-user-mode-management-functions)のprovider/sublayer/transaction/dynamic sessionとフィルタ条件を比較。**DoD**：標準機能より改善する明確な要件、所有物だけの回復、BFE/他製品/優先順位との衝突を試験。**独自カーネルドライバーは別の設計審査を通るまで不採用**。Portmasterのdriverをコピーしない。

**Phase 3出口**：監査で誤検知/誤帰属が許容範囲に入り、各遮断ルールに期限・承認・所有者・復旧があることをテストで証明。誤遮断時の操作時間/復旧時間は隔離VMで計測し、定義された閾値を超えたら導入禁止。**復旧**：独立復旧CLIでAegisGuard所有ルールだけを列挙・削除し、期限切れの残存を修復。Defender/Windows Firewallの有効状態と他製品ルールは維持。**自動で広域遮断へ移行しない**。

## Phase 4 — 認証情報窃取兆候、Defender安全監査、GUI

**依存**：Phase 2のProcessGuid/イベント品質・Phase 3の監査/復旧基盤。GUIはローカルread-only APIから開始。ユーザーの認証情報やChromeのCookie/パスワードDBを読み込まない。ブラウザー独自の秘密化/保護を回避しない。

1. **P4-01 認証情報窃取の「兆候」相関（M〜L）**：ファイル名/スクリプトからの単独静的シグナルを出発点に、Sysmon Event 10（process access、設定した場合）、1/3/11/12〜14、Defender/ASRイベントを**複数根拠として**相関。FIMが読取exfilを検出しないことを明記。**DoD**：合成の「正規バックアップ」「ブラウザー更新」「無害なテストプロセスアクセス」と「怪しい組合せ」のfixtureで、誤警告・未観測・イベント欠損を検証。監査対象の内容や資格情報を保存しない。
2. **P4-02 Defender/ASR読取専用状態監査（S〜M）**：Microsoft公開のGet-MpComputerStatus/Get-MpPreference・[Defender Operationalイベント1121/1122/1129/5007等](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-windows-events)を読み取り、設定の「管理主体」「有効/監査/未適用/不明」を区別する。**DoD**：ASR GUID未知、CFA/有効化未設定、権限なし、GPO/MDM競合を異常ではなく根拠付き状態へ。**変更前後のDefender値が同一**。ConfigureDefenderのEXE/旧AutoItソースを呼び込まず、HIGH/MAXプリセットの適用やポリシーキー削除なし。
3. **P4-03 非特権の監査GUI・通知と復旧導線（M）**：既存JSONL/限定IPCからイベント/ルール根拠/ソース鮮度/検査不可/権限状態を表示。GUIと管理者サービスは分離。**DoD**：特権操作は別確認、GUI終了やクラッシュで検出が過大に報告されない、HTML/表示エスケープ/データ最小化、空/古い情報が誤って正常表示されない。復旧CLIはGUIなしでも使える。
4. **P4-04 任意のメモリread-only PoC（L、別途承認・通常機能にはしない）**：テスト用に作った自プロセスだけを対象に、読み取れた領域/拒否/打切りを分けたYARA照合。**DoD**：ユーザー同意・PIDと開始時刻一致・PPL/アクセス拒否を尊重・生メモリを保存しない・領域跨ぎマッチを禁止・CPU/RSS上限。全PIDの定期巡回、DefenderやOS保護の回避はしない。Phase4の出荷をこのPoCの成功に依存させない。

**Phase 4出口**：観察専用GUIとDefender監査がWindows 11環境で整合し、認証情報窃取「可能性」への偽陽性・カバレッジが説明できる。**復旧**：GUI/相関ルールを無効化し、前の監査ルール・イベントモデルに戻す。Defenderの設定は一切変更しない。メモリPoCは同意撤回・キャンセルで終了。

## 5. 依存グラフ・段階的リリースゲート

| ゲート | 開始必須条件 | 完了の証拠（DoD） | 未達時の行動 |
|---|---|---|---|
| G0 基盤 | 最新main照合、15件の調査PR再レビュー、依存権利確認 | CI Windows/Linux、異常入力と部分判定、ACL/復旧、性能baseline | 新エンジン導入停止、既存CLI維持 |
| G1 YARA/更新 | G0、MSRV/第三者ルール権利台帳 | 署名付きsource→compile→scanの再現、依存SBOM、偽陽性/負荷 | YARA OFF、旧ルール世代へ戻す |
| G2 センサー | G0、OS権限/イベント構成（G1は証拠モデルだけ依存） | Event 1/5・任意3/7/22の欠損率/復元/遅延、ProcessGuid相関 | 購読停止、誤欠損を健康値へ残す |
| G3 C2遮断 | G1更新管理、G2プロセス帰属、承認・rollback | dry-run/隔離VM実適用の全ケース、復旧CLI/期限切れ | **Firewallへの書込み不可**、観察のみ |
| G4 GUI/監査 | G2・IPC権限、G3は適用UIのみ依存 | 権限境界/PII/GPO認識、監査状態の再現、誤検知評価 | GUI/検出ルールだけOFF、OS設定は不変 |

**必要性とコストの先行判断**：実行前遮断・カーネルドライバーは初期要求ではない。導入を再提案する場合は①Sysmon事後観測で達成できない具体的脅威/ユースケース、②Windows Firewall/WFP user-modeで達成できない制約、③WDK・署名・Windows更新互換、④BSODと復旧コスト、⑤ライセンス、⑥VMでの停止/誤遮断率を文書化し、所有者による別のgo/no-go判断を必須とする。

## 6. 開発者AIへ渡すPRバックログ（1PR=1責務、実装はこの調査ではしない）

| 順序 | PRタスク | 入力/依存 | 完了時に提出するもの |
|---|---|---|---|
| 01 | `P0-01` 結果状態スキーマと互換性 | 現行`model.rs` | 仕様+単体/golden tests、秘密の非露出 |
| 02 | `P0-02` 安全なファイルハンドル/identity | P0-01 | reparse/差替えfixture＋Windows CI |
| 03 | `P0-03` 資源予算/fuzz | P0-01 | 対象ごとの上限・不完全理由・stress結果 |
| 04 | `P0-04` キャッシュ/ログ復旧 | P0-01 | 2世代切替・障害注入・ACL |
| 05 | `P0-05` 依存/SBOM/CIと性能baseline | 現行main | Windows/Linux CI、数値付き計測記録 |
| 06 | `P1-01` YARA-X crate vs CLI/MSRV PoC | G0 | 比較記録・法務台帳・選択決定 |
| 07 | `P1-02` 固定ルールコンパイルQA | P1-01 | エラー/warnings/互換テスト |
| 08 | `P1-03` raw/復号層YARAアダプタ | P1-02 | 証拠/部分判定/FP評価 |
| 09 | `P1-04` 署名付きルール更新/回復 | P0-04、P1-02 | 署名検証と戻しのfault injection |
| 10 | `P2-01` Windows EventLog/bookmark | G0 | gap・再生テスト・持続キュー |
| 11 | `P2-02` Sysmon正規化とプロセス寿命 | P2-01 | EID1/5から段階拡張、欠損計測 |
| 12 | `P2-03` 相関器・時間窓 | P2-02 | deterministic replayと理由付き結果 |
| 13 | `P2-04` 限定FIM/差分再走査 | P2-01 | 重要パスの差分・復旧/負荷評価 |
| 14 | `P2-05` サービス/IPC権限分離 | 連続収集が必要になった場合 | ACL/SIDテスト・権限図 |
| 15 | `P3-01` IOC/DNS/C2相関 | P1-04、P2-02 | TTL・確度・未知状態のfixture |
| 16 | `P3-02` 遮断候補dry-run | P3-01 | ルール計画・理由・承認モデル（書込なし） |
| 17 | `P3-03` Windows Firewall限定適用 | **G3の事前承認必須** | VMでの適用/障害復旧/復旧CLIの実測 |
| 18 | `P3-04` WFP管理APIとの比較 | P3-03で不足判明時 | 必要性とコストのgo/no-go報告 |
| 19 | `P4-01` 窃取兆候の複合ルール | P2-03 | 無害な対照群・誤警告比較 |
| 20 | `P4-02` Defender読取監査 | P2-01 | 公開APIのみ、設定不変の証跡 |
| 21 | `P4-03` GUI/非特権通知 | P2-05、P4-02 | PII、権限、欠損UI・復旧導線 |
| 22 | `P4-04` 指定プロセスメモリPoC | 別承認、P1-03 | 実機隔離・領域別coverage・同意撤回 |

各実装PRは**変更ファイルを担当スコープだけに保ち**、(a) DoDのテスト実行ログ、(b) リスクと未検証事項、(c) 偽陽性fixture、(d) CPU/RSS/I/O比較、(e) 戻し手順、(f) Defender/Firewall設定の不変確認、(g) 新しい依存とライセンスを記載する。ルール/ドライバー/サービスの無断バンドルや自動マージを行わない。

## 7. オープンな意思決定・停止条件

- **ライセンス方針**：本体の配布ライセンス未設定。YARA-XのBSD通知/依存、各YARAルールの帰属と再配布、公開IOCフィード条件、Sysmonの導入/管理責任、GPL/AGPL製品を別プロセス利用する場合の配布責任が未承認。専門家判断が要る場合は合格扱いしない。
- **MSRV**：Rust 1.85を引き上げるか、YARA-X CLI隔離かをPhase 1で決める。それまでは公式crateを本体へ依存追加しない。上流の最新版/脆弱性/署名を再調査する。
- **OS権限と復旧**：Windowsの管理者操作、Defender、UAC、GPO、Tamper Protection、企業管理端末・サードパーティAVの競合を検証。管理者権限が取れないときに権限回避・保護停止はしない。
- **観測限界**：Sysmon ID 3/7は既定OFF、暗号化DNS/VPN/共有プロセスで帰属に限界。FIMで読み取りだけの情報持出しを検知できない。識別不能は未判定のまま残す。
- **安全ゲート**：未知入力の無制限デコード、未署名更新、自動遮断、期限/ownerのないFWルール、復旧CLIがないOS書込、ルールの無許可再配布、全PIDメモリ常時検査が必要なら、フェーズを中止して設計再審査。

**ロードマップの完了とは**：フェーズごとのDoDがWindows実機/CI・法務/情報保護・誤検知・性能・復旧で実証され、人間が承認した状態をいう。現時点では**Phase 0〜4のすべてが計画であり完了0件**。調査PRがレビュー後に変わったときは、固定SHA付き[採用マトリクス](ADOPTION_MATRIX.md)から再評価する。
