# AegisGuard 実装ロードマップ（調査結果からの開発計画）

> **2026-11-05追補**: 最新調査対象は [main 5eea9b7](https://github.com/choko510/AegisGuard/tree/5eea9b7142de677a1939ae4c4f0760701cf24cb0)。**第0〜7章は当初の意思決定履歴、第8章がマージ済み機能の実績、第9〜15章が今後の実装優先順位**。実機の性能・誤検知・復旧試験は未実施であり、CI成功を本番安全性と混同しない。

> 作成日: 2026-11-05（JST） / 比較対象 `main`: [83fcf0d150e8d760baff5f971c106deb09c1f8e4](https://github.com/choko510/AegisGuard/tree/83fcf0d150e8d760baff5f971c106deb09c1f8e4)  
> 関連：[ADOPTION_MATRIX.md](ADOPTION_MATRIX.md)（15件の固定head/Squash SHA、重み付き比較・法務/安全ゲート）。**ここは当初調査時点の計画。現在の実装は第8章、次期計画は第9章以降に更新済み**。調査基盤PR [#2](https://github.com/choko510/AegisGuard/pull/2) と調査PR [#3〜#17](https://github.com/choko510/AegisGuard/pulls?q=is%3Apr+is%3Amerged) は2026-11-05に全件mainへマージ済み。提出者アカウントから16件へ技術COMMENTレビューを行ったが、独立APPROVEはなし。**Windows 11実機性能・誤検知・復旧試験は利用者の指示で今回スキップ（合格ではない）**。

## 0. 現行の開始点と実装原則

**当初の開始点（履歴）**：AegisGuardは静的ファイル解析とC2照合だけのRust CLIから開始した。**現在のmain**にはYARA-X（任意）、署名付きルールパック、Windowsイベント収集、ProcessGuid相関、限定FIM、Defender監査、遮断dry-run、静的HTMLが実装済み。egui GUI・常駐サービス・継続的な行動相関・ブラウザ専用検出・実遮断は未実装（第8章参照）。[現行CLI](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/main.rs#L1-L78)・[現行設計](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md)・[SECURITY.md](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md)を出発点とする。

- **保護を弱めない**：Defender・Firewall・ASRを無効にしない、ポリシーやGPO/Tamper Protectionを回避しない。OS設定の書込みはPhase 3で**ユーザー明示承認**と安全復旧の後だけ。
- **観測→監査→限定適用**：検査不能/欠損/遅延/不明な帰属は「陰性」や「防御成功」と表示しない。誤検知は説明・例外・監査で扱い、検出だけで自動削除・隔離しない。
- **Rust-first、境界は分離**：ローカルのcore/model、read-only sensor、rules/IOC updater、privileged response、一般ユーザーUIを明示的に分割。最初からすべてを別crateにせず、APIの境界だけ先行定義する。
- **外部ソースをコピーしない**：Wazuh GPL/AGPL、ClamAV GPLv2、Portmaster/simplewall/Loki-RS GPLv3、ConfigureDefender独自条件。Windows公開APIと独自設計を採用。YARA-X公式BSD-3-ClauseはMSRV/依存ライセンスを検証後に候補。
- **初期は未知サンプルを実行しない**：合成した無害なPE/スクリプト/イベント/IOC、専用テストルール、Mock HTTP/Windows 11隔離VMだけを使う。資格情報やブラウザDB、生のプロセスメモリをログ・クラウドへ送らない。
- **依存の開始ゲート**：15件のマージ済み報告と技術COMMENTを参照し、実装PR着手時にその時点の`main`/Cargo/CIを再確認する。独立第三者承認は未取得、AegisGuard本体ライセンスは所有者未決定。**本統合ドキュメントのマージにあたり両者を合格扱いしない**。外部資産の同梱・改変・再配布は許諾が決まるまで行わない。

## 調査統合と実装検証の区別

**今回完了すること**：調査基盤+15件の報告書のmain反映、固定SHA/出所/ライセンスを照合した採否の文書化、次のAI向けの実装タスク分割。**今回明示的に行わないこと**：Windows 11実機の性能・誤検知・復旧試験、コード実装、Defender/Firewall/サービス設定変更、悪性検体の実行。スキップした試験を過去に実施したことにはしない。将来実装して本番出荷する場合の安全ゲートは下記に残す。

**外部コンポーネントの代替方針**：Feodo Trackerは[abuse.ch利用規約3.4](https://abuse.ch/terms-of-use/)のCC0例外の範囲で出所と鮮度を確認し、C2IntelFeedsは[公式CC BY-NC-SA 4.0](https://github.com/drb-ra/C2IntelFeeds/blob/eda1465f49e07fea4df4246a310fc94dd78873ed/README.md)のため商用/再配布製品の標準フィードにしない。Sysmonは[Microsoftライセンス](https://learn.microsoft.com/en-us/sysinternals/license-terms)により同梱せず、ユーザーがMicrosoft公式から別導入。YARA-Xは自作ルールだけで最小PoC。ConfigureDefender EXEやGPL/AGPLプロジェクトのコードは組み込まず、公開Windows APIから独立実装する。これらの**法務上の論点は利用しない設計によって隔離**したのであって、第三者の追加許諾を取得したわけではない。

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

**Phase 0出口（将来の実装に対するゲートであり、今回の調査マージ条件ではない）**：WindowsとLinuxの既存テスト・異常入力・情報保護・クラッシュ復旧が合格し、ハードウェア別性能予算が決定済み。不明な検査を陰性に分類しない。**復旧**：後続機能フラグOFF、検査/更新を停止し前回有効なC2キャッシュ/JSONL形式に戻す。Defender/Firewallは一切変更しない。

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
- **MSRV（当初の保留は解決済み）**：YARA-X公式crateは既定OFFの任意featureとして実装済み。CLI標準ビルドのRust 1.85とYARA-X有効時のRust 1.95以上を区別し、egui導入時のMSRVは別に検証する。
- **OS権限と復旧**：Windowsの管理者操作、Defender、UAC、GPO、Tamper Protection、企業管理端末・サードパーティAVの競合を検証。管理者権限が取れないときに権限回避・保護停止はしない。
- **観測限界**：Sysmon ID 3/7は既定OFF、暗号化DNS/VPN/共有プロセスで帰属に限界。FIMで読み取りだけの情報持出しを検知できない。識別不能は未判定のまま残す。
- **安全ゲート**：未知入力の無制限デコード、未署名更新、自動遮断、期限/ownerのないFWルール、復旧CLIがないOS書込、ルールの無許可再配布、全PIDメモリ常時検査が必要なら、フェーズを中止して設計再審査。

**研究統合の完了**：調査基盤PR #2、15件のレポートPR #3〜#17をmainにマージし、技術COMMENTと一次資料確認を[採用マトリクス](ADOPTION_MATRIX.md)へ反映した。**実装ロードマップの達成とは別**：実装状況は第8章で更新済み。CLI機能のCI完了と、Windows 11実機での誤検知・性能・長時間監視・復旧の実証は別のゲートである。今回はユーザー指示によりWindows 11実機試験をスキップするため、スコアや設計は製品の運用安全性を保証しない。将来の調査訂正が発生した場合は、マージ済み固定SHAとともに再評価する。

## 8. 実装状況（2026-11-05）

上の本文は計画当時の記述のまま残し、実装の結果をここに記録する。「完了」はCI（Windows/Linux、既定と `yara` feature、MSRV 1.85、cargo-deny）とPR記載のテストで確認した範囲を指す。**Windows 11実機・隔離VMでの性能・誤検知・復旧の検証は、利用者の指示によりすべて未実施**（合格扱いしない）。

| タスク | 状態 | PR | 残っている条件・制限 |
|---|---|---|---|
| P0-01 安全モデル・JSONL vNext | 完了 | #19 | — |
| P0-02 ファイルidentity/TOCTOU | 完了 | #20 | 同じサイズ・更新時刻のまま読取中に書き換えられた場合は検出できない |
| P0-03 有界資源・異常入力 | 完了 | #21 | cargo-fuzz（nightly）は未導入。決定的なプロパティテストで代替 |
| P0-04 C2キャッシュ/ログ耐障害 | 完了 | #22 | 停電・AVのファイルロックは手順単位のシミュレーションのみ |
| P0-05 CI/依存監査・基準値 | 完了 | #23 | 性能の合格閾値は未設定（実機計測が前提） |
| **G0** | **一部未達** | — | ハードウェア別の性能予算が未決定（実機計測をスキップしたため）。他の条件はCIで確認 |
| P1-01 YARA-X方式決定 | 完了 | #24 | 決定記録：[YARA_X_INTEGRATION.md](YARA_X_INTEGRATION.md)。既定OFFの任意feature |
| P1-02 自作ルールのゲート | 完了 | #24 | 第三者ルールは許諾を1件ずつ確認するまで追加しない |
| P1-03 原本/復号層アダプタ | 完了 | #24 | YARA-Xのタイムアウトは秒単位で即時中断を保証しない |
| P1-04 署名付き更新・ロールバック | 完了 | #25 | 配信（HTTPS取得）は未実装。鍵の運用方針は所有者の決定待ち |
| P2-01 Event Log・永続カーソル | 完了 | #26 | Sysmon導入済み実機での長時間収集は未検証 |
| P2-02 ProcessGuidプロセス寿命 | 完了 | #27 | Sysmonスキーマ版の不一致は未検出 |
| P2-03 相関のオフライン再生 | 完了 | #28 | 実データでの誤検知率は未計測 |
| P2-04 限定FIM | 完了 | #29 | レジストリ差分は対象外 |
| P2-05 サービス/IPC権限分離 | **見送り** | — | 着手条件「連続収集が必要になった場合」を満たしていない。現状はすべて単発CLI、GUIはJSONLから作る静的HTML |
| P3-01 IOC出所・DNS/IP/プロセス相関 | 完了 | #30 | 許諾を確認できたドメインIOCフィードは無く、ローカルIOCのみ |
| P3-02 遮断候補dry-run・承認監査 | 完了 | #31 | OS設定を変更するコードは含まない |
| P3-03 Windows Firewall限定適用 | **未着手（ゲート）** | — | G3：隔離VMでの適用・障害復旧・復旧CLIの実証と、明示の事前承認が必要。実機・VM検証のスキップ指示のもとでは着手しない |
| P3-04 WFP管理APIとの比較 | **未着手（条件未発生）** | — | P3-03で不足が判明した場合のみ |
| P4-01 認証情報窃取の兆候 | 完了 | #32 | Sysmon ID 10/11・Defenderイベントの実データでの誤検知率は未計測 |
| P4-02 Defender読み取り監査 | 完了 | #33 | 管理者以外では除外の件数が不明になる |
| P4-03 非特権の監査レポート | 完了 | #34 | GUIはローカルの静的HTML。常駐GUIは未実装 |
| P4-04 プロセスメモリPoC | **未着手（ゲート）** | — | ロードマップ上「別途承認・通常機能にはしない」。承認が無いため着手しない |

**次に必要な判断（所有者）**：AegisGuard本体のライセンス、ルール署名鍵の運用、P3-03の実施可否（隔離VMの用意を含む）、P4-04の実施可否、Windows 11実機での性能予算の計測。


---

## 9. 最新の到達目標と現状差分（2026-11-05）

**最終像：Rust製の防御エンジン＋Windows常駐サービス＋egui/eframeデスクトップUI。** Microsoft Defenderは有効のまま共存し、GUIを閉じてもセンサーは継続稼働。ファイル、プロセス、DLL、レジストリ、通信の**観測できた範囲**を、時系列の根拠付きで説明する。特にブラウザ乗っ取り・認証情報窃取の**兆候**を重点対象とする。

**いま可能なこと**：`scan`（限定的なPE・難読化スクリプト静的解析）、任意YARA-X、C2 IOCの手動更新・照合、Sysmon/Defenderイベントの単発収集、ProcessGuidのオフライン相関、限定FIM、Defender読取監査、遮断候補dry-run、静的HTML。

**いま不可能なこと**：ブラウザDLL/COM乗っ取りの専用検出、ブラウザ認証情報ファイルの読取りを直接知ること、イベントの常時収集/自動通知、egui GUI、OSの通信阻止・実行前阻止。検査で痕跡が見つからないことは感染していない証拠ではない。

| 現在のコード・根拠 | 具体的な不足 | 次の対応 |
| --- | --- | --- |
| `src/script.rs::analyze_layer` | 正規表現の同一本文共起はコメント/未実行関数も反応 | P5-02/03（誤警告評価・AST） |
| `src/pe.rs` | PE構造とエントロピーまで | P5-04（署名/インポート/オーバーレイ） |
| `src/main.rs` | CLIと業務処理が結びつきGUI用型APIなし | P5-01（core/engine/CLI境界） |
| `src/events/process.rs` | Sysmon ID 7はDLL読込み**件数**のみ、ID12〜14は専用相関なし | P6-02 |
| `src/events/mod.rs` | `ImageLoaded`/`TargetObject`は読めるが、ID13のレジストリ値`Details`は安全な形で保存していない | P6-02 |
| `src/fim.rs` | `Login Data`/`Cookies`等は**意図的に読まず**、読み取り監視でもない | P6-04 |
| `src/events/collector.rs`/`correlate.rs` | 単発収集＋オフライン再生中心 | P8-02/04 |
| `src/policy.rs` | 承認してもFirewallには適用しないdry-run | P10（別ゲート） |
| `src/report.rs` | 静的HTML。GUI/IPC/常駐サービスなし | P7〜P9 |

**原則**：既存のCLIサブコマンド、JSONL v2の「検出強度と解析完全性の別軸」、署名付きルール更新・２世代復元・IOC鮮度管理を壊さない。プロセスが監視されていない、ログ欠損、権限不足、パーサーが途中停止した場合、**安全/未感染と表示しない**。初期は検査対象を実行せず、認証情報の本文を開かない。

## 10. P5 — 品質・検出精度・共通Rust API（最優先）

### P5-01 CLI/GUI/サービスで共用する型と機能境界（M）

- `aegis-core`（`ScanReportV2`、`CorrelationFinding`、`SensorHealth`、`RuleStatus`、`SourceFreshness`、`JobProgress`、`Assessment`等）と、既存エンジンの読み取り専用APIを抽出。最初から過剰なcrate分割はせず、まず公開I/O契約を固定してから段階的にCargo Workspaceへ。既存`main.rs`を薄いCLIアダプターへ。
- GUIをCLIのstdout解析や特権子プロセス起動で構築しない。将来のIPC/GUIも同じ型を受け取る。バージョン不整合・未知フィールド・壊れたJSONL・取消を型で表現。
- **DoD**：既存CLIとJSONL互換のテスト、旧/新レポート両方の読み込み、再現ビルド、Windows/Linux CI、Rust 1.85既定ビルドとYARA有効ビルドの切り分けが成功。

### P5-02 正常な管理スクリプトの誤警告削減（M）

- `docs/BASELINE.md`で合成`benign_admin` 300/300が`review`。`src/script.rs`は`DOWNLOAD`+`EXEC`等の共起を判定しており、独立した文・コメント・文字列リテラル・未到達処理を区別できない。
- 元の300件の期待値を単に書換えず、無害な正規管理スクリプトの対照群、synthetic positive 100件、難読化テストを固定する。単独の一般的な管理操作と、同一実行経路上の資格情報アクセス＋送信を区別し、証拠と打切りの情報を保持。
- **暫定の合成評価目標**：benign_adminの`review`を**15/300以下**まで低減し、既存100件の合成positive検出は維持。ただしこれを現実のFP/FN率と宣伝しない。実際の正常ソフトのサンプルで別途評価し、検出抜け・コーパスへの過適合なら差戻し。
- **DoD**：false positive/negative、未解析/不明、ルール・出所・評価時刻・バージョンを出力し、スコア低下だけで見かけの改善を行わない。

### P5-03 ASTベースのスクリプト解析・難読化（L、分割導入）

- PowerShell→JavaScript→Pythonの順に構文解析器/安全なパーサーを比較し、コマンド・呼び出し・変数参照・データの流れを**静的**に評価。BAT/CMD/VBSは既存の有界復号を維持。独自暗号化/動的生成/ネット経由コードの復元に万能性はない。
- コメントや未実行コードの文字列一致を単独高リスク判定にしない。多段Base64/UTF-16/16進/圧縮/連結が上限に到達したら`incomplete`。サンプルコード、復号内容、認証情報は一切実行・外部送信しない。
- **DoD**：各言語の正常例/難読化例/壊れた構文/巨大入力、上限、CPU時間、fuzz、未知判定、エンジンの署名・ライセンス検証。

### P5-04 PE/DLLのAuthenticode・imports/exports強化（M）

- 既存PE構造解析に、Windowsの署名検証API/WinVerifyTrust、imports/exports、overlay等の上限付き解析を追加。`signed / invalid / unsigned / chain_unknown / revocation_unknown / not_assessed` の違いを表現し、**署名が有効でも安全とは断定しない**。
- **DoD**：正規署名済みDLL、未署名のテストDLL、破損PE、失効確認不能、オフライン、ファイル変更/再解析ポイント/署名API失敗を検証。

### P5-05 YARA-X検査精度・キャッシュ・運用（M）

- 既存の任意`yara` featureを維持し、raw/復号層での根拠・ルールセット世代・エンジン版を共通APIへ渡す。ファイルSHA-256×ルール版×エンジン版で有界キャッシュ。ファイル変更やルール更新時に必ず無効化。
- 自作ルールの誤警告・性能試験、署名付き更新の失敗時に旧検証済み世代を保持。外部ルール/IOCの利用許諾は個別確認。
- **DoD**：ルール更新直後のキャッシュ誤使用なし、無効パック/期限切れ/コンパイル失敗で検査済み扱いしない。

## 11. P6 — ブラウザ整合性・DLL/COM乗っ取り・認証情報アクセス（高優先）

**既知インシデントの検出と汎用行動分析は別ルールとして管理。** 2026年のNIKKE/`k2f_chan`事例のようなブラウザ領域へのDLL設置、HKCU CLSID変更、ブラウザによるDLL読込みを想定。ただし**正常な`PlatformExperienceHelper`フォルダー自体は悪性ではない**。実在の検体は実行せず、無害な合成fixtureを使用する。

参照先：[事件の公式案内（転載）](https://nikke.gg/official-announcement-pc-launcher-security-incident/) / [Microsoft公式Sysmonイベント](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

### P6-01 既知痕跡のread-onlyチェック（S〜M、サービス化前にも実装可）

- Chromeの`%LOCALAPPDATA%\Google\Chrome\User Data\PlatformExperienceHelper\`以下の**64桁16進数のディレクトリ＋`platform_experience_helper.dll`**と、`HKCU\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\InprocServer32`の実際の参照先の**組合せ**を確認。別ユーザーハイブやWOW6432Nodeの可視性は適切に検証し、異なるHKLMの正規キーと混同しない。
- ファイルは既存の安全なハンドル・PE検査APIを使い、署名/ハッシュ/ファイルidentityとパス正規化を取得。検出結果は`indicator_present`（単独兆候）、`correlated_suspicion`（複合）、`not_observed`、`not_assessed`を区別。
- **DoD**：正規フォルダーのみ、CLSIDのみ、DLLのみ、両方、署名済みの無害DLL、異なる64桁/別ユーザー、アクセス拒否、reparse pointをテスト。**自動でファイル/レジストリを削除しない**。

### P6-02 Sysmon ID 7/11/12〜14の意味を失わない正規化・相関入力（M）

- `events/mod.rs`に`ImageLoaded`、`TargetFilename`、`TargetObject`はあるが、現在`events/process.rs`はIMAGE_LOADを件数だけ増やし、レジストリ変更の値内容を安全に関連付けられない。Sysmon Event 13の`Details`等は機密値を含み得るため**無制限にログへ保存せず**、COM InprocServer32等の限定した証拠だけ型付きで抽出する。
- ID 1（プロセス作成）、7（DLLロード）、11（ファイル作成）、12/13/14（レジストリのキー/値変更）をProcessGuid・時刻・パス/ファイルidentityと結ぶ。PID再利用/別ユーザー/順序逆転と「収集元が無効」を区別。Sysmon ID7は高負荷かつ既定OFFのため**対象を絞った、利用者が明示的に導入する設定**を前提にする。
- **DoD**：プロセスAがDLL配置→COM変更→ブラウザBがロード、正規ブラウザ更新、同名別ファイル、キー値なし、ID7無効、ログ欠損を合成再生。未観測は`missing_sources`で「不明」にする。

### P6-03 汎用的なブラウザハイジャック相関ルール（M）

- `AG-B001`：通常ブラウザと無関係なプロセスによるブラウザ領域へのDLL作成（単独なら観測/要調査）。
- `AG-B002`：HKCU COM InprocServer32がユーザーデータ等のDLLを参照（署名/親プロセス/パス一致も評価）。
- `AG-B003`：DLL作成→COM登録→同DLLのブラウザ読込みをProcessGuid/時刻/identityで連結（複合の調査優先度を高める）。
- `AG-B004`：監査で取得できた**不審な認証情報ファイル読み取り**と、外部送信・新鮮なC2 IOCの接続を相関。取得できない場合は`not_evaluable`。
- `AG-B005`：上記K2F固有のパス＋CLSID組合せ。IOC出所・ルール版・誤警告対照を併記し、名称や単独のパスだけで「感染確定」としない。
- **DoD**：各ルールは`rule_id/version`、イベント参照、時刻、欠損元、抑制理由、調査優先度を返す。正規ブラウザ更新、無害なCOM登録、正規署名DLL、同名別パス、共有IP、古いIOC、ログ欠損を全て反例で確認。誤検知を減らすために検出漏れを隠さない。

### P6-04 Credential Access Monitor（L、監査ソースの追加は別承認）

- FIMは**変更検知であり読み取り検知ではない**。Sysmon Event 11も作成のイベントであり、Cookies/`Login Data`への読み取りを捕捉しない。Windows Security Event 4663等の対象を絞ったファイルアクセス監査を候補として、監査ポリシー・SACLが必要なこと、正常なブラウザ/バックアップの大量ログがあることを前提に評価する。
- **最初は合成済み監査イベントのオフライン分析のみ**。OS監査ポリシー/SACLの変更は管理者の明示承認、以前の設定の保存、復元、性能確認の別PRまで行わない。ユーザーのCookie/パスワードDBの内容は読まない、保存しない、アップロードしない。
- **DoD**：監査無効・権限不足・アクセス拒否・見逃しが「安全」表示にならない。正規の読み取りと外部プロセスのアクセスを対照で比較し、機械的に全アクセスを悪性扱いしない。

### P6-05 Edge/Brave/Firefox等の拡張（M、Chrome検証後）

- Chromium系でも構成差、Firefoxでは拡張・資格情報保存方式・レジストリ経路が異なる。Chrome文字列を置換するだけではなく、ブラウザごとの合法な読み込み方法、ディレクトリ、正常更新の対照を別プロファイルとして調査。
- ブラウザ保護画面には**各ブラウザの対応範囲と不足しているセンサー**を明示する。

## 12. P7 — egui/eframe 読み取り専用GUI（サービス完成前に着手）

### P7-01 eguiの起動基盤とデザインシステム（M）

- `apps/aegis-ui`：通常ユーザー権限のegui+eframe GUI。初期はサービス不要でローカルJSONL/合成データを表示。既存HTMLは削除しない。導入時にegui/eframeの版・MSRV・Windows描画バックエンドを確認し、Rust1.85既定CLIとビルド経路を分離する。
- 画面：**ホーム / スキャン / ブラウザ保護 / リアルタイム監視 / ネットワーク / 検出履歴 / ルール・設定**。未実装は操作可能に見せず「まだ利用できない」「ソース無効」と表示。
- **DoD**：Windows起動/終了、ダーク/ライト、高DPI/小画面、日本語文字切れ、キーボード操作、誤った「保護中」表示の不在。

### P7-02 JSONL/レポート共通APIアダプター（M）

- 検査結果、相関、IOC、Defender、FIM、ルール署名状態をP5の型で表示。GUIスレッドでスキャン/大量JSONL読込を行わず、有界ワーカーと非同期結果通知を用いる。パスワード/クッキー/復号本文は表示しない。
- **DoD**：不正JSONL、古い版、アクセス拒否、巨大ログ、将来日付、想定外の長いファイル名でもクラッシュ・フリーズなし。仮想化リスト/ページング。CLIの結果と表示を突合する。

### P7-03 視覚設計・ブラウザタイムライン（M）

- 一目で理解できるホームに**Defender稼働、AegisGuard稼働、センサー不足、最終更新、要調査件数**を別々に示す。検出の詳細は「何が起きたか」「何が見えなかったか」「推奨確認」の3段階。
- **K2F等を想定したタイムライン**：ランチャー → DLL配置 → COM値変更 → ブラウザDLL読込 → 外部通信。**実際に観測された段階だけ**結び、不明な段階を補作しない。
- eguiはログ到着時に必要な再描画を行い、常時高FPS描画をしない。大量ログには仮想化/ページング。GUIを閉じてもバックエンドが継続する旨は**P8後にだけ**表示。
- **DoD**：100/1000/100000件の合成履歴、高DPI、キーボード、色だけに依存しない警告、長い説明文。可視性不足・部分解析・古い情報を「安全」と誤読させない。

## 13. P8 — Windows常駐サービス・IPC・リアルタイム相関

### P8-01 Windows Serviceの最小権限導入（L）

- 旧P2-05は「常駐要件なし」で見送りだったが、**常駐を製品目標にしたことで着手条件が変わった**。`aegis-service`はSession 0の独立サービス、`aegis-ui`は通常ユーザー。初期は観察のみでDefender/Firewall設定は変更しない。
- **DoD**：GUIなしでも起動・停止・復帰・イベント保持が可能。サービスクラッシュ、シャットダウン、ログオン/ログオフ、設定破損、権限不足が検出の虚偽報告に繋がらない。

### P8-02 有界イベントの継続購読・耐障害スプール（L）

- 既存EvtQuery/ブックマークの保存順序を維持し、EvtSubscribe等との比較後、再起動可能な継続監視を実装。SysmonのID3/7/10/11/12〜14/22は**目的に応じてフィルタ**。特にID7を全システムで無制限に有効化しない。利用者のSysmon設定を無断変更しない。
- **DoD**：保存完了前にカーソルを進めない。欠損・ログ上書き・重複・容量上限・負荷増大・ディスク不足を`SensorHealth`で示す。低負荷・スリープ・ゲーム中の測定値は将来Windows 11 VMで評価。

### P8-03 認証付きNamed Pipe IPC（M〜L）

- サービスとGUI間の型付きAPI/版数/有界メッセージ。Named PipeのACL/SID/セッションと認可を設計し、一般ユーザーGUIが任意管理者コマンド/任意パス操作を指示できないようにする。スキャン依頼/キャンセルとread-only状態照会を分ける。
- **DoD**：不正クライアント/他ユーザー/権限なし、壊れたデータ、再接続、キュー詰まり、プロトコル変更で権限昇格・OOM・取りこぼしの隠蔽なし。

### P8-04 ProcessGuidの差分相関・通知（M）

- 既存のオフライン`ProcessTable::build`/`correlate`を時間窓と状態期限のある有界エンジンに拡張。P6ブラウザルールと既存AG-C001〜012、ネットワークIOCを実行時相関し、各ルールの`missing_sources`を維持。通知は重複抑制。
- **DoD**：並び替え/遅延/重複、PID再利用、プロセス終了、サービス再起動、IOC失効でもオフライン再生と同じ判定。p50/p95遅延・CPU/RSSは実機で計測してから閾値決定。

## 14. P9 — eguiライブ運用・C2・ブラウザ保護

- **P9-01 GUIとIPC統合（M）**：P7の表示モデルを変えずローカルファイル読み取りからサービスIPCへ切替。切断・旧データ・再接続を表示。GUIが終了/クラッシュしてもサービスは監視。UI描画スレッドに重い処理なし。
- **P9-02 C2通信のライブ監査（M）**：プロセス/宛先IP/ポート・DNSの帰属とIOCの期限/出所/共有CDNの不確実性をeguiで表示。未知IP、DoH/VPN、イベント欠損は「通信なし」と混同しない。最初は検出・通知のみでFirewall変更なし。
- **P9-03 ブラウザ保護ページ（M）**：Chrome/Edge/Brave/Firefox別の対応範囲と、DLL作成/COM変更/ロード/認証情報アクセス（監査ソースがある場合だけ）を時系列に表示。正常更新・DLL不在・監査無効の対照で表示を確認する。公式の手動確認手順への案内は可能だが、ブラウザファイルやレジストリを勝手に削除しない。
- **P9-04 トレイ、通知、設定、ルール更新UX（M〜L）**：トレイの終了はサービス停止ではない。通知の重複抑制、例外理由、署名鍵とIOCの期限/失敗、最小権限、複数ユーザー、障害復旧を検証。ルール署名鍵の管理主体とライセンスが未決定なら無断自動配信を行わない。

## 15. P10 — 実際の遮断と本番出荷（独立の安全ゲート）

- **P10-01 OSへの通信遮断（旧P3-03、保留）**：現在の`policy.rs`はdry-runだけ。Windows 11隔離VMで管理者承認、アプリ・共有IP/IPv6/VPN、期限切れルール、停止/再起動/巻戻し、Defender/他製品の維持を証明し、所有者から別途GOを得るまで実適用しない。AegisGuard所有ルール**だけ**を扱う独立復旧CLIが必須。
- **P10-02 実行前・書き込み前のブラウザ保護（保留）**：Sysmon/FIM/イベント監査は事後検出であり、ChromeへのDLL作成や認証情報アクセスを「書き込み前に阻止」する機能ではない。OS標準のアプリ制御/Defender ASRなどの適合を先に評価し、独自カーネルドライバーやMinifilterは署名・BSOD・Windows更新・復旧の別審査なしで導入しない。
- **P10-03 リリース品質ゲート（未達）**：Windows 11隔離VM/実機のCPU/RSS/ディスク・アイドル/ブラウザ起動/高負荷、少なくとも24時間の継続監視、誤警告、GUIクラッシュ・サービス再起動、イベント欠損、低権限、ロールバック、Defender有効状態を検証。CI成功だけで「本番対応」「リアルタイム保護完成」と言わない。今までのユーザー指示に従い実機試験は未実施、将来の出荷前の**未達必須ゲート**として残す。

### 次のPR順（1PR=1責務、実装ではなく計画）

| 優先 | PR候補 | 最小成果物/前提 |
|---|---|---|
| 01 | P5-01 core/CLI/UI共通型 | 既存CLI・JSONL互換、MSRV/依存のCI |
| 02 | P5-02 benign_adminの誤警告対策 | 300件対照群、100件positiveを維持した評価表 |
| 03 | P6-01 K2F既知痕跡のread-only検査 | DLL+CLSID一致・正規フォルダーの反例 |
| 04 | P6-02 SysmonのDLL/COMイベント拡張 | ID7/11/12〜14、`Details`安全抽出、欠損の明示 |
| 05 | P6-03 AG-B001〜005のオフライン相関 | ProcessGuid、複数証拠と正常更新の反例 |
| 06 | P7-01 egui起動とデザインシステム | GUI単体、非特権、MSRV別ビルド |
| 07 | P7-02 ローカル結果の読み取りAPI | 巨大/破損JSONLでもUI非ブロック |
| 08 | P7-03 ホームと脅威タイムライン | 不完全・未観測・古いデータの表示 |
| 09 | P5-03 AST段階導入 | Python/JS/PowerShellの各安全fixture |
| 10 | P5-04 PEの署名・imports解析 | 署名有無/有効性/確認不能/壊れたPE |
| 11 | P5-05 YARA品質と結果キャッシュ | ルール版変更による無効化と誤警告テスト |
| 12 | P8-01 SCM Windowsサービス | GUI独立・最小権限、停止/復旧 |
| 13 | P8-02 継続イベント・スプール | 欠損/重複/高負荷/容量上限 |
| 14 | P8-03 Named Pipe IPC/ACL | セッション越境/別ユーザー拒否/再接続 |
| 15 | P8-04 インクリメンタル相関 | オフライン再生との判定一致 |
| 16 | P9-01 eguiをIPCへ接続 | GUIを閉じても監視続行 |
| 17 | P9-02 C2ライブ監査・通知 | ProcessGuidと期限付きIOC、観測限界 |
| 18 | P9-03 ブラウザ保護UI | Chrome・他ブラウザのカバレッジ表示 |
| 19 | P6-04 資格情報ファイル読取監査 | 4663等は別承認、内容収集なし |
| 20 | P6-05 Edge/Brave/Firefox拡張 | ブラウザ別仕様/正常対照 |
| 21 | P9-04 トレイ・更新・設定 | 署名/許諾/権限と復旧 |
| 保留 | P10-01 実Firewall適用 | 所有者承認・Windows隔離VMの復旧実証 |
| 保留 | P10-02 実行前アクセス阻止 | OS標準代替とドライバー要否の独立判断 |
| 最後 | P10-03 出荷ゲート | 実機性能/誤警告/24時間稼働/復旧 |

**並列の目安**：P5-02（誤警告）、P6-01（read-only既知痕跡）、P7-01（egui骨格）は別担当で実装可能。P6-02/03はイベントモデル契約を先に固定。P8-03とP9はP5-01の型を共有し、GUIから権限昇格・任意コマンド実行はさせない。

**所有者の未決定事項**：本体配布ライセンス、ルール署名鍵の運用、Windows 11実機の性能閾値、実遮断/監査ポリシー変更の承認、外部ルール/IOCの利用・再配布権利。どれもGitHub Actions成功だけでは決まらない。
