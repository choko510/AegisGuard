# 調査報告：Portmaster / portmaster-service-ui

> 担当：`portmaster-service-ui` / 調査日：2026-11-05 / 調査結果：**ソース調査完了・Windows実機検証未実施**

## 0. 結論（3〜5行）

- **AegisGuardへの価値は高いが、コード移植ではなく設計参考が中心。** 常駐コア、権限を分離したUI、サービスの状態管理、署名更新、保管期限の切り分けは参考になる。
- **最優先：①最小Windowsサービス＋非特権CLI境界、②認可付きローカルIPC＋監査、③署名付きルール/設定更新と復旧。** まず監査専用で動かし、DefenderやFirewallには触れない。
- PortmasterのGoコア・WFPドライバー、Angular/Electron/Tauri GUI全体、SPNをAegisGuardに持ち込まない。Portmasterには**Tauri/Rust UIが既に存在**する一方、コアサービスはGoであり、Rust crateとして直接流用できる構造ではない。
- **重要な留保：** Portmasterの標準コア起動設定ではバイナリ更新には署名検証用トラストストアが渡されるが、インテリジェンス更新用の`VerifyIntelUpdates`設定は同じ初期化箇所で指定されていない。**「全データ更新が署名検証される」とは断定できない**。AegisGuardは双方をfail-closedにすべき。
- ライセンスは本体のGPL-3.0を確認。AegisGuard自体は調査時点でライセンス未設定。第三者部品・ルール・データの再配布条件は未精査であり、**法的評価未完了**。

## 1. 対象の固定と調査方法

| 要素 | 値 / 根拠 |
|---|---|
| 公式リポジトリ | [safing/portmaster](https://github.com/safing/portmaster)。取得時デフォルトブランチは`development`（GitHubリポジトリメタデータで確認）。 |
| 調査コミット / 固定URL | [`bffef134cd709d2a74295cd8450cf0c6231bd60d`](https://github.com/safing/portmaster/tree/bffef134cd709d2a74295cd8450cf0c6231bd60d)。2026-11-05に`development`のGit refから固定。調査時のリリースタグとの一致は未確認。 |
| AegisGuard比較先 | [`83fcf0d150e8d760baff5f971c106deb09c1f8e4`](https://github.com/choko510/AegisGuard/tree/83fcf0d150e8d760baff5f971c106deb09c1f8e4)（2026-11-05時点の`main`）。 |
| ライセンス | Portmaster：[LICENSE（GNU GPL v3）](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/LICENSE#L1-L16)、[TRADEMARKS](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/TRADEMARKS#L1-L5)。第三者素材の別条件は個別に検査。 |
| 主なソース確認 | `cmds/portmaster-core`、`cmds/cmdbase`、`service/instance.go`、`service/firewall/api.go`、`base/api`、`base/config`、`base/database/migration`、`service/updates`、`service/netquery`、`service/ui`、`desktop/tauri`、`desktop/angular`、`packaging/windows`、`go.mod`、`LICENSE`。 |
| テスト/依存関係 | [API権限試験](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/base/api/authentication_test.go#L58-L178)、[更新系テスト](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/updates/updates_test.go#L25-L153)、[パス検証テスト](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/updates/index_test.go#L5-L51)、[Go依存](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/go.mod#L1-L96)、[Tauri依存](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/desktop/tauri/src-tauri/Cargo.toml#L1-L77)、[Angular依存](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/desktop/angular/package.json#L1-L100)を静的確認。 |
| 実機・ビルド・テスト | **未実施**。GitHub上のソース・テスト定義の読解のみ。Windowsサービス起動、WFP、更新サーバーとの実通信、署名鍵管理、ACLの実効性、複数ユーザーを実測していない。悪性検体・ドライバーは実行していない。 |
| AegisGuard現状 | `src/main.rs`のコマンドは`scan`と`c2 update/check/status`のみ（[根拠](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/main.rs#L13-L76)）。[`Cargo.toml`](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/Cargo.toml#L1-L23)、[SECURITY](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md#L1-L33)、[ARCHITECTURE](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L1-L50)でもサービス/GUI/Windowsイベント収集/遮断/署名更新は未実装。 |

**実装確認**＝固定コミットの処理経路とテストを読めた事項、**文書のみ**＝README・コメントの説明のみ、**設計提案**＝AegisGuard向けの将来案。以下で混同しない。

## 2. 実装アーキテクチャとソース調査

| 機能 | 主要ファイル/シンボル、入力→出力、失敗処理 | commit SHA固定の一次情報 | 状態 |
|---|---|---|---|
| 常駐コア/モジュール編成 | `service.New`でconfig→DB/API→各ネットワーク機能→UIなどを`mgr.NewGroup`に登録し、`Instance.Start/Stop`が群を管理。起動失敗はエラーを返す。SPNは別群。 | [`service/instance.go` L127-193](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/instance.go#L127-L193)、[L335-390](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/instance.go#L335-L390)、[L700-755](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/instance.go#L700-L755) | 実装確認 |
| Windowsサービス制御 | `WindowsSystemService.Execute`がSCMに`StartPending/Running/StopPending/Stopped`を通知し、`Stop/Shutdown`を受けてサービス終了完了を待つ。`RestartService`はPowerShellから停止待ち→SCM再起動。 | [`cmds/cmdbase/service_windows.go` L22-179](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/cmds/cmdbase/service_windows.go#L22-L179)、[L190-208](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/cmds/cmdbase/service_windows.go#L190-L208) | 実装確認 |
| ユーザーUIとSCM境界 | Tauriの`WindowsServiceManager`は通常`QUERY_STATUS`だけを開き、開始には`ShellExecuteW("runas", sc.exe, ...)`でUAC昇格を要求。UIが単純に管理者権限を継承し続ける設計ではない。 | [`desktop/tauri/.../windows_service.rs` L35-100](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/desktop/tauri/src-tauri/src/service/windows_service.rs#L35-L100)、[L111-149](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/desktop/tauri/src-tauri/src/service/windows_service.rs#L111-L149) | 実装確認 |
| UI/API通信 | Coreの既定HTTP待受`127.0.0.1:817`。Go HTTP APIが`/ui/modules/portmaster/`等のZIP UIアセットを提供。AngularはWebSocket APIを使い、Tauri側にもRust WebSocketクライアント/再接続処理がある。**localhost自体は認証ではない**。 | [`service/core/base/module.go` L11-12](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/core/base/module.go#L11-L12)、[`service/ui/serve.go` L20-112](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/ui/serve.go#L20-L112)、[`desktop/tauri/.../portmaster/mod.rs` L1-64](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/desktop/tauri/src-tauri/src/portmaster/mod.rs#L1-L64) | 実装確認 |
| API権限モデル | `PermitAnyone/User/Admin/Self`を操作ごとに区分し、Bearer/Basic/セッションCookieまたは外部Authenticatorにより判定。`core/restart`はAdmin、`core/shutdown`はSelf。`app/auth`は通知を通じて第三者APIキー発行を要求。 | [`base/api/authentication.go` L44-85](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/base/api/authentication.go#L44-L85)、[L136-240](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/base/api/authentication.go#L136-L240)、[`service/core/api.go` L35-105](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/core/api.go#L35-L105)、[L345-440](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/core/api.go#L345-L440) | 実装確認 |
| ローカル呼出元検証 | `firewall.apiAuthenticator`が接続元IP・port→PID→実行ファイル/親プロセスをたどり、配布バイナリ領域か許可されたクライアントかを判定。識別できなければ拒否/再試行。これはOSトークン/セッションIDに基づく厳密なWindowsユーザー分離の証明ではない。 | [`service/firewall/api.go` L32-203](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/api.go#L32-L203) | 実装確認＋境界の留保 |
| ブラウザー境界 | `router.go`にCSP/Origin/Host/CORS検査、`SameSite=Strict`のCookie、時間制限がある。ただし`chrome-extension` Originを包括許可するTODOが存在し、CORSは能力認可の代替にならない。 | [`base/api/router.go` L118-209](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/base/api/router.go#L118-L209)、[`base/api/authentication.go` L475-505](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/base/api/authentication.go#L475-L505) | 実装確認 |
| 設定と障害時の挙動 | JSONの`config.json`をロードし、設定値検証・一部値のマイグレーション処理あり。`SaveConfig`は`os.WriteFile`で直接上書きするため、**書込途中障害に対する原子的保存はコード上確認できない**。JSONパース失敗は起動エラー。 | [`base/config/main.go` L39-60](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/base/config/main.go#L39-L60)、[`base/config/persistence.go` L30-97](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/base/config/persistence.go#L30-L97)、[`base/config/set.go` L40-110](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/base/config/set.go#L40-L110) | 実装確認 |
| DBマイグレーション | バージョン昇順で各`MigrateFunc`を適用し、成功バージョンをDBへ記録、失敗時は`Diagnostics`を返す。**全マイグレーションのロールバック保証は確認していない**。 | [`base/database/migration/migration.go` L15-135](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/base/database/migration/migration.go#L15-L135)、[`service/profile/migrations.go` L18-50](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/profile/migrations.go#L18-L50) | 実装確認 |
| 署名付きバイナリ更新 | `ParseIndex`はtrustStoreが非nilならJESSでJSON署名を検証。`configure.BinarySigningTrustStore`に公開署名鍵を保持し、標準Core CLIは`VerifyBinaryUpdates`に設定。アーティファクトはSHA-256照合、更新の世代/時刻/ファイル名を検証。 | [`service/updates/index.go` L151-211](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/updates/index.go#L151-L211)、[L255-324](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/updates/index.go#L255-L324)、[`service/configure/updates.go` L28-50](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/configure/updates.go#L28-L50)、[`cmds/portmaster-core/main.go` L93-110](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/cmds/portmaster-core/main.go#L93-L110) | 実装確認 |
| **更新の信頼境界に注意** | `ParseIndex`はtrustStore=nilの場合に署名検証をスキップ。`MakeUpdateConfigs`は`VerifyIntelUpdates`を受け渡すが、通常の`portmaster-core/main.go`初期化は**バイナリ用しか設定しない**。従って、既定のIntel取得について署名保証を一般化できない。なおSHA-256は署名済みインデックスが前提で初めて配布元真正性の根拠になる。 | [`service/updates/index.go` L153-161](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/updates/index.go#L153-L161)、[`service/config.go` L125-157](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/config.go#L125-L157)、[`cmds/portmaster-core/main.go` L93-110](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/cmds/portmaster-core/main.go#L93-L110) | 実装確認（起動形態の全網羅は未確認） |
| 更新失敗/復元 | 更新中はUI ZIPのハンドルを閉じてupgrade lock、古い資産をpurge領域へ退避、転送失敗時は復元を試行。アーカイブ展開→SHA照合の順で、ダウンロード本体には`io.ReadAll`が使われる。メモリ上限・DoS耐性は別途要検証。 | [`service/updates/upgrade.go` L16-55](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/updates/upgrade.go#L16-L55)、[L56-174](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/updates/upgrade.go#L56-L174)、[`service/updates/downloader.go` L198-254](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/updates/downloader.go#L198-L254) | 実装確認 |
| 履歴/ログプライバシー | 接続先IP/ドメイン/パス等をSQLite`history.db`へ保存し、アプリ単位の保持日数により削除。サービス`.log`は30日TTLで日次掃除。Tauri UI側は`RotationStrategy::KeepAll`であり、サービスログと同一の期限があるとは言えない。 | [`service/netquery/database.go` L68-114](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/netquery/database.go#L68-L114)、[L511-569](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/netquery/database.go#L511-L569)、[`service/core/base/logs.go` L14-56](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/core/base/logs.go#L14-L56)、[`desktop/tauri/.../main.rs` L185-223](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/desktop/tauri/src-tauri/src/main.rs#L185-L223) | 実装確認 |

**注意すべき非実装/未証明点：** Portmasterの全APIに対するWindowsユーザーSID別の認可、ルール変更の耐改ざん監査台帳、設定書き換えのatomic rename+fsync、UIログの総容量上限、全更新経路の署名必須化は、この範囲のソースでは**確認できなかった**。ないと断定するのではなくAegisGuardでは明示要件とする。サービスの`ImagePath`引用符欠落を補修するCWE-428対策は[`cmds/portmaster-core/main_windows.go` L21-108](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/cmds/portmaster-core/main_windows.go#L21-L108)に確認できるが、インストーラー全経路の実機状態は未確認。

## 3. 具体的な取り込み候補と選択肢

| 候補機能 | 利用方法と判定 | AegisGuard接続先 | 優先度 | 工数 | 阻害要因/採用条件 |
|---|---|---|---|---|---|
| **A. Windowsサービス＋ライフサイクル** | **AegisGuard独自実装**（PortmasterのSCM設計参考）。Rust `windows-service`等を個別評価 | 将来`aegis-service`、既存`aegis-core`化 | **P0 / 上位1** | **M** | Windows専用、SCM/UAC、サービスアカウントACL、復旧ポリシー。Goコードはコピーしない |
| **B. 認可付きローカルIPC** | **独自実装**（権限表/起動順・拒否設計参考）。既定はWindows Named Pipe＋ACL/SID検証を提案 | 将来`aegis-ipc`、CLI、GUI | **P0 / 上位2** | **M** | 不正クライアント、セッション越境、管理者/一般ユーザー境界、バージョン互換 |
| **C. 署名検証・アトミック更新・復旧** | **独自実装**。Portmasterのインデックス/ハッシュ/復旧テストを設計参考 | 既存`src/c2.rs`を将来`aegis-updates`へ分離 | **P0 / 上位3** | **M** | 鍵配布・ローテーション、ルール出所ライセンス、リプレイ防御、Windowsロック |
| D. 設定スキーマ、移行、監査 | **独自実装**。Portmasterの検証・移行履歴を参考 | `aegis-config`、`aegis-audit` | P1 | M | 書込原子性、破損復旧、監査の秘匿と永続性。標準の単純上書きは踏襲しない |
| E. 通知・状態・ヘルスチェック | **独自実装/設計参考**。`status`、`notifications`、Tauri再接続を参照 | 将来`aegis-events`、CLI `status`、GUI | P1 | S〜M | イベント欠落時の再同期、通知連打、個人情報。GUI未実装段階はCLIのみ |
| F. Portmasterを外部CLI/サービスとして利用 | **外部サービス連携は条件付き・既定見送り**。Portmaster HTTP APIの読み取りのみ検討 | 任意の診断アダプタ（将来） | P2 | M | 利用者による別途導入、権限承認、ポート競合、Defender/WFPとの重複、GPL法的検討 |
| G. Portmaster Go内部モジュールをRust crateとして直接リンク | **不採用** | なし | - | L | Goのサービス状態・依存・GPL・Windowsドライバーとの結合。Rust crateではない |
| H. Electron/Angular/Tauri GUI一式、SPN、WFP独自ドライバー | **不採用（設計参考に限定）** | なし | - | L | UI規模・技術スタック・SPN課金/ネットワーク・WFPドライバー配布/署名/競合の大幅増加 |

**候補A（入出力/異常系/PoC）：** `ServiceCommand{Start,Stop,Status}`と`ServiceState{Starting,Ready,Degraded,Stopping,Stopped,Failed}`を契約として提案。`scan`や`c2`は現行CLIの読み取り専用処理を再利用し、GUIとは別プロセスに置く。起動時は最小構成のルール/設定読み込み→ヘルスチェック→Ready。サービス開始失敗は`Failed`/Windowsイベントログを返し、Defender・Firewallを変更しない。PoCでは非管理者CLIの`status`と、SCM停止→再起動→状態整合を確認する。

**候補B：** リクエストは`Request{id,version,action,payload}`、応答は`Response{id,ok,data,error_code}`、通知は連番付き`Event{sequence,type,redacted_payload}`。`status`/`scan enqueue`は一般ユーザー、更新適用や将来の遮断は明示的管理者承認とOS SID検証を要求。接続拒否・期限切れ・リプレイ・予期せぬ切断・メッセージサイズ超過は安全に失敗させる。PoCでは別ユーザー/低権限からの書き込み拒否、同一ユーザーへの閲覧用フィルタ、再接続後のイベントギャップ通知をテストする。**PortmasterのPID→パス判定をセキュリティ境界の唯一の根拠にしない**。

**候補C：** 入力`Manifest{schema,version,channel,issued_at,expires_at,entries:[sha256,size,content_type],signature}`、出力`Verified/Staged/Applied/Rejected(reason)`と監査ID。署名と許可済み公開鍵の検証→マニフェスト世代確認→ダウンロード上限/展開上限→SHA-256→一時領域へ書き込み→原子的切替→障害時ロールバック、の順を**AegisGuardで独自設計**する。ネットワーク/検証失敗では直前の正常版を維持し、期限超過は`stale`で明示。**現行`src/c2.rs`にはサイズ上限、フィード別鮮度、`tmp/bak`退避が存在する**ため、完全に作り直す前にこれを再利用する（[L13-48](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L13-L48)、[L250-309](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L250-L309)）。しかし現行のフィードは署名付きではなく、設定・ルールの安全な自動適用を意味しない。

**候補D/E：** 設定入力は型付き`ConfigChange{actor_sid,revision,expected_revision,changes}`、出力は`Applied/Conflict/ValidationError/RestartRequired`。差分、操作者、承認、前後revision、タイムスタンプを秘匿された追記型監査に保存（パス・IP・ユーザー名は表示用にマスク）。スキーマ移行前にバックアップを作り、破損時は診断付き読み取り専用モードへ。通知は`severity`と`event_id`で重複排除し、CLIから`status --json`と`events --since`を参照可能にする。将来GUIはこの同じAPIを使用し、直接ディスクやFirewallに触れない。

## 4. ライセンス・再配布・依存関係

| 対象/利用形態 | 一次情報と判断 |
|---|---|
| Portmaster本体ソースのコピー・改変・直接リンク | [ルートLICENSE](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/LICENSE#L1-L16)はGNU GPL v3。Goコア/API実装、サービス制御、Angular UIのコードのコピーや改変・結合と再配布はGPLの義務を含む可能性が高く、**独立ライセンスのAegisGuardへ無断コピーしない**。適用範囲の例外を全ファイルで確認したわけではない。 |
| 独立サービス/外部CLI連携 | Portmasterを利用者が**別途インストール**し、公開API経由で利用する設計は技術的候補。ただしIPC/APIだから常にライセンス上安全、とは言えない。密結合・一体配布・同梱形態は法的評価が必要。 |
| Rust crate直接利用 | 本体コアは[Go module](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/go.mod#L1-L65)。Tauri UIのRust側も[`Cargo.toml`](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/desktop/tauri/src-tauri/Cargo.toml#L1-L75)で独立したUIアプリ（`license = ""`）。そのまま安全・合法に再利用できる公開汎用crateであることは未確認。 |
| Windowsドライバー、UI素材、インストーラー | Windowsパッケージは`portmaster-kext.sys`とUI/Goバイナリを同梱（[スクリプト](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/packaging/windows/generate_windows_installers.ps1#L200-L230)）。Tauriパッケージには別のNSISプラグインライセンス（[License.txt](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/desktop/tauri/src-tauri/templates/NSIS_Simple_Service_Plugin_Unicode_1.30/License.txt)）があり、[Robotoライセンス例](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/assets/data/fonts/Roboto-regular/LICENSE.txt)も個別に存在。これらを「Portmaster GPLのみ」と一括りにしない。 |
| 署名鍵・公開鍵とアップデートインデックス | 公開鍵は[`configure/updates.go`](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/configure/updates.go#L28-L50)で確認。**鍵文字列や署名をAegisGuard用の信頼根として流用しない**。署名済み公式データのミラー・再配布条件は別途要確認。 |
| ブロックリスト/ルール・GeoIP・SPNデータ | 自動Intel更新インデックスを通じた外部データ取得は確認できるが、各配信データの権利者・個別ライセンス・利用条件は**未確認**。ソース・ルール・配布署名・利用統計は別々に権利確認する。SPNサービスと商標はコードのGPLと別問題。 |
| 商標 | [TRADEMARKS](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/TRADEMARKS#L1-L5)でSafing/Portmaster/Gate17の名称・ロゴ権利を明示。AegisGuardの名称/ロゴへの転用なし。 |
| AegisGuard側 | [README ライセンス節](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md#L114-L125)ではコードライセンス未設定。利用条件・独立実装の設計を決める前に、既存GPLコードを取り込まない。 |

依存例：Goは`gorilla/websocket`、`gorilla/mux`、`modernc.org/sqlite`、`zombiezen.com/go/sqlite`、`safing/jess`、`x/sys`等（[go.mod](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/go.mod#L1-L95)）。UIはAngular/TypeScript、Rust Tauri2と`windows-service`、`reqwest`、`tokio-websockets`（[Cargo.toml](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/desktop/tauri/src-tauri/Cargo.toml#L14-L75)、[package.json](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/desktop/angular/package.json#L20-L101)）。**各依存のSPDX、再配布通知、フォント/画像/ドライバー署名、脆弱性情報の全件監査は未実施。法的評価未完了。**

## 5. Defender共存・Windows制約・権限境界

Portmasterの監視は単純なユーザーモードのログ購読ではなく、WindowsではWFPカーネルドライバーとパケット処理/接続所有者特定に依存する（[README技術説明](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/README.md#L26-L53)、[Windows interception](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/interception/interception_windows.go)、[ドライバー接続サービス](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/interception/windowskext/service.go)）。そのままAegisGuardに追加するとDefenderや既存Windows Firewall/VPN/他社AVとのフィルタ競合、遮断の責任、ドライバー署名・メンテナンス負担が発生する。**WFPを使わずに防御が同等となるという主張もしない**。

AegisGuardの現行`main`にはSysmon Event ID 1/3/7、ETW、AMSI、WFP、リアルタイム常駐、遮断は未実装（[ARCHITECTURE](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L17-L53)、[SECURITY](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md#L12-L26)）。最初のサービスPoCは現行CLIの`scan`とC2キャッシュ参照、Windowsイベント**観察のみ**を対象とする。将来Sysmon/ETWは提供されたアクセス権で購読し、失敗/欠落を可視化する。AMSIはスクリプトホスト依存、Defenderの代替ではない。WFP/Firewallルール変更は別担当の明示許可・事前プレビュー・rollbackが揃うまで行わない。

権限は`LocalSystem`や管理者の必要最小化を要設計。PortmasterではUI側のサービス状態照会は低権限、サービス開始はUACに委譲する一方、コアのAPIにはPID/実行ファイルによる独自認可経路がある。**同一PC上の別ユーザーセッション・ローカル管理者・資格情報窃取済みプロセス**に対する認可モデルの詳細は追加検証が必要。AegisGuardではWindows Named Pipeの`SECURITY_DESCRIPTOR`/SID・実行ユーザーの判定、OSによるサービス操作の保護、特権処理の固定アクション化、GUIの非特権実行を提案する。ブラウザーからの接続を後に追加する場合も、loopback/CORSだけで信頼せずCSRF、origin、token、session分離を必須とする。

## 6. 性能・堅牢性・誤検知

- **計測事実：なし。** 起動時間、常駐RSS/CPU、DNSレイテンシ、SQLite I/O、WFP負荷、ノートPC電池消費の数値を本調査で測っていない。Portmasterのベンチや本番値をAegisGuardの予測値に流用しない。
- **起動負荷：** `service/instance.go`の依存モジュール群・更新確認・SQLite/パケット処理は潜在的ボトルネック。AegisGuardは起動時の全ディレクトリ再スキャンや同期ネットワーク呼出しを避け、サービスReadyとルール鮮度を別状態で管理。起動後に増分処理、bounded queue、イベント脱落カウンタを持つ。
- **失敗と設定破損：** PortmasterはJSONロード失敗でエラー、保存は非原子的な`os.WriteFile`。AegisGuardは`tmp`への書込み・flush/sync・バックアップ・検証・切替、起動時復旧、最後の正常設定と`safe mode`、設定が壊れてもDefender/Firewallは現状維持を要求。
- **更新の攻撃入力：** Portmasterのインデックスは署名チェックを条件付きで実行し、ファイル名に`../`/ドライブ指定/ADSを禁止（[実装](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/updates/index.go#L182-L211)、[単体テスト](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/updates/index_test.go#L5-L51)）。一方ダウンロードは`io.ReadAll`、展開は最大`MaxUnpackSize=1<<30`でバイト列を保持（[downloader](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/updates/downloader.go#L223-L311)）。AegisGuardは圧縮前・展開後サイズ、アイテム数、処理時間、圧縮率を**もっと小さな合理的上限**に制限し、署名検証を展開に先行させる。
- **履歴とプライバシー：** 接続履歴の`history/keep`既定は30日（[profile/config.go](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/profile/config.go#L268-L286)）。0日は無期限保持扱い（[database.go](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/netquery/database.go#L527-L561)）。サービスログは30日消去するがTauriの`KeepAll`と統一されていない。AegisGuardは既定で最小限のイベントメタデータのみ、保管期間/総容量/件数/ユーザー別ACLの三重上限、利用者による削除、パス・IP等のレダクションを採用する。
- **誤検知/見落とし：** IOC一致や疑わしい通信は阻止・感染確定ではない。許可リスト、失効時刻、検知根拠、センサー停止/ログ欠落を別々に表示する。サービス停止中の検査漏れを「正常」と誤記しない。Defenderは継続稼働させ、リアルタイム二重ファイルスキャンを初期状態では避ける。
- **セキュリティ監査：** API routerはOrigin/HostとCSPを検査するが、ブラウザー拡張Originを包括許可するTODO（[router L171-191](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/base/api/router.go#L171-L191)）。更新パイプラインに非署名Intel indexの可能性があり、要求ごとの認可・監査・供給元信頼を明確に独立評価する。
- **テスト読解：** APIの全権限×メソッド組合せ（[authentication_test.go](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/base/api/authentication_test.go#L58-L178)）、更新成功/同一版破損修復（[updates_test.go](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/updates/updates_test.go#L25-L153)）、パス検証（[index_test.go](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/updates/index_test.go#L5-L51)）の存在を確認。**テスト成功とは主張しない**。Tauri/Windows ACL/SCM/UACの結合試験は未確認。

## 7. 推奨する小さなPoCと成功基準

**前提：** Windows 11 x64の隔離VM（スナップショットあり）、Defender有効、一般ユーザーと管理者のテストアカウント、実運用Firewall/ネットワーク設定を改変しない。Portmaster本体/ドライバーはインストールせず、AegisGuard独立のスタブサービス/テストデータのみを使う。データ保存先は明示的ACLと容量上限を用意。

1. **段階0：無効/静的。** 現行`scan`と`c2 status`がサービスなしでも正常動作。サンプルは harmless PE/スクリプト、期限切れのダミーIOC、意図的に破損したJSON/署名/ZIPだけ。Defenderの状態やFirewallルールに差分が**ない**ことをWindowsの標準管理APIで確認。
2. **段階1：監査・可視化。** 権限を制限したサービスから、認可付きIPCで`status`/`events`/`scan enqueue`を提供。別ユーザー・権限なし要求は拒否、認証済み読み取りと操作ログを区別。停止/クラッシュ/再起動/電源断相当の障害注入で`Failed/Degraded`を可視化し、欠落連番・上限超過・再接続を正しく報告。
3. **段階2：限定有効化。** **実際の遮断ではなく**テスト用設定revision適用と署名済みテスト用IOCの更新だけを有効化。正当な鍵とsha256が一致するデータのみ適用。署名不正・旧版リプレイ・期限切れ・フィード空・圧縮爆弾・パス越境・更新中プロセス終了の場合は**以前の正常版を保持**し、明確なerror_codeと監査記録を生成。

**受け入れ基準：** (a) 権限のない操作・異なるSIDによる変更がすべて拒否される、(b) 切断やサービス再起動後に権限が昇格せず`status`と監査履歴が整合する、(c) 不正/破損更新は適用ゼロで直前版へ復旧、(d) JSONパス・レポート・ログの漏えいがACL/マスキングの検査で発見されない、(e) 読取不能/データ欠落を明示的に報告し検知成功と扱わない、(f) Defenderと既存Firewallの構成が実験前後で不変、(g) 起動時間、RSS/CPU、ディスク使用量、IPC遅延、イベント落ち件数を**実測して記録**し事前合意した予算内、(h) テストが再現可能で静的スキャンの既存仕様を破らない。**予算値は現段階で未設定、実測後に決める**。

**失敗時/ロールバック：** PoCサービス停止→自動起動無効→テスト用保存領域をバックアップから復元→VMスナップショット復帰。Defender/既存Firewallは元から変更しない。**中止条件：** データ消失、権限越境、未検証の更新適用、バッファ無限増加、Defender警告、意図せぬ遮断・ドライバー導入・権限昇格の発生。

## 8. 採用しない設計と理由

1. **PortmasterのGoコア/WFPドライバーの直接コピー・Rust置換の一括作業：見送り。** 依存が巨大で、GPLの派生物・配布要件、ドライバー署名、WFP競合、ライフサイクルを同時に背負う。AegisGuardの現在の目的はまず静的解析＋イベント観察であり、早期のドライバー導入に見合わない。
2. **Portmaster UI/Angular/Electron/Tauri＋SPNの統合：見送り。** 現行AegisGuardはCLI MVP。GUIとSPNの構成は独立要件が多く、監査可能なサービス/API契約より先に表層UIを導入しても権限分離・更新安全性は改善しない。将来GUIは最小Rust/OS-nativeクライアントを別プロセスで検討する。
3. **HTTP loopbackだけで全操作を許可：見送り。** Portmaster自身も細かい認可と呼出元検証を実装している。AegisGuardはSID別ACL・明示的なアクション許可表・監査・CSRF対策を必須とする。
4. **アップデートインデックスのSHAだけを信頼：見送り。** 署名のないインデックスを攻撃者が差し替えると正しいSHAも同時に差し替えられる。**全更新クラスの署名を必須**とし、失敗時は更新しない。

## 9. 他担当との境界・引継ぎ

- **`portmaster-policy-dns`担当：** DNSリダイレクト、アプリ別ポリシー、WFPドライバー、遮断・allowlist、Defender共存、既存VPN干渉についての実装根拠・実機検証はそちらを優先。本報告はサービス制御/権限/更新/UI契約に限定。
- **外部IOC/署名更新担当：** 署名鍵管理、証明書の失効・ローテーション、フィード出所と著作権、更新フォーマット共通化は他研究と横断調整。AegisGuardの`src/c2.rs`を改造する実装方針は本PRでは確定しない。
- **Windowsイベント担当：** Sysmon/ETW/AMSIのイベント粒度、権限、ギャップ検知、ProcessGuid相関は別途検証。本担当はイベント運搬と監査APIのみ提案。
- **統合設計担当：** GUI/CLIの操作権限、利用者SIDと管理者承認、サービス停止・再起動後の復旧状態、セキュリティログのACL/削除ポリシーを共通仕様にする。

## 10. 未確認事項・追加調査項目

| 重大度 | 未確認・追加検証 |
|---|---|
| **高** | 標準Core起動の`VerifyIntelUpdates`未指定（署名検証を通らない可能性）。他の起動経路/配布物で検証強制されるか、署名付きIntel配信がどのように扱われるか、正式配布経路を含め要確認。 |
| **高** | Windowsで複数ユーザー/セッション、管理者/SYSTEM、任意のブラウザー拡張、PID再利用/親プロセスなりすまし、APIトークン漏えい時の実際の権限境界。実機認証試験未実施。 |
| **高** | GPL-3.0とAegisGuard未設定ライセンスの関係、Go/Tauri/ドライバー/NSIS/フォント/SPN/配布ルールの権利・署名主体・許諾条件。**法的評価未完了**。 |
| **高** | Windows SCM自動起動/サービス回復ポリシー/未引用パスの補修が既存インストーラー全経路で適切に動くか。UACキャンセル、サービス開始不能、Windowsアップデート後の復旧。 |
| **中** | 設定破損の現場での復旧、複数同時設定変更の整合性、監査ログの実効改ざん耐性、データ削除時のSQLite`VACUUM`とプライバシー。 |
| **中** | Tauriログ`KeepAll`のディスク使用量上限・ユーザーACL、サービス30日TTLとの違い。ダウンロード`io.ReadAll`や展開最大1GiBによるピークRSS。 |
| **中** | SHA/署名/データ更新の鍵ローテーションとリプレイ耐性、CDN障害/途中書込/OS電源断/同時更新時の復旧、全テストのCI結果とWindows結合試験の網羅性。 |
| **中** | Windows 11 x64でDefender/Windows Firewall/WFP/ETW/Sysmonとの実競合、アイドルCPU/メモリ/起動レイテンシ/誤検知/観測欠落の実測。 |
| **低** | Portmaster`development`が現在の正式安定配布とどのタグ/commitで対応するか、旧Electronと現Tauriの実際の配布比率。 |

## 11. 一次情報一覧

いずれも**2026-11-05参照、Portmaster `bffef134cd709d2a74295cd8450cf0c6231bd60d` / AegisGuard `83fcf0d150e8d760baff5f971c106deb09c1f8e4`固定**。主要断定をREADMEだけで支えていない。

1. サービス起動順・群管理：[`service/instance.go` L127-193](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/instance.go#L127-L193)、[L335-390](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/instance.go#L335-L390)、[L700-755](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/instance.go#L700-L755).
2. Windows SCM停止/再起動：[`cmds/cmdbase/service_windows.go` L22-208](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/cmds/cmdbase/service_windows.go#L22-L208); 未引用サービスパスの修正：[`cmds/portmaster-core/main_windows.go` L21-108](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/cmds/portmaster-core/main_windows.go#L21-L108).
3. Tauri低権限状態照会/UAC開始：[`windows_service.rs` L35-149](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/desktop/tauri/src-tauri/src/service/windows_service.rs#L35-L149); IPC経路：[`portmaster/mod.rs` L1-65](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/desktop/tauri/src-tauri/src/portmaster/mod.rs#L1-L65).
4. Go API権限/認証：[`base/api/authentication.go` L44-240](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/base/api/authentication.go#L44-L240); Cookie：[L475-505](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/base/api/authentication.go#L475-L505); Windows呼出元認証：[`service/firewall/api.go` L32-203](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/api.go#L32-L203).
5. CORS・ブラウザー拡張Origin・CSP：[`base/api/router.go` L118-209](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/base/api/router.go#L118-L209); 権限試験：[`base/api/authentication_test.go` L58-178](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/base/api/authentication_test.go#L58-L178).
6. 更新JSON署名/パス検証：[`service/updates/index.go` L151-211](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/updates/index.go#L151-L211); 公開鍵：[`service/configure/updates.go` L28-50](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/configure/updates.go#L28-L50); 既定CLI設定：[`cmds/portmaster-core/main.go` L93-110](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/cmds/portmaster-core/main.go#L93-L110); Intel用設定の受渡し：[`service/config.go` L125-157](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/config.go#L125-L157).
7. 更新/復元・圧縮・ハッシュ：[`service/updates/upgrade.go` L16-174](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/updates/upgrade.go#L16-L174); [`service/updates/downloader.go` L198-311](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/updates/downloader.go#L198-L311); [`service/updates/index_test.go` L5-51](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/updates/index_test.go#L5-L51); [`service/updates/updates_test.go` L25-153](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/updates/updates_test.go#L25-L153).
8. 設定ロード/永続化：[`base/config/main.go` L39-60](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/base/config/main.go#L39-L60); [`base/config/persistence.go` L30-97](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/base/config/persistence.go#L30-L97); DB移行：[`base/database/migration/migration.go` L15-135](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/base/database/migration/migration.go#L15-L135).
9. 履歴データと清掃：[`service/netquery/database.go` L68-114](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/netquery/database.go#L68-L114); [L511-569](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/netquery/database.go#L511-L569); [`service/netquery/module_api.go` L123-166](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/netquery/module_api.go#L123-L166); ログ：[`service/core/base/logs.go` L14-56](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/core/base/logs.go#L14-L56); UIログ：[`desktop/tauri/src-tauri/src/main.rs` L185-223](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/desktop/tauri/src-tauri/src/main.rs#L185-L223).
10. ライセンス/依存：[`LICENSE`](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/LICENSE#L1-L16); [`TRADEMARKS`](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/TRADEMARKS#L1-L5); [`go.mod`](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/go.mod#L1-L95); [`Cargo.toml`](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/desktop/tauri/src-tauri/Cargo.toml#L1-L75); [`package.json`](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/desktop/angular/package.json#L1-L101).
11. AegisGuard比較：[`src/main.rs` L13-76](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/main.rs#L13-L76); [`src/c2.rs` L13-48, L250-309](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L250-L309); [`docs/ARCHITECTURE.md`](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L1-L53); [`SECURITY.md`](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md#L1-L30).

**総括：** 採るべきなのは「特権を持つ小さな常駐サービス」「非特権クライアントとの強い認可境界」「検証したデータだけを段階適用し復元できる更新」である。Portmasterの実装をそのまま利用すればこれらが自動で満たされるわけではない。実機検証と法的評価を通るまでは**設計参考のみ**とする。
