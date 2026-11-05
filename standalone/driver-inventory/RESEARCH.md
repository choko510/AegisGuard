# 調査記録：Windows SCMドライバー・サービス棚卸し

- 確認日：**2026-11-06（日本時間）**
- 対象：Windows 11 x64 / 独立Rust 1.85 CLI
- 参照ソース：Microsoft Learn（一次資料）、AegisGuard main の README.md、SECURITY.md、docs/ARCHITECTURE.md、src/model.rs、src/authenticode.rs
- 検証状態：**公式API文書は確認済み。Windows 11実機での動作・誤検知・性能は未確認。** この調査時の実行コンテナにはRust/Cargoが存在しないため、コンパイル・テスト成功を主張しない。

## 1. 技術選択と根拠

| 対象 | 一次資料URL | 採用・制約 |
| --- | --- | --- |
| SCM接続 | https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw | OpenSCManagerW(NULL,NULL,SC_MANAGER_ENUMERATE_SERVICE)。現在の権限で読取のみ。管理者昇格しない。 |
| 登録済サービス・ドライバー列挙 | https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-enumservicesstatusexw | EnumServicesStatusExW(SC_ENUM_PROCESS_INFO, SERVICE_DRIVER と SERVICE_WIN32, SERVICE_STATE_ALL)。256KiBページ、resume handle、ERROR_MORE_DATAによる再試行。APIはSERVICE_QUERY_STATUS権限のないサービスを無言で省略し得るため、可視範囲を必ず明記。 |
| SCM構造体 | https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_status_process | SERVICE_STATUS_PROCESS の dwServiceType/dwCurrentState を型付きで読む。現在のステータスは瞬間値で変更可能。PIDは採取しない。 |
| 登録情報 | https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfigw | OpenServiceW(SERVICE_QUERY_CONFIG)、QueryServiceConfigW。最大8KiB、ERROR_INSUFFICIENT_BUFFER、拒否はpermission_denied。稼働中に変更した設定は次回起動用の値の場合がある。 |
| 登録項目 | https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-query_service_configw | dwStartType は boot/system/auto/demand/disabled、lpBinaryPathName は引数を含み得るのでそのまま出さない。dependencies (MULTI_SZ) は最大1024 UTF-16要素を検証し、最大64件の件数のみ出力。名前を保存しない。 |
| オプション設定 | https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2w | QueryServiceConfig2W(SERVICE_CONFIG_DELAYED_AUTO_START_INFO)を使用。エラー時はnullでありfalseとしない。 |
| 遅延自動起動 | https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_delayed_auto_start_info | 自動起動サービスでのみ意味がある設定。flagを独立して保持。 |
| アクセス制御 | https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights | ENUMERATEとQUERY_CONFIG最小権限。拒否を隠さず、完全性と不審度を分ける。 |
| ファイル署名 | https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust | WinVerifyTrustは0だけが成功。埋込み署名のみオプション。WinTrust actionはGENERIC_VERIFY_V2、UIなし。 |
| 署名入力 | https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_file_info | WINTRUST_FILE_INFO、パス文字列を渡す。開いたファイルハンドル経由の不変性保証は本MVP未対応。 |
| ネットワーク抑止 | https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data | WTD_UI_NONE、WTD_CACHE_ONLY_URL_RETRIEVAL、WTD_REVOCATION_CHECK_NONE、WTD_STATEACTION_IGNORE。CRL/OCSPのネットワーク取得はしない。 |
| PnP別経路（不採用） | https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdienumdeviceinfo | SetupAPIはPnPデバイス情報集合に対する列挙で、SCM登録ドライバー全件と等価ではない。デバイス/INFとの相関は別フェーズ。 |

## 2. 実装仕様と代替案

- **採用：SCM Win32 APIの直接FFI**。ランタイムでPowerShellやsc.exeを起動しない。外部のドライバーを配布しない。固定構造体は公式Windowsヘッダーのレイアウトに合わせ、UTF-16は固定バッファ内のポインタ・終端・長さを検証して読み取る。32-bitと64-bitでポインタ幅が変わるためrepr(C)を用いるが、両環境とも未コンパイル。
- **不採用：レジストリのServicesキー直接列挙**。SCMの実行中状態、サービスAPIによる可視性・権限の扱いと乖離し、登録項目の理解が難しい。SCM管理下の登録範囲に限定。
- **不採用：SetupAPI全件・Driver Store列挙**。対象がPnPドライバーパッケージおよびデバイスであり、今回のSCM登録サービス棚卸しと集合が一致しない。
- **不採用：PowerShell Get-Service / sc.exe / CIM のコマンド実行**。テキスト整形・ロケール・引数解釈への依存が生じ、プロセス実行を避けたい。
- **採用：埋込み署名の限定確認のみ**。Windowsコンポーネントはカタログ署名が多い。WinVerifyTrustだけでTRUST_E_NOSIGNATUREが返っても unsigned と断定せず unknown とする。必要なら将来本体の src/authenticode.rs が使う CryptCATAdminAcquireContext2/CryptCATAdminEnumCatalogFromHash をアダプタ経由で再利用する。ただし今回は本体importを禁止し、実装コピーもしない。
- **パス解釈**：SCM ImagePathは実行可能ファイルと引数を含む。引用されたパス、ローカル絶対パス、\SystemRoot、%SystemRoot%、%windir%、System32相対を限定サポート。それ以外（任意環境変数、\Device、未引用の空白付きパス、相対遡り、UNC）はunknown。任意環境変数の展開とプロセス実行を避ける。
- **ファイル状態**：存在/欠損/拒否/不明を分離。保護領域・仮想/疑似ドライバー、暗黙ImagePath、権限不足では未評価。ファイル名、配置先、署名だけで悪性と断定しない。
- **プライバシー**：名前は128文字以内・制御文字等除外。生のImagePath文字列・引数を出さない。SystemRoot配下以外の実パスは既定でredactし、--show-pathsを要求する。取得の根拠はsourceフィールドで提示。IP、ホスト名、証明書主題、ユーザー名、依存配列は出さない。
- **上限**：4096件、32ページ、256KiB/ページ、8KiB/config、256KiB/fixture、10秒の処理間ソフト上限、署名最大256件。FFIブロック単位の絶対的なキャンセルは未実装。
- **エラーと判断**：completeは権限上可視の範囲の列挙完了のみ。permission_denied/partial/unavailable/errorを区別し、空entriesや署名unknownから「安全」を導出しない。

## 3. ソースコード・ライセンス

- 自前FFI: Microsoft Win32 APIの関数仕様から構造体/呼出しを設計し、外部GPL/AGPLソースはコピーしていない。OS SDKの.dllへのシステムリンクのみ。
- Cargoの唯一の直接依存: **serde_json =1.0.154**、MIT OR Apache-2.0。ソース: https://github.com/serde-rs/json ; metadata: https://docs.rs/crate/serde_json/latest/source/Cargo.toml
- 間接依存（ロックファイルで固定）: serde, serde_core, serde_derive, syn, quote, proc-macro2, unicode-ident, itoa, memchr, zmij。Serde群はMIT OR Apache-2.0、zmijはMIT。https://github.com/serde-rs/serde ; https://github.com/dtolnay/zmij
- Cargo.lockは、同リポジトリの並列PRの小型serde_json依存パッケージのlockfileを参考にし、パッケージ名を専用名に変更したもの。依存の整合性は実Cargoでの再生成・--lockedビルドで要確認。
- ルートAegisGuardの配布ライセンスの最終決定はリポジトリ管理者の判断による。既存アプリ本体のコードをimport/変更しない。

## 4. 残課題・Windows実機未確認

1. cargo fmt、cargo clippy、cargo test、Windows x64の cargo build --release を実行し、必要な構文・FFI・挙動の不具合を修正する（このセッションではツールチェーン未設置のため未実行）。
2. Windows 11一般ユーザー/管理者のサービス可視性差、実行/停止/仮想ドライバー、ERROR_MORE_DATA多ページ、QueryServiceConfig2失敗、WOW64ファイルシステムリダイレクト、Windows 11 ARM64、署名失効/カタログ、DLL実行ホストを検証する。
3. MULTI_SZ依存の名前/グループ種別の詳細取得は省略（件数のみ）。SetupAPI相関は別スコープ。Kernelドライバー登録が無い場合、管理権限なしでは絶対件数を保証できない。
4. WinVerifyTrustの同期待ちハードタイムアウト、ファイル同一性固定と親ディレクトリ差替え対策を検討する。SCM照会時に状態が変わる競合も残る。
5. 将来のP5 typed APIにはDriverInventoryEvidenceV1 JSONアダプターを追加する。status/coverageの完全性、indicatorsの強さ、署名の確かさを別々に取り扱う。P5本体・共通schemaへの変更は行わない。
