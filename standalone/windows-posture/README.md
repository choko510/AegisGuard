# windows-posture（独立した読み取り専用診断CLI）

AegisGuard本体から独立したRustパッケージです。Windows 11で **Secure Boot / TPM 2.0 / VBS / HVCI（メモリ整合性）/ OSボリュームのBitLocker保護**を照会します。Defender、ASR、Firewall、GPO、レジストリ、サービスは変更しません。外部送信・昇格・再起動も行いません。

> **注意:** これは初期MVPです。診断結果が「enabled」であっても端末の安全を保証しません。Windows 11実機での成功・権限・性能・誤判定は未検証です。

## 起動

Rust 1.85以上、Windows 11 x64とWindows PowerShell 5.1を想定します。

~~~powershell
cd standalone/windows-posture
cargo run --locked -- audit --format json
cargo run --locked -- inspect-fixture fixtures/enabled.json
cargo run --locked -- inspect-fixture fixtures/contradiction.json
~~~

生成物は単独実行ファイルの `windows-posture.exe` です。AegisGuard本体のCargo workspace、型、ライブラリ、CLIは参照しません。Linux/macOSでの `audit` は照会せず `status: unavailable` / `windows_only` を返します。Linuxでも `inspect-fixture` は使用できます。

Secure Boot の `Confirm-SecureBootUEFI` は管理者が必要です。TPMの `Win32_Tpm.IsReady` もローカル管理者限定です。WMIアクセス権は端末・ポリシー・エディション・企業管理の状態に依存します。**CLIは自動で昇格しません。** 非管理者・ポリシー制限下の照会不能は有効/無効と区別されます。

## JSON契約 v1

成功/部分成功/失敗のいずれでも、原則として標準出力に **1個のJSONオブジェクト**を出します。エラー説明は固定コードのみで、パス・回復キー・WMI生出力・コマンドエラー全文を出しません。

~~~json
{
  "schema_version": 1,
  "module": "windows-posture",
  "generated_at_unix_ms": 1793880000000,
  "status": "complete",
  "entries": [
    {"id":"secure_boot","availability":"supported","state":"enabled","source":"Confirm-SecureBootUEFI","checked_at":1793880000000,"warnings":[]},
    {"id":"tpm_2_0","availability":"supported","state":"enabled","source":"Win32_Tpm.SpecVersion;IsReady","checked_at":1793880000000,"warnings":[]},
    {"id":"vbs","availability":"supported","state":"enabled","source":"Win32_DeviceGuard.VirtualizationBasedSecurityStatus","checked_at":1793880000000,"warnings":[]},
    {"id":"hvci","availability":"supported","state":"enabled","source":"Win32_DeviceGuard.SecurityServicesRunning","checked_at":1793880000000,"warnings":[]},
    {"id":"bitlocker_os_volume","availability":"supported","state":"enabled","source":"Win32_EncryptableVolume.ProtectionStatus;ConversionStatus","checked_at":1793880000000,"warnings":[]}
  ],
  "warnings": [],
  "coverage": {"expected":5,"assessed":5,"unknown":0,"permission_denied":0}
}
~~~

- `availability`: `supported`（照会APIが状態を返した。ハードウェア機能の完全な互換性認定ではない）、`not_applicable`（BIOS/TPM非対応等の確認済みケース）、`permission_denied`、`unknown`。
- `state`: `enabled` / `disabled` / `not_applicable` / `permission_denied` / `unknown`。ここでの `enabled` は**実際の稼働/保護状態**を指し、単なる設定レジストリ値とは異なります。
- `status`: `complete`（5項目すべて評価、非対応の項目も含む）/ `partial`（一部評価）/ `permission_denied`（評価ゼロで権限拒否あり）/ `unavailable`（評価ゼロ）/ `error`（入力・内部契約違反）。
- 終了コード：`0` complete、`1` partial/unavailable/permission_denied、`2` errorまたは引数不正。`complete` や `disabled` はマルウェアの有無を示しません。

## セキュリティ・制約

- OS照会は組み込みの固定PowerShellスクリプトのみ。入力したfixtureをコマンドに挿入しません。PowerShell 4プローブは各10秒の独立タイムアウト、標準出力は各8KiB以内、失敗時はunknown/permission_denied（最大約40秒）。
- BitLockerは `Win32_EncryptableVolume` の `VolumeType=0`（OSボリューム）について `ProtectionStatus` と `ConversionStatus` の**プロパティだけ**を照会します。回復パスワード、キー保護方法、ID、マウントパス、暗号鍵、TPM OwnerAuthは要求・保存・表示しません。0件/複数件/矛盾/部分暗号化は保護済みと判定しません。
- `Win32_DeviceGuard` の VBS=1（構成済みだが非稼働）はenabled扱いしません。`SecurityServicesRunning`に2が無ければHVCIは稼働中とみなしません。設定済みで非稼働なら警告します。
- TPM 2.0の判別には `Win32_Tpm.SpecVersion`、準備状態には管理者専用の読み取りメソッド `IsReady` を使います。生のバージョン文字列や認証情報は出力しません。
- fixtureは最大64KiB、1ファイルのみ、最終コンポーネントのシンボリックリンク拒否、固定フィールド以外を拒否、サービス配列は最大16件。入力そのものはログに出しません。親ディレクトリのリンク入れ替え等の完全な競合対策は未実装です。
- Windows Home/Pro/Enterprise/Education差は**観測値に優先しません**。VM、リモートセッション、UEFI非対応、管理ポリシー、CIM provider欠落ではunknownやnot_applicableになり得ます。Windowsの実機挙動は未検証です。
- UACおよびLSA保護はランタイムの裏付けが不足するため**未実装**。将来実装ではポリシー値と現在の有効性を区別します。OS全ボリューム、暗号化進捗率、保護キー情報も収集しません。

## fixtureスキーマ

`inspect-fixture` はOS/APIの代わりに**合成済みの照会結果**を入力します。生のPowerShellログや機器情報の取り込み機能ではありません。

~~~json
{
  "edition":"home",
  "secure_boot":{"status":"ok","enabled":false},
  "tpm":{"status":"ok","present":true,"ready":false,"spec_2_0":true},
  "device_guard":{"status":"ok","vbs_status":1,"running_services":[],"configured_services":[2]},
  "bitlocker":{"status":"ok","os_volume_count":1,"protection":0,"conversion":1}
}
~~~

各probeの `status` は `ok` / `unsupported` / `permission_denied` / `timeout` / `error`。プローブ自体が無い場合は未収集であり、安全とはみなしません。未知のフィールド（例：`recovery_key`）は拒否し、その値は出力しません。エディション値はfixture向けの合成ラベルで、診断時にはOSのエディションを取得しません。

## 将来のP5 typed APIとの接続

本モジュールの `PostureControl` 相当のJSON v1をAegisGuardのread-side adapterで解釈する案です。`schema_version`を検査し、`id`ごとの `availability` / `state` / `source` / `checked_at` / `warnings` をtyped APIへマッピングします。`coverage`と`status`を維持して、観測できなかった項目を「安全」と見なさないようにします。**本PRでは本体への統合・ルートCargo/CI変更はしません。**

根拠と不採用案は [RESEARCH.md](RESEARCH.md) を参照してください。
