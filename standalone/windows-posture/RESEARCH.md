# Windows防御状態診断：一次資料調査・設計判断

- 調査日：**2026-11-05**（Microsoft公式ページを照合）
- 対象：Windows 11 / Rust 1.85 / Windows PowerShell 5.1 / CIM (WMI)
- スコープ：Secure Boot、TPM 2.0、VBS、HVCI、BitLockerのOSボリューム
- 実機検証：**未実施**。本記録のAPI仕様は一次資料による確認であり、Windows 11での実動作の裏付けではない。
- 実装：`src/windows.rs`の固定スクリプトで状態照会、`src/lib.rs`で型制限・矛盾検証・保守的分類、`src/runner.rs`で時間/出力制限。

## 1. Secure Boot

**採用：** PowerShell SecureBootモジュールの `Confirm-SecureBootUEFI`。戻り値は `True`（有効）/ `False`（対応UEFIで無効）。公式仕様でUEFI/Secure Boot非対応は `Cmdlet not supported on this platform`、非管理者はアクセス拒否と明記。したがって未昇格での失敗を無効扱いせず、`permission_denied`または`unknown`とする。既知の非対応エラーのみ`not_applicable`へ変換する。日本語OS上で判定できない未対応エラーは保守的にunknownへ倒す。

- Microsoft Learn: https://learn.microsoft.com/en-us/powershell/module/secureboot/confirm-securebootuefi?view=windowsserver2025-ps
- 関連API: `Get-SecureBootUEFI`（UEFI変数が必要なケース向け） https://learn.microsoft.com/en-us/powershell/module/secureboot/get-securebootuefi

**不採用：** UEFI変数 `PK`/`KEK`/`DB` の読み出し。Secure Boot有効性の判断に不要で、出力サイズと機器固有データの範囲が増える。GUI `msinfo32` の文字列スクレイピングもロケール依存。UEFI非対応と実行権限不足の区別は実機で再検証が必要。

## 2. TPM 2.0

**採用：** `root\CIMV2\Security\MicrosoftTpm` の `Win32_Tpm.SpecVersion`（TPM仕様バージョン）と、`Win32_Tpm.IsReady()`（使用可能な状態かどうかの読取専用WMIメソッド）。`SpecVersion` の先頭バージョン成分が2.0のときだけTPM 2.0と判定し、`IsReady` の `ReturnValue=0` かつ `IsReady=true` を有効とする。準備状態が取得できない場合はunknown。TPM非存在が確認できた場合、またはバージョン1.x確定時はnot_applicable。矛盾するpresent/ready/specはunknown。

- Win32_Tpm class: https://learn.microsoft.com/en-us/windows/win32/secprov/win32-tpm
- IsReady method（**local administrators only**）: https://learn.microsoft.com/en-us/windows/win32/secprov/win32-tpm-isready
- IsEnabled method（別概念）: https://learn.microsoft.com/en-us/windows/win32/secprov/isenabled-win32-tpm

**不採用：** `Get-Tpm` は扱いやすいが、返す `TpmObject` に**OwnerAuth認証情報**を含む可能性がある。不要なシークレットを保持しない原則から呼び出し自体を回避。 https://learn.microsoft.com/en-us/powershell/module/trustedplatformmodule/get-tpm?view=windowsserver2025-ps

**留意：** `IsReady` は管理者専用と公式資料に記載。UAC制限下でreadyを取得できず、versionが読めても結果はpermission_denied/unknownとなり得る。TPMが無い場合のWMI provider/instanceの返り方、fTPM/離散TPM/仮想TPMの差は実機未確認。TPM 2.0が存在してもBitLockerが有効とは限らない。

## 3. VBS / HVCI / メモリ整合性

**採用：** `root\Microsoft\Windows\DeviceGuard\Win32_DeviceGuard` の
`VirtualizationBasedSecurityStatus` = 0（無効）/1（有効に構成されたが未稼働）/2（有効・稼働）、
`SecurityServicesRunning`（2が含まれればHVCI稼働）、`SecurityServicesConfigured`（2が含まれても稼働の証拠ではない）。

- Microsoft Learn「Enable memory integrity」/ 「Validate enabled VBS and memory integrity features」: https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity
- Credential Guard検証での同じWMIクラス利用: https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure

**判定：** 実行中でないVBS=1は状態をdisabled＋`configured_but_not_running`警告。HVCIは `SecurityServicesRunning`に2があり、かつVBS=2のときに限りenabled。VBS=0/1なのにHVCI running=2、Runningに0と他値が共存、サービス値の重複は矛盾としてunknown。Runningが取得できない場合もunknown。WMI provider取得成功の`availability=supported`は照会が可能だった意味で、UEFI/HW要件の保証ではない。

**不採用：** `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\...` の設定値のみを利用する方法は「構成」と「実稼働」を混同する。CSPの設定値や`msinfo32`の表示の取得は監査対象端末の管理方法・ロケールで異なる。HVCIが稼働しない場合（ドライバ相性、仮想化非対応など）の詳細原因はMVPでは追跡しない。

## 4. BitLocker / デバイス暗号化

**採用：** WMI `root\CIMV2\Security\MicrosoftVolumeEncryption\Win32_EncryptableVolume` を**プロパティ照会のみ**で使用。`VolumeType=0`（OSボリューム）を1件だけ採用し、`ProtectionStatus`（0=保護なし、1=保護あり、2=不明）と`ConversionStatus`（0=完全復号、1=完全暗号化、2〜5=処理中/一時停止）を組み合わせる。

**判定：** `ProtectionStatus=1`かつ`ConversionStatus=1`だけがenabled。`ProtectionStatus=0`は暗号化されていても保護停止・一時停止の可能性があるのでdisabledと警告。異なる状態が矛盾するとき、0件/複数OSボリューム、status=2、プロパティがない場合はunknown。**ボリュームの非表示/未検査を無暗号と推定しない。**

- Class and properties: https://learn.microsoft.com/en-us/windows/win32/secprov/win32-encryptablevolume
- GetProtectionStatus（読取専用、より新しい状態の取得に有用）: https://learn.microsoft.com/en-us/windows/win32/secprov/getprotectionstatus-win32-encryptablevolume
- GetConversionStatus（読取専用、より新しい状態の取得に有用）: https://learn.microsoft.com/en-us/windows/win32/secprov/getconversionstatus-win32-encryptablevolume

**重要な制約：** プロパティはインスタンス化時点の値のため、暗号化が進む最中の鮮度保証はない。Microsoftは最新状態には上記2メソッドを推奨している。MVPではシークレットを含まないプロパティだけに絞っている。次版で読み取りメソッドを加える場合もエラー・競合・タイムアウトと結果を検証する。デバイス暗号化（Home）/ BitLocker UI（Pro以上）の違いをハードコードせず、実際のプロバイダの状態に従う。

**不採用：** `Get-BitLockerVolume` や `manage-bde -status` の一括出力、回復キー/`GetKeyProtectors`/`GetKeyProtectorNumericalPassword`などの取得。前者は余計なフィールドやロケール依存があり、後者はシークレット漏出リスクがある。ディスクの識別子・ドライブレターも出力しない。非システム固定ディスクやリムーバブルボリュームは対象外。

## 5. UAC / LSA

**初期実装しない。** 公式資料にある `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` の値はLSA保護を要求する設定だが、UEFI lockや起動後の実際のPPL状態の完全な裏付けにならない。UACの `EnableLUA` もポリシー設定値であり実稼働・プロセストークン昇格との混同がある。read-onlyで確実なランタイム判定が成立するまで「enabled」と断定しない。

- LSA保護の公式設定説明: https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
- Device Security UI（概要）: https://support.microsoft.com/ja-jp/windows/security/windows-security/device-security-in-the-windows-security-app

## 6. 権限・端末差・失敗の扱い

- **権限**：SecureBoot cmdletとTPM IsReadyは管理者権限が必要。WMI namespace ACL、UAC、CIM provider、Enterprise GPO/MDM、PowerShell実行制限で失敗する。昇格しない。アクセス拒否はpermission_denied、失敗原因が確定しない場合はunknown。
- **エディション**：Home/Pro/Enterprise/Educationの差だけでunsupportedを確定しない。Homeでデバイス暗号化が利用可能な機種が存在するため、WMI結果を優先。
- **環境差**：VM/リモート接続/仮想TPM/BIOS起動/UEFI Secure Boot非対応/32-bit powershell WOW64リダイレクトは実機未確認。VMでSecure Bootをオフにしても物理機の構成を証明しない。
- **プライバシー**：固定スクリプトのみ、出力項目を指定、WMI/PowerShell生エラー出力は捨てる、外部通信なし。Windowsプローブは各10秒、標準出力各8KiB。想定最大4件・約40秒（起動/回収のオーバーヘッドは別）。fixtureは64KiB/サービス配列16件。予期しない値は安全扱いしない。
- **誤判定**：単一スナップショットとCIM providerのキャッシュ、BIOS言語差、管理者不足、起動直後のVBS遷移、BitLocker保護一時停止などにより結果が不確実。未知理由をwarningsに記録する。プローブ取得失敗を「disabled」にマッピングしない。

## 7. 依存関係・ライセンス・ソース調査

Rust標準ライブラリに加え、JSONの構文・型の安全な取り扱いのため `serde_json = 1.0.154` のみを直接依存として採用。transitive: serde, serde_core, itoa, memchr, zmij（パッケージ固定は専用Cargo.lock）。serde/serde_json はMIT OR Apache-2.0ライセンス。MicrosoftのAPI仕様を参照して独自の短いPowerShell照会を記述。外部サンプルコード、GPL/AGPLコード、Defender実装をコピーしない。

- serde_json (source/LICENSE): https://github.com/serde-rs/json
- serde (source/LICENSE): https://github.com/serde-rs/serde
- Rust standard library: https://github.com/rust-lang/rust
- Microsoft `Get-CimInstance`パラメータ/timeout: https://learn.microsoft.com/en-us/powershell/module/cimcmdlets/get-ciminstance?view=powershell-5.1
- `Cargo.lock`チェックサムの基準は同リポジトリ最新mainのルートlockfile（**ファイルは変更していない**）。独立Cargo実行でlockfileの整合を再検証すること。

## 8. 検証実績と未解決

- 合成fixtureとRust unit/integration testsを用意：有効、無効、権限拒否、非対応、欠損、矛盾、重複、エディション差、匿名化、サイズ上限、CLI不正入力、Unix実行タイムアウト。
- **この環境にはcargo/rustc/rustfmtがなく、ネットワークからのインストールも不可**：`cargo fmt --all -- --check` / `cargo clippy --all-targets -- -D warnings` / `cargo test` / `cargo build --release`は**未実行・未確認**。ソースのGitHub登録は実施。CIに本パッケージの追加はしていない（共通ルールで禁止）。
- Windows 11実機・通常ユーザー/管理者/Domain・MDM管理下・Home/Pro・UEFI/Legacy・fTPM/仮想TPM・BitLocker暗号化途中・VM/RDP、32-bit/64-bitの照会と所要時間は**未検証**。
- 今後：Windows 11テスト環境で各プローブの出力型/昇格失敗/ロケールを確認。BitLocker最新状態の読み取りメソッド導入の是非。TPM IsReady権限不足の詳細判定。Cargo lock/fmt/clippy/testを実際に実行し、P5 typed read-side adapterへ統合する専用PRを後日検討。
