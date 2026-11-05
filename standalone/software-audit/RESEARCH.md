# installed-software / CVE candidate matching 技術調査

確認日: **2026-11-06 JST**。Windows 11実機は **未確認**。一次情報の記述と実機検証を区別します。

## Windows API調査と採否

| 項目 | 一次情報 | 判断 |
| --- | --- | --- |
| Uninstall | https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key | 採用。DisplayName、DisplayVersion、PublisherをHKLM/HKCUのUninstall配下から読み、MSIのみへの限定はしない。ただしソフトウェアの全件を保証しない |
| WOW64 registry | https://learn.microsoft.com/en-us/windows/win32/winprog64/accessing-an-alternate-registry-view ; https://learn.microsoft.com/en-us/windows/desktop/sysinfo/32-bit-and-64-bit-application-data-in-the-registry | 採用。KEY_WOW64_64KEY=0x0100 / KEY_WOW64_32KEY=0x0200で2パス。Wow6432Node文字列を直接指定しない。HKCUの共有ビューでは重複あり |
| Open registry | https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexw | 採用。RegOpenKeyExWをKEY_READまたはKEY_QUERY_VALUEに限定。レジストリ書込みAPIなし、アクセス拒否を明示 |
| Enumerate keys | https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumkeyexw | 採用。RegEnumKeyExWをUTF16バッファで呼び、最大4096件/ビュー。途中のレジストリ更新ではスナップショット一貫性を保証できない |
| Query value | https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvalueexw ; https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types | 採用。RegQueryValueExWで最大4KiB、REG_SZだけ処理。2回読み出しの間のサイズ/型変化はpartial。NULL終端欠如・壊れたUTF16も考慮。REG_EXPAND_SZは展開しない |
| Close key | https://learn.microsoft.com/en-us/windows/desktop/api/winreg/nf-winreg-regclosekey | 採用。RegCloseKeyをRAII Dropで呼ぶ |
| WMI Win32_Product | https://learn.microsoft.com/en-us/troubleshoot/windows-server/admin-development/windows-installer-reconfigured-all-applications | **不採用**。Win32_Product問合せはMSI製品整合性検査・自動修復/再構成等の副作用がある |
| MSIX PackageManager | https://learn.microsoft.com/en-us/uwp/api/windows.management.deployment.packagemanager.findpackagesforuser | 将来。WinRT初期化と権限/ユーザーごとの扱いが必要 |
| Get-AppxPackage | https://learn.microsoft.com/en-us/powershell/module/appx/get-appxpackage | 不採用。外部PowerShell起動と他ユーザー照会権限が必要。今回のMVPにはMSIXを含めない |

HKCUは実行ユーザーのHiveだけであり、全ユーザーの台帳ではありません。WOW64アーキテクチャのビューは実際のインストール済アプリのCPUアーキテクチャの証拠にはなりません。RegOpen/RegEnum/RegQueryの生データは信頼可能なベンダー署名を提供せず、改竄された登録値にも注意が必要です。

## CPE / NVD / CVE / ベンダーアドバイザリ

- NVD CPE FAQ: https://nvd.nist.gov/general/faq-sections/cpe-faqs
- NVD Vulnerability Detail / CPE applicability: https://nvd.nist.gov/vuln/Vulnerability-Detail-Pages
- NVD Match Criteria API / incremental updates: https://nvd.nist.gov/developers/products

CPE名とCPE Match Criteriaは異なり、版範囲・ワイルドカード・製品共存条件を含みます。CVEの同一製品名一致だけでは実際のビルドの脆弱性を確定できません。vendor公式アドバイザリ、正確な版条件、修正済みビルド、バックポート、ESU/KB、editions、実際の構成条件を照合する必要があります。**NVDの生JSON/CPE複合適用式は今回の実装では評価しません**。代わりに人手で信頼できるURLと条件を確認して作成したローカルの限定リストだけを扱います。

採用した条件: vendor + productの厳密な名前一致（明示aliasのみ許可）、版の数値セグメント比較と境界、任意の除外ビルド/arch/edition、アドバイザリ作成時刻。確信が欠ければunknown、条件が明確に外れる場合は照合候補なし。最大信頼度はmedium/candidate（**affected確定を返さない**）。source_url・source_checked_atは利用者入力にすぎず、電子署名や更新確認ではない。期限超過30日・未来時刻5分超はunknownへ下げる。この30日は本MVPの運用方針でありNVDが保証する鮮度ではない。

## ネットワーク・キャッシュ・性能・個人情報

ネットワーク機能を追加しない判断により、NVD API key・rate limit・取得失敗時のリトライ・未認証キャッシュのリスクを実装から除外した。将来オンライン更新が必要なら明示オプトイン、固定HTTPS宛先、NVDページング・API rate limit遵守、取得サイズ/件数/時間上限、更新日/ETag、署名などの検証、2世代ローカルキャッシュ、期限切れのunknown化を別レビューする。**端末のインストール済みソフト一覧は外部送信しない**。

1MiB/2MiB入力上限、2048アプリ、1024 advisories、1024 matches、4096キー/ビュー。マッチ処理2秒は定期的な経過時間チェックのみであり強制停止ではない。WindowsレジストリAPIは同期でありハードタイムアウトではない。OSはWindows 11 x64を想定し、ARM64、ユーザー切替、ACL拒否、レジストリが走査中に変更された場合、現物版との差異、実際の処理時間を未検証とする。

読み取るレジストリ値は名前・版・発行者に限定。個人パス/シリアル/UninstallString/実行コマンドは読まず、内部のレジストリキー名も出力しない。ただし台帳自体が利用端末の機微情報なので、保存・外部共有は利用者の判断が必要。ファイル書込みはCLI内部では行わない。

## Rust依存元・ライセンス確認

- Rust標準ライブラリとWindows Advapi32の公開API。GPL/AGPLコードの転用なし。
- serde 1.0.229: https://github.com/serde-rs/serde , MIT OR Apache-2.0。Cargo.tomlとderive実装・テスト構成を確認。
- serde_json 1.0.154: https://github.com/serde-rs/json , MIT OR Apache-2.0。Cargo.toml、src、testsを確認。
- 単独Cargo.toml/Cargo.lockを配置。ロックのcrate解決バージョン/チェックサムは先行して作成されたstandalone/windows-posture/Cargo.lockの構成から採用した。**Cargoで再生成・整合性を実行確認できていない**。
- この単独crateはMIT OR Apache-2.0を宣言するが、現時点でリポジトリ上位の統一LICENSE未確認。採用時に所有者の判断が必要。

## テストと未達

fixturesは無害・架空で実在するCVE／ベンダーの脆弱性を主張しない。テストコードは数値比較（1.9 < 1.10）、範囲境界、類似名/出版社相違、明示alias、arch/edition条件、修正・バックポート版、unknownバージョン、欠損版/出版社、重複ビュー、古い/未来のadvisory、permission_denied、欠損ソース、悪意ある過大JSON、CPEだけの偽一致、負例5件への誤陽性ゼロを検証するために用意した。

**実施した検査**: 入力fixtureのJSONパースとCargo.toml/Cargo.lockのTOMLパース（Python標準ライブラリによる構文検査）。**実行できなかった**: cargo fmt --all -- --check、cargo clippy --all-targets -- -D warnings、cargo test、cargo build --release/--locked。この環境にはcargoとrustcが無く、外部からのツールチェーン取得もできなかった。実装がコンパイル・テスト合格したとは主張しない。

**Windows 11実機未確認**: FFIリンク、レジストリ実データ、一般ユーザー権限/ACL、非WindowsとWindows間の出力整合、実データ上のFalse Positive/Negative、性能、同期APIブロック、WOW64/ARM64特性。MSIX・winget・NVD API自動取得・CPE複合式・vendorバックポート追跡・電子署名検証・P5本体統合は未実装。本PRは単独crate内のみ変更し、本体やP5〜P10コードには触れない。
