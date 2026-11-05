# software-audit — 独立Rust CLI

Windows 11のUninstallレジストリを**読み取り専用**で棚卸しし、人手で確認したローカルのアドバイザリJSONと**オフライン**で照合するMVPです。脆弱性の確定判定器ではありません。AegisGuard本体への依存・書き込み・OS設定変更・自動通信はありません。

## 実行例

~~~powershell
cd standalone/software-audit
cargo build --release --locked
.\target\release\software-audit.exe inventory --format json > inventory.json
.\target\release\software-audit.exe inspect-fixture .\fixtures\registry-fixture.json
.\target\release\software-audit.exe match --inventory inventory.json --advisories .\fixtures\local-advisories.json

cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
~~~

一般ユーザーで走らせ、管理者昇格はしません。非Windows環境のinventoryはstatus=unavailableとなり、fixtureとmatchのみオフラインで使用できます。Windows 11実機の動作は未検証です。

## JSON v1契約

すべての出力に schema_version=1、module=software-audit、generated_at_unix_ms、status、entries、warnings、coverage が付きます。statusは complete / partial / unavailable / permission_denied / error です。complete は**対象のHKLM/HKCU × 32/64ビューの読み取り範囲内だけ**の完了を意味し、端末の全ソフトや全脆弱性を網羅しません。

inventoryおよびinspect-fixtureのentriesはSoftwareEntry（name, version, publisher, architecture, edition, install_scope, sources）です。matchのentriesはAdvisoryMatch（software_name, installed_version, advisory_id, classification, confidence, evidence, source_checked_at_unix_ms, advisory_url）です。classificationはcandidate/unknownだけで、confirmed/affectedなどの確定出力はしません。

出力JSONの例（合成台帳、架空の製品）:

~~~json
{
  "schema_version": 1,
  "module": "software-audit",
  "generated_at_unix_ms": 1793900000000,
  "status": "complete",
  "entries": [{
    "name": "Example Widget",
    "version": "1.9",
    "publisher": "Example Labs",
    "architecture": null,
    "edition": null,
    "install_scope": "machine",
    "sources": ["hklm64"]
  }],
  "warnings": ["msix_and_other_package_managers_not_covered"],
  "coverage": {
    "scope": "uninstall_registry_only; current_user_and_machine; msix_not_included",
    "sources": [
      {"id":"hklm64","status":"complete","seen":1},
      {"id":"hklm32","status":"complete","seen":0},
      {"id":"hkcu64","status":"complete","seen":0},
      {"id":"hkcu32","status":"complete","seen":0}
    ],
    "skipped":0,"truncated":false,"evaluated":1
  }
}
~~~

合成アドバイザリとの照合出力例（実在CVEではない）:

~~~json
{
  "software_name":"Example Widget",
  "installed_version":"1.9",
  "advisory_id":"CVE-2026-12345",
  "classification":"unknown",
  "confidence":"low",
  "evidence":[
    {"kind":"product_name_exact_or_explicit_alias","detail":"Example Widget"},
    {"kind":"publisher_exact_or_explicit_alias","detail":"Example Labs"},
    {"kind":"architecture_unknown","detail":"constraint_not_evaluable"}
  ],
  "source_checked_at_unix_ms":1793900000000,
  "advisory_url":"https://example.org/advisory/example"
}
~~~

## オフライン照合の仕様

fixtures/local-advisories.jsonにスキーマ例があります。必須はschema_version、source_checked_at_unix_ms、advisories。個々にCVE形式のID、vendor/product、明示的なalias（任意）、version_ranges（start_inclusive/end_exclusive）、unaffected_versions（任意）、architectures/editions（任意）、HTTPSのsource_urlが必要です。**製品名だけでの脆弱性確定はしません**。出版社名の完全一致か明示aliasの一致を必要とし、CPEによる自動補完はしません。

バージョンは1〜4個の数値セグメントのみ比較し、1.9は1.10未満です。不明な版、プレリリース表記、発行者不明、arch/edition不明など条件が解決できない場合はunknownです。30日超/未来5分超のアドバイザリもunknownに格下げします。版範囲から外れたものや明示した非該当ビルドは候補になりませんが、ベンダーのバックポート、ESU、KB等の有無は検証していません。取得時刻やURLは利用者が入力した自己申告であり、配布物の署名検証とは異なります。

Uninstallレジストリのビューはバイナリのarchを示すものではありません。実機のarchitecture/editionはnullです。MSIX/ストアアプリ、ポータブルソフト、winget/他管理器の履歴、他ユーザーのHKCUは対象外で、coverageとwarningsに漏れを記録します。

## 制限・プライバシー

入力上限はfixture/inventory 1MiB、advisory 2MiB、アプリ2048件、advisory1024件、match結果1024件。各ビュー最大4096キー。照合は2秒の**ソフト上限**で、Windows同期レジストリ読み取りを強制中断するハードタイムアウトではありません。不正・権限不足・上限時はpartial等を出し、「0件だから安全」とは扱いません。入力はJSONの厳密な型検査と文字列長制限を通します。

読取値はDisplayName、DisplayVersion、Publisherだけです。UninstallString/InstallLocation/端末識別子/ブラウザー情報を収集せず、ネットワークアクセスも実装しません。台帳出力には利用アプリ情報が含まれるため、標準出力をリダイレクトする際のファイル権限・共有は利用者が管理してください。ソフトの実行・変更・削除・インストールは一切しません。

終了コード0はそのコマンドの対象範囲でcomplete、3はエラーまたは未完了の結果です。エラー時もstatus=errorのJSONを標準出力します。

## P5 typed APIへ統合する際の注意

本PRでは本体への統合作業を行いません。将来はInventoryReportV1 / AdvisoryMatchV1を上限付きJSONデシリアライザで取り込み、coverage/statusとevidenceを落とさず読み取り専用の型付きAPIに写像します。candidateを確定脆弱性/マルウェア判定へ昇格させません。実装したAPIと未対応項目、公式ソース、ライセンスはRESEARCH.mdに記載します。
