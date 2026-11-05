# driver-inventory — Windowsドライバー・サービス棚卸し（独立CLI）

Windows Service Control Manager (SCM) が**現在の権限で列挙できる**登録済みサービス・ドライバーを読み取り専用で収集します。AegisGuard本体と依存関係はありません。**不審点は調査の手掛かりであり、悪性確定ではありません。**

## ビルドと実行

Rust 1.85以降。このディレクトリで実行します（ルートワークスペースとは独立）。

~~~sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
~~~

~~~powershell
.\target\release\driver-inventory.exe list --format json
.\target\release\driver-inventory.exe list --drivers-only --format json
.\target\release\driver-inventory.exe list --format json --verify-signatures
.\target\release\driver-inventory.exe list --format json --show-paths
.\target\release\driver-inventory.exe inspect-fixture fixtures\sample.json
~~~

- **list** はWindowsのみ。非Windowsでは status=unavailable、終了コード1。
- **inspect-fixture** はWindows以外でも動作し、サービス/ファイル/レジストリを一切照会しません。
- **--verify-signatures** は任意。既定は署名検証なし。最大256ファイルの埋込み署名のみをキャッシュ限定・UIなしで確認します。カタログ署名・オンライン失効情報は未検証です。
- **--show-paths** 指定時だけWindowsディレクトリ外のフルパスを表示。Windowsディレクトリ配下は既定で表示。コマンドライン引数は出力しません。
- 一般ユーザーでも列挙できる場合があります。ただしサービスACLによって項目自体が省略され、SERVICE_QUERY_CONFIG不許可なら個別項目は部分的になります。自動昇格しません。
- **complete** は「見えているSCMエントリの列挙が終了した」という意味で、全件監査済みではありません。warnings に scm_permission_filtered_possible を常時付けます。

## JSON v1出力（抜粋例）

~~~json
{
  "schema_version": 1,
  "module": "driver-inventory",
  "generated_at_unix_ms": 1793890000000,
  "status": "complete",
  "entries": [
    {
      "service_name": "ExampleDriver",
      "kind": "kernel_driver",
      "service_type_raw": 1,
      "state": "running",
      "start_type": "system",
      "delayed_auto_start": null,
      "dependency_count": 0,
      "binary": {
        "normalized_path": "C:\\Windows\\System32\\drivers\\example.sys",
        "path_resolution": "resolved",
        "file_state": "exists",
        "signature": "not_checked",
        "signature_scope": "embedded_only",
        "source": "scm_query_service_config"
      },
      "indicators": [],
      "config_error": null,
      "source": "windows_scm"
    }
  ],
  "warnings": ["scm_permission_filtered_possible"],
  "coverage": {
    "enumerated": 1,
    "reported": 1,
    "pages": 1,
    "max_entries": 4096,
    "scope": "visible_scm_entries",
    "drivers_only": false,
    "complete_for_visible_services": true,
    "permission_filtered_possible": true
  }
}
~~~

statusは complete / partial / unavailable / permission_denied / error。部分成功や失敗では終了コード1。missing や署名 invalid は調査対象の目安であり悪性判定ではありません。署名不明と未検証を区別します。file_stateとstatusは独立しています。

kindは kernel_driver / file_system_driver / recognizer_driver / win32_own_process / win32_shared_process / unknown。stateは停止・稼働・遷移中。start_typeは boot / system / automatic / demand / disabled / unknown。delayed_auto_startは読み取れない場合 null。

## 上限と安全性

- SCM列挙: 最大4096件、32ページ、1ページ256KiB、列挙10秒のソフト上限。設定取得: 1サービス8KiB。UTF-16名前256要素、実行パス2048要素。fixture: 最大256KiB。
- ファイル確認と任意署名検証: 全体10秒の処理間判定。WinVerifyTrust等の**単独同期APIにハードタイムアウトなし**。性能実測未実施。
- \SystemRoot、%SystemRoot%、%windir%、System32相対、ローカル絶対パスのみ限定的正規化。他の環境変数・デバイス名前空間・曖昧な未引用パスは推測せずunknown。
- サービスの開始・停止・作成・削除、権限昇格、レジストリへの書込み、ドライバーのロード、メモリ読取り、BYOVD実行、外部ネットワーク送信、実行ファイル起動は行いません。
- OSによる暗黙のドライバーパス解決、親ディレクトリの再解析ポイント差替え、WOW64のリダイレクトを完全には再現しません。実ファイルの存在確認は最終要素のsymlinkを拒否します。
- SCMの依存配列（MULTI_SZ）は有界なパーサーで件数のみ数え、サービス名やグループ名は出力しません。SetupAPIのPnPデバイスやドライバーパッケージ一覧とは異なります。
- source はAPI上の取得元であり、信頼済みの出所ではありません。

## fixtureの形式とテスト

[fixtures/sample.json](fixtures/sample.json)を参照。schema_version=1、enumeration_status、services[]が基本。file_state・signature・config_errorは**合成された主張**であり、実ファイルに照会しません。引数付き image_path から実行ファイルの部分だけを抽出し、資格情報などを出力に混入させません。

## 将来のAegisGuard P5 typed APIへの接続

後日 DriverInventoryEvidenceV1 アダプターでJSONを読み、schema_version（互換性）、status（完全性）、coverage（可視範囲）、entries[].indicators（調査対象）を独立した軸として取り込みます。file_state=missing をmaliciousと解釈しません。このPRでは本体APIやルートCargo、CIに触れません。

詳細は[RESEARCH.md](RESEARCH.md)を参照してください。
