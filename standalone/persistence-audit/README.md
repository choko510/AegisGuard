# persistence-audit — Windows永続化の読み取り専用監査

AegisGuard本体に依存しないRust CLIです。Windowsの自動起動・永続化設定を**観察するだけ**で、削除、書き換え、修復、実行、常駐、権限昇格、外部通信を行いません。Windows Defenderの代替ではありません。

## ビルドと使い方

このディレクトリを作業ディレクトリとして実行します。Rust 1.85以上とWindows PowerShell 5.1（Windows実環境スキャン時）が必要です。

~~~powershell
cd standalone\persistence-audit
cargo build --release --locked

# Run/RunOnce (HKCU/HKLM, 32/64bit)、Startup、Task Scheduler 2.0
.\target\release\persistence-audit.exe scan --format json --limit 500

# 永続WMIの一部クラスを追加
.\target\release\persistence-audit.exe scan --format json --include-wmi --limit 500

# 合成fixtureを読む（Linux/macOSでも利用可能）
cargo run --locked -- inspect-fixture tests/fixtures/synthetic.jsonl
~~~

scanはWindows以外でOSを読まず、status=unavailableのJSONを返します。inspect-fixtureは**1行1 JSONオブジェクトの収集fixture**を読み、Windowsに何も書き込みません。--include-wmiを付けるとWMIカバレッジも必須になります。--limitは1〜2000、既定500です。異常な引数やfixtureには終了コード2、部分成功や収集不可は1、完全な収集は0を返します。**終了コード0でも悪性がないという意味ではありません。**

### 継続追跡用の匿名ID（推奨）

登録名・タスク名を推測できる単純なSHA-256は使いません。安定IDが必要な場合、**同じ32バイトの秘密鍵を実行環境変数に設定**してください。CLIは鍵ファイルを作成・保存せず、標準出力に鍵を表示しません。

~~~powershell
# 32バイトのランダム鍵をPowerShell内で生成（表示しない）
$bytes = New-Object byte[] 32
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
$env:AEGISGUARD_PERSISTENCE_ID_KEY_B64 = [Convert]::ToBase64String($bytes)

.\target\release\persistence-audit.exe scan --format json --include-wmi
~~~

この鍵を新しく生成するたびIDが変わります。継続比較する場合は利用者が安全な秘密管理手段で**同じ鍵を再設定**してください。鍵は端末の環境変数に存在する間、同権限のプロセス等に読み取られる可能性があります。共有・公開・コミットは禁止です。

IDはPowerShell側でセクション名と元の登録識別子からHMAC-SHA-256を計算し、`h1:` + 64桁の小文字16進数で出力します。秘密鍵未設定・不正・識別子欠損なら`entry_id=null`となり、連番の仮IDは作りません。これは読み取り専用監査のため、秘密鍵をOSに自動保存しない設計上の制約です。

## 収集対象

| ソース | 範囲 | データ保護 |
|---|---|---|
| レジストリ | HKCU/HKLM Run/RunOnce × Registry32/Registry64 | 値名、引数、ユーザー名を報告しない。値型が文字列以外なら実行先不明 |
| Startup | 現在ユーザーと共通Startup | .lnkはショートカットのTargetPathだけを参照。引数は読まない。ファイルは実行しない |
| タスク | Task Scheduler **2.0** COM のフォルダー（隠しタスク含む） | ExecAction.Pathのみ。Arguments、タスク名、XML、Principalを読まない。非Execアクションは実行先不明 |
| WMI（任意） | root/subscription の __EventFilter、CommandLineEventConsumer、__FilterToConsumerBinding | WQL、SID、テンプレート本文、名前を出力しない。テンプレートの有無と動的実行先の可能性を記録。結び付きの相関は未実装 |

他ユーザーのHKCU、任意のStartupコピー、ActiveScriptEventConsumer、任意名前空間のWMI、WMI関係の対応付け、サービス・ドライバー、ブラウザーCLSIDs、永続化の変更追跡は未対応です。レジストリやタスクの途中変更、非表示/ACL保護された項目、PowerShell/COM依存関係により漏れが生じます。権限拒否・列挙失敗はcoverageに残します。

## JSON API v2

schema_version, module, generated_at_unix_ms, status, entries, warnings, coverageを返します。statusはcomplete / partial / unavailable / permission_denied / error。completeは要求したソースの**列挙完了**だけを意味し、端末が安全であることは意味しません。

以下は説明用の省略JSONです（実際には全ソースのcoverageと日時が含まれます）。

~~~json
{
  "schema_version": 2,
  "module": "persistence-audit",
  "generated_at_unix_ms": 1793830000000,
  "status": "partial",
  "entries": [
    {
      "kind": "run",
      "scope": "user",
      "location_redacted": "registry_hkcu_64_run",
      "entry_id": "h1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "target_path": "C:\\Users\\<redacted>\\AppData\\Local\\Tool\\updater.exe",
      "signature_status": "not_checked",
      "evidence": ["read_only_enumeration", "signature_not_verified"],
      "assessment": {
        "state": "review",
        "priority": "medium",
        "reason": "user_writable_location_not_proof"
      }
    }
  ],
  "warnings": [{"source": "task_scheduler", "code": "permission_denied"}],
  "coverage": [
    {"source": "registry_hkcu_64_run", "status": "complete"},
    {"source": "task_scheduler", "status": "permission_denied"}
  ],
  "entry_ids_complete": true,
  "entries_truncated": false
}
~~~

v2の重要なフィールド:

- `entries[].entry_id`: 安全な32バイト鍵で作成したHMAC（登録名の平文は出力しない）。未設定では`null`。
- `entries[].location_redacted`: セクション名のみ。列挙順による連番を廃止。
- `entry_ids_complete`: 収集したエントリすべてに検証可能な書式のIDがある場合のみtrue。0件はfalse。
- `entries[].wmi_template`: WMI CommandLineEventConsumerの場合のみ`present`、`dynamic_target`、`target_source`を出力。値`possible`は動的ターゲットの**疑い**であり確定ではありません。
- WMIで`ExecutablePath`がNULLでもテンプレートの先頭が静的な実行ファイルなら`target_source=template_static`、動的・曖昧なら`template_unresolved`・`assessment.state=unknown`・`assessment.priority=medium`。テンプレートの本文は出力しません。
- v1とは互換性のない変更です。旧fixtureの`raw_target`は秘密流出回避のため**拒否**します。

entries[].assessment.stateの意味:

- observed: 一般的な配置の観測。**正規・安全とは判定していない**。
- review: ホスト型実行ファイルやユーザー書込み可能な場所など、人間による確認の優先度。
- unknown: 実行先未定義・パス評価不能・メタデータだけの場合。

signature_statusは常にnot_checked。Authenticode、署名チェーン、ファイルの実在、ACL、ハッシュ、最終実行日時を検証していません。正規アップデーターにもreviewが出ることがあります。感染の確率、悪意の断定には使わないでください。

## 安全性・資源上限

- 権限昇格を要求しません。読み取れない項目はpermission_denied / unavailableとします。
- 収集プロセスの時間制限は15秒、WMI有効時25秒。stdoutの許容量2 MiB、1行8 KiB、レコード最大10000、エントリ最大2000、PowerShellのタスクフォルダー最大128。
- fixtureファイルは最大2 MiB。コマンドの平文を含む従来のraw_target形式は拒否。任意フィールドは再出力せず、target_pathにもコマンド引数や未匿名化ユーザー名を許しません。
- タスクやWMIを表示する際、PowerShell内部でコマンド文字列から実行先だけを抽出・匿名化してからRustへ送ります（raw_targetは渡しません）。UNCやURL、引数が混ざる曖昧な値は実行先不明にします。
- **端末の設定は一切変更しません。** src/collector.ps1は固定スクリプトであり、レジストリのOpenSubKeyはread-only、COM Task Schedulerは列挙と読み取りだけ、WMIはGet-CimInstanceだけです。
- Windows PowerShell 5.1/COM利用に依存するため、PowerShell無効化やAppLocker/WDACにより実スキャンが不可能な場合があります。

## 検証

~~~bash
cd standalone/persistence-audit
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
~~~

本提出環境にはcargo / rustcがなく、これらのコマンドおよびWindows 11実機テストは**未実施**です。テストコードはsrc/lib.rsとtests/fixture_scan.rsに用意しています。LinuxからWindows APIの成功を確認したという主張はしません。

## 将来の本体統合

本体のP5型付きAPIに組み込む場合は、このモジュールをワークスペースへ直接混ぜる前に、PersistenceEntry相当のentries[]と、ソースごとのcoverage[] / warnings[]を持つ版付きDTOへ変換する**独立アダプター**を別PRで実装してください。ユーザーやパスの機密保護を維持し、observedを安全判定へ昇格させないでください。既存本体のsrc/ / Cargo / CIにはこのPRでは触れていません。

設計根拠・公式API・代替案・ライセンス・未確認事項は[RESEARCH.md](RESEARCH.md)を参照してください。
