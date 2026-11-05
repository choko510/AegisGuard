# AegisGuard Validation Lab — 独立CLI

実際のマルウェア・EICAR・DLL・スクリプトを**生成・実行しない**、完全オフラインの合成Sysmonイベント検証ラボです。AegisGuard本体のコード、Windowsのイベントログ、監査設定、Defender、レジストリ、ブラウザーは変更しません。

**注意:** 合成ケースの一致は相関ルールの回帰テストです。現実のマルウェア検出率や誤検知率を意味しません。イベント未観測や評価不能を安全と判断しない設計です。

## 実行

単独のCargoパッケージなのでルートworkspaceに参加しません。Rust 1.85以上を想定。

```powershell
cd standalone/validation-lab
cargo build --release --locked
cargo run --locked -- generate --out .\lab-corpus --seed 42 --profile all
cargo run --locked -- verify --dir .\lab-corpus
cargo run --locked -- summarize --expected .\lab-corpus\manifest.json --actual .\actual.jsonl

# 1ケースだけ生成することも可能
cargo run --locked -- generate --out .\one-case --seed 42 --profile k2f-analog-chain

cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
```

出力先は**存在してはいけません**。上書き・自動削除はしません。`--profile` は `all` または下記10ケースのいずれか、seedはu64です。

### 生成物

- `manifest.json`：schema 1、seed、case_id、各ファイルの相対パス・サイズ・SHA-256、期待ルール・event_refs・欠損情報。
- `<case_id>/events.jsonl`：既存 `src/events/mod.rs` の `EventEnvelope v1` に対応するJSONL。
- `<case_id>/event-000.xml` 等：Sysmonに似たイベントXML **テキスト**。Windows Event Logへ書き込まない。
- `<case_id>/inert.txt`：非実行型の無害なダミーファイル。
- `stale-ioc/expired-ioc.json`：ダミーの失効IOC。**現行AegisGuardのC2キャッシュと互換性なし**。

`schema_version/module/generated_at_unix_ms/status/entries/warnings/coverage` を持つJSONを標準出力に1行返します。`status` は `complete/partial/unavailable/permission_denied/error`。実際の権限・実装不明は安全判定しません。標準出力の生成時刻は実行ごとに異なりますが、**生成コーパス自体**は固定時刻・UTF-8・LFで保存し、同seedならバイト単位で同一です。

`verify` 出力例（時刻のみ省略）:

```json
{
  "schema_version":1,
  "module":"validation-lab",
  "status":"complete",
  "coverage":{"cases":10,"events":38},
  "warnings":[],
  "entries":{"verification":"hash_and_schema_only","malware_executed":false}
}
```

ケース: `browser-update`（普通のブラウザー更新）、`benign-com`（正規COM登録）、`k2f-analog-chain`（架空のDLL→COM→読込み）、`missing-log`（EventRecordIDギャップ）、`pid-reuse`（異なるProcessGuidでPID再利用）、`delayed-events`（順序逆転と重複）、`duplicate-event`（同一UID再配送）、`lookalike-path`（同名別パス）、`stale-ioc`（失効した文書用IOC）、`admin-script`（通常の管理スクリプトのコマンドラインを**実行せず**記述）。

`expected[].outcome` は `present / absent / unknown / planned` です。`present` は観測可能かつrule/evidence参照の一致が必要。`absent` は観測可能かつfindingがない場合のみ合格。`unknown`（未観測・ログ欠損・鮮度未確認）と `planned`（未実装）は別集計し、検出なし・安全に換算しません。

## AegisGuardの既存CLIとの手動接続

本ラボは本体を呼び出しません。AegisGuardの `events correlate --spool` に対してケース別の `events.jsonl` を渡し、出力される `Correlation {rules, findings, ruleset_version}` に `case_id` を付けて1行1ケースのJSONLを作成します。**複数ケースを1度に混合してはいけません**（未観測イベントIDの意味が変わります）。

以下はWindows PowerShellでの例です（AegisGuard本体を別途ビルド済みとする）。

```powershell
$root = Resolve-Path .\lab-corpus
$actual = Join-Path (Get-Location) "actual.jsonl"
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
if (Test-Path $actual) { throw "Refusing to overwrite existing report" }
foreach ($name in @("browser-update","benign-com","k2f-analog-chain","missing-log","pid-reuse","delayed-events","duplicate-event","lookalike-path","stale-ioc","admin-script")) {
    $spool = Join-Path (Join-Path $root $name) "events.jsonl"
    $raw = & ..\..\target\release\aegisguard.exe events correlate --spool $spool
    if ($LASTEXITCODE -ne 0) { throw "Correlation failed for $name" }
    $result = $raw | ConvertFrom-Json
    $result | Add-Member -NotePropertyName case_id -NotePropertyValue $name
    $line = $result | ConvertTo-Json -Depth 32 -Compress
    [System.IO.File]::AppendAllText($actual, $line + [char]10, $utf8NoBom)
}
cargo run --locked -- summarize --expected .\lab-corpus\manifest.json --actual $actual
```

比較入力の1行の例:

```json
{"case_id":"benign-com","rules":[{"rule_id":"AG-B002","evaluable":true,"missing_sources":[]}],"findings":[]}
```

1ケースだけなら `case_id` を省略できます。複数ケースでは必須。ルールが `evaluable=false` のときは、findingがなくても成功として計上しません。これは**実検出率の測定ではありません**。

## 権限・セキュリティ・非対応

一般ユーザーで実行できます。Windows API・プロセス実行・ネットワーク・Sysmon導入・管理者昇格はありません。ユーザー名・ブラウザーDB・資格情報を収集しません。CommandLineはJSONLではSHA-256に置換します。Windows風のパスやドメインは架空、IPは文書用アドレス（192.0.2.42）です。

manifest最大512 KiB、actual最大8 MiB、個別fixture最大1 MiB、JSONL行最大256 KiB、16ケース、ケース内XML最大128件。検証・比較ループの時間予算は5秒ですが、**ファイルシステムI/Oのハードタイムアウトは未実装**です。`verify` は危険な相対パス、symlink/reparse pointを拒否します。ただし親ディレクトリの競合差替えに対する完全防御はありません。信頼できるローカルフォルダーを使ってください。

manifest自体は署名されておらず、**manifestも含めて改ざんされた場合はSHA-256のみでは検出できません**。外部配布では別経路での署名/manifestハッシュ検証が必要です。出力の `complete` は「整合性・書式が確認できた」であり、セキュリティ上の安全判定ではありません。

今回未実装: Report v2静的スキャナーとの自動比較、実Sysmonイベント収集、Windows 11実機性能・誤検知検証、失効IOCキャッシュの本体への自動挿入、P5/P8/P10への自動統合、CI統合。これらは将来の独立PRで行います。

技術調査とライセンスは [RESEARCH.md](RESEARCH.md) に記載します。
