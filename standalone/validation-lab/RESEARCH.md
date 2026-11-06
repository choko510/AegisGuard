# Validation Lab 技術調査・判断記録

**確認日:** 2026-11-06（JST）  
**読取対象のmain:** `5c4ce77d12056ef9887ccdf0d622faa08f6f245b`  
**Windows 11実機:** 未確認。ビルド／Cargo実行結果を伴わない事項は未実行と記載。

## リポジトリ内の実ソース

| 読取ファイル | 実際に確認した契約 |
| --- | --- |
| [src/events/mod.rs](https://github.com/choko510/AegisGuard/blob/5c4ce77d12056ef9887ccdf0d622faa08f6f245b/src/events/mod.rs) | `EventEnvelope` schema 1、`parse_event_xml`、`SYSMON_PROVIDER`。UIDはchannel・record_id・provider・event_id・timeを区切ってSHA-256化した先頭32文字。CommandLineはSHA-256、ID13のCOM Detailsはhashと許可されたパスのみ保持。 |
| [src/events/process.rs](https://github.com/choko510/AegisGuard/blob/5c4ce77d12056ef9887ccdf0d622faa08f6f245b/src/events/process.rs) | ProcessGuidで生存期間を識別、PID再利用・重複イベント・ID1/3/5/7/11/12/13/14/22の定数・未観測の扱い。 |
| [src/events/browser_rules.rs](https://github.com/choko510/AegisGuard/blob/5c4ce77d12056ef9887ccdf0d622faa08f6f245b/src/events/browser_rules.rs) | AG-B001/B002/B003/B005が実装済み。AG-B004はcredential_file_read_auditが入力にないため常に評価不能。実K2Fの痕跡パス/CLSIDそのものを使わず、架空の類似連鎖でテストする。 |
| [src/events/correlate.rs](https://github.com/choko510/AegisGuard/blob/5c4ce77d12056ef9887ccdf0d622faa08f6f245b/src/events/correlate.rs) | `Correlation {ruleset_version,rules,findings}`、`Finding {rule_id,event_refs,confidence,missing_sources,verdict}`、`RuleStatus.evaluable`。評価不能を陰性扱いしない。 |
| [src/main.rs](https://github.com/choko510/AegisGuard/blob/5c4ce77d12056ef9887ccdf0d622faa08f6f245b/src/main.rs) | `events correlate --spool` が相関JSONを返す。ケースごとに実行し、case_idを追加したJSONLをsummarizeの入力に採用。 |
| [examples/bench_corpus.rs](https://github.com/choko510/AegisGuard/blob/5c4ce77d12056ef9887ccdf0d622faa08f6f245b/examples/bench_corpus.rs)、[docs/BASELINE.md](https://github.com/choko510/AegisGuard/blob/5c4ce77d12056ef9887ccdf0d622faa08f6f245b/docs/BASELINE.md)、[tests/fixtures](https://github.com/choko510/AegisGuard/tree/5c4ce77d12056ef9887ccdf0d622faa08f6f245b/tests/fixtures) | 既存の静的スキャン用の合成データ、検出率ではないベースライン。これらは一切変更せず、イベント相関専用の独立コーパスを作成。 |
| [README.md](https://github.com/choko510/AegisGuard/blob/5c4ce77d12056ef9887ccdf0d622faa08f6f245b/README.md) / [SECURITY.md](https://github.com/choko510/AegisGuard/blob/5c4ce77d12056ef9887ccdf0d622faa08f6f245b/SECURITY.md) / [docs/ARCHITECTURE.md](https://github.com/choko510/AegisGuard/blob/5c4ce77d12056ef9887ccdf0d622faa08f6f245b/docs/ARCHITECTURE.md) | Report v2は`assessment`と`signal_level`を別々に扱う。今回のsummaryはCorrelation形式のみを対象にし、静的スキャナーの精度評価と混同しない。 |

## Microsoft公式仕様・外部資料（2026-11-06確認）

1. [Sysmon公式ドキュメント](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon): Sysmon ID1はプロセス作成、ID3は通信、ID7はDLL読み込み、ID11はファイル作成、ID12–14はレジストリ操作、ID22はDNS。ProcessGuidはPID再利用への対策に有効。ID3/7は構成次第で出ず、「存在しない」とは言えない。
2. [Sysmon configuration files](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-configuration-files): EventFilteringの各イベント種別とData名を参照。Sysmonドライバー/サービスを導入したり設定を変更したりしない。
3. [Windows Event Schema](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-elements): `Event/System/Provider/EventID/TimeCreated/EventRecordID/Channel/EventData/Data` のXML構造を採用。実OSイベントではなく**合成XMLテキスト**を保存する。
4. [EvtRender 関数](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtrender): `EvtRender(Context,Fragment,Flags,BufferSize,Buffer,BufferUsed,PropertyCount)` はWindowsイベントをXML化するAPI。今回の用途は人工XMLの作成であり、OSの権限・ハンドル・Event Logサービスに依存させたくないため**呼び出さない**。
5. [Consuming Events](https://learn.microsoft.com/en-us/windows/win32/wes/consuming-events): `EvtQuery` の読取特性とマルチスレッドの順序逆転可能性を確認。順序の違う遅延イベントを合成する。OSからのイベント収集は採用しない。
6. [Bookmarking Events](https://learn.microsoft.com/en-us/windows/win32/wes/bookmarking-events): `EvtCreateBookmark / EvtUpdateBookmark / EvtRender(EvtRenderBookmark)` の設計に基づき、再読み込みで同じEventUIDが繰り返されるケースを追加。実ブックマークの更新なし。
7. [EICAR公式](https://www.eicar.org/download-anti-malware-testfile/): 代替テストファイルの目的を確認。ただしEICARは実行可能DOS形式でAVの隔離対象にもなるため、**EICARファイル/文字列を生成・同梱・実行せず**、無害な `inert.txt` を選ぶ。

## 技術採否・依存とライセンス

- **serde・serde_json:** [Serde](https://github.com/serde-rs/serde) / [serde_json](https://github.com/serde-rs/json)。MIT OR Apache-2.0。型付きmanifest・JSONL入力解析・安定したキー順のシリアライズ用に採用。実際の `Cargo.lock` ではserde 1.0.229、serde_json 1.0.154。
- **sha2:** [RustCrypto/hashes](https://github.com/RustCrypto/hashes) / [sha2/Cargo.toml](https://github.com/RustCrypto/hashes/blob/master/sha2/Cargo.toml)。MIT OR Apache-2.0。`Sha256` と `Digest::digest` を採用。依存version 0.10.9。非暗号学的ハッシュは改ざんの証拠として弱く不採用。
- **CLI解析:** 標準ライブラリの引数処理。`clap` 等を不要とし、実行モードを限定。ネットワーク、第三者GPL/AGPLコードのコピーなし。本体のRust crateにも依存しない。
- **Windows API:** 直接利用しない。Sysmonドライバー・Windows Event Log・レジストリ・COM・Defenderへの書込や、偽の実イベントを注入するAPIは対象外。
- **Cargo.lock:** ルートCargo.lockに記載された該当バージョン/チェックサム/推移依存から作成。Rust/Cargoがない環境での手動抽出であるため、`cargo test --locked` とlockfile整合は未検証。

## 再現性・異常・期待値の限界

1. `seed + case_id + role` をSHA-256して架空のProcessGuidへ変換。タイムスタンプは固定UTC、パスは常に架空のWindows風文字列、出力はLF/UTF-8、同seedでbyte-for-byteを狙う。Windows/Linuxでのバイト同一性は**双方で実行して初めて確認可能**。
2. 10ケースを混ぜると「必要なイベントIDが観測されているか」の意味が変わるため、1ケースにつき独立のevents.jsonlとして相関させる。
3. `present / absent` は既存ルールで`evaluable=true`の場合のみ採否。`unknown` は欠損/未観測、`planned` は未実装で、発見ゼロ・安全と同一視しない。実ルールの改訂時には期待値の版を更新する必要がある。
4. 入力の件数・サイズ・経過時間を上限化し、コーパスのハッシュと長さ、XML/JSONL件数、期待するevent_refsの存在を検証。5秒制限はユーザーモードのループ制限で、同期I/Oのブロックに対するハードタイムアウトではない。
5. `create_new` で既存データを上書きしない。危険な相対パス・symlink/reparse pointを拒否する。ただし親ディレクトリの競合差替えや、信頼できないmanifestとファイルを一緒に書き換える攻撃は防御未完。署名や別経路のmanifestハッシュが将来必要。
6. 固定架空パス、`example.invalid`、文書用IPv4 `192.0.2.42` のみ。CommandLineをJSONLではSHA-256にし、actualレポートの生のフィールド値を出力しない。実ユーザーの資格情報やブラウザーDBは一切読まない。

## 未実装・将来連携

- **未実装:** 実Sysmon/Windows Event Logの収集と実機での正しさの証明、Report v2静的スキャンとの完全な照合、実際の検出率/負荷測定、外部IOCキャッシュへの変換、署名付きfixture、TOCTOU完全対策、Windows 11/管理者・非管理者・ACLの実機検証、CI。
- **P5 typed APIへの案:** 別PRで `ManifestV1(case_id, expected.rule_id, event_refs)` と `CorrelationFinding/RuleStatus/SensorHealth` を結ぶアダプターを設ける。将来 `ScanReportV2` を扱う場合、`assessment` と `signal_level` は独立軸を維持。今回本体の `src/`・root Cargo/CIを一切変更しない。
