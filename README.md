# AegisGuard

**Rust製のWindows向け防御的セキュリティツール（開発初期段階）**

Microsoft Defenderを無効化せず、EXE / DLL / スクリプトの静的解析と、公開C2 IPフィードとの照合を追加するプロジェクトです。**検査対象のファイルは実行しません。** 不審なファイルや通信先を、根拠付きのJSONLデータとして分析することを目的としています。

> [!WARNING]
> 現在はRust製CLIの**MVP（基盤実装）**です。製品レベルの常駐保護・実行前遮断・Windows Firewall操作・署名検証は未実装です。「検出なし」は安全の証明ではありません。

## 実装済み

- Rust CLIで単独ファイルまたはフォルダーを読み取り専用検査。結果を標準出力とJSONLに出力
- EXE / DLL / SYS / OCX / SCR / CPL：PEヘッダー・セクション表検証、W+Xセクション、高エントロピー検出
- PY / PYW / JS / JSE / MJS / CJS / PS1 / PSM1 / PSD1 / BAT / CMD / VBS / VBE / WSF / HTA：危険な操作の**組み合わせ**を検査
- スクリプトの限定的な静的難読化解除：Base64、UTF-16、zlib/gzip、JS fromCharCode、Python chr列、文字列連結、JS文字列逆転、16進/Unicodeエスケープ、BATの変数・キャレット
- デコード深度3、最大16層、復元バイト数の上限、入力ファイルサイズ上限
- 公開C2 IPフィードの**手動更新とオフライン照合**（Feodo Tracker／C2IntelFeeds）。キャッシュ不鮮度を表示。通信遮断なし
- GitHub Actions：Windows・Linuxでfmt／clippy／テスト、宣言したMSRV（1.85）でのビルド、`cargo-deny` によるライセンス・脆弱性・取得元の検査、ライセンス一覧とCycloneDX SBOMの生成、合成コーパスでの性能・誤検知ベースライン計測（毎週の定期実行あり）。Actionはコミットハッシュで固定し、`Cargo.lock` をコミットしています

## 必要な環境

- Rust 1.85以上（stable）
- 開発対象：Windows 11 x64。初期CLIの静的検査部分はLinuxでも動きます

## ビルド・実行

```powershell
cargo build --release
cargo test

# 単体スキャン
cargo run --release -- scan "C:\Users\YOURNAME\Downloads\sample.ps1"

# フォルダーを再帰的に検査
cargo run --release -- scan "C:\Users\YOURNAME\Downloads" --recursive --output reports\scan.jsonl

# C2リスト取得（インターネット接続が必要）
cargo run --release -- c2 update

# 保存済みIPリストだけで照合（外部通信なし）
cargo run --release -- c2 check 1.2.3.4

# フィード鮮度と件数
cargo run --release -- c2 status
```

※上のコマンドはRust CLIの使用例です。掲載したIPは使用例でありC2の実例ではありません。

## 判定と制限事項

- `low_signal`：実装済みルールで強い兆候が見つからなかった。安全とは限りません。
- `incomplete`：復元したコードの展開、候補数、解析層数または深さの上限に達し、一部の内容を検査できなかった状態。**スコア0でも安全判定ではありません。** レポートの `analysis_complete=false` と `incomplete_reasons` を確認してください。
- 検出根拠がある場合は `risk=review/high` を維持しますが、`status=incomplete` の場合は解析漏れが残ります。
- `review` / `high`：調査優先度の目安。悪性確定ではありません。
- `not_assessed`：対象外、検査失敗、異常なPE構造、サイズ超過など。安全と扱いません。
- スコアは初期ヒューリスティックスであり感染確率ではありません。コメントや正規の管理スクリプトにも反応し得ます。
- 独自暗号化、動的に生成されるコード、メモリだけで実行されるペイロード、複雑なJS ASTの復元などには未対応です。
- PEのAuthenticode署名検証、インポートテーブル解析は未実装です。YARA-Xは任意機能（`--features yara`）で、YARAのモジュール（`pe`等）は使えません。
- C2フィードが空・古い・未登録であっても、感染していないことを示すわけではありません。
- C2キャッシュはバージョン2でフィード単位の `last_success_at` と48時間の期限を管理します。**更新に失敗したフィードの時刻は変更しません。**
- `c2 status` の `feeds[].stale` を参照してください。`c2 check` は期限切れのIPを `matched=true` にせず、`stale_matches_ignored` に区別して表示します。
- 古いバージョン1のキャッシュは保存済みの `collected_at` を保守的に引き継ぎます。古い情報を新規取得済みとみなしません。
- C2キャッシュは2世代で保存します。新しい内容を `<cache>.tmp` に書いてフラッシュし、読み戻して検証してから、旧版を `<cache>.prev`、新版を `<cache>` にします。途中で停止・破損した場合は、次の読み込みで検証済みの新しい世代か旧世代を使い（`cache_generation` が `pending` / `previous` になり警告を表示）、次の `c2 update` で修復します。有効な世代が1つもない場合は、空のキャッシュとして扱わずエラーにします。
- キャッシュとJSONL出力ファイルは作成時に所有者のみがアクセスできる権限にします（Unixは0600、Windowsは所有者・SYSTEM・Administratorsのみの保護されたDACL）。
- `--output` のJSONLは `--output-max-bytes`（既定64 MiB）でローテーションし、`--output-generations`（既定5）世代まで残します。先頭行がAegisGuardのレポートでないファイルには追記・ローテーション・削除をせずエラーにします。途中で切れた最終行は改行で区切ってから追記します。
- デフォルトでネットワークへファイルや解析結果を送信しません。`c2 update`を明示した場合のみ指定フィードへのHTTPS要求を行います。

### JSONLレポート（スキーマ v2）

`scan` は1行1ファイルのJSONを出力します。v1（`schema_version` なし）の全フィールドは名前・型・意味を変えずに残し、v2はフィールドを**追加のみ**しています。読み手は未知のフィールドを無視してください。

| フィールド | 用途 |
| --- | --- |
| `schema_version` | `2`。互換性のない変更をする場合だけ増やします |
| `assessment` | **完全性の軸**：`analyzed` / `incomplete` / `not_assessed`。`analysis_complete` は `assessment == "analyzed"` と常に一致します |
| `signal_level` | **検出の軸**：`low_signal` / `review` / `high` / `not_evaluated`（未検査かつ検出なし）。完全性とは独立に、見つかった根拠の強さだけを表します |
| `not_assessed_reason` | 未検査の理由コード（例：`unsupported_file_type`、`metadata_failed`、`symlink_not_followed`、`not_regular_file`、`size_limit_exceeded`、`open_failed`、`read_failed`、`file_grew_during_read`、`malformed_pe`、`text_decode_failed`、`walk_failed`、`identity_unavailable`、`path_identity_mismatch`、`file_changed_during_scan`、走査停止時の `scan_file_limit`・`scan_byte_limit`・`scan_time_limit`・`scan_cancelled`）。`status` は従来値のまま残ります |
| `coverage` | 実際に読んだバイト数、適用したサイズ上限、実行した解析器。到達できなかった範囲は `incomplete_reasons` / `not_assessed_reason` に出ます |
| `file_identity` | サイズ・更新時刻・取得元（`path_metadata` / `handle_metadata`）と、開いたハンドルの `device_id`・`file_id`・`link_count`（Windowsはボリュームシリアル＋ファイルインデックス、Unixはdev＋inode）。読み取り後にパスが同じファイルを指すか再確認します |
| `engine` | エンジン名・バージョンと組み込みルールセットID（ルール変更時に更新） |
| `started_at_unix_ms` / `completed_at_unix_ms` | 検査の開始・終了時刻（UNIXミリ秒） |

- 従来の `risk` は2つの軸から導出され、`low_signal` になるのは `assessment=analyzed` の場合だけです。
- フォルダー列挙に失敗したエントリと、検査対象拡張子のシンボリックリンクも `not_assessed` の行として出力します（以前は標準エラーのみ、またはスキップ）。列挙失敗の行は `kind=unknown` になる場合があります。
- 標準エラーに `analyzed / incomplete / not_assessed` の件数サマリーを出します。
- レポートに検体の本文、復号結果、一致した文字列は含めません。ローカルパスは含むため、取り扱いに注意してください。

### 資源上限（P0-03）

| 上限 | 既定値 | 到達時の扱い |
| --- | --- | --- |
| PE / スクリプトの入力サイズ | 64 MiB / 4 MiB | `not_assessed`（`size_limit_exceeded`） |
| 復号層・深さ・累積復号量・候補数 | 16層・3段・512 KiB・種類ごと16〜32件 | `incomplete`（理由コード付き） |
| 1ファイルの解析時間 `--file-time-limit-ms` | 10000 | `incomplete`（`analysis_time_limit`） |
| 検査ファイル数 `--max-files` | 200000 | 走査を止め `status=scan_stopped`（`scan_file_limit`）の行を出力し、終了コード非0 |
| 読み取り総量 `--max-total-bytes` | 32 GiB | 同上（`scan_byte_limit`） |
| 走査時間 `--max-duration-secs` | 14400 | 同上（`scan_time_limit`） |
| Ctrl-C | — | 処理中の単位を終えて `scan_cancelled` を記録し、終了コード非0 |

走査は単一スレッドです。ZIP等のアーカイブ展開は実装していません。

### YARA-X（任意機能・監査のみ）

`--features yara` でビルドした場合だけ使えます（Rust 1.95以上が必要。既定ビルドはRust 1.85のまま）。

```powershell
cargo build --release --features yara
# ルールのゲート検査（台帳・コンパイルエラー・警告・必須メタデータ）
.\target\release\aegisguard.exe rules check rules\aegisguard
# 原本と復号層をYARAでも検査（一致は根拠として記録するだけで、削除・遮断はしません）
.\target\release\aegisguard.exe scan C:\path\to\folder --recursive --yara-rules rules\aegisguard
```

- ルールはテキストのみを本体内でコンパイルします。`include`・未許可の`import`・警告・メタデータ欠落・台帳（`ledger.json`）にないファイルがあれば、ルールセット全体を拒否します。
- 結果は `yara` フィールド（ルールセットのSHA-256、検査した層の数、一致したルールID・層・オフセット）と `yara_rule_match` シグナルに出ます。一致したバイト列は記録しません。
- 時間切れ・タイムアウト・エンジンエラーは `incomplete` になります。
- 同梱ルール（`rules/aegisguard`）は自作のみです。第三者ルールは使用・再配布の許諾を確認して台帳に記録するまで追加しません。方式の比較と決定は [YARA_X_INTEGRATION.md](docs/research/decisions/YARA_X_INTEGRATION.md) を参照してください。

#### 署名付きルールパック（P1-04）

ルールの配布・更新は、Ed25519で署名したパックだけを受け付けます。**AegisGuardに組み込みの信頼済み鍵はありません。** 利用者が信頼する公開鍵を明示して使います。配信サーバーはなく、ローカルのパックディレクトリを対象にします。

```powershell
aegisguard rules keygen keys\maintainer            # maintainer.key（秘密鍵、所有者のみアクセス可）と maintainer.pub
aegisguard rules pack rules\aegisguard --key keys\maintainer.key --sequence 2 --out pack2
aegisguard rules install pack2 --trusted-key keys\maintainer.pub --store data\rules
aegisguard scan C:\path --recursive --rule-store data\rules --trusted-key keys\maintainer.pub
aegisguard rules rollback --trusted-key keys\maintainer.pub --store data\rules
```

- 導入時に、署名・鍵ID・有効期限（最長400日）・ペイロードのSHA-256と長さ・ファイル名・台帳・**連番が前回より大きいこと**（リプレイ拒否）・**コンパイルの合格**を検証します。どれかに失敗すると、導入済みのパックをそのまま使い続けます。
- 導入済みパックは2世代で保存します。`rollback` は前世代を再検証してから戻します（最大連番は保持するので、戻した後に古いパックを再導入することはできません）。
- `scan` は読み込むたびに署名と期限を再検証し、期限切れや信頼しない鍵の場合は走査を始めずにエラーにします。
- `yara` featureのないビルドではコンパイルを確認できないため、パックを導入できません。
### Windowsイベントログの収集（P2-01、読み取りのみ）

```powershell
# 既定はSysmon（Microsoft公式から利用者が別途導入したもの）。AegisGuardはSysmonを同梱・設定変更しません
aegisguard events collect --channel Microsoft-Windows-Sysmon/Operational --spool data\events\sysmon.jsonl --checkpoint data\events\sysmon.checkpoint.json
```

- Windows Event Log API（`EvtQuery`・`EvtNext`・`EvtRender`・ブックマーク）で指定チャネルを読み、`EventEnvelope v1` としてスプール（JSONL）に追記します。監査ポリシー・チャネル設定・Sysmon設定は変更しません。
- **スプールをフラッシュした後にだけ**カーソル（ブックマーク）を2世代保存で進めます。途中で止まると次回に同じイベントを再読込します（`event_uid` が同じ重複は起こり得ますが、取りこぼしはしません）。
- ブックマークの記録が消えた（ログが上書きされた）場合や `EventRecordID` が飛んだ場合は、`gaps` に記録して `status=gap` にします。未来のイベントだけに切り替えて黙って続けることはしません。チャネルが無い・権限がない場合は `status=degraded` で、終了コードは非0です。
- 保存するのは許可リストのフィールドだけです（ProcessGuid・Image・宛先IP/ポート・DNS名・ハッシュ等）。`CommandLine` はSHA-256だけを保存し、ユーザー名や端末名は保存しません。
- `aegisguard events processes --spool dataventssysmon.jsonl` はスプールからProcessGuid単位のプロセスの生存期間（作成・終了・通信先・DNS・DLLロード数・アクセス先）を組み立てます。PIDだけでは同一視しません。作成イベントを見ていないプロセスは `start_observed=false`、重複・時刻の逆転・同じPIDの同時生存は `anomalies` に出します。**観測されなかったイベント種別（例：Sysmon ID 3/7/22が無効）は `unobserved` に出し、「通信なし」とは扱いません。**
- `aegisguard events correlate --spool ... --c2-cache datar-cache.json` は組み込みの相関ルール（AG-C001：Officeアプリがスクリプトホスト等を起動、AG-C002：起動後5分以内に新鮮なC2 IOCへ接続、AG-C003：1分以内に子プロセス10個以上）をオフラインで実行します。結果は確認のための根拠（`review` / `observed`）で、悪性の判定ではありません。必要なイベント種別が観測されていないルールは `evaluable=false` と `missing_sources` で示します。遮断・削除はしません。
- 認証情報窃取の兆候（P4-01）：`events correlate` に AG-C010（システム／Defender以外のプロセスがlsassをメモリ読み取り権限で開いた）、AG-C011（その後10分以内に同じプロセスが `.dmp` を作成）、AG-C012（Defenderが報告したファイルがその後に起動された）を追加しました。Defenderのイベントは `events collect --channel "Microsoft-Windows-Windows Defender/Operational" --spool data\events\defender.jsonl ...` で集め、`--spool` を複数指定して一緒に分析します。認証情報ストアやプロセスのメモリは読みません。管理・バックアップツールでも起こり得るため、結果は確認用の根拠です。
- `aegisguard events iocs --spool ... --c2-cache data\c2-cache.json [--local-iocs my-iocs.json] [--allowlist allow.json]` は、IOCの根拠をプロセスに結び付けます（P3-01）。`basis` は `direct_ip`（接続先IPが一致）・`dns_query`（IOCドメインを問い合わせた）・`dns_then_connect`（問い合わせの回答に含まれたIPへ5分以内に接続）で、ドメイン名だけでは接続先の証明にしません。期限切れのIOCは `stale_only`、利用者の例外は `suppressed`（理由付き）、3種類以上のプログラムが接続した宛先は共有基盤の可能性として確度を下げます。DoH/DoT・VPN・NRPT経由やSysmonで無効なイベント種別は `visibility` に「見えない」と明記します。
- ローカルIOCと例外は利用者が管理するJSON配列です（`{"type":"ip|domain","value":"...","expires_at_unix":...}`、例外は `reason` が必須）。期限のない項目は受け付けません。`c2 check` は各一致の出所・ライセンス・期限を `evidence` に出します。

### 遮断候補の計画（P3-02、dry-runのみ）

```powershell
aegisguard policy plan --spool data\events\sysmon.jsonl --out plans\plan-001.json --expiry-hours 24
aegisguard policy approve plans\plan-001.json --approver "admin" --note "ticket 123" --out plans\plan-001.approved.json
```

- **Windows FirewallやWFPなどOSの設定は一切変更しません。** このビルドには適用処理がありません（P3-03は隔離VMでの復旧検証と明示承認が必要なため未実装）。
- 候補は「アプリのパス × 宛先IP」の送信遮断で、`AegisGuard-` で始まる名前・有効期限（最長7日）・巻き戻しIDを持ち、最大50件です。
- 次は候補にせず、理由付きで `rejected` に入れます：プロセス不明、共有のシステムプロセス（svchost・lsass・explorer・Defender等）、DNS名だけの根拠、期限切れの根拠、利用者の例外、共有の宛先、調査用ソース（C2IntelFeeds）だけの根拠、確度不足、非公開アドレス、上限超過。
- `approve` は承認を監査ログ（`data\policy\audit.jsonl`）に追記するだけで、適用しません。計画ファイルは上書きしません。

### Microsoft Defenderの読み取り専用監査（P4-02）

```powershell
aegisguard defender audit
```

- Microsoft公式の `Get-MpComputerStatus` と `Get-MpPreference`（および Defenderのポリシーキーの有無の確認）だけを、固定のスクリプトでシステムのPowerShellから呼びます。**設定の変更・除外の追加・プリセットの適用は一切しません。**
- リアルタイム保護・改ざん防止・クラウド保護・ネットワーク保護・フォルダーアクセスの制御・PUA・ASRルール（Microsoftの公開GUIDで名前を表示、未知のGUIDは `unknown_rule`）の状態を出します。
- 読めなかった値は `unknown` とし、保護されているとは扱いません。管理者以外では除外の一覧が見えないため件数は `null` になります。**除外パスそのものは出力しません。**
- ポリシーキーがある場合（`policy_key_present`）は、グループポリシーやMDMの設定が優先され、表示値と実際の適用状態が異なる可能性があります。

### ローカルHTMLレポート（P4-03、読み取り専用）

```powershell
aegisguard scan C:\path --recursive --output reports\scan.jsonl
aegisguard defender audit > reports\defender.json
aegisguard report html --scan reports\scan.jsonl --defender reports\defender.json --out reports\report.html
```

- 各コマンドの出力（JSON/JSONL）から静的なHTMLを1つ作ります。スクリプトを含まず（CSPで禁止）、すべての値をエスケープし、外部へ送信しません。管理者権限は不要で、既存のファイルは上書きしません。
- 完全に解析できなかったファイルを先頭に警告として出します。渡されなかった項目は「未提供（不明）」、読めなかったDefenderの値や期限切れのフィードは強調表示し、「問題なし」とは表示しません。
- 常駐のGUIや特権サービスとのIPC（P2-05）は、常駐収集が必要になるまで実装しません。

### 限定FIM（P2-04、読み取りのみ）

```powershell
aegisguard fim baseline C:\ProgramData\MyApp\config C:\Users\me\.ssh\config --db data\fim\baseline.json
aegisguard fim check --db data\fim\baseline.json
aegisguard fim watch --db data\fim\baseline.json --duration-secs 600   # Windowsのみ
```

- 明示したパス（ファイル、または深さ8までのフォルダー、最大1万件）だけを対象に、サイズ・更新時刻・ファイル同一性・SHA-256を記録します（2世代保存）。
- `check` は再走査して、`created` / `modified`（内容変更・別ファイルへの差替え・メタデータ変更）/ `renamed` / `deleted` / `unreadable` を個別に報告します。読めなくなったファイルを「削除」とは扱いません。
- `watch` はWindowsの変更通知（`ReadDirectoryChangesW`）を使いますが、**判定はすべて再走査**で行います。通知の取りこぼし（バッファあふれ）と監視の停止は `overflow` / `monitor_stopped` として出し、その時点と終了時に再走査します。
- ブラウザーの認証情報・Cookieのファイル（`Login Data`、`Cookies`、`key4.db`、`logins.json` 等）やレジストリハイブは**開かず**、`excluded_sensitive` として記録だけします。
- FIMは変更しか見えません。ファイルを読み取って持ち出す行為（変更を伴わないもの）は検出できません。

### 今後の本番機能

Windowsサービス、ProcessGuid相関、AMSI連携、Authenticode、DNS/ドメインIOC、明示的なWindows Firewallアウトバウンド遮断と安全な巻き戻し、ログローテーション、署名付きルール更新、GUIなどを段階的に追加します。詳細は [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) を参照してください。

## 脅威フィード

- [Feodo Tracker](https://feodotracker.abuse.ch/blocklist/)：推奨IPブロックリスト。将来の遮断機能を検討するための候補ですが、現時点では照合のみです。
- [C2IntelFeeds](https://github.com/drb-ra/C2IntelFeeds)：検証済みのIPフィード。**CC BY-NC-SA 4.0（非商用）のため既定では取得しません。** 利用条件を確認したうえで `c2 update --include-source c2intel_verified` と明示した場合だけ取得します。誤検知とIP再割当があり得るため、確度は `low` として扱います。

フィードのデータそのものはリポジトリに同梱・再配布しません。

## 外部ツールの導入調査（AI並列調査プロンプト）

Loki-RS、Portmaster、Wazuh、ClamAV、YARA-X、simplewall、ConfigureDefenderの採用可否を、15担当のAI＋1統合担当で調べるための[調査ガイドと個別プロンプト](docs/research/README.md)を用意しています。各AIは結果だけを独立したMarkdownとPRで提出し、ソース実装・マージは行いません。

## セキュリティ方針

無断で検体をアップロードしない、自動削除しない、Defenderの保護を弱めない、テレメトリーを外部送信しない設計です。既知の設計上の制約は [SECURITY.md](SECURITY.md) にまとめています。初期開発段階のため、信頼できない検体を手元で**実行しないでください**。

## ライセンス

現時点でコードのライセンスは未設定です。オープンソース公開時の条件はリポジトリ所有者が決定します。
