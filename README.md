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
- PEのAuthenticode署名検証、インポートテーブル解析、YARA-Xの実行は未実装です。
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

### 今後の本番機能

Windowsサービス、Sysmonイベント1/3/7の購読とProcessGuid相関、AMSI連携、YARA-X、Authenticode、DNS/ドメインIOC、明示的なWindows Firewallアウトバウンド遮断と安全な巻き戻し、ログローテーション、署名付きルール更新、GUIなどを段階的に追加します。詳細は [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) を参照してください。

## 脅威フィード

- [Feodo Tracker](https://feodotracker.abuse.ch/blocklist/)：推奨IPブロックリスト。将来の遮断機能を検討するための候補ですが、現時点では照合のみです。
- [C2IntelFeeds](https://github.com/drb-ra/C2IntelFeeds)：検証済みのIPフィード。誤検知とIP再割当があり得るため、遮断対象には自動登録しません。**利用時はフィードのライセンスを必ず確認**してください。

フィードのデータそのものはリポジトリに同梱・再配布しません。

## 外部ツールの導入調査（AI並列調査プロンプト）

Loki-RS、Portmaster、Wazuh、ClamAV、YARA-X、simplewall、ConfigureDefenderの採用可否を、15担当のAI＋1統合担当で調べるための[調査ガイドと個別プロンプト](docs/research/README.md)を用意しています。各AIは結果だけを独立したMarkdownとPRで提出し、ソース実装・マージは行いません。

## セキュリティ方針

無断で検体をアップロードしない、自動削除しない、Defenderの保護を弱めない、テレメトリーを外部送信しない設計です。既知の設計上の制約は [SECURITY.md](SECURITY.md) にまとめています。初期開発段階のため、信頼できない検体を手元で**実行しないでください**。

## ライセンス

現時点でコードのライセンスは未設定です。オープンソース公開時の条件はリポジトリ所有者が決定します。
