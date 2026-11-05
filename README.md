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
- Windows・Linux両環境でCargoのfmt／clippy／テストを走らせるGitHub Actions

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
- デフォルトでネットワークへファイルや解析結果を送信しません。`c2 update`を明示した場合のみ指定フィードへのHTTPS要求を行います。

### 今後の本番機能

Windowsサービス、Sysmonイベント1/3/7の購読とProcessGuid相関、AMSI連携、YARA-X、Authenticode、DNS/ドメインIOC、明示的なWindows Firewallアウトバウンド遮断と安全な巻き戻し、ログローテーション、署名付きルール更新、GUIなどを段階的に追加します。詳細は [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) を参照してください。

## 脅威フィード

- [Feodo Tracker](https://feodotracker.abuse.ch/blocklist/)：推奨IPブロックリスト。将来の遮断機能を検討するための候補ですが、現時点では照合のみです。
- [C2IntelFeeds](https://github.com/drb-ra/C2IntelFeeds)：検証済みのIPフィード。誤検知とIP再割当があり得るため、遮断対象には自動登録しません。**利用時はフィードのライセンスを必ず確認**してください。

フィードのデータそのものはリポジトリに同梱・再配布しません。

## セキュリティ方針

無断で検体をアップロードしない、自動削除しない、Defenderの保護を弱めない、テレメトリーを外部送信しない設計です。既知の設計上の制約は [SECURITY.md](SECURITY.md) にまとめています。初期開発段階のため、信頼できない検体を手元で**実行しないでください**。

## ライセンス

現時点でコードのライセンスは未設定です。オープンソース公開時の条件はリポジトリ所有者が決定します。
