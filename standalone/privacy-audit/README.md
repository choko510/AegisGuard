# privacy-audit — ログ・レポートの機密情報QA

AegisGuard本体から独立した**読み取り専用**Rust CLIです。指定されたUTF-8ログ/JSONLを監査し、資格情報・Cookie・BitLocker回復パスワード・ユーザー名を含むパスなどの意図しない混入を探します。秘密の元文字列・入力パス・JSONプロパティ名を報告書に出しません。

**検出がないことは安全の証明ではありません。** マスク処理やログ出力の代替にはなりません。

## ビルドと使い方

このフォルダーから実行します（ルートのCargoワークスペースには参加しません）。

    cargo build --locked --release
    cargo run --locked -- check --input fixtures/synthetic.jsonl --format json --mode jsonl
    cargo run --locked -- check --input C:\temp\sample.log --format json --mode log
    cargo run --locked -- self-test

実行可能ファイルを直接呼ぶ場合:

    privacy-audit check --input <jsonl-or-log> --format json [--mode auto|jsonl|log]
    privacy-audit self-test

- `--input` **必須**。明示された**通常ファイル1つ**だけを開き、ディレクトリ再帰・レジストリ操作・資格情報ストア探索・ブラウザDB閲覧・ネットワーク送信はしません。
- `--format json` だけ対応（既定もJSON）。入力ファイルを上書き・削除しません。
- `--mode jsonl` は各非空行をJSON object/arrayとして構造解析。壊れたJSONは失敗し、平文にはフォールバックしません。
- `--mode log` は各行を平文扱い。`--mode auto`（既定）は `{` で始まる行のみJSON、それ以外は平文として扱います。JSON配列やログ中の `{` ではじまる文字列がある場合は明示モードを選んでください。
- Symlinkはトップレベルで拒否。親ディレクトリの再解析ポイントや差し替え競合を完全に防ぐハンドル固定処理は未実装です。**機密入力を監査するときは、アクセス制御された安定したディレクトリのコピーを用いること**。

## 出力スキーマ（v1）

出力例（生成時刻は説明用、元値は含めません）:

    {
      "schema_version": 1,
      "module": "privacy-audit",
      "generated_at_unix_ms": 1793920000000,
      "status": "complete",
      "entries": [
        {
          "category": "credential",
          "severity": "high",
          "line_no": 1,
          "rule_id": "structured_secret_field",
          "redacted_excerpt_or_hash": "[REDACTED]"
        }
      ],
      "warnings": [],
      "coverage": {
        "lines_read": 1,
        "bytes_read": 44,
        "json_lines": 1,
        "log_lines": 0,
        "json_nodes": 2,
        "max_file_bytes": 8388608,
        "max_line_bytes": 65536,
        "max_token_bytes": 4096,
        "max_lines": 20000,
        "max_findings": 1000,
        "mode": "jsonl",
        "complete": true
      }
    }

これは**JSON構造の例**であり、`bytes_read` と時刻は実行結果の再現値ではありません。`LeakFinding` は `{category, severity, line_no, rule_id, redacted_excerpt_or_hash}` として扱えます。最後の値は常に `[REDACTED]` です。元データをハッシュして持ち出すこともしません。

| 終了コード | 意味 |
| --- | --- |
| 0 | 入力の指定範囲を最後まで処理し、このルール群の検出なし（安全保証ではない） |
| 2 | 処理完了。ただし1件以上の機密混入疑いを検出 |
| 3 | 解析不能、制限超過、権限拒否、空入力、部分成功、引数不正、セルフテスト失敗 |

`status` は `complete`（評価できた範囲をすべて評価）/ `partial`（途中停止・空）/ `error`（開始時に失敗）/ `permission_denied` を区別します。`warnings` は固定の理由コードだけで、OS例外・パス・元の文字列を含みません。漏えいがあっても `status=complete` になり得るため、`entries` と終了コードを必ず併読してください。

## 規則と範囲

- JSON: 再帰的に文字列のキー/値を検査。重複JSONキーで古い値が上書きされる場合に備え、生のJSON行にも固定パターンを適用（一般的な秘密書式の補助検出であり完全検出ではない）。`password`、`authorization`、`cookie`、`access_token`、`api_key`、`private_key`、`bitlocker_recovery_key` などのキーを検出。`null`・明示的な `[REDACTED]`・`***` 等は誤検知抑制。
- 平文/JSON文字列: Bearer、JWT形、Cookieヘッダー、キー代入、PowerShell引数、機密URLクエリ、Windows/Unixのホームパス、48桁のBitLocker回復パスワード形、秘密鍵PEM見出しを検出。
- HTML数値実体の一部、URLの `%3D` 等の一部、全角英数字を限定的に正規化して検査。
- 長さが十分なランダムなbase64だけでは秘密と決めつけません。強いヒューリスティックスも正常値を誤検出し得ます。

## 上限と非対応

| 監査上限 | 値 | 超過動作 |
| --- | --- | --- |
| ファイル | 8 MiB | error/partial、コード3 |
| 1行 | 64 KiB | 同上 |
| 1つの平文トークン/JSON文字列 | 4 KiB | 同上 |
| 行 | 20,000 | 同上 |
| JSONノード/深さ | 10,000 / 32 | 同上 |
| Findings | 1,000 | 同上 |
| 実行時間 | 約5秒の協調タイムアウト | 同上（厳密なハード中断ではない） |

入力が破損した場合は**正常終了としません**。UTF-8以外（UTF-16、ANSI）、複数行JSON、圧縮/暗号化文字列、完全なUnicode NFKC、エンコードの多重変換、環境変数・コマンド実行で生成される秘密には非対応。JSON文字列/オブジェクト自体の深さもSerde側の既定制限の影響を受けます。複雑なスクリプト・OSに直接残る秘密も探索しません。

ログの全てをクラウドへ送る用途には使わず、監査対象のファイルへの権限を最小化してください。管理者昇格は不要。Windows 11実機、Windowsのリンク/ACL/共有モード、ウイルス対策との同時アクセスは**未検証**です。

## テストと将来の統合

    cargo fmt --all -- --check
    cargo clippy --all-targets -- -D warnings
    cargo test --locked
    cargo run --locked -- self-test

`tests/integration.rs` と `src/lib.rs` のユニットテストは合成データのみ使用。`fixtures/synthetic.jsonl` も架空値です。実行環境にcargo/rustcがないため、上記コマンドは**本PR作成時には実行できていません**。Windows実機テストも未実施です。

将来P5 typed APIに接続する場合は、JSON v1と `module=privacy-audit` を検証し、`coverage.complete`、`status`、`entries`、`warnings` を**別軸**として読み込むアダプターを作成します。`status=complete` を「漏えいゼロ」と解釈しないこと。元のログ本文は持ち込まず、レポートと元入力の識別・権限・保持期間を別途定義してください。

詳細な公式ソース、ライセンス、現行AegisGuard出力契約との対応は `RESEARCH.md` に記録しています。
