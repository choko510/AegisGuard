# AegisGuard：P5〜P10と並行する独立7担当AI

各担当は **[共通プロトコル](PROTOCOL.md)** と **自分のプロンプト1件**を読んで、調査→独立Rust CLI実装→テスト→**日本語PR提出（マージしない）**まで進める。

| 担当 | 個別プロンプト | 実装する専用フォルダー |
|---|---|---|
| A 永続化監査 | [persistence-audit](prompts/persistence-audit.md) | `standalone/persistence-audit/` |
| B ダウンロード出所監査 | [file-origin-audit](prompts/file-origin-audit.md) | `standalone/file-origin-audit/` |
| C Windows防御状態診断 | [windows-posture](prompts/windows-posture.md) | `standalone/windows-posture/` |
| D ドライバー・サービス棚卸し | [driver-inventory](prompts/driver-inventory.md) | `standalone/driver-inventory/` |
| E インストール済ソフト・CVE監査 | [software-audit](prompts/software-audit.md) | `standalone/software-audit/` |
| F 無害な合成データ検証ラボ | [validation-lab](prompts/validation-lab.md) | `standalone/validation-lab/` |
| G ログ・レポートの機密情報QA | [privacy-audit](prompts/privacy-audit.md) | `standalone/privacy-audit/` |

## 実行方法

1. このプロンプト一式が`main`に入った後、7つの別セッションで各担当URLを渡す。マージ前ならこのブランチのblob URLを使い、プロトコルもこのブランチから読むよう指示。
2. 各担当は**最新mainから**独立した`standalone/<slug>`ブランチを切り、指定のフォルダー以外のファイルを変更しない。
3. 7件とも別PRを作成し、ユーザーのレビューを受ける。**各AIにはマージさせない**。P5〜P10が終わってから共通APIへの接続を別PRで行う。

## 起動用の短い依頼文

以下の担当プロンプト全文と、同じブランチの `docs/parallel-agents/PROTOCOL.md` を読んでください。必ず公式仕様と既存コードを調査し、指定された自分専用の`standalone/<slug>/`だけを使って独立したRust CLIを実装・テストし、日本語のPRを作成してください。調査のみで終了しないでください。既存P5〜P10の変更ファイル、ルートCargo、CI、他担当は一切変更せず、PRをマージしないでください。
