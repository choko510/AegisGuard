# AegisGuard 7担当：並列調査＋実装 共通プロトコル

この文書と担当個別プロンプトを**全文読んでから開始**。調査だけで止まらず、担当専用のRustモジュールを実装・テスト・**日本語PR提出まで**進める。P5〜P10とは別系統の作業。

## 競合回避の絶対ルール

- 変更できるのは、個別プロンプトで指定した **`standalone/<slug>/` 以下だけ**。他の7担当とも書き込み領域を共有しない。
- **変更禁止**：ルート`Cargo.toml` / `Cargo.lock` / `src/` / `apps/` / `crates/` / `tests/` / `examples/` / `rules/` / `docs/` / `.github/` / `.cargo/` / ルート`README.md` 等、上記専用フォルダー以外すべて。共通スキーマ/ルートCI/ルートWorkspaceへの統合も今は行わない。
- 担当専用の`standalone/<slug>/Cargo.toml`と`Cargo.lock`により**独立したCargoパッケージ**を構成する。既存`aegisguard`ライブラリに依存しない。後日統合できるようにJSON APIだけ文書化する。
- 必ず最新`main`とオープンPRを確認。既に同担当実装が存在すれば競合を避ける。専用ブランチ`standalone/<slug>`（名前衝突時は一意な名前）を**最新mainから作成**。担当ディレクトリだけをコミット。**PRは日本語タイトル/説明・マージ禁止**。
- デフォルトは**読み取り専用**。OSのレジストリ/タスク/サービス/Firewall/Defender/監査設定を変更しない。管理者昇格、ドライバーのロード・停止、ソフトの実行・削除・隔離・インストール、マルウェアの実行、ブラウザ資格情報の収集、外部への端末情報送信をしない。

## 必須ワークフロー

1. **リポジトリ確認**：最新mainと進行PR、既存技術基準を確認。`README.md`、`SECURITY.md`、`docs/ARCHITECTURE.md`、現行CLI/JSONL契約を読む。
2. **一次情報による調査**：Microsoft Learn等の公式API仕様と実際の実装候補の依存/ソース/ライセンス、Windows 11の権限・32/64ビット、欠損時挙動、性能・プライバシーを調査。`standalone/<slug>/RESEARCH.md`に日付・参照URL・採否理由・未確認事項を残す。推測と確認済みを区別。README要約だけの調査は不可。
3. **設計**：独立CLI、有限の入力件数/バイト数/時間、JSONスキーマ、警告/評価不能の意味、非Windows対応方針、将来の統合アダプター案を決める。
4. **実装**：`standalone/<slug>/{Cargo.toml,Cargo.lock,src/,tests/,README.md,RESEARCH.md}`内で実装。Windows固有は`#[cfg(windows)]`で明示分離。GUIや本体のサービスは作らない。外部GPL/AGPLコードの無断コピーはしない。
5. **テスト**：無害な合成fixtureを必ず用意し、正常/欠損/権限不足/不正形式/過大入力/空/重複/変動する時刻を確認。各パッケージ内で`cargo fmt --all -- --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test`。Windows利用可能なら`cargo build --release`と安全な実環境read-onlyテストも実施。Windows実機がない場合は**未実施と明示**、コンパイルしたふりをしない。
6. **提出**：日本語PR（マージしない）。PR説明に実装範囲、調査根拠、コードの変更一覧、実行したコマンド/成功・失敗、実機未確認、必要権限、プライバシー/性能、将来の統合案を書く。最後にPR URL・成果物URL・未達事項を報告。

## 共通JSONと品質

各CLIは機能ごとにバージョン付きの構造化JSONを標準出力し、`schema_version`、`module`、`generated_at_unix_ms`、`status`、`entries`、`warnings`、`coverage`を基本とする。テキスト診断はstderrへ。`complete/partial/unavailable/permission_denied/error`を区別し、0件・見つからない・監査できないことを「安全」と見なさない。

取得件数、サイズ、入力解析、ネットワークアクセス、時間、メモリ、出力を上限管理。失敗・キャンセルは理由付き。秘密/個人情報/回復キー/認証情報/コマンドライン中のパスワード・ブラウザDB本文を保存/出力しない。フォルダーやプロセスのパスは可能ならredact/hashする。データによるpanic・無制限割り当てを防ぐ。

**最終diffに担当`standalone/<slug>/`以外があれば必ず除外**。本体や他の7担当に触れない。実装・テスト不能な環境であれば可能な範囲を作り、未完了の理由をPR本文に明記する。
