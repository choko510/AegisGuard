# 調査＋実装担当B：ダウンロードファイルの出所監査

あなたは **choko510/AegisGuard の独立Rustモジュール開発担当** です。外部仕様の調査・技術選定・コード実装・テスト・日本語PRまで**この作業で完遂**してください。P5〜P10と同時進行中なので、対象外の既存実装は変更しないでください。

**担当ID：** file-origin-audit
**リポジトリ：** https://github.com/choko510/AegisGuard
**編集可能なパス：** `standalone/file-origin-audit/` **以下だけ**
**作業ブランチ：** `standalone/file-origin-audit`（最新mainから作成。衝突する場合は一意な別名）
**提出PRタイトル：** `調査・実装: ダウンロードファイルの出所監査`
**作業条件：** **PRを作成するがマージしない**。他の6担当のディレクトリにも触れない。

## 0. まず読み込む

**`docs/parallel-agents/PROTOCOL.md` の全文**、このプロンプトの全文、最新のルート`README.md`/`SECURITY.md`/`docs/ARCHITECTURE.md`、現在のオープンPRと担当パスの重なり。共通プロトコルの書込禁止・read-only・安全テスト・PRルールは絶対条件です。プロンプトを読み飛ばしたまま実装しないこと。

## 1. 目標

実行ファイル・スクリプトなどのダウンロード出所に関するWindowsメタデータを、ファイル内容を実行せずに読み取り専用で解析する。

## 2. 調査で突き止めること

- Microsoftの Attachment Services/Mark-of-the-Web、NTFS Alternate Data Streams (`Zone.Identifier`)、FILE_STREAM_INFORMATIONまたは列挙APIの公開仕様を調査。Web由来の印の意味・ない場合でもネットから来た可能性を説明。
- ZIP/解凍・コピー・他FS・クラウド同期によるMOTWの伝播差、ACL/NTFS以外のFS、偽装された`HostUrl`や`ReferrerUrl`の信頼限界、streamサイズ制限を確認。
- URLに認証トークンが含まれる可能性があるので**raw URLは既定出力しない**。ドメイン以外はredact/hashできるか調査。

各技術選択について、Microsoft等の**一次情報URL、確認日、採用したAPI/関数/型と制約、代替案と不採用理由**を`standalone/file-origin-audit/RESEARCH.md`に残してください。Windowsで実行していないものは「実機未確認」とすること。

## 3. 実装を完了する内容

- CLI：`file-origin-audit inspect <path> --format json`、`file-origin-audit inspect-fixture <fixture>`。読み取り専用でZoneId、MOTWの有無/読取可能性、最小限の出所（必要ならホスト名のみ）を返す。
- `status` は`present/absent/not_supported/permission_denied/error`などの観測状態。MOTWが欠けても`trusted`とは判定しない。
- トラバーサル/reparse point/TOCTOUに注意。ファイルの実行、出所URLへのアクセス、Zone.Identifierの変更・削除はしない。

**リポジトリの既存モジュールをimportしてコンパイルさせない。** 単独`Cargo.toml`で構築し、`README.md`にCLI使用例とJSON出力例、権限、非対応、統合先となる将来の型を記載。少なくとも動作するMVPと安全なfixture経路を完成させること。広範囲な機能で全件が実装できなければ、どこまでが実装済みか明示し、未完了を成功扱いしない。

## 4. テストすべき条件

- 無害なMOTWのZoneId 0〜4、CRLF/Unicode/BOM、未知キー/重複キー、長大stream、改行挿入、認証トークン付きURL、ADSなし、FAT等非対応、symlink、アクセス拒否、直前のファイル差し替え。
- 外部インターネットアクセスなしでfixtureパーサーを試験。Windows実機では手元の無害なテストファイルに限定する。

安全なfixtureとWindows/APIのモックを用意し、入力異常・時間/件数/ファイルサイズ上限・権限拒否・誤判定を明示的に検証。Linux上でWindows APIの実機成功を捏造しない。`cargo fmt --all -- --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test` を専用フォルダーから実行し、失敗は直す。

## 5. 提出条件

- 追加/編集：`standalone/file-origin-audit/` 内の`src/`・`tests/`・`Cargo.toml`・`Cargo.lock`・`README.md`・`RESEARCH.md`などのみ。
- 出力はversion付きJSON。診断不能/権限なし/部分成功と空・安全を区別。危険入力、誤検知、秘密の漏出を見逃さない。
- **最新mainからPR**、日本語タイトル/説明。PR本文には使った公式仕様/ライセンス、達成した機能、未実装、テスト実績、Windows実機有無、リスク、将来のP5 typed APIへの接続案を記載。
- PR前に`git diff --name-only origin/main...HEAD`を確認して**自分の専用フォルダー外の変更ゼロ**を保証。
- **PRはマージしない**。最後にPR URL・成果物・重要な技術判断・テスト結果・残課題を報告。コネクタが書けない場合はその事実を述べ、作成したファイルを引き渡す。

**調査報告だけで作業を終えないこと。実装と検証まで責任を持って進めること。**
