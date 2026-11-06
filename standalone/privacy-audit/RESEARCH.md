# プライバシー監査 調査・技術判断

- **確認日：2026-11-06**
- 対象：`choko510/AegisGuard`、`main` の `5c4ce77d12056ef9887ccdf0d622faa08f6f245b`
- 担当：`standalone/privacy-audit/` のみ。`src/`・root Cargo/CI/他担当は変更しない。
- 状態：**実装・コード追加済み / Cargo実行およびWindows 11実機確認は未実施**。Linux/Windowsでコンパイル・実動作した事実はない。
- 調査の方針：一次情報とソースコードが示す事実に限り仕様とする。自作ルールの検出品質は合成試験の実施まで暫定。

## 1. 現行AegisGuardの出力契約（読むだけ）

参照はすべて上記mainコミットのコード。

| 出力源 | 読み取った契約・プライバシー上の点 | 今回の監査方針 |
| --- | --- | --- |
| `src/model.rs` の `Report` | `REPORT_SCHEMA_VERSION = 2`。`path: String`、`assessment`/`signal_level` と `coverage` を含む。検体本文・復号内容は原則出さないが、ローカルファイルパスを保持する。 | JSON object全体の文字列を見て、ホームディレクトリ名入りのパスや秘密フィールドを検査。Schema v2を固定条件にしない。 |
| `src/events/mod.rs` `EventEnvelope` | `ENVELOPE_SCHEMA_VERSION = 1`。`payload_redacted: BTreeMap<String,String>` は許可リスト方式。`CommandLine`/`ParentCommandLine` を `_sha256` 付きで保存し平文を避ける。一方、`Image`/`TargetFilename`/`Path`/`Old Value`/`New Value` の一部は保持される。 | SHA-256を資格情報流出と誤認しない。値を逐語検査してパス、コマンドライン、URL、トークンを検出。`payload_redacted` という名前を安全の証拠にしない。 |
| `src/report.rs` | スキャンJSONLと複数JSONを読みHTMLを構築。パス・テキストはエスケープされる。表示される情報自体はプライバシー情報を含み得る。 | 出力エンコードと秘密削除は別物と判断。HTMLエスケープ済みのテキストも一部復号して監査。 |
| `src/defender.rs` | Defenderの実稼働状態と設定を読む。`ExclusionPath` 等はパスそのものを公開せず件数のみ表示する設計。 | 件数だけなら原則検出しない。将来の拡張で生値が混入した際にキー・値を監査。 |
| `src/jsonl.rs` | 先頭行が対象形式のJSONLか確認し、専用の世代ローテーションで追記する。 | 本CLIは既存JSONL出力を一切開き直して修正/ローテーションしない。指定ファイルを読むだけ。 |

現行本体の `src/events/mod.rs` における `_sha256` は**塩なし固定ハッシュ**であり、元の値の機密性を一般に保証しない。低エントロピーの値の総当たりや、ログを横断する同一値の突合は成立する。SHA-256の整合性用途とプライバシー匿名化を混同しない。今回の `redacted_excerpt_or_hash` は常に `[REDACTED]` として、再識別可能なダイジェストすら出さない方針とした。

コードリンク：

- https://github.com/choko510/AegisGuard/blob/5c4ce77d12056ef9887ccdf0d622faa08f6f245b/src/model.rs
- https://github.com/choko510/AegisGuard/blob/5c4ce77d12056ef9887ccdf0d622faa08f6f245b/src/events/mod.rs
- https://github.com/choko510/AegisGuard/blob/5c4ce77d12056ef9887ccdf0d622faa08f6f245b/src/report.rs
- https://github.com/choko510/AegisGuard/blob/5c4ce77d12056ef9887ccdf0d622faa08f6f245b/src/defender.rs
- https://github.com/choko510/AegisGuard/blob/5c4ce77d12056ef9887ccdf0d622faa08f6f245b/src/jsonl.rs

## 2. 公式資料、採否、制約

### Microsoft — Windowsイベント/コマンドライン

**一次資料**：
- Event 4688: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
- コマンドライン監査の注意点: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
- Sysmon Event ID 1: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- PowerShell保護されたイベントログ: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows

**確認**：Windowsのプロセス作成イベント4688のコマンドラインは設定により平文でイベントログへ残り得る。Sysmon Event ID 1にはフルコマンドラインが含まれる。PowerShellもログ収集水準により認証情報を記録し得る。

**採用**：`-Password` などのコマンドライン引数、Bearer/キー代入の**合成**表現を文字列として検出。実ログの収集やPowerShell呼出し自体は採用しない。Windows 11/Home・Proの差、イベントチャネル権限の差はこのモジュールでは検証対象外。

### Microsoft — BitLocker

**一次資料**：https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/faq

**確認**：BitLocker回復パスワードは48数字・8グループ。回復キー・パスワードは暗号化ドライブへのアクセスに使われる重要秘密。

**採用**：8組×6桁、ハイフン区切りを合成fixtureで検知する。WindowsのBitLocker API（`Win32_EncryptableVolume`、キー保護情報など）にはアクセスしない。48数字の書式は他の文脈にも現れるため、単独一致は誤検知の可能性がある。実機の回復情報は一切取得しない。

### Windows API — ファイルを開く/リンク

**一次資料**：
- `CreateFileW`: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
- `GetFinalPathNameByHandleW`: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew
- Reparse points: https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points

**実際に採用した型**：Rust標準ライブラリの `std::fs::symlink_metadata`、`std::fs::File::open`、`File::metadata`、`std::io::BufReader`。Windows APIは**直接呼び出さない**。管理者権限を要求せず、explicitファイルのみ扱う設計。

**未対応の安全上の制約**：`symlink_metadata` で最後のシンボリックリンクを事前拒否するが、検査とオープンの間に差し替え可能（TOCTOU）。親ディレクトリのreparse pointや、同サイズの再書込み・ハードリンク交換も完全には防げない。開いた前後のファイルサイズ一致は完全な識別確認ではない。Windows固有の `FILE_FLAG_OPEN_REPARSE_POINT`、ディレクトリハンドルを起点にした安全な相対オープン、volume/file IDの比較を代替候補とするが、移植性・複雑さ・実機検証不足によりこのMVPでは不採用。**機密環境で堅牢なハンドル固定が必要なら、別タスクとして実装・テストしてから利用する。**

### Rustクレート — JSONと規則

**一次ソース/仕様**：
- `serde_json` `Value` と `from_str`: https://docs.rs/serde_json/1.0.154/serde_json/enum.Value.html
- `serde_json` Cargo manifest: https://docs.rs/crate/serde_json/1.0.154/source/Cargo.toml
- `regex` 実装の説明とライセンス: https://docs.rs/crate/regex/1.13.1
- `regex` のコード/特徴: https://docs.rs/crate/regex/1.13.1/source/Cargo.toml.orig
- `RegexBuilder::size_limit`: https://docs.rs/regex/1.13.1/regex/struct.RegexBuilder.html

**採用**：`serde_json::Value` を再帰的に調べ、JSON文字列のバックスラッシュ/Unicodeエスケープをパースした**値**として監査。JSONの重複キーで先行値が消えるケースには原文行のルールスキャンも併用する（Unicodeエスケープされた重複キー等は検出保証なし）。`regex::RegexBuilder` で固定パターンをコンパイルしサイズ上限を指定。ユーザー入力を正規表現として評価しない。`regex` の有限オートマトン系エンジンにより破滅的バックトラックを避ける。

**不採用**：JSON全文を生の正規表現だけで判定する方式（エスケープや型を見失う）、無制限のBase64デコード（誤検知・計算資源・元データの増幅）、入力テキストやマッチした文字列の再出力。`String`/`Value` に解析対象が一時的に展開されることは避けられないため、プロセスダンプ/スワップ/メモリ残留までの安全性は保証しない。

## 3. ログ禁止情報・エスケープ・Unicode

**権威資料**：
- OWASP Logging Cheat Sheet（設計指針、Microsoft以外の一次プロジェクト文書）: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- Microsoft HTMLエンコード/XSS: https://learn.microsoft.com/en-us/aspnet/core/security/cross-site-scripting

OWASPは認証情報、セッショントークン、個人情報、暗号鍵などを安易にログへ残さない方針を示す。HTMLで安全に表示するための**コンテキストに沿ったエンコード**と、プライバシーのための秘密値削除は別工程。HTML実体（`&amp;` 等）と全角英数字を限定正規化するのは「監査で見落としにくくする」ためのみ。**完全なUnicode NFKC、類似文字、IDN、複数回エンコード、UTF-16やShift_JIS等は未対応**。HTMLへ結果を組み込む際も出力側で適切なエンコードが必須。

**False Positive管理**：短い `key`/`token` の通常語、単なるBase64風の文字列、マスク済み値、`C:\Users\Public` などは不用意に高危険判定しない。JSONの `password` など強いキー名は値がマスク済みでなければ条件付きで検出する。テンプレートの `token=` やパス文字列には誤検知が残る。強い検出ルールだけで「漏えい確定」と断定しない。

**False Negative管理**：未知フィールド名、短い秘密、パスの異表記、改行分割/暗号化済み秘密、JSON文字列以外のデータ、画像/添付、ネットワークに流れるデータは検出できない。監査対象の全てを読めなかった場合、`status=partial/error/permission_denied` と終了コード3を返し、検出ゼロを「合格」にしない。

## 4. 実装上の制限と運用

- 入力は明示された単一UTF-8ファイル。プログラム自体はファイル書換え、ログ保存、OS監査ポリシー変更、インターネット接続をしない。
- 8MiB/64KiB行/4KiBトークン/2万行/1000検出/1万JSONノード/32階層/約5秒を上限とする。`Read::take` と `BufRead::read_until` で、長い行を丸ごと無制限に読み込まない。
- 上限到達・不正UTF-8・壊れたJSONは部分成功かエラー、終了コード3。権限拒否は独立の状態。空入力も部分成功として扱う。
- `LeakFinding.redacted_excerpt_or_hash` は固定マーカー。秘密をstdout/stderr/保存ファイルへ複製しない。パス・ユーザー名・エラー文字列の生値も出さない。
- 読み取り中の同サイズ改変、ハンドル取得時の競合、外部からの強制終了、短時間でのメモリ不足、Windowsファイル共有/ACLの挙動は残存リスク。
- 任意のJSONを文字列として出力するのは検査結果の**固定フィールドのみ**。原文を含むpanic文やログ出力を呼ばない。
- 既定で外部サービスやDefenderの設定を変更しない。

## 5. ライセンス・依存の調査

直接依存のみを固定している。

- `regex = 1.13.1`：公式リポジトリ https://github.com/rust-lang/regex 、MIT OR Apache-2.0。Unicodeテーブルは追加のUnicode License表記あり。
- `serde_json = 1.0.154`：公式 https://github.com/serde-rs/json 、MIT OR Apache-2.0。
- Rust標準ライブラリ・既存AegisGuard本体コードのコピーはなく、本体依存はゼロ。
- `Cargo.lock` のパッケージとチェックサムは2026-11-06時点のAegisGuardメインのロックから固定版と依存閉包を抜き出して作成。**Cargo生成・再解決は未実施**。不要なoptional依存が含まれる可能性があり、Cargoによる `--locked` 検証を残す。
- AegisGuardのmain直下には確認時点で `LICENSE`/`LICENSE-MIT`/`LICENSE-APACHE` が存在しない。そのため本パッケージは `publish = false` とし、独自のライセンス指定は保留。依存クレートのライセンスとは別に、リポジトリ全体の配布条件を所有者がマージ前に確認する必要がある。
- 外部GPL/AGPLソースコード・独自ルールは複製していない。第三者コードの詳細ライセンス監査・脆弱性DB照合は `cargo-deny` 等が使える環境で再確認する。

## 6. テスト計画/実施状況

**追加したが未実行**：
- `src/lib.rs`：JSON/ログ、Bearer/PowerShell/URL/Cookie/JWT/BitLocker形、マスク・全角、巨大行、UTF-8破損、不正JSON、未評価入力、出力に秘密を含めないこと。
- `tests/integration.rs`：CLI終了コードとstdout/stderr、部分成功、重複規則、HTML実体、権限拒否mock、出力時刻、Unixのsymlink拒否。
- `fixtures/synthetic.jsonl`：架空値のみ。実アカウント、実回復パスワード、ブラウザCookieは一切使用しない。
- `self-test`：架空の7ケースを読み取り、固定構造のJSONで結果を返す。

**2026-11-06 実施不可**：実行環境に `cargo`、`rustc`、`rustfmt` がなく、外部ネットワークの名前解決もできない。`cargo fmt --all -- --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test`、`cargo build --release` はすべて**未実行**。未検証を成功と記載しない。

**Windows 11実機：未実施**。一般ユーザー/管理者、32/64bit、Windowsリパースポイント・ACL・共有ロック・エンコーディング・Defenderとの干渉、偽陽性、性能、長時間実行を測定していない。CLI単体にはWindows APIコールが無いが、Windows上のファイルオープン挙動は本体とは異なる可能性がある。

## 7. P5 typed APIへの将来接続案

提案するアダプター入力：`PrivacyAuditResultV1 {schema_version, module, generated_at_unix_ms, status, entries: Vec<LeakFinding>, warnings, coverage}`。P5側で型を定義する（今回変更しない）。`status=complete` と `entries.is_empty()` は独立した軸として扱い、`coverage.complete=false`・読み取った行数0・unknown schemaは明確な未評価にする。報告したルールIDは不変の機械判定IDとしてバージョン管理し、P5のログ出力/GUIへ原文のコピーをしない。これによりP5〜P10と並行実装しても変更競合しない。
