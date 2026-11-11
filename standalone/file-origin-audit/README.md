# file-origin-audit (standalone MVP)

Windows 11 向けの **読み取り専用** Mark-of-the-Web (MOTW) / `Zone.Identifier` 監査CLIです。AegisGuard本体への依存・組み込みはありません。ファイル本文、実行ファイル、スクリプト、URLへアクセス・実行・送信しません。**MOTWの欠落・ZoneId=0/1/2を安全判定に使わないでください。**

## ビルド・使用例

Rust 1.85以上。依存crateなし。**このディレクトリから**実行します。

```powershell
cd standalone/file-origin-audit
cargo build --release
.\target\release\file-origin-audit.exe inspect "C:\Users\me\Downloads\sample.exe" --format json
.\target\release\file-origin-audit.exe inspect-fixture "fixtures\zone3.ini"
```

Linux/macOS での `inspect` は `not_supported/unavailable` を出力し、Windows処理を実行しません。`inspect-fixture` はOSに依存せず、無害な INI バイト列だけを最大64 KiB読み込みます。指定ファイルがシンボリックリンクなら拒否します。

### JSONスキーマ v1.0.0 の例

```json
{
  "schema_version": "1.0.0",
  "module": "file-origin-audit",
  "generated_at_unix_ms": 1793888000000,
  "status": "present",
  "entries": [
    {
      "status": "present",
      "motw_present": true,
      "zone_id": 3,
      "zone_name": "internet",
      "source_url_recorded": true,
      "referrer_url_recorded": true,
      "origin_confidence": "unverified",
      "probe": "fixture"
    }
  ],
  "warnings": ["metadata_is_untrusted"],
  "coverage": "complete"
}
```

- **`status`**: `present` (ストリーム観測), `absent` (対応ボリュームで観測できず), `not_supported` (非対応), `permission_denied`, `error`。Windowsでない場合も `not_supported`。
- **`coverage`**: `complete` (対象ストリームの観測に成功。無害性を意味しない), `partial` (ストリーム有り、ZoneId不明/不正/曖昧), `unavailable`, `permission_denied`, `error`。MOTWが無い場合でも評価範囲は完全なので `complete`、しかし `absence_does_not_imply_safety` の警告付き。
- **`motw_present`**: `true` / `false` / `null` (不明)。`zone_id` は0〜4か `null`、`origin_confidence` は常に `unverified`。
- **秘密保護**: `HostUrl`/`ReferrerUrl` は存在フラグのみ出力します。**URL、ドメイン、query、トークン、ファイルパスは標準出力・stderrに一切出さず、ハッシュ化もせず保持しません**。このためネットワーク問い合わせ・DNS解決もありません。
- コマンドライン引数が不正なら終了コード2、`coverage=unavailable/permission_denied/error` は3、`complete/partial` は0。機械処理では終了コードだけでなく `coverage` と `entries[].status` の両方を確認してください。
- JSONは標準出力に1行のみ。診断は固定文言のstderrのみ。無制限のフォルダー列挙や再帰処理はありません。

## 権限・安全上の境界

- 通常ユーザーによる対象ファイル/ADSの読み取り権限が必要。昇格しない。OS設定や `Zone.Identifier` の作成・削除・変更はしない。
- Windows: ローカルのドライブ文字から始まる**絶対ファイルパスのみ**。UNC/デバイス名前空間/マップ済みネットワークドライブ/再解析ポイント（対象および祖先）/ディレクトリ/疑わしいADSパスを拒否します。
- `FILE_FLAG_OPEN_REPARSE_POINT` 付き読み取りハンドル、開いたベースファイルに対する `GetFinalPathNameByHandleW` の正規化済み最終パス照合（初回・事後）、ベースファイルとADSの128-bit FileId/volume ID照合、読み取り後の再オープンとサイズ・更新時刻確認を行います。照合が不一致・取得不能なら **`path_identity_mismatch` / `resolved_path_unavailable` 等のエラーで失敗側に倒します**。ただし最終パス照合自体は原子的な親ディレクトリ固定ではなく、検査中にディレクトリを差し替える高度な競合、ハードリンク、同一IDへの書換え、同サイズ/同時刻の変更を**完全には防げません**。
- 入力は1ファイル、パス最大2048文字、ADS/fixture最大65536バイト、最大1024行、1行最大8192文字、文字コードはUTF-8/BOM付きUTF-8/UTF-16 LE・BE BOM。読み込みは65537バイトで打ち切り。3秒のソフト処理制限がありますが**OSの同期I/Oのハードタイムアウトではありません**。
- 不正形式、未知のZoneId、ZoneId重複、制御文字、長大入力は `partial` または `error`。HostUrl/ReferrerUrl は署名・検証済みデータではなく、攻撃者による偽装が可能です。
- ZIPの解凍やクラウド同期をまたいだMOTWの有無は出所・処理方法・アプリ・バージョンに依存します。このCLIは「どうダウンロードしたか」「どのサイトが本物か」について断定できません。

## テスト

```bash
cd standalone/file-origin-audit
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

合成fixture、ZoneId 0〜4、CRLF/Unicode/BOM、未知キー・重複・改行攻撃、長大stream、秘密URLの無出力、ADS欠損・権限拒否・非対応・差し替えの模擬、Unix symlink拒否を `tests/fixture_tests.rs` に収録。`tests/windows_integration.rs` はWindowsで一時ファイルに無害なADSを作り、MOTWの実読取り・最終ファイル/親ディレクトリのsymlink拒否を確認します。symlinkの作成権限がない場合は警告してスキップするため、必須テストでは `FILE_ORIGIN_AUDIT_REQUIRE_REPARSE=1` を指定してください。

**Windows 11 / ローカルNTFSでの実機確認（ユーザーが手元で実行する検証コマンド）**:

```powershell
cd standalone/file-origin-audit
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
.\tests\run-windows-ntfs.ps1 -WithAcl -RequireReparse
```

`run-windows-ntfs.ps1` は新しく作成した**無害な一時ファイルだけ**に対してADSの作成、symlink作成、オプションのアクセス拒否ACL付与を行い、`finally` で元に戻して削除します。**本体CLIは読み取り専用のまま**です。テストスクリプトの `-WithAcl` はテストファイルに読み取り拒否ACEを追加・復元します。symlinkにはWindows Developer Modeまたは対応権限が必要です。環境がNTFSでない場合は失敗となり、検証済み扱いにしません。

**検証状況**: この追加時点ではWindows 11実機および専用crateのCargoコンパイル/テストは**未実行**です。ルート`.github/workflows/ci.yml` の成功はAegisGuard本体の成功であり、この独立crateのテスト成功を意味しません。Windows実機でのADS・ACL・再解析ポイントの出力結果とコマンド終了コードを取得した後にDraft解除を判断してください。再解析ポイント競合のストレステスト、FAT32/exFAT/ReFS差分、同期I/Oのハードタイムアウトは依然として未対応です。

## 将来のP5型付きAPI接続

将来は `schema_version` を検査するadaptorでこのJSONを `FileOriginEvidenceV1 { status, coverage, zone_id: Option<u8>, motw_present: Option<bool>, source_url_recorded: bool, referrer_url_recorded: bool, warnings: Vec<String>, observed_at_ms }` としてマッピングし、スキャン結果と**別軸**で相関します。`absent` を `trusted` に変換せず、未観測状態は `None` を維持してください。P5〜P10の本体や共有スキーマには本PRから変更を加えません。

技術選定、一次情報、ライセンス・未検証事項は [RESEARCH.md](RESEARCH.md) を参照してください。
