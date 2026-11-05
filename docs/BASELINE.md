# 初期ベースライン（P0-05）

CIの `baseline` ジョブが毎回同じ合成コーパスで再計測し、ジョブサマリーと成果物 `baseline-<OS>` に残します。ここには**最初の記録**だけを固定して残します。**性能の合格閾値は未設定**です（Windows 11実機での計測は未実施のため）。

- 計測日：2026-11-05、コミット `b1cc71b`（PR #23）、GitHubホストのランナー（`ubuntu-latest` / `windows-latest`）
- コーパス：`cargo run --example bench_corpus -- generate`（900ファイル、決定的に生成、何も実行しない）
- コマンド：`aegisguard scan bench/corpus --recursive`（releaseビルド、既定の上限）

| OS | 経過時間 | CPU時間 | 最大メモリ |
| --- | --- | --- | --- |
| Linux | 0.09 s | 0.09 s（user 0.07 + sys 0.02） | 42.3 MiB（最大RSS） |
| Windows | 0.70 s | 0.47 s | 39.0 MiB（20 msごとに採取した最大ワーキングセット） |

ディスク：読み取りのみ。出力はJSONL（標準出力）だけで、走査対象は変更しません。

## 判定の分布（合成コーパス）

| category | low_signal | review | high | incomplete | not_assessed |
|---|---|---|---|---|---|
| benign | 400 | 0 | 0 | 0 | 0 |
| benign_admin | 0 | 300 | 0 | 0 | 0 |
| benign_pe | 100 | 0 | 0 | 0 | 0 |
| synthetic_positive | 0 | 0 | 100 | 0 | 0 |

- `benign_admin`（インストーラーのダウンロード＋`Start-Process`、スケジュールタスク登録、`requests`＋`subprocess`）は**全件が誤検知候補**です。現行ヒューリスティックの既知の弱点として残し、ルール変更時はこの表と比較します。
- 合成データだけの結果で、実環境の検出率・誤検知率ではありません。

## P5-02 誤警告対策後（組み込みルール `builtin-static-2`）

`src/script.rs` に、コメントの分離（PowerShell `#`/`<# #>`、Python `#`、JavaScript `//`/`/* */`、BAT `rem`/`::`、VBS `'`。文字列リテラル内の記号はコメント扱いしない）と、文（行継続・`;`）単位の評価を追加した。

- **ダウンロード→コード実行**（`download_and_execute`, 45）：取得した内容が、同じ文で、または取得結果を代入した変数（推移的に追跡）を通して `iex` / `Invoke-Expression` / `eval` / `exec` などへ渡る場合だけ。
- **ダウンロードとプロセス起動が同じファイルにあるだけ**：`download_and_run`（20、記録はするが単独では `low_signal`）。平文HTTP・IPアドレスのURL・一時/ユーザー書込み可能パス・非表示ウィンドウを伴えば `download_and_run_staged`（35、`review`）。
- **永続化**：Runキー、またはスクリプトホスト・非表示/エンコード済みコマンド・ユーザー書込み可能パス・URLを実行するタスク/サービスは `persistence`（30）。それ以外のタスク/サービス作成は `persistence_admin_task`（15）。
- **コメント内だけの指標**：`indicator_in_comment_only`（5）として記録し、隠さない。
- 資格情報参照＋送信（`possible_exfiltration`, 75）は従来どおりファイル単位の共起で判定し、弱めていない。

### 合成コーパス（`summarize --check` でCIのゲートにした）

| category | low_signal | review | high | incomplete | not_assessed |
|---|---|---|---|---|---|
| benign | 400 | 0 | 0 | 0 | 0 |
| benign_admin（元の300件、期待値は書き換えていない） | 300 | 0 | 0 | 0 | 0 |
| benign_admin_extra（コメント内の指標・更新確認：新規の対照群） | 300 | 0 | 0 | 0 | 0 |
| benign_pe | 100 | 0 | 0 | 0 | 0 |
| synthetic_positive（元の100件） | 0 | 0 | 100 | 0 | 0 |
| synthetic_positive_more（取得→実行、危険な永続化＋除外設定：新規） | 0 | 200 | 100 | 0 | 0 |

ゲート：`benign_admin` の review/high が15件以下、他の benign 系は0件、`synthetic_positive*` は全件が review 以上。合成データでの結果であり、実環境の誤検知率・検出率ではない。

### 実機（このWindows 11の付属スクリプト、読み取りのみ）

2026-11-05、変更前（`builtin-static-1`）と変更後を同じファイルで比較（スクリプトのみ集計）。

| 対象 | 変更前 review/high | 変更後 review/high |
|---|---|---|
| `C:\Windows\System32\WindowsPowerShell\v1.0`（239件） | 7 / 1 | 3 / 1 |
| `C:\Program Files\WindowsPowerShell\Modules`（103件） | 2 / 0 | 1 / 0 |
| `C:\Windows\diagnostics`（378件） | 0 / 0 | 0 / 0 |

残る指摘の主因は、モジュールマニフェスト（`.psd1`）がコマンド名を**文字列として列挙**していること（例：`Invoke-Expression` を含むエクスポート一覧）。文字列リテラルと実際の呼び出しの区別は構文解析（P5-03）で扱う。`PSDesiredStateConfiguration.psm1` は review から `incomplete`（既存の `candidate_match_limit`）に変わったが、未完了の表示であり安全扱いではない。

## P5-03 第1段階：PowerShellの文字列リテラルの分離（`builtin-static-3`）

PowerShellの文字列（`'...'`・`"..."`・ヒア文字列 `@'...'@` / `@"..."@`）の中身を空白に置き換えた「コード部分」と、元の全文の両方で判定するようにした。コマンド・呼び出しの指標（ダウンロード、実行、タスク/サービス作成、Defender除外・ログ消去のコマンド）はコード部分で、データの指標（URL、資格情報ストア名、Runキーのパス、AMSIの型名）は全文で見る。`iex` などコード実行に渡る文は全文で読む（文字列がコードとして実行されるため）。`$(...)` を含む展開文字列と閉じていない文字列は空白化しない。

| 対象（このWindows 11、スクリプトのみ） | P5-02後 review/high | P5-03後 review/high |
|---|---|---|
| `C:\Windows\System32\WindowsPowerShell\v1.0` | 3 / 1 | 0 / 0 |
| `C:\Program Files\WindowsPowerShell\Modules` | 1 / 0 | 1 / 0（PowerShellGet の `PSModule.psm1`：実際にモジュールを取得・導入する処理） |
| `C:\Windows\diagnostics` | 0 / 0 | 0 / 0 |

合成コーパスのゲート（benign 系 0 件、synthetic_positive 系は全件 review 以上）は維持。
