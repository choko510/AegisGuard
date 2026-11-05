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
