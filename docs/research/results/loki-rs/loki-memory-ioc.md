# 調査報告：Loki-RS / loki-memory-ioc

> 担当：`loki-memory-ioc` / 調査日：2026-11-05（JST） / 調査結果：**ソース調査完了・実機検証未実施**

## 0. 結論（3〜5行）
- **AegisGuardに取り入れる価値：高。ただし移植対象は「機能の考え方」と「観測契約」であり、Loki-RSの全プロセス一斉メモリ読取を最初の常時保護機能にはしない。** Windows版には実働を意図した読取処理がある一方、領域境界・欠落・権限拒否の扱いと同時実行負荷に穴がある。
- **最優先候補：** ①プロセス/通信/IOCの相関を観測専用で設計、②IP・ドメイン・ハッシュの出所/鮮度/不確実性を統一、③利用者が明示した対象に限定した読み取り専用メモリPoC。
- **見送り候補：** 全プロセスの並列・周期的な400MiB級メモリ収集と、Loki-RS本体のソース取り込み（GPL-3.0、AegisGuard側ライセンス未設定）。
- **最大の制約：** PPL・アクセス制御、読取できなかった領域を「陰性」にしないこと、機密メモリの取り扱い、ルール/IOCの権利確認と誤検知。
- 重要な実装上の発見：Loki-RSは**各メモリ領域をひとつのバイト列に連結してYARA-Xへ渡す**。領域境界を失い、未読領域・個別失敗の証跡が残らないため、AegisGuardでは採用しない（[src/modules/process_check.rs:800-865](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L800-L865)）。

## 1. 対象の固定と調査方法

| 要素 | 値 / 根拠 |
|---|---|
| 公式リポジトリ・commit固定URL | [Neo23x0/Loki-RS（固定リビジョン）](https://github.com/Neo23x0/Loki-RS/tree/0866b3d0e32d82f8b5776f61c67b655a34a55b4a) |
| 調査コミットSHA・タグ | `0866b3d0e32d82f8b5776f61c67b655a34a55b4a`、デフォルトブランチ `master`、`Cargo.toml` version `2.13.1` / 公開リリース `v2.13.1`（2026-09-27）。[Cargo.toml:1-18](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/Cargo.toml#L1-L18) |
| AegisGuardの比較先SHA | `83fcf0d150e8d760baff5f971c106deb09c1f8e4`、2026-11-05取得の `main`。[README.md:1-22](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md#L1-L22) |
| ライセンスファイルと対象範囲 | Loki-RSルート [LICENSE（GPL v3原文）](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/LICENSE#L1-L25)、[READMEのライセンス宣言](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/README.md#L324-L326)。同梱 `vendor/yara-x` は [Cargo metadataでBSD-3-Clause表記](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/vendor/yara-x/Cargo.toml#L12-L38)。外部ルールは別途確認を要する。 |
| ソース/ドキュメント確認範囲 | `src/modules/process_check.rs`, `src/main.rs`, `src/helpers/{yara,throttler,helpers,unified_logger}.rs`, `src/loki_util/main.rs`, `Cargo.toml`, `LICENSE`, `README.md`, `USAGE.md`, `.github/workflows/test.yml`, `tests/`の検出・権限テスト、`docs/parity_matrix.md`。AegisGuard側 `src/{c2,scan,model,main}.rs`、`Cargo.toml`、`README.md`、`SECURITY.md`、`docs/ARCHITECTURE.md`。 |
| 実機・ビルド・テスト | **未実施。** GitHubソースとテスト定義の静的読解。Windows 11上での実行、管理者/PPL/Defender共存、CPU/メモリ実測、CI実行結果の検証は実施していない。悪性検体を実行していない。 |
| 日付・未検証制限 | 2026-11-05。対象SHA以降の修正・外部ルールの将来の内容は対象外。Microsoft公式API契約とコード構造からの推論は「推定」と区別する。 |

AegisGuardの現行実装は、ファイル/フォルダ静的検査とC2 IP手動更新・オフライン照合のCLIであり、Windowsセンサー/サービス/ETW/Sysmon連携/AMSI/WFP遮断は計画段階（[src/main.rs:1-77](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/main.rs#L1-L77)、[docs/ARCHITECTURE.md:7-42](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L7-L42)）。したがってプロセス診断は既存機能への単純なスイッチ追加ではない。

## 2. 実装アーキテクチャとソース調査

| 機能 | 主要なファイル/シンボルと役割 | commit SHA固定の一次情報 | 確認状態 |
|---|---|---|---|
| CLI入口・既定範囲 | `Cli` の `--no-procs` / `--no-fs`、`--threads`、`--cpu-limit`、`--yara-timeout` 等。プロセス検査は通常のスキャン経路。 | [src/main.rs:21-54](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L21-L54)、[src/main.rs:115-163](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L115-L163) | 実装確認 |
| プロセス列挙・選別 | `scan_processes`：`sysinfo::System::new_all/refresh_all`、Rayon `par_iter`。自PID・同一実行ファイルのみ除外。 | [src/modules/process_check.rs:103-187](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L103-L187) | 実装確認 |
| プロセス属性・ファイルハッシュ | `process_single_process`：PID/PPID、開始時刻、コマンドライン、ユーザー、CPU/メモリ、実行ファイルのMD5/SHA-1/SHA-256。実行ファイルは `std::fs::read` で丸ごと読む。 | [src/modules/process_check.rs:233-275](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L233-L275) | 実装確認 |
| Windowsメモリ読取 | `read_process_memory`：`OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ)` → `VirtualQueryEx` → `MEM_COMMIT` かつ `PAGE_NOACCESS/PAGE_GUARD` でない領域 → `ReadProcessMemory` → `CloseHandle`。総読取最大400MiB。 | [src/modules/process_check.rs:800-865](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L800-L865) | 実装確認 |
| YARA-Xプロセス照合 | 取得した連結バッファに `Scanner::scan` とタイムアウト。メタデータ・マッチ文字列を結果へ格納。読取バッファが空なら `skipped`。 | [src/modules/process_check.rs:453-519](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L453-L519)、[src/modules/process_check.rs:529-629](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L529-L629) | 実装確認 |
| メモリ失敗時の継続 | `OpenProcess`失敗・`ReadProcessMemory`失敗を領域単位で返さず、成功したデータのみを連結。YARAのエラーは専用ロガーに流して続行。 | [src/modules/process_check.rs:800-865](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L800-L865)、[src/helpers/yara.rs:11-58](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/helpers/yara.rs#L11-L58) | 実装確認・完全性は**未担保** |
| ファイル名/ハッシュIOC | `initialize_hash_iocs` / `initialize_filename_iocs` と `find_hash_ioc`：手元の `signatures/iocs` を読み、ハッシュ検索・パス/コマンドライン正規表現とFP例外を適用。 | [src/main.rs:288-395](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L288-L395)、[src/main.rs:736-873](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L736-L873)、[src/modules/process_check.rs:350-450](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L350-L450) | 実装確認 |
| IP/ドメインIOC | `initialize_c2_iocs` は `c2` 名のローカルファイルから `server;score` を読込。 `check_c2_match` はIPv4完全一致、文字列末尾のドメイン照合。CIDRはTODO。 | [src/main.rs:568-733](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L568-L733) | 実装確認（宣伝との差に注意） |
| プロセス通信取得 | `get_process_network_info`：`netstat2` でTCP/UDPソケット列挙、PID一致ソケットの**非Listen TCPリモートIP**のみIOC照合。UDPはスキップ。 | [src/modules/process_check.rs:724-798](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L724-L798) | 実装確認 |
| ルール更新 | `loki-util update` はYARA-Forge Core ZIP取得→ステージ→YARAコンパイル検証→置換・ロールバック。IOCはテンプレート作成のみで自動収集/鮮度更新ではない。 | [src/loki_util/main.rs:12-17](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/loki_util/main.rs#L12-L17)、[src/loki_util/main.rs:290-397](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/loki_util/main.rs#L290-L397)、[src/loki_util/main.rs:407-507](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/loki_util/main.rs#L407-L507) | 実装確認 |
| ログ・根拠 | `process_match` にPID、プロセス名、スコア、ルール理由、ハッシュ、開始時刻などを載せる。**Sysmon ProcessGuidやメモリ領域一覧は含まない**。 | [src/helpers/unified_logger.rs:1091-1130](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/helpers/unified_logger.rs#L1091-L1130) | 実装確認 |
| 単体/CIテスト | C2マッチ上限テスト、IOC照合・タイムアウト・更新失敗/ロールバックのテストがある。Windows CIは `cargo test` とバイナリ版数/ヘルプのスモーク検証。管理者/PPL実メモリテストは確認できない。 | [src/modules/process_check.rs:1093-1143](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L1093-L1143)、[src/main.rs:1927-1971](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L1927-L1971)、[src/loki_util/main.rs:899-985](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/loki_util/main.rs#L899-L985)、[.github/workflows/test.yml:129-252](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/.github/workflows/test.yml#L129-L252) | テスト**定義**確認・実行未実施 |

### 2.1 読取完全性・Windows実装についての重要な評価
- **欠落情報の不可視化（重要）**：読める領域を `buffer.extend_from_slice` で隙間なしに連結するため、仮想アドレスや領域属性、読めなかった場所、読み取った割合が残らない。**別々の領域を跨ぐ偽の連続パターンが検出され得る**（コードからの論理的帰結・実際の誤検知頻度は未測定）。逆に失敗した領域にあるIOCは見落とす。[src/modules/process_check.rs:818-864](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L818-L864)
- **読取粒度が大きい**：1領域につき `min(RegionSize,remaining)` を一度に確保して一度の `ReadProcessMemory` を試す。領域途中でアクセス不能となるとAPIは失敗し得る。ページ単位の再試行・部分失敗の記録はない。Microsoft [ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory) は要求範囲全体がアクセス可能である必要がある。[src/modules/process_check.rs:835-858](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L835-L858)
- **400MiB上限は過負荷対策の十分条件でない**：上限は**プロセスごと**、かつ `Vec` の先行割当と最終バッファへのコピーがあり、Rayon並列化との掛け算になる。CPUスロットル（[src/helpers/throttler.rs:9-94](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/helpers/throttler.rs#L9-L94)）はメモリ総量・同時読取数・ディスクI/O・全体時間を保証しない。定量的なピーク値は要実測。
- **権限境界**：単なる管理者権限でもPPL/Protected Processのメモリ読取を保証しない。Loki-RSは権限不足時に警告する（[src/main.rs:1329-1340](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L1329-L1340)）が、PPL検出・特別な迂回/昇格処理は確認できない。Microsoft [Process Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights) は保護プロセスで `PROCESS_VM_READ` 等を制限する。
- **PID再利用**：`sysinfo` の開始時刻はログにあるが、スキャン時のPIDと開始時刻の同一性再検証、Sysmon ProcessGuid結合は実装されていない。プロセス生成/終了間の競合は要検証。[src/modules/process_check.rs:233-260](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L233-L260)
- **ドメインIOCは現在の通信源に届かない**：文字列のドメイン照合関数は存在するが、接続元は `tcp_info.remote_addr.to_string()` のIP文字列。DNS/ドメイン観測ではない。また単純 `ends_with` はドメインのラベル境界を検証しない。CIDRは未実装、IPv4判定は4オクテット専用。[src/modules/process_check.rs:758-798](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L758-L798)、[src/main.rs:694-733](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L694-L733)
- **証跡のプライバシー**：マッチした生文字列（ASCIIまたはhex）やコマンドラインがログへ入る可能性がある。メモリにはトークン、パスワード、セッション情報が含まれ得る。生データを既定で保存・送信しない設計が不可欠。[src/modules/process_check.rs:536-585](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L536-L585)、[src/helpers/unified_logger.rs:1091-1130](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/helpers/unified_logger.rs#L1091-L1130)

## 3. 具体的な取り込み候補と選択肢

| 候補機能 | 利用方法（crate/API・外部CLI・独自実装・参考・見送り） | AegisGuard接続先 | 優先度 | 工数目安 S/M/L | ライセンス・技術上の阻害要因 |
|---|---|---|---|---|---|
| **①観測イベントへのIP IOC照合・プロセス相関** | **独自実装**。既存 `src/c2.rs` を拡張し、将来のSysmon/ETWの観測に紐付ける | `src/c2.rs` → 将来 `windows_sensor`/相関層 | **P0** | **M** | 現行はIP照合のみ・イベント取込未実装。PID再利用/欠落/タイムスタンプの設計 |
| **②IOC provenance/鮮度/分類/例外** | **独自実装**。Lokiの`score`/FP正規表現を参考にするが実装をコピーしない | `src/c2.rs`・将来 `ioc` | **P0** | **M** | ソースごとTTL・署名・証跡、ドメイン/IP/ハッシュの形式差。フィード利用許諾 |
| **③限定プロセス・メモリYARA** | **Rust crate/API直接利用**（上流YARA-X）＋ Windows API読取ラッパーは**独自実装** | 将来 `on_demand_memory`/結果モデル | **P1** | **L** | PPL、同意、最小権限、領域メタデータ、アドレス/内容秘匿、負荷上限、ルール権利 |
| 実行ファイルSHA-256/名/パス/起動コマンドの観測 | **独自実装**＋イベント連携（必要ならSysmonのハッシュを優先） | `src/model.rs`、`src/scan.rs`、将来センサー | P1 | M | ファイル置換TOCTOU、内容収集最小化、コマンドラインPII |
| YARAのタイムアウト/エラー分類 | **上流YARA-X API直接利用**＋Lokiの失敗継続設計のみ参考 | 将来静的YARA・メモリ検査 | P1 | S〜M | タイムアウトは読取処理の制限を保証しない。未走査は`incomplete` |
| IOCローカルファイル形式・FPルール | **設計参考のみ**。生regexを外部入力として無制限に受けない | 将来`ioc`/policy | P2 | M | 正規表現の誤検知・複雑性、allowlistの出所/有効期限 |
| `loki` の外部CLI観測専用 | **外部CLI**（調査・手動トリアージ限定） | 手動インポート/隔離された診断経路 | P2 | S〜M | GPL-3.0配布条件、ログ機密、署名固定、タイムアウト、バージョン差、既定でプロセス走査 |
| `loki-util` 署名更新設計 | **設計参考のみ**。ステージ→検証→入替→復旧は参考になる | 将来ルール更新器 | P2 | M | URL/ルール権利、DL最大サイズ・署名認証・透明性検証の不足 |
| 既存Loki-RS Windowsメモリ関数の移植 | **見送り** | — | — | — | GPL、領域連結・欠落不可視・スケール、PPL |
| 全PID常駐・同時メモリスキャン | **見送り** | — | — | — | 過負荷、機密収集、Defender/EDRとの干渉、未観測領域の過少報告 |

**取り込み候補の入力/出力契約（新規設計、現時点では未実装）**
1. **プロセス相関**：入力＝`{timestamp,process_guid?,pid,process_start_time?,image_path?,remote_ip,remote_port,protocol,event_source}`。出力＝`{ioc_id,source_id,observed_at,match_type,confidence,correlation_status,evidence_refs}`。Sysmon Event 1/3/5/7/22（利用できるとき）をProcessGuid中心に結び、取得不能な場合は低確度の暫定相関とする。失敗・イベントギャップは`unknown`として明示。PoCは安全なローカルソケットのイベント再生で照合確認。
2. **IOC管理**：入力＝型が明示されたIP/ドメイン/ファイルハッシュ、発行元、取得日時、更新日時、TTL、ライセンス、信頼度、allowlist/expiry。出力＝`valid / stale / invalid / unavailable`と一致根拠。IPは`IpAddr`、ドメインは正規化後のラベル境界一致、ハッシュはSHA-256優先。ダウンロード失敗時は前回成功を保持し、**期限切れを有効一致にしない**。既存 `src/c2.rs` のフィード単位48時間管理を壊さず拡張（[src/c2.rs:10-42](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L10-L42)、[src/c2.rs:90-109](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L90-L109)、[src/c2.rs:264-326](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L264-L326)）。
3. **限定メモリ検査**：入力＝**利用者が明示したPIDとプロセス開始時刻/ハンドル同一性、ルールセット識別子、バイト/領域/時間予算、同意トークン**。出力＝`scanned / partial / denied / protected / exited / timed_out / cancelled / not_assessed`、読取/失敗領域数、読取範囲識別子、YARA rule id、根拠のハッシュ/一部伏せ字。少数の許可対象・非PPLの無害な検証プロセスだけを扱い、領域毎に境界を維持して検査。中止時はハンドルを必ず閉じ、一時バッファを速やかに破棄し、ログは保護ACLで保管。PoCは静的な既知パターンを保持する自作の無害なテストプロセスを使う。

## 4. ライセンス・再配布・依存関係

| 対象 | 確認内容 | AegisGuardへの影響 |
|---|---|---|
| **Loki-RS本体ソース** | ルート `LICENSE` が **GNU GPL v3**、READMEにも宣言。[LICENSE:1-25](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/LICENSE#L1-L25)、[README.md:324-326](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/README.md#L324-L326) | コードの直接転用や改変バイナリ配布にはGPL条件の検討が必要。AegisGuard自身はライセンス未設定（[README.md:59-69](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md#L59-L69)）。**法的評価未完了**につきソースコピーしない。 |
| **YARA-X依存** | `Cargo.toml` は `yara-x=1.17.0` を `vendor/yara-x` にパッチ。vendored `Cargo.toml` は `BSD-3-Clause` 表記、Rust 1.91.0要求。[Cargo.toml:32-36](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/Cargo.toml#L32-L36)、[Cargo.toml:65-73](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/Cargo.toml#L65-L73)、[vendor/yara-x/Cargo.toml:12-38](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/vendor/yara-x/Cargo.toml#L12-L38) | 上流YARA-Xの**API利用**をLoki-RSのGPLコード取り込みと区別。BSDの通知・著作権表示、同梱個別ファイルの権利、依存ライセンス/SBOMを調べる。AegisGuard `rust-version=1.85`（[Cargo.toml:1-7](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/Cargo.toml#L1-L7)）とMSRV整合性はブロッカー。 |
| **IOCデータ/独自ルール** | `signatures/iocs` はローカルの任意ファイル。スキャン側は作者/権利/取得時刻を記録しない。[src/main.rs:288-395](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L288-L395)、[src/main.rs:568-691](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L568-L691) | 「スキャナ本体GPLだから任意IOC再配布可」ではない。発行元ごとに利用/再配布/更新条件を確認し、許諾不明のフィードは同梱しない。 |
| **YARA-Forge Coreの生成物** | `loki-util` がYARA-ForgeのリリースZIPを取得。YARA-Forgeは複数の外部ルールを統合し、生成設定に `license_url` メタデータがある（[公式プロジェクト](https://github.com/YARAHQ/yara-forge)、[設定](https://github.com/YARAHQ/yara-forge/blob/master/yara-forge-config.yml)）。[src/loki_util/main.rs:12-17](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/loki_util/main.rs#L12-L17) | YARA-ForgeツールのGPL宣言と**含まれる各ルールの著作権/許諾は別問題**。生成物の同梱・販売・更新を一括許可と扱わず、ルール単位で確認。**法的評価未完了**。 |
| **外部CLIの別プロセス実行** | `loki` と `loki-util` は別bin。[Cargo.toml:1-14](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/Cargo.toml#L1-L14) | 呼び出しただけで無条件にライセンス問題が解消するわけではない。バイナリ同梱/配布/改変/ログ処理の形態を決めて法務確認。ユーザーに既存の実行ファイルを無断実行させない。 |

主要な依存関係：`sysinfo`（列挙）、`rayon`（並列化）、`netstat2`（接続列挙）、`windows 0.62.2`（Windows API）、`yara-x 1.17.0`（検査）、`regex`/ `csv`（IOC）、`md5`/`sha1`/`sha2`（ハッシュ）、`ureq`/`zip`（ルール取得・展開）、`serde_json`（報告）。根拠：[Cargo.toml:15-73](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/Cargo.toml#L15-L73)。リポジトリには `Cargo.lock` があるが、脆弱性/サプライチェーン監査の実行は**未実施**。

## 5. Defender共存・Windows制約・権限境界
- **Windows 11 x64における最低限のAPI**：`OpenProcess`（必要なアクセス権だけ要求）、`VirtualQueryEx`、`ReadProcessMemory`、`CloseHandle`。対象ハンドルはACLに従い、`PROCESS_QUERY_INFORMATION` と `PROCESS_VM_READ` が必要。[src/modules/process_check.rs:800-864](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L800-L864)、[Microsoft VirtualQueryEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex)、[Process Security](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)。
- **昇格・PPL**：権限不足を示して明示的な同意を得るが、通常ユーザーで観測可能な範囲はユーザー権限で完結させる。管理者権限は必要時の操作に限定し、`SeDebugPrivilege` の常時有効化は採用しない。PPLや保護プロセスはアクセス拒否が正常な結果になり得る。Defenderや他EDRの保護を解除せず、禁止アクセスを繰り返さない。
- **Defenderとの干渉**：メモリ読取や大きなファイルのハッシュ計算、複数プロセスの反復検査はEDRやDefenderに監視され得る。共存は**設計上の目標であり実機で未検証**。除外設定の強制、Defender停止、プロセス停止・書換、独自ドライバーの導入は行わない。
- **Sysmon/ETW/AMSI/WFPの役割差**：Sysmon Event ID 1（プロセス作成）/3（通信）/5（終了）/7（モジュール）/22（DNS）が使えれば、イベント相関がPIDのみのスナップショットより堅牢。Event 3・7は既定有効とは限らない（[Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)、[Sysmon Configuration](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-configuration-files)）。ETWは将来のイベント取得手段、AMSIは対応ホストから渡されるスクリプト内容の検査経路、WFPは将来のネットワーク制御経路であり**メモリ読取の代替ではない**。AegisGuardはいずれも現時点で未実装（[docs/ARCHITECTURE.md:15-37](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L15-L37)）。
- **監査とユーザー同意**：開始主体、対象プロセスID＋開始時刻、目的、開始/終了、アクセス権、領域件数、アクセス拒否理由、キャンセル、ルールの識別子を監査。メモリ本体/コマンドライン/一致文字列を既定でログに出さない。保存は暗号化・ACL・保持期限・削除を要求。権限昇格後もサービスが不必要な高権限を持続しない構成を検討する。
- **停止時復旧**：読取専用のため通常は状態変更を残さない設計とする。キャンセルで新規読取を止め、開いたハンドルを閉じ、バッファを解放し、部分結果を `cancelled/partial` として確定。タイムアウトをスキャナ側だけに頼らず、読取処理と全体予算にも適用する。

## 6. 性能・堅牢性・誤検知

| 論点 | コードで確定した状態 | 推定される影響・検証 |
|---|---|---|
| メモリ使用量 | PIDごとの上限は400MiB。領域の `vec![0;chunk_size]` と累積`buffer` が同時存在し、Rayonで複数PID同時実行。[src/modules/process_check.rs:140-185](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L140-L185)、[src/modules/process_check.rs:800-862](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L800-L862) | 複数プロセスで大きなピーク/ページングの可能性。**実測なし**。全体バイト・並列数・待機列に独立した上限が必要。 |
| 時間・CPU | `Scanner::set_timeout` と処理後のCPUスロットリングあり。[src/modules/process_check.rs:453-458](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L453-L458)、[src/helpers/throttler.rs:31-94](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/helpers/throttler.rs#L31-L94) | **メモリ読取時間自体はYARAタイムアウト対象外**。ページングやアクセス失敗の長時間化は要実測。 |
| 偽陰性 | 不可読な領域は読み飛ばすが、結果は空なら`skipped`、一部のみ読めた時の部分性は出力しない。[src/modules/process_check.rs:488-519](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L488-L519)、[src/modules/process_check.rs:835-864](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L835-L864) | アクセス拒否/ガード/サイズ上限で検査漏れ。AegisGuardの`analysis_complete`と`incomplete_reasons`を踏襲（[src/model.rs:27-40](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/model.rs#L27-L40)、[src/model.rs:78-113](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/model.rs#L78-L113)）。 |
| 偽陽性 | メモリ領域連結の境界跨ぎ、単純ドメイン末尾一致、外部IOCの古さ、一般的なYARA文字列。[src/modules/process_check.rs:846-860](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L846-L860)、[src/main.rs:696-715](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L696-L715) | ルール別適合性・FPリスト・評価母集団が必要。自動隔離/遮断に直結させない。 |
| 悪意ある入力 | YARAルールやIOCファイルは外部入力。ダウンロードしたYARAのコンパイル検証はあるが、`ureq`の読取総量制限や配布元署名・ハッシュ固定はこの経路に見当たらない。[src/loki_util/main.rs:317-397](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/loki_util/main.rs#L317-L397) | ZIP展開容量、ルール数、CPU、署名検証、更新失敗時復旧を自前の品質ゲートにする。**未確認部分を「安全」とはしない**。 |
| 機密性・監査量 | `logger.info_w` は実行コマンドライン等を記録し、YARAマッチ生文字列を結果に載せ得る。[src/modules/process_check.rs:279-336](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L279-L336)、[src/modules/process_check.rs:558-612](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L558-L612) | JSONLのアクセス制御・ローテーション・赤字化/機密除去が必要。個人端末では特に重要。 |
| テスト妥当性 | IPC/IOCや更新失敗の単体テストは存在。Windows CIのスモークは版数/ヘルプ中心。[.github/workflows/test.yml:129-252](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/.github/workflows/test.yml#L129-L252) | **実メモリのアクセス拒否・PPL・400MiB境界・読取競合・Defender共存の回帰テストは未確認**。 |

数値的な性能改善率、誤検知率、保護対象の被覆率は一切測定していないため記載しない。

## 7. 推奨する小さなPoCと成功基準
- **前提：** Windows 11 x64の隔離した検証VMまたは専用テスト端末、Defender有効、ユーザーの明示操作、ルール/検体は自作の無害な文字列のみ。通常ユーザーで開始し、昇格は別の許可ステップ。ネットワークブロック、永続サービス、ドライバー導入、保護回避は行わない。
- **安全なサンプル/検証方法：** 自作テストプロセスに識別用の無害な文字列を保持させる。領域を複数割り当て、読み取り可能/禁止/ガード属性、解放/終了、巨大領域、同名プロセスの再起動を模擬。YARAの単純な自作ルールを走らせ、実バイト内容ではなくルールID・範囲識別子・状態を確認。IPC側は架空のドキュメント用IP/ローカルDNSを使い、フィード更新失敗と期限切れを再生。未検証環境では実施しない。
- **受け入れ基準：** (1) 指定PID/開始時刻以外にはOpenProcessしない、(2) 全領域について`read/denied/skipped/truncated/exited`と総試行バイト数・理由を監査、(3) 領域間パターンが誤って連結マッチしない、(4) 上限到達・一部失敗・YARA timeoutを**陰性ではなくpartial**として記録、(5) キャンセル/終了後にハンドル・バッファ・一時ログを残さない、(6) ログに生メモリや認証情報を出力しない、(7) PPL/拒否時に昇格やセキュリティ設定変更を自動試行しない、(8) 元のDefender設定・ファイアウォール・サービスが不変。
- **成功条件と性能測定方法：** ケースごとに既知の期待マッチ/非マッチと到達可能領域・未走査領域を比較。ETW/Sysmonの既知イベントと起動時刻で相関の取り違えがないか検証。プロセス別/システム全体のピークRSS、読取バイト、スキャン時間、CPU、ページフォールト、ログサイズ、Windowsイベントのアクセスエラーを測る。**しきい値はVM/実機ベースライン測定後に設定**し、根拠のない目標数値は置かない。
- **失敗時の扱い・ロールバック：** すべて`not_assessed/partial`で保存し、自動ブロックしない。PoCは機能フラグ初期OFF、監査のみ→指定PIDのみ→評価終了でOFFの順。設定とテスト生成物を消去し、Defenderの設定は変更しない。
- **中止条件：** PPLや通常アクセス権を越えようとする必要が生じた、AV/EDR干渉・不安定化、メモリ/時間上限違反、機密文字列の漏出、テストプロセス以外へのアクセス、イベント欠損を陰性として扱う、いずれかの時点で即停止。
- **最小PoC判定**：メモリ検査を製品の第一段階にしない。先に既存C2 IP管理の観測品質とイベント相関を固め、メモリ診断は明示起動・単一対象・部分性保持が成立した後に限定提供する。

## 8. 採用しない設計と理由
1. **Loki-RSの`read_process_memory`をそのままコピーし、全PIDへ周期的に実施する案：不採用。** 権限拒否や読取不能領域が隠れ、領域境界が消え、400MiB/PIDと並列実行が同時ピークを引き起こし得る。PPL/Defender干渉の実測もない。GPLの再利用条件にも問題が残る。[src/modules/process_check.rs:140-187](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L140-L187)、[src/modules/process_check.rs:800-865](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L800-L865)
2. **Loki-RSのローカルC2ドメイン照合をそのままネットワーク遮断判断にする案：不採用。** 接続取得はTCP IPのみ、UDP/DNS未観測、CIDR TODO、文字列末尾一致はドメインラベル境界に無関心、取得時刻/有効期限なし。今のAegisGuardの「期限切れ不一致」「手動更新のみ」を後退させる。[src/main.rs:568-733](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L568-L733)、[src/modules/process_check.rs:758-798](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L758-L798)、[src/c2.rs:90-109](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L90-L109)
3. **YARA-ForgeのすべてのルールとLoki本体を無審査で同梱する案：不採用。** コンポーネント/ルールごとの権利、偽陽性と更新署名・サプライチェーンが未解決。[src/loki_util/main.rs:12-17](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/loki_util/main.rs#L12-L17)、[LICENSE:1-25](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/LICENSE#L1-L25)

## 9. 他担当との境界・引継ぎ
- **YARA-X/ルール専任担当へ**：Rust crateのABI/API、コンパイル・ルール署名・同梱権利、スキャン対象サイズ制限、メモリ用ルール選別、Windows x64でのMSRVを引き継ぐ。本担当はプロセスメモリ境界との接続のみ評価。
- **Loki-RSのファイルスキャン/シグネチャ更新担当へ**：ZIP/ルール更新検証、ロールバック・配布認証・ライセンスの深掘りはそちらで確定。本担当はメモリ/IOC契約との影響のみ記述。
- **Windowsイベント/ETW/Sysmon担当へ**：ProcessGuid、Event 1/3/5/7/22、欠損検出・バックプレッシャー・PID再利用の相関設計を引継ぎ。Sysmon設定は既存ポリシーを尊重。
- **C2/ネットワーク遮断担当へ**：IOC型、発行元、TTL、ドメイン境界、DNSとIPの時刻差、遮断前の誤検知評価。WFP・Firewallは本担当範囲外。
- **PE/静的検査担当へ**：実行中ファイルの`fs::read`によるハッシュと実プロセスのマッピングのTOCTOUを分けて評価。
- 相互依存が解消するまでは、この報告を**採用決定・Windows動作保証・法的承認とはみなさない**。

## 10. 未確認事項・追加調査項目
1. **重大：Windows 11 x64＋Defender有効の実機アクセス検証未実施**。PPL、管理者/標準ユーザー、セッション差、EDR誤検知、ReadProcessMemory失敗率、イベント監査の実態は未確認。
2. **重大：ライセンス監査未完了**。YARA-Forge内の全ルールの`license_url`、第三者IOCの再配布条件、vendored YARA-Xの全ファイル/依存ツリー、AegisGuardの将来ライセンスについて法的評価未完了。
3. **重大：リソース実測なし**。400MiB×並列PIDでのピークRAM/スワップ、長時間の読取、プロセスの終了/アドレス空間変化、スレッド数を変えた再現性未測定。
4. **高：メモリ領域境界/失敗率と検出精度**。PAGE_EXECUTE等の非可読ページ、ガードページ、部分Read/ページング、YARAの領域跨ぎ偽陽性、失敗でも一部データがあると「scanned」となる観測仕様をテストで確認する必要。
5. **高：PID/ProcessGuid相関**。スナップショットとSysmon/ETWの時刻同期、PID再利用、イベント消失時のfallback契約、個人情報の取り扱い未検証。
6. **高：署名/IOC更新認証**。YARA-Forge配布物の署名/ハッシュ検証、ZIP総展開量、HTTP応答の異常、ルール差分と削除時の安全性、外部IP/ドメインIOCの鮮度を実データで評価していない。
7. **中：テスト実行の有無**。ソース内のユニットテスト/CIワークフローの**存在**のみ確認。テスト成功を主張しない。現時点のCI履歴/実行時間/Windows PPLテストなし。
8. **中：最新mainとの差分**。本調査は記載の固定SHAで再現可能な静的スナップショットであり、以降の上流変更があれば再評価が必要。

## 11. 一次情報一覧
以下はいずれも**2026-11-05参照**。Loki-RSは上記固定commit、AegisGuardは上記固定commitで参照先を固定している。

1. Windows `OpenProcess`/`VirtualQueryEx`/`ReadProcessMemory`、400MiB、領域連結：[src/modules/process_check.rs:800-865](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L800-L865)。
2. スキャン対象列挙・自己除外・Rayon並列化とCPU抑制：[src/modules/process_check.rs:103-187](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L103-L187)、[src/helpers/throttler.rs:9-94](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/helpers/throttler.rs#L9-L94)。
3. メモリYARA-X、スキップ/失敗、マッチ根拠と生文字列：[src/modules/process_check.rs:453-629](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L453-L629)、[src/helpers/yara.rs:11-58](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/helpers/yara.rs#L11-L58)。
4. C2 IOC読込・ドメイン末尾/IPv4判定/CIDR TODO：[src/main.rs:568-733](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L568-L733)；ネットワーク接続のTCP-only：[src/modules/process_check.rs:758-798](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L758-L798)。
5. ハッシュ・ファイル名IOC、誤検知例外：[src/main.rs:288-395](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L288-L395)、[src/main.rs:736-873](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/main.rs#L736-L873)。
6. 署名更新の取得/コンパイル検証/復旧：[src/loki_util/main.rs:290-397](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/loki_util/main.rs#L290-L397)、[src/loki_util/main.rs:407-507](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/loki_util/main.rs#L407-L507)；更新失敗テスト：[src/loki_util/main.rs:899-985](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/loki_util/main.rs#L899-L985)。
7. Windows CI（ユニットテスト定義とスモーク）：[.github/workflows/test.yml:129-252](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/.github/workflows/test.yml#L129-L252)；C2容量テスト：[src/modules/process_check.rs:1093-1143](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/src/modules/process_check.rs#L1093-L1143)。
8. GPLv3原文/明示、vendored YARA-X BSD-3-Clauseと依存：[LICENSE:1-25](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/LICENSE#L1-L25)、[README.md:324-326](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/README.md#L324-L326)、[vendor/yara-x/Cargo.toml:12-38](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/vendor/yara-x/Cargo.toml#L12-L38)、[Cargo.toml:15-73](https://github.com/Neo23x0/Loki-RS/blob/0866b3d0e32d82f8b5776f61c67b655a34a55b4a/Cargo.toml#L15-L73)。
9. AegisGuardのIP IOC TTL/未検査表現・未実装センサー：[src/c2.rs:10-42](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L10-L42)、[src/c2.rs:90-109](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L90-L109)、[src/model.rs:27-40](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/model.rs#L27-L40)、[docs/ARCHITECTURE.md:7-42](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L7-L42)。
10. Microsoft公式：[Process Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)、[VirtualQueryEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex)、[ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)、[Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)、[Sysmon Configuration](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-configuration-files)（2026-11-05確認）。
11. YARA-Forge公式：[repository](https://github.com/YARAHQ/yara-forge)、[ruleset生成設定](https://github.com/YARAHQ/yara-forge/blob/master/yara-forge-config.yml)（ルール由来別の権利確認が必要）。
