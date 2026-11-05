# 調査報告：YARA-X / yara-rust-api

> 担当：yara-rust-api / 調査日：2026-11-05 / 調査結果：ソース調査完了、実機・ビルド試験未実施

## 0. 結論（3〜5行）

- **取り入れる価値：高。** ルールを一度コンパイルして静的PEとスクリプト各復元層をオフライン検査でき、既存のヒューリスティックを補完できる。ただしYARA一致は感染確定ではない。
- **最優先：Rust crateを利用する分離可能なYARA検査アダプタ。** コンパイル済みRulesを複数Scannerで共有し、入力・出力・資源上限をAegisGuard側で統一する。
- **最大の阻害要因：MSRV差。** AegisGuardは1.85、調査時点のYARA-X mainは1.95.0（版1.22.1）。このまま直接依存を追加しても1.85という保証を維持できない。
- **見送り：改変可能な外部のコンパイル済みルールの直接deserialize、検出を根拠にした自動削除・遮断。**
- **導入順序：** 明示的なローカル実行によるPoC → ルール品質・性能測定 → 観察専用の限定運用。Defenderの保護は維持する。

## 1. 対象の固定と調査方法

| 要素 | 値 / 根拠 |
|---|---|
| 公式リポジトリ・commit固定URL | [VirusTotal/yara-x](https://github.com/VirusTotal/yara-x/tree/910a938569a0fa16db5ad7d0d492b18ad8e70d93)。main先頭を2026-11-05に確認 |
| 調査コミットSHA・タグ | **910a938569a0fa16db5ad7d0d492b18ad8e70d93**。確認時の最新公開リリースは **v1.22.1**（2026-10-26公開）。[Cargo workspace](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/Cargo.toml#L1-L18) |
| AegisGuard比較先 | [main 83fcf0d150e8d760baff5f971c106deb09c1f8e4](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/Cargo.toml#L1-L25) |
| ライセンス | YARA-X本体は [BSD-3-Clause](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/LICENSE#L1-L26)。AegisGuard自身はREADME上でライセンス未設定：[README](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md#L69-L76) |
| ソース/文書確認範囲 | YARA-Xの lib/src/lib.rs、compiler/mod.rs、compiler/rules.rs、scanner/mod.rs、scanner/matches.rs、models.rs、modules/pe/mod.rs、CLIのscan.rs、Cargo.toml、lib/Cargo.toml、build.rs、CI/tests.yaml、関連テスト。AegisGuardのREADME、SECURITY、ARCHITECTURE、Cargo、src/scan.rs、model.rs、pe.rs、script.rs、main.rs |
| 実機・ビルド・テスト | **未実施**：この調査ではGitHubの固定コミットにあるソース・テストコード・CI設定を静的に査読。Windows 11でのCargoビルド/動的検証・計測の結果は得ていない |
| 確認日の限界 | Cargo設定のMSRVは公表した下限であり、全依存クレートの現在の解決・ビルド可能性は実機未確認。CI定義の存在はCI成功の証明ではない |

**比較対象の現在地。** AegisGuardは[64MiBのPE、4MiBのスクリプトを上限に読み取り](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/scan.rs#L9-L80)、SHA-256採取後にPE解析またはスクリプト検査を実行する。復元器は[128KiB/層、512KiB総量、16層、深度3](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/script.rs#L12-L15)。検査不能は[analysis_complete=false / incomplete_reasons](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/model.rs#L27-L112)で区別する。YARA-X実行・Windows常駐センサー・遮断はまだ実装されていない。比較元のAPIを置き換えるのではなく、この安全境界を継承すべきである。

## 2. 実装アーキテクチャとソース調査

| 機能 | 主要なファイル/シンボルと役割 | commit SHA固定の一次情報 | 確認状態 |
|---|---|---|---|
| コンパイル | Compiler::add_source(&str / &[u8] / SourceCode) → Result、Compiler::build() → Rules。構文・型のエラーをerrorsに蓄積し、成功したルールのみbuildに残せるため、AegisGuardでは**エラーが1件でもあればルールセット全体の公開を停止** | [add_source](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/mod.rs#L617-L706)、[build](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/mod.rs#L825-L900) | 実装確認 |
| 不正/危険ルール抑制 | Compiler::enable_includes(false)、error_on_slow_pattern(true)、error_on_slow_loop(true)、ban_module()、警告/無視ルールを収集して公開を判定 | [includes](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/mod.rs#L1116-L1129)、[slow pattern/loop](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/mod.rs#L1099-L1113)、[ban_module](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/mod.rs#L995-L1022) | 実装確認 |
| スキャン | Scanner::new(&Rules)、scan(&[u8])、scan_file(path)、scan_with_options。メモリバッファは任意バイト列、scan_fileはファイル読込 | [scanner/scan](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/mod.rs#L188-L205)、[scan_file](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/mod.rs#L346-L396) | 実装確認 |
| ルール共有と並列性 | Rulesは複数Scannerへ共有可能、Scannerは同一インスタンスで逐次再利用、並列処理は別Scannerを構築する。ScanResultsがScannerから借用するので、必要情報を所有型にコピーしてから次のscanに進む | [crateの説明](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/lib.rs#L6-L40)、[Scanner](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/mod.rs#L188-L205)、[ScanResults](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/mod.rs#L840-L867) | 実装確認 |
| マッチ証拠 | matching_rules() → Rule::identifier/namespace/metadata/tags → Pattern::identifier/matches → Match::range/data/xor_key。private rule/patternは既定で非列挙。並び順は任意 | [結果](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/mod.rs#L853-L866)、[Rule](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/models.rs#L25-L85)、[Pattern/Match](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/models.rs#L349-L391)、[offset/data](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/models.rs#L456-L500) | 実装確認 |
| ファイルとmmap | 32,000,000 bytes超のファイルは既定でmmap使用。use_mmap(false)でバッファ読み込みへ変更可。OpenError/MapErrorを返す | [load_file](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/mod.rs#L562-L603)、[mmap説明](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/mod.rs#L289-L303)、[ScanError](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/mod.rs#L51-L98) | 実装確認 |
| タイムアウト/上限 | set_timeout(Duration)は努力目標で厳密な即時停止ではない。max_matches_per_pattern、fast_scan、max_scan_sizeは存在するが、**max_scan_sizeは拒否ではなく入力を切り捨てる** | [timeoutとfast_scan](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/mod.rs#L208-L285)、[size上限](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/mod.rs#L305-L357)、[match既定値](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/matches.rs#L247-L271) | 実装確認 |
| PEモジュール | pe-moduleはデフォルトモジュールに入り、PE解析をYARA conditionから使用可能。破損PEはis_pe=falseの構造を返す設計。既存のPEヘッダ検査は別途保持 | [feature](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/Cargo.toml#L249-L253)、[default](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/Cargo.toml#L288-L322)、[PE main](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/modules/pe/mod.rs#L24-L49) | 実装確認 |
| コンパイル済みルール | Rules::serialize / deserialize、MAGIC/version/一部参照整合性チェック。**第三者が操作可能なバイナリをdeserializeするとパニック等の危険**とソース明記 | [serialize/deserializeの注意](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/rules.rs#L285-L338)、[追加検証](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/rules.rs#L343-L418) | 実装確認 |
| Wasmtime実行基盤 | ルール条件をWASMに変換して実行、Windows非WASMターゲットはWasmtime Cranelift/runtime。Pulleyはoptional、JITは実行可能メモリを要する | [WASM生成](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/mod.rs#L901-L923)、[wasmtime](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/Cargo.toml#L386-L391)、[Pulley](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/Cargo.toml#L126-L139) | 実装確認 |
| CLI/出力 | yr CLIはscan、--timeout、--no-mmap、--fast-scanを実装。JSON/NDJSON出力にルール識別子、名前空間、meta、tags、文字列証拠を含める構造 | [CLI引数](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/cli/src/commands/scan.rs#L41-L125)、[JSON構造](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/cli/src/commands/scan.rs#L596-L685)、[NDJSON](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/cli/src/commands/scan.rs#L920-L963) | 実装確認 |

**安全上の読み替え：** max_scan_size(64MiB)は64MiBを越えた部分を「未検査」にするので、そのまま結果0件をlow_signalに変換してはならない。AegisGuard現行の「サイズ超過はnot_assessed」に合わせ、ファイル全長を事前確認して拒否、または明示的にpartial/incomplete扱いにする。[YARA-Xの切り詰めテスト](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/tests.rs#L953-L991)もこの動作を確認している。

**APIの補足：** ルールからのmetaには任意の記述があり、信頼できる検出器の判定名や感染確率として扱わない。実メモリ上の任意バイト列はscan(&[u8])に渡せるが、**他プロセスのメモリ採取機能を提供するAPIとは別**である。Windowsの別プロセスメモリを読む設計や権限について本調査では実装を確認していない。

### テスト実装の確認（実行はしていない）

- [scanner reuse](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/tests.rs#L198-L237) は複数入力でマッチ状態が再初期化されることを検証。
- [scan_file / no-mmap](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/tests.rs#L812-L864) はファイル入力とメモリ読み込みモードを検証。
- [max_scan_size](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/tests.rs#L953-L991) は切り詰め後にマッチが失われることを検証。
- [負荷を作ったTeddy timeout](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/tests.rs#L1324-L1361) はTimeoutエラーの試験。ただしWindows上での最悪遅延保証ではない。
- [コンパイル済みルールの破損/版不一致](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/tests/mod.rs#L14-L78)、[include禁止](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/tests/mod.rs#L1697-L1715) のテストが存在。
- [CI matrix](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/.github/workflows/tests.yaml#L19-L38) にMSRV 1.95.0、[Windows MSVC/GNU/32bit](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/.github/workflows/tests.yaml#L80-L107) と[テスト・CLIビルド](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/.github/workflows/tests.yaml#L178-L204) のジョブが定義されている。**各ジョブ成功の個別実行確認は未実施**。

## 3. 具体的な取り込み候補と選択肢

| 候補機能 | 利用方法 | AegisGuard接続先 | 優先度 | 工数目安 | ライセンス・技術上の阻害要因 |
|---|---|---|---|---|---|
| **1. バイト列YARA判定（第一候補）** | Rust crate/API直接利用 | src/scan.rsから将来のyaraアダプタ、model.rs | P0 | M | Rust 1.95.0へのMSRV引き上げ、依存・ビルド検証 |
| **2. 復元スクリプト層ごとの判定** | Rust crate/API直接利用 | src/script.rsの各層処理、model.rs | P0 | M | 二重処理、元データと復元層の混同、証拠の秘匿 |
| **3. ルールロード検証とバージョン管理** | AegisGuard独自実装（YARA-X Compiler利用） | ルール管理・初期化境界 | P0 | M | 署名・配布元・ルール個別ライセンス未確定 |
| 4. YARA-X peモジュールによる補助情報 | Rust crate/API直接利用 | src/pe.rsの既存所見を補助 | P1 | M | 既存PEパーサと解釈差、破損/切り詰めPE |
| 5. 現行MSRVを固定した評価 | 外部CLI/サービス（yrを別ビルドし子プロセス） | 任意の検査アダプタ | P1/代替 | M | 固定バイナリの署名/アップデート/IPC/起動負荷 |
| 6. v1.0.0固定試験 | 旧Rust crate/API直接利用（評価限定） | 一時的なPoC依存 | P2/代替 | M | 旧版の保守・脆弱性・ルール互換・間接依存のMSRV |
| 7. JSON/NDJSONの設計 | 設計参考のみ（YARA-X CLIのスキーマをコピーせず自前定義） | src/model.rs、src/scan.rs | P1 | S | CLIスキーマへの密結合回避 |
| 8. 自前のYARAエンジン再実装 | 見送り | なし | 対象外 | L | ルール互換・攻撃面・検証コストが大きい |
| 9. 改変可能なバイナリRulesをロード | 見送り | なし | 対象外 | — | 上流が危険性を明記 |

**上位3件の具体案とPoC：**

**1. バイト列検査（P0/M）**：入口は現在の src/scan.rs がすでに読み込んだ &[u8]（PEは最大64MiB、スクリプトは最大4MiB）。起動時またはルール更新時に Compiler::enable_includes(false) / add_source → errors・warningsのゲート → build によりRulesを所有し、Arcなどで共有。実行workerごとにScanner::new(&rules)を持ち、scan(&data)後に ScanResults の借用中に自前の所有型へ識別子、namespace、pattern名、offset、length、xor_keyをコピー。fail/timeout/size超過では「検査不能/未完了」へ遷移。最小PoCは無害なASCII定型列へ一致する1ルール、非一致1件、壊れたルール、タイムアウト、切り詰め禁止を観察する。

**2. 復元層検査（P0/M）**：入口は src/script.rs で生成した各LayerのテキストUTF-8バイト列。原文（stage=raw）と復元各層（stage=decoded、層番号、変換由来、SHA-256）を**別々**にYARAへ渡す。重複する一致はstageを含むキーで正規化。ログは復元文字列そのものではなく層ハッシュ、ルール/パターンID、バイトオフセット・長さだけを保存。復元を打ち切ったらYARA一致0でも analysis_complete=falseを維持。最小PoCは合成Base64文字列が原文では非一致、復元層で一致することと、上限到達がincompleteとなることを検証。

**3. ルール検証ゲート（P0/M）**：入口は出所と版を記録したテキストルールのみ。コンパイル成功・エラー0件・禁止モジュール不使用・想定外includeなし・署名/ハッシュ/利用許諾確認済みを満たしたRulesを、原子的に旧版と交換する。コンパイル途中で一部のルールだけ成功しても、成功扱いのまま運用へ公開しない。更新失敗は最後に検証済みのRulesを保持し、現在の結果にルール版と適用状態を記録。PoCは意図的な構文エラーとinclude命令を拒否して既存ルールを維持する。

**代替手法の比較：** 最新crate直接利用は入力バイト列と報告モデルを共有しやすいがMSRV引上げが必須。CLI隔離はRust 1.85の本体を維持し、タイムアウト時に子プロセスを強制停止できる代わり、実行ファイルの配布/ハッシュ固定、プロセス起動、標準入出力、エスケープ、JSON処理、クラッシュ復旧が必要。旧crate固定は[v1.0.0のCargo.toml](https://github.com/VirusTotal/yara-x/blob/v1.0.0/Cargo.toml)にMSRV **1.85.0** と明示されるが、**最新版の代替として安全性を保証しない**。すべての方式でルール検証は共通。

## 4. ライセンス・再配布・依存関係

| 対象 | 確認できたもの | 導入時の扱い |
|---|---|---|
| YARA-Xソース/Rust crate/CLI本体 | [LICENSE BSD-3-Clause](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/LICENSE#L1-L26)、[workspace/packageのlicense](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/Cargo.toml#L1-L19) / [lib](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/Cargo.toml#L1-L14) | 直接リンク・バイナリ再配布・改変物配布時も著作権・ライセンス・免責表示を維持。名前による推奨/後援の表示禁止。実際の配布物で通知方法を確定 |
| 外部依存crate | [workspace dependencies](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/Cargo.toml#L26-L111)、[lib dependencies](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/Cargo.toml#L324-L405) にWasmtime、protobuf、daachorse、regex、memmap2、暗号ライブラリなど | **依存ごとのライセンスとNOTICEは未網羅**。Cargo.lock固定後にSBOM/license inventory/auditを実施。BSD-3-Clauseだから依存が一括して同じ条件になるわけではない |
| ルール（.yar） | YARA-Xエンジンのライセンスと独立。今回再配布予定の具体的ルールセットは未指定 | 個別ライセンス、著作権、商用利用/改変/再配布可否を確認。PoCでは自身で作成した無害ルールのみ。第三者ルールの同梱は**法的評価未完了** |
| 署名・脅威フィード・スキャンデータ | エンジンのBSD-3-Clauseはこれらの権利を与えない | 署名付与者/配布元/利用条件を別途確認。個別ファイルの内容、平文の検出断片、パス、検体を外部に送信しない |
| AegisGuardソース | [READMEのライセンス未設定記載](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md#L69-L76) | AegisGuard自体のライセンス方針を決め、noticeと再配布条件を確認してから頒布 |
| CLI別プロセス | 同一BSD-3-Clauseエンジンを別実行ファイルとして利用 | プロセス境界だけで権利処理を免れるわけではない。バイナリ同梱ならライセンス告知と依存の再配布確認が必要 |

**ビルド：** 最新YARA-X [workspace Cargo](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/Cargo.toml#L1-L19) は版1.22.1、edition 2024、MSRV **1.95.0**。AegisGuard [Cargo](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/Cargo.toml#L1-L24) はedition 2021、MSRV **1.85**。edition差そのものより、crate・transitive依存の要求するrustc最低版が直接依存の実障害である。旧版固定の場合もその時点のCargo.lockと依存crateのMSRVを再解決して検証すること。最新の[Wasmtime 48.0.8（main）](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/Cargo.toml#L99-L112)、[libのWASM依存](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/Cargo.toml#L386-L391)は特にビルド・リンク・バイナリサイズ・リソースを計測すべき。標準featureに[generate-proto-codeがある](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/Cargo.toml#L315-L322)一方、build.rsは[protoc利用の分岐](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/build.rs#L305-L322)を持つ。標準でprotocが必須とは断定しない。Windowsではまず x86_64-pc-windows-msvc のビルド、Release、署名、Defender有効下で起動試験を行う。

## 5. Defender共存・Windows制約・権限境界

- **Windows 11 x64 / 一般ユーザー**：明示したファイルをユーザー権限で読んでscan(&[u8])するPoCはWFP、ETW、Sysmon、AMSI、管理者権限を前提としない。ただしアクセス権のないファイルは読み取り失敗として報告する。管理者権限を要求して無差別走査しない。
- **Defenderとの共存**：検査だけを行い、Defenderのリアルタイム保護、ASR、Firewallを無効化しない。両者が同じファイルを読む二重I/Oを計測し、負荷が大きければ明示的検査・同一ハッシュ/ルール版の重複抑止・優先度制御を使う。検出だけでファイルを削除・隔離・通信遮断しない。
- **WFP / ETW / Sysmon / AMSI**：YARA-X単独でイベント購読やネットワーク遮断、AMSIインターセプトをするものではない。将来それらが渡すファイル/復元バイト列とイベント識別子を相関する受動的な解析器とする。Sysmonイベント7やWFPの有効化、AMSIの導入は別担当の承認待ちであり、本調査のPoCには含めない。
- **入力と権限の境界**：AegisGuardは現在symlinkを初期チェックするものの、開くまでのpath swap / reparse point競合が残ると自認している：[src/scan.rs](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/scan.rs#L30-L63)。PoCは現状で読んだバッファをそのままYARAへ渡し、YARA側で再度path openしない。将来のサービスではハンドル識別と再解析ポイント処理を保証する。
- **プロセス隔離**：信頼できないファイル・未知のルール・巨大入力を評価する本番構想では、低権限の検査ワーカー、Windows Job Objectによる時間/メモリ/子プロセス上限、監視親プロセスによる異常終了検知を検討。Job Objectによる制限は**AegisGuardに未実装**。CLI実行も外部入力をシェル文字列に埋め込まず引数配列/ハンドルを用いる。
- **プライバシー**：YARAのmetadataやpattern matchのraw dataには機密データが含まれ得る。SHA-256と限定的な証拠だけをACL保護されたJSONLへ書く。外部送信しない。現行[SECURITY.md](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md#L1-L31) と整合。

## 6. 性能・堅牢性・誤検知

- **実測**：なし。CPU時間、RSS、ビルド時間、Windows 11でのP95/最大遅延、exeサイズ、ルール数上限は**要実測**。上流のベンチマークやコミットメッセージの高速化主張をAegisGuardの性能保証に転用しない。
- **メモリ・並列**：共通Rulesを共有し、同時スキャン数に比例してScanner/入力バッファ/出力のメモリが必要。Scannerは単一の入力を逐次処理するため並列workerごとに別インスタンス。メモリ上限はライブラリのmax_scan_sizeだけでは満たされない。
- **timeout**：上流のset_timeoutは即時中断を厳密保証せず、[timeoutを監視するカウンタ](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/mod.rs#L100-L106)と[実装テスト](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/tests.rs#L1324-L1361)はあるが、時間超過後の継続余地がある。厳格な安全境界は別プロセスの監視/強制終了を検討する。
- **巨大ファイル・切り詰め**：max_scan_sizeはサンプルを拒否せず切り詰めるため、元のAegisGuardのサイズ上限を保持し、超過はnot_assessedへ。PEモジュールも切り詰めによって正しく解析できない可能性が[明記](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/mod.rs#L305-L315)されている。
- **mmap**：大きなファイルでのmapはファイル切り詰めと競合しうると[上流が警告](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/mod.rs#L289-L303)。初期PoCは既存バッファでのscan(&[u8])、またはuse_mmap(false)を優先する。
- **結果の意味**：fast_scanは重複出現を省略するため、offsetをすべて出す証拠モードでは無効。マッチ数制限・private pattern除外に注意。[fast_scan](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/mod.rs#L233-L284)。[matches上限](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/matches.rs#L247-L271)。
- **誤検知/検査漏れ**：正常インストーラのPE、管理スクリプト、テキスト例示が一致し得る。パッカー、暗号化、動的生成、復元上限、ルール未対応、壊れたPEでは陰性になり得る。検出ルール単体だけでrisk=highを固定せず、確信度・検出経路・False-positiveレビューの根拠を持たせる。
- **ルール供給攻撃**：外部includeを禁止し、コンパイル警告/エラーと速度の悪いパターンを検査し、更新を原子的に行う。外部からのserialized Rulesを信用しない。ロールバック可能なバージョン/ハッシュを持つ。
- **入力を使った不正コード実行は不要**：PoCは合成無害データだけを利用。未知の実行コード、検体、スクリプトの実行は禁止。

## 7. 推奨する小さなPoCと成功基準

- **前提**：Windows 11 x64、Defender有効の検証用VM。AegisGuard main(83fcf0d150e8d760baff5f971c106deb09c1f8e4)を比較ベースにする。更新先Rust 1.95+を分離した実験環境で検証し、直接導入を決めるまで既存Cargoを変更しない。全依存・ルールは固定、ネットワークへの検体送信はなし。
- **安全なサンプル**：自作ルールで無害なASCII記号列を検出、文字列を含まないバイト列を陰性、存在しないファイル、壊れたPE、サイズ上限直上、無害なBase64復元、構文エラー/禁止includeルールを投入。現行src/script.rsの無害テストと同じく検体を実行しない。
- **機能受け入れ基準**：a) コンパイル結果と失敗理由がJSONLへ正確に分類、b) raw/decodedの層別検出が再現、c) matching_rule/namespace/pattern/offset/length/ルール版/入力SHA-256を保持、d) false-matchで感染確定にしない、e) size超過/timeout/不完全復元でlow_signalに落とさない、f) 不正ルール全体の公開が遮断される、g) 前のルールにロールバックできる、h) 並列実行結果が逐次実行と一致しメモリが所定予算を越えない。
- **互換性・測定**：最新版crateをRust 1.95+ / Windows MSVCでビルド・testし、Rust 1.85の旧版固定候補、別プロセスCLIを同じルール/入力で比較。Cargo.lock・SBOM固定、dependency license/audit、Windows ReleaseビルドとWindows Job Object運用可能性を確認。入力サイズ・ルール数・worker数ごとにCPU、ピークRSS、wall time、処理件数、timeout超過幅、JSONLサイズを記録し、測定前に閾値を決定。
- **失敗時・ロールバック**：初期無効→手動スキャンのみ→限定的な監査。ルールコンパイル失敗時は旧Rules保持、タイムアウト時はincomplete記録、隔離workerは再起動。直接crate不適合なら依存を戻しCLI PoCに切替。Defender設定は変更しない。
- **中止条件**：検査不能を安全判定してしまう、外部データからのクラッシュや制御不能なリソース増大、想定外通信、権限昇格依存、署名/ルールの権利確認不能、再現性のない検出のいずれか。
- **定量値の扱い**：受け入れ用の性能数値はここで捏造しない。測定環境と許容上限が決まるまでは「要実測」とする。

## 8. 採用しない設計と理由

1. **外部が提供するコンパイル済みRulesをそのままdeserializeして適用**：上流は第三者が操作できるバイナリによるパニック等の危険性を[明記](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/rules.rs#L295-L305)。ハッシュ固定・署名検証のみで済むとせず、まず信頼できるテキストルールを管理・検証し内部でコンパイルする。署名済みの内部生成キャッシュ再利用は別途脅威モデルを決めて評価。
2. **YARAヒットを根拠とした自動削除・隔離・Firewall遮断**：ルールは誤検知し、Defenderとの重複や復旧不能な状態を生む。AegisGuard現状も観察専用であり、検出の根拠表示に留める。
3. **YARA-X機構一式をRustで独自再実装**：既存エンジンのAPI・テストがある一方、互換性、PE・正規表現、性能、パーサの脆弱性を再実装して保守する負担が過大。
4. **fast_scanとmax_scan_sizeを「完全スキャン成功」の最適化として無条件使用**：前者は証拠出現を省略し、後者は入力を欠落させる。完全性要件を満たすスキャンと高速スキャンを明示的に分ける。

## 9. 他担当との境界・引継ぎ

- **YARAルール調査担当**：ルールの入手元/許諾、署名方式、版固定、分類、悪意あるルールのlint/検証、更新時のアトミックな公開の具体基準。
- **PE / 難読化解析担当**：既存PE判定とYARA-X pe-moduleの所見統合、復元層の原本/導出追跡、サイズ制限・incompleteの伝播、誤検知事例の検証。
- **Windowsセンサー/運用担当**：イベント採取、ProcessGuid相関、権限分離、Windows Job Object、サービスの再起動・レート制限、Defender共存の実測。
- **レポート統合担当**：Rule/Pattern/Matchの証拠スキーマとPIIの最小化。YARA-XのCLI JSON形式は参考に留め、AegisGuardの既存Reportと整合させる。
- **本担当の境界**：GitHubソースの静的調査と導入判断まで。実装・CI/設定編集・検体実行・外部依存の法的最終評価は行っていない。

## 10. 未確認事項・追加調査項目

1. **高：直接依存の互換性**。Windows 11 MSVCでYARA-X 1.22.1をRust 1.95+でビルド/testできるか。MSRVを引き上げた場合のAegisGuard本体依存との衝突、exeサイズ、リンク条件、cargo lock解決は未確認。
2. **高：隔離・強制終了**。悪意あるルール/ファイルでの最長停止遅延、プロセス分離時のJob Object/親監視、JIT実行ページのDefender/企業ポリシーとの相性は未確認。
3. **高：ライセンス**。依存クレートすべてのライセンス・NOTICEおよび利用予定ルール/署名データのライセンスは未監査（**法的評価未完了**）。
4. **高：実測性能と誤検知**。既存PE/スクリプト検査との比較CPU・RSS、最悪メモリ、false-positive率、Rulesの再利用効果は未実測。
5. **中：旧版選択の健全性**。v1.0.0は宣言上MSRV 1.85.0だが、修正漏れ、既知脆弱性、Cargo.lock・ルール互換性、サポート期間の検証が必要。恒久的な採用推奨ではない。
6. **中：ルールキャッシュ**。serializeのフォーマット版・native-code-serialization・プロファイルfeature差・プロセス間互換、第三者改変検知、内部キャッシュの保管ACLが未決定。
7. **中：ファイル一貫性**。スキャン中のファイル変更・reparse-point競合を一貫して検出するWindowsハンドル設計が未確認。
8. **中：CIステータス**。上流テストソースとCI定義を確認したが、固定コミットの全CIジョブの成否・実行ログは個別に未確認。

## 11. 一次情報一覧

すべて2026-11-05参照。YARA-Xの固定コミットは 910a938569a0fa16db5ad7d0d492b18ad8e70d93、AegisGuard固定コミットは 83fcf0d150e8d760baff5f971c106deb09c1f8e4。主な断定に結び付く一次ソース：

1. [YARA-X workspace Cargo / MSRVと版](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/Cargo.toml#L1-L20)、[AegisGuard Cargo / MSRV](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/Cargo.toml#L1-L25)。
2. [コンパイル入口 add_source](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/mod.rs#L617-L706)、[build とRules共有の設計](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/mod.rs#L825-L855)。
3. [Scannerの入力・上限・タイムアウト](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/mod.rs#L188-L396)、[負荷テスト](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/tests.rs#L1324-L1361)。
4. [Match出力の識別子/offset/data](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/models.rs#L349-L500)、[CLI NDJSONの参考スキーマ](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/cli/src/commands/scan.rs#L596-L685)。
5. [Rulesシリアライズと外部データ警告](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/rules.rs#L285-L418)、[異常入力のテスト](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/tests/mod.rs#L14-L78)。
6. [PEモジュール実装](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/modules/pe/mod.rs#L24-L49)、[default feature](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/Cargo.toml#L288-L322)。
7. [BSD-3-Clause原文](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/LICENSE#L1-L26)、[Wasmtimeなどの依存](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/Cargo.toml#L324-L405)、[Windows/MSRV CI matrix](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/.github/workflows/tests.yaml#L19-L107)。
8. [AegisGuard入力上限・原本バッファ](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/scan.rs#L9-L80)、[復元上限](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/script.rs#L12-L15)、[不完全を表すReport](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/model.rs#L27-L112)。
