# 調査報告：YARA-X / yara-rules-maintenance

> 担当：yara-rules-maintenance / 調査日：2026-11-05（JST） / 調査結果：部分完了（一次コード・テスト・設定・ライセンスの静的調査完了、実機・互換率の再現試験未実施）

## 0. 結論（3〜5行）
- **導入価値：高。** YARA-X の Rust API はファイル全体と復号済みメモリ領域の両方を走査でき、ルールに対応する根拠を AegisGuard の JSONL に付加できる。ただし現行 MVP への統合は**未実装**。
- **最優先候補：** ルール互換性ゲート（構文・警告・除外ルールの検査）と、証拠データを保存しない監査モード。更新配布より先に安全な固定ルールセットで検証する。
- **見送り候補：** ライセンス未審査の YARA Forge 全量同梱、署名・互換性確認のない自動更新、信頼できないコンパイル済みルールの直接ロード。
- **最大の技術制約：** YARA-X v1.22.1 系のワークスペースは Rust 1.95.0 以上、AegisGuard は 1.85 以上であり、同一ビルドへの crate 追加にはツールチェーン計画が要る（[YARA-X Cargo](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/Cargo.toml#L1-L15)、[AegisGuard Cargo](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/Cargo.toml#L1-L15)）。
- **最大の供給網制約：** YARA-X 本体の BSD-3-Clause と、YARA Forge 集約ツールの GPL-3.0、各上流ルール著作者の条件は**別契約**。YARA Forge の QA は従来 YARA エンジンで行われ、YARA-X 互換を保証しない。

## 1. 対象の固定と調査方法

| 要素 | 値 / 根拠 |
|---|---|
| 公式リポジトリ・commit固定URL | [VirusTotal/yara-x の固定ツリー](https://github.com/VirusTotal/yara-x/tree/910a938569a0fa16db5ad7d0d492b18ad8e70d93)（公式組織、デフォルトブランチ main） |
| 調査コミットSHA・タグ | **910a938569a0fa16db5ad7d0d492b18ad8e70d93**。確認時の最新リリース **v1.22.1**（2026-10-26 公開、[リリース](https://github.com/VirusTotal/yara-x/releases/tag/v1.22.1)）。調査対象はタグではなく上記 main SHA。 |
| 併せて調べたルール集 | [YARAHQ/yara-forge 固定ツリー](https://github.com/YARAHQ/yara-forge/tree/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89)（デフォルト master、SHA **38825cf1e3cdda6e0112d0bab6a262ea2ea50f89**）。確認時の最新公開ルールパッケージ [20261103](https://github.com/YARAHQ/yara-forge/releases/tag/20261103)（2026-11-03 公開）。 |
| AegisGuard の比較先SHA | 最新 main **83fcf0d150e8d760baff5f971c106deb09c1f8e4**（[ツリー](https://github.com/choko510/AegisGuard/tree/83fcf0d150e8d760baff5f971c106deb09c1f8e4)）。依頼の調査指示は別の docs/research-agent-program ブランチから読んだ。 |
| ライセンスファイルと対象範囲 | YARA-X [LICENSE](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/LICENSE#L1-L26) / [ワークスペース明記](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/Cargo.toml#L1-L14)：BSD-3-Clause。YARA Forge [LICENSE](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/LICENSE#L1-L20)：GPLv3、ただし同梱される**第三者ルールの包括的許諾ではない**。AegisGuard は [README](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md) にコードライセンス未設定と明記。 |
| ソース/ドキュメント確認範囲 | YARA-X：compiler、scanner、Rules シリアライズ、CLI check/scan、Cargo、回帰テスト、互換差の公式ドキュメント、リリース。YARA Forge：収集・加工・QA・出力・テスト・requirements・GitHub Actions・設定・GPL。AegisGuard：README、SECURITY、ARCHITECTURE、Cargo、src/main/scan/script/model/pe/c2、CI。 |
| 実機・ビルド・テスト | **未実施**。外部プロジェクトの未知のコードやサンプルを実行せず、公式のテスト**実装を読んだ**。Windows 11 + Defender の検証、バイナリビルド、実ルールの差分比較・性能ベンチマークは未実施。 |
| 日付・未検証制限 | 2026-11-05。最新 SHA / リリース / ライセンスはこの日の取得状態。データセットを使った互換率、誤検知率、実行時のリソース消費、ルールの個別許諾は**未確認**。 |

## 2. 実装アーキテクチャとソース調査

### 機能マップ（コード・テストで確認できたこと）

| 機能 | 主要なファイル/シンボルと役割 | commit SHA固定の一次情報 | 確認状態 |
|---|---|---|---|
| YARAソースのコンパイル | **Compiler::add_source** は文字列・バイト列・複数ソースを受ける。失敗後も成功ルールだけが build 対象になり得るため「build できた」だけで全件成功と判定不可。 | [compiler/mod.rs L617-L659](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/mod.rs#L617-L659) | 実装確認 |
| コンパイル警告・欠落の把握 | **Compiler::errors / warnings / ignored_rules**。**ignore_module** は依存するルールも除外する。既定で無視せず、供給時には無効化件数を監査する。 | [compiler/mod.rs L995-L1022](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/mod.rs#L995-L1022)、[L1150-L1175](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/mod.rs#L1150-L1175)、[回帰テスト L931-L977](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/tests/mod.rs#L931-L977) | 実装・テスト確認 |
| 互換性と厳格な構文 | YARA 4.x との差として regex のリテラル左波括弧のエスケープ、無効なエスケープ、3文字未満の base64、ルール名ワイルドカード、xor+fullword の意味差。**relaxed_re_syntax** は存在するが安易な既定有効化は避ける。 | [differences L21-L145](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/site/content/docs/writing_rules/differences.md#L21-L145)、[L161-L198](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/site/content/docs/writing_rules/differences.md#L161-L198)、[L231-L249](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/site/content/docs/writing_rules/differences.md#L231-L249)、[compiler L1073-L1097](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/mod.rs#L1073-L1097) | 仕様・実装確認 |
| 利用可能モジュール | PE・hash などは feature gated。**cuckoo** は互換性目的で維持するが積極的な保守は推奨されない。外部で使うモジュール/フィールドの差分はルール単位で検証が必要。 | [lib/Cargo L162-L214](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/Cargo.toml#L162-L214)、[L249-L253](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/Cargo.toml#L249-L253)、[モジュール登録](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/modules/add_modules.rs#L3-L40) | 実装確認 |
| 実走査と上限 | **Scanner::scan(&[u8]) / scan_file**、**set_timeout / max_matches_per_pattern / fast_scan / max_scan_size / use_mmap**。タイムアウトは絶対的な即時停止保証ではなく、max_scan_size は無警告の切り詰めを生じうるため呼出側で**不完全判定**する。 | [scanner/mod.rs L201-L231](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/mod.rs#L201-L231)、[L233-L318](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/mod.rs#L233-L318)、[L346-L396](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/mod.rs#L346-L396)、[上限テスト](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/tests.rs#L661-L707)、[タイムアウトテスト](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/tests.rs#L1333-L1360) | 実装・テスト確認 |
| ルールのキャッシュ | **Rules::serialize / deserialize**。第三者が操作し得るバイト列の deserialize はスキャン中 panic リスクがあると公式コードが明示警告。形式バージョンは検査するが署名検証ではない。 | [rules.rs L285-L325](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/rules.rs#L285-L325)、[L421-L455](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/rules.rs#L421-L455) | 実装確認 |
| 危険パターンの静的ゲート | **error_on_slow_pattern / error_on_slow_loop / enable_includes(false)**。コンパイル時に重いパターンを検出・拒否し、予期しない include 解決を防止できる。Unicode regex の非対応や巨大正規表現を検査するテストもある。 | [compiler/mod.rs L1099-L1130](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/mod.rs#L1099-L1130)、[tests L2335-L2365](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/tests/mod.rs#L2335-L2365) | 実装・テスト確認 |
| CLI 運用 | **yr scan** はコンパイル済みルール入力、ファストスキャン、マッチ上限、タイムアウト等を受ける。**yr check** はソース/メタデータ検査（現時点で help 非表示）を含み、テストがある。 | [cli/scan.rs L40-L126](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/cli/src/commands/scan.rs#L40-L126)、[cli/check.rs L18-L52](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/cli/src/commands/check.rs#L18-L52)、[CLIテスト](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/cli/src/tests/check.rs#L6-L55) | 実装・テスト確認 |
| Forge のルール収集・ライセンス追跡 | **retrieve_yara_rule_sets** は各上流を clone し commit を記録、LICENSE を探し見つからなければ **NO LICENSE SET** とする。**process_yara_rules** は source_url と license_url をメタデータへ追加。 | [collector L78-L130](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/main/rule_collector.py#L78-L130)、[L169-L184](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/main/rule_collector.py#L169-L184)、[processors L176-L210](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/main/rule_processors.py#L176-L210) | 実装確認 |
| Forge のパッケージ分類 | **write_yara_packages** は core / extended / full の品質・スコア閾値、private 依存ルール、上流 commit とライセンスヘッダを処理。閾値は品質指標であり実測誤検知率ではない。 | [output L123-L177](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/main/rule_output.py#L123-L177)、[L180-L195](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/main/rule_output.py#L180-L195)、[config L300-L365](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/yara-forge-config.yml#L300-L365)、[テスト](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/tests/test_rule_output_guardrails.py#L96-L129) | 実装・テスト確認 |
| Forge の QA エンジン | **check_syntax_issues / check_issues_critical / check_yara_packages** が **yara-python の yara.compile** を用いて検査。**YARA-X コンパイル結果ではない**。 | [qa/rule_qa.py L243-L301](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/qa/rule_qa.py#L243-L301)、[L320-L342](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/qa/rule_qa.py#L320-L342)、[requirements](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/requirements.txt#L1-L8) | 実装確認 |
| Forge の公開配布経路 | 毎週の GitHub Actions がルール ZIP とログを release asset に upload。確認した workflow / 最新 release asset 一覧には**独立した署名や .sig は見当たらない**（外部署名処理の完全な不存在は未確認）。 | [weekly-release L1-L36](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/.github/workflows/weekly-release.yml#L1-L36)、[L66-L92](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/.github/workflows/weekly-release.yml#L66-L92)、[L116-L148](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/.github/workflows/weekly-release.yml#L116-L148)、[公開release](https://github.com/YARAHQ/yara-forge/releases/tag/20261103) | 配布手順確認・署名保証未確認 |
| AegisGuard の接続点 | **scan_file** は PE 64MiB / script 4MiB の上限内で bytes を読む・SHA256 算出後 pe::inspect または script::inspect を呼ぶ。**script::inspect** は raw と限定復号層を処理。 | [scan.rs L9-L81](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/scan.rs#L9-L81)、[script.rs L499-L563](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/script.rs#L499-L563) | 現行実装確認 |
| AegisGuard の検知出力 | **Report** は status/risk/analysis_complete/incomplete_reasons を保持し、シグナルを集約。JSONL には path があり機密性に注意。スクリプトテストは復号内容の URL が出力に残らないことを確認している。 | [model.rs L3-L41](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/model.rs#L3-L41)、[L78-L114](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/model.rs#L78-L114)、[scriptテスト L594-L603](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/script.rs#L594-L603)、[scan L122-L129](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/scan.rs#L122-L129) | 現行実装・テスト確認 |

**互換率についての判定：** YARA-X の[公式サイト](https://virustotal.github.io/yara-x/)には「99% rule compatible」との表示があるが、対象ルール集合、分母、テスト手順をこの調査で再現できていない。**AegisGuard が採用するルール集合の互換率は未測定**とする。単なる構文通過率では不十分で、検出結果の一致/不一致、import モジュール差、warning、無効化ルール、誤検知を別々に記録する。旧 YARA との API 差とプロセス走査非対応は[公式比較文書](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/site/content/docs/intro/yara_vs_yara-x.md#L124-L137)に明記される。

### 実装済みと提案事項の区別
- **AegisGuard 実装済み：** 読み取り専用ファイル検査、SHA256、限定静的復号、JSONL、C2 フィードの手動更新と鮮度管理。C2 キャッシュの退避とロールバックは [c2.rs L277-L307](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L277-L307) に実装があるが、これは **YARA ルール更新機能ではない**。
- **未実装：** YARA-X コンパイラ/スキャナの取り込み、ルール更新・暗号署名・個別ライセンス審査、ルール除外/allowlist、監査用ルールID保存、バックグラウンド監視、Windows サービス。現行 CLI は **scan / c2** だけ（[main.rs L24-L75](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/main.rs#L24-L75)）。
- **設計提案（未実証）：** ルール検証・署名パッケージ、バージョン固定、ハンドル単位のルールスナップショット切替、除外ポリシー、復号層の匿名化証拠、差分回帰環境。

## 3. 具体的な取り込み候補と選択肢

| 候補機能 | 利用方法（crate/API・外部CLI・独自実装・参考・見送り） | AegisGuard接続先 | 優先度 | 工数目安 S/M/L | ライセンス・技術上の阻害要因 |
|---|---|---|---|---|---|
| 1. 互換性 CI ゲート、ルール台帳 | **crate/API直接利用**（長期本命）、**外部CLI**（現時点の隔離 PoC） | 将来の rule-qa（現存せず）、scan の前段 | **P0** | **M** | MSRV 1.95、import 乖離、部分成功/ignored ルール、個別ライセンス |
| 2. 読み取り専用の raw/復号層走査 | **crate/API直接利用** | src/scan.rs と src/script.rs、src/model.rs | **P0** | **M** | 復号層のメモリ/PII、タイムアウト不確実、Windows テスト |
| 3. ルール更新・署名検証・ロールバック | **AegisGuard独自実装**（YARA-X は実行エンジン） | 将来の rule-store / updater（現存せず） | **P1** | **L** | 署名鍵運用、上流ルール別許諾、原子更新、解決可能な依存 |
| 4. 警告/ルール無効化/allowlist | **AegisGuard独自実装**、YARA-X lint/API を利用 | model の signals と将来の policy | **P1** | **M** | 検出抑止の監査/有効期限/理由/可視化 |
| 5. Forge のソース追跡と品質スコア | **設計参考のみ**（コード転用なし） | 将来の rule-qa / 調達台帳 | **P1** | **S** | Forge コード GPL-3.0、スコアは誤検知実測を代替しない |
| 6. 任意の Forge ルール ZIP を自動同梱 | **見送り** | なし | — | — | 原著作権の個別確認不足、未確認の外部署名、YARA-X での再検証不足 |
| 7. 信頼できない外部コンパイル済みルールを deserialize | **見送り** | なし | — | — | 公式が第三者改ざんバイト列の危険を明示 |

**候補1の契約と失敗処理：** 入力は UTF-8 のルールソース/固定ソースSHA/ライセンス台帳/期待する rule ID 集合。出力は compile errors、warnings、ignored_rules、import、受理/拒否件数とルールパック SHA256。未知モジュール、部分成功、想定外の警告は**不採用**として旧版を保持。PoC は手書き無害ルールで従来 YARA と YARA-X の両方に対し compile + 同一 fixture の走査を比較する（あらかじめ信頼できる固定ツールのみ）。

**候補2の契約と失敗処理：** 入力は scan_file が読み込んだ境界付き bytes と script の一時的な raw/復号 Layer bytes（文字列はデコード用メモリのみに残す）。出力は **namespace / rule ID / pack digest / 原本 SHA256 / layer SHA256 / layer 種類 / status / 処理時間** のみ。Scanner::scan の Result とスキャン上限を用い、TimeOut、部分復号、サイズ切り詰めは **not_assessed / incomplete** 相当にし、無検出として扱わない。既存 JSONL との統合前に無害 fixture で私的情報非出力をテスト。

**候補3の契約と失敗処理：** 入力は HTTPS 取得の検証対象 manifest（版、各ファイル SHA256、ルールID、上流 SHA、ライセンス、期限、署名）とルールソース。署名鍵を固定した検証、サイズ制限、zip展開時の path traversal 対策、ライセンス審査、YARA-X compile、回帰テスト後、**候補状態→監査→明示昇格**。起動時・クラッシュ時は署名検証済み旧パックを選ぶ。更新の途切れで「最新版」を装わない。PoC は署名不正/期限切れ/ロールバック要求の**無害な模擬パック**で拒否・復元を確認。

**候補4の契約と失敗処理：** 入力は namespace、rule ID、スコープ（原本ハッシュ優先）、理由、承認者、期限、設定の digest。出力は原始検出/除外理由/通知抑制の**両方**。除外はファイルパス全体・機器全体に広げない。ポリシー破損/期限切れは勝手に大域 allow にせず、監査通知と安全側の扱いにする。PoC は無害な管理スクリプトで除外が期限切れ後に戻ることを確認。

## 4. ライセンス・再配布・依存関係

| 対象 | 確認済みの条件 | AegisGuardへの意味 / 未解決点 |
|---|---|---|
| **YARA-X エンジン/ソース** | ワークスペース宣言は **BSD-3-Clause**。再配布時の著作権・条件・免責文の保持、商標/推奨を誤認させない義務（[LICENSE](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/LICENSE#L1-L26)）。 | crate 直接利用の有力候補。コード変更/バイナリ同梱時は notices を整える。**依存 crate ごと**の SBOM・再配布条件監査は未完了。 |
| **YARA-X の依存** | [Cargo.toml](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/Cargo.toml#L33-L125) に wasmtime 48.0.8、regex、bincode、protobuf 等の設定。feature 次第で暗号・各種パーサ依存も入る（[lib Cargo](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/Cargo.toml#L146-L253)）。 | サイズ/CPU/メモリ、依存の脆弱性、MSRV/Windows x64、ビルド・runtime の個別条件を別途監査。BSD 本体が全依存物の許諾を自動的に代表するわけではない。 |
| **YARA Forge 集約処理コード** | [GPLv3 原文](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/LICENSE#L1-L20) と [requirements.txt](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/requirements.txt#L1-L8)（Python、plyara、yara-python 等）。 | Python 処理コードを AegisGuard にコピー/リンクしない。**別プロセス CLI なら必ず問題ない**とは断定できない。配布形態、派生物性、利用規約は専門家判断を要する。 |
| **Forge が集めた第三者ルール** | [collector](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/main/rule_collector.py#L113-L130) は上流ルートまたは発見した LICENSE を保存、見つからなければ **NO LICENSE SET**。各ルールに [source_url/license_url](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/main/rule_processors.py#L180-L190) を付け、[パッケージヘッダ](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/yara-forge-config.yml#L330-L364) に上流テキストを挿入。 | **収集できた・zip に入っている ≠ 同梱/再配布の許可**。個々のルールやサブフォルダ、個別 meta 指定、上流コミット、改変物、著作者表示、非商用・share-alike・禁止条件を審査する。欠落/不明ライセンスは自動同梱禁止。 |
| **署名・フィード・他の解析データ** | 調査した Forge の [週次公開ワークフロー](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/.github/workflows/weekly-release.yml#L66-L92) は ZIP リリースを行う。最新版の公開 asset は log/issues/core/extended/full の各ファイル。独立署名の同梱は確認できていない。 | HTTPS や GitHub リリースタグだけで作者の署名を代用しない。AegisGuard 独自の検証済み manifest・ハッシュ・署名方針を策定。公開元の生成物に署名が存在するかは別途調査。 |
| **AegisGuard** | [README](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md) は現時点でライセンス未設定。 | 外部ルールを組み込んだ将来の公開/配布を前提に、プロジェクト所有者と法務が全体方針を確定するまで同梱しない。 |

差分設計：ローカルで利用者が個別に取得しているルールを**利用者権限内でスキャンに使う**行為、AegisGuard 製品への**同梱**、こちらが**ダウンロード/改変して再配布**する行為、Forge **GPL コードの転用**は異なる。いずれも法的最終評価は未完了。検討だけでルール著作権の許諾を推定しない。[Forge 設定の Elastic ソース除外コメント](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/yara-forge-config.yml#L9-L18) も、集約側で再配布条件の制約が現に生じることを示す。

## 5. Defender共存・Windows制約・権限境界

**現行の事実：** AegisGuard は Windows 11 x64 / Defender 継続利用の読み取り専用 MVP であり、Sysmon、ETW、AMSI、WFP/Windows Firewall 操作、常駐サービスはまだ存在しない（[SECURITY](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md)、[ARCHITECTURE](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md)）。検査ファイルの自動実行・アップロードは禁止。現在の scan は通常の読み込み権限に従い、アクセス拒否を unreadable/not_assessed にする（[scan.rs L30-L82](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/scan.rs#L30-L82)）。

**提案：** YARA-X は**同じファイルの追加静的検査**として段階導入し、Defender の保護設定・隔離判断・ASR・Firewall を変更しない。二重スキャンの CPU/ディスク I/O は専用ベンチで測る。AMSI はホスト依存であり、YARA-X の raw bytes 走査を PowerShell/JS/Python 実行監視の代用品としない。ETW/Sysmon の時系列相関と WFP による遮断は別担当の将来機能と区別。ユーザーモードで読めない保護対象を「陰性」にしない。将来のサービス更新は高権限プロセス/ユーザープロセスを分離し、ACL・再解析ポイント・TOCTOU・更新原子性を検証する。YARA-X の scan_file は既定 mmap を許容し、対象の切り詰め時に問題があり得るため [use_mmap(false)](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/mod.rs#L289-L303) または既存の有界バイト列から scan() する方向を優先する。

**プライバシー：** YARA のルールやメタデータには出所不明の文字列・サンプル記述を含み得る。マッチした生バイト、照合前後の断片、復号済み文字列、ブラウザ認証情報らしき値、URL のクエリ、ルールの自由入力メタデータを JSONL/エラーログへ複写しない。既存 Report.path 自体が PII になり得るため保存先 ACL と保存期間を別途策定する。

## 6. 性能・堅牢性・誤検知

**実測：** 本調査の実測は**ゼロ**。公式比較資料の速度例は AegisGuard/Windows/対象ルールの検証値ではない（[YARA-X 比較資料](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/site/content/docs/intro/yara_vs_yara-x.md#L60-L100)）。Forge の quality/score も検出精度の保証ではない。

**攻撃者入力への境界：** サイズ超過と復号制限は現行 scan/script が持つ（[scan L9-L11](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/scan.rs#L9-L11)、[script L12-L15](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/script.rs#L12-L15)、[L521-L562](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/script.rs#L521-L562)）。これを YARA-X にも引き継ぎ、ルールソース総サイズ/ルール数/コンパイル時間/regex の slow warning / scan 時間/同時ジョブ数/匹配件数/JSONL 件数に上限を設ける。**set_timeout は遅延し得る**ので、高危険・未審査ルールのコンパイルは隔離ワーカーと OS 側でのタイムアウト/メモリ制限を検討する。スキャン前に全件 UTF-8/allowlisted module/import/実ファイルの範囲を検証し、include を原則禁止。compiled rules は[第三者バイト列を直接デシリアライズしない](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/rules.rs#L298-L305)。

**誤検知：** 単独のキーワード（Admin スクリプト中の認証情報文字列、無害な管理用 PowerShell、テスト fixture、ドキュメント記載の IOC）や復号層の同じ文字列に重複で反応し得る。優先順は (a) 原本/復号層での検出を**別記録**、(b) ルール ID + 版 + provenance を表示、(c) SHA256 などファイル固有の許可と期限付き除外、(d) Defender がすでに検知/隔離したものは重複通知を集約、(e) 通知は監査段階で手動分類して閾値を**ベースラインから決める**。YARA Forge core/extended/full の閾値は [設定ファイル](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/yara-forge-config.yml#L300-L328) にあるが、AegisGuard のリスクスコア閾値に転写しない。

**検査漏れ・キャッシュ：** ファイル先頭の切り詰め、サイズ超過、復号層数/深度/総量の上限、パスの差替え、ルールの一部コンパイル失敗、unknown/ignored module、Unicode 解釈やファイル種別差は false negative の源泉。結果キャッシュキーには原本 SHA256、**復号層 SHA256**、復号器/設定の版、ルールパック SHA256、YARA-X の版、scan/除外設定 digest を含める。原本更新、ルール切替、復号器更新、期限切れ allowlist、設定変更では無効化する。未知の中断は clean 判定を保持しない。

**更新とスキャンの競合：** 既存の scan が使うルール参照は切替時点の**不変スナップショット**として保持し、新規 scan だけ新しい署名済みルールを使用する。途中差替えやキャッシュ混在を禁止し、各結果に使用した pack digest を記録する。書込みは staging →検証→atomic replace→明示昇格、失敗なら last-known-good の維持/復帰。クラッシュ再起動・ディスク枯渇・期限切れキー・署名失敗を fault-injection テスト対象とする。ここに挙げた処理は**未実装の設計案**である。

## 7. 推奨する小さなPoCと成功基準

- **前提：** Defender 有効の隔離された Windows 11 x64 テスト VM。ネットワーク送信を行わず、無害・自作のルールと fixture、確認済みの固定バージョンを使用。YARA-X 1.22.1 の **Rust 1.95 MSRV** に合わせるか CLI を別環境で稼働し、AegisGuard 本体ツールチェーンの無断更新はしない。
- **安全なサンプル/検証方法：** （1）文字列一致/非一致の平文、無害な PE fixture、Base64/UTF-16 を含む人工的スクリプトを用意。（2）YARA の旧版と YARA-X で構文・expected rule ID・matched/unmatched を比較。（3）非対応構文（非エスケープの波括弧、無効 escape、短い base64、rule wildcard）、unknown module、意図的な slow pattern を**ルール文字列だけ**として検証。（4）Forge はコードを実行せず、ライセンス審査済み**少数**ルールのみ手動で固定・検査。
- **成功条件と性能測定方法：** (a) 自作の正/負 fixture で期待 rule ID の不一致 **0**、検査に失敗した fixture の clean 扱い **0**、無視されたルール/予期しない警告 **0**。(b) raw/decoded の再現可能な各層から得るマッチの**ルールIDと層hashのみ**が JSONL に残り、テスト用秘密文字列/復号全文/マッチ生データのログ流出 **0**。(c) 境界到達、timeout、切り詰め、不正 include、無署名/破損パックを**エラーまたは incomplete**として記録。(d) 単独スキャンと Defender 有効/無変更の条件で wall time、p50/p95、CPU、ピークRSS、I/O、JSONL サイズを同一 fixture・同一マシンで各回測り、ベースラインと比較。**性能の合否閾値は実測後に決定**。
- **段階：** 無効 → 監査のみ（ユーザー操作のローカル検査）→ ライセンス審査・誤検知レビューが済んだ少数ルールだけを限定有効化。デフォルトで遮断/削除/Defender設定変更はしない。サンプル数が増えてもパックごとに回帰テストを再実行する。
- **失敗時の扱い・ロールバック：** 旧ルールパック digest を保持し、新ルールの不採用・旧版への復元・有効設定の解除を監査ログに記録。スキャンは not_assessed/incomplete、通知は過度な確定表現を用いない。作業の中断で旧パックを破棄しない。
- **中止条件：** 不正署名を受理、利用条件不明ルールを同梱、生の検体/復号文字列がログへ出る、無害 fixture で大幅負荷やクラッシュ、Defender の既存保護を変更する必要が出る、または入力が予期せずネットワーク/実行に進む場合。

## 8. 採用しない設計と理由

1. **YARA Forge の core/extended/full を丸ごと標準同梱して自動通知・遮断する案：見送り。** Forge の repo-level LICENSE/メタデータ収集は法的審査の完成を意味せず、QA は YARA-X ではなく旧 YARA。大量ルールの精度/性能は未実測。まず個別監査済みの少数ルールで段階導入する。
2. **外部からダウンロードした compiled-rules をそのまま Rules::deserialize して即切替する案：見送り。** [公式警告](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/rules.rs#L295-L305) に反する。署名やハッシュで検証したソースを安全なビルド環境でコンパイルし、ローカル生成物だけを使う方針とする。
3. **YARA-X の一致だけで Defender/Firewall を自動停止・遮断、あるいは「陰性＝安全」と判断する案：見送り。** 不完全解析、誤検知、既存保護との競合がある。観察モードを維持する。
4. **互換モードを常時有効にしてエラーを握りつぶす案：見送り。** 意味差や部分コンパイル失敗を隠す。互換緩和は移行用の一時運用とし、差分を版管理する。

## 9. 他担当との境界・引継ぎ

- **Rust コア/ビルド担当：** YARA-X 1.22.1 の MSRV 1.95、edition 2024、Wasmtime/ネイティブコード/feature 構成と Windows x64 ビルド・SBOM の判断。現行 AegisGuard は 1.85 で、ここでは変更しない。
- **静的難読化・PE 担当：** raw bytes とデコード層の受け渡し時のライフタイム・入力上限・ハッシュ/検査漏れの意味付け。PE モジュールの既存独自解析との重複を調整。
- **脅威フィード/更新担当：** C2 キャッシュの堅牢化とは分離したルール署名鍵、配布 manifest、原子的更新、TTL、失効、ロールバック、ルール単位の利用権台帳。
- **Windows センサー/応答担当：** Sysmon/ETW/AMSI の入力、イベント相関、Defender 重複通知、権限境界、WFP への判断の輸送路は本担当では実装/決定しない。
- **プライバシー/UI 担当：** 復号テキストのログ禁止、ファイルパスの ACL、証拠 digest、allowlist の監査画面、通知文面、保管期限。第三者の自由文言 metadata はそのまま表示しない。

## 10. 未確認事項・追加調査項目

1. **重大／法務：** 採用候補ルールの**個別**著作権表示・ライセンス（配布/改変/同梱/商用利用、ルール内 meta とサブディレクトリ）および AegisGuard の最終ライセンス決定。法的評価未完了。
2. **重大／供給網：** YARA Forge release assets に使用可能な署名・ハッシュ・透明性記録が別経路に存在するか、公開タグから上流 commit と成果物の再現性を検証できるか、鍵の失効/ロールバック管理の運用。
3. **重大／互換：** 採用予定ルール集合の**実測** compile 成功率、ignored/warnings 数、旧 YARA と YARA-X の判定差、PE/その他 module のフィールド差、正規表現の意味差。「99%」の分母は未確定。
4. **高／依存：** Windows 11 x64 / Rust 1.95 でのビルド、静的/動的リンクの依存ライセンス、crate feature、Wasmtime/プロセス別隔離のコスト、CI 再現性と依存脆弱性。
5. **高／セキュリティ：** third-party rules による regex/loop負荷、巨大圧縮ファイル、タイムアウト遅延、YARA-X のシリアライズ由来の将来的な脆弱性、OS ワーカー分離の効果。
6. **高／品質・運用：** 実データに近い**安全な** benign fixture での false positive rate と層別重複、allowlist 誤設定、CPU/RSS/I/O/電力、Defender との二重走査、更新中/再起動時の回復。
7. **中／外部 CLI：** CLI 配布形態・署名・実行可能ファイルの供給網と、正規化された JSON/NDJSON 出力・exit code の運用可否。CLI による PoC をそのまま製品統合とみなさない。

## 11. 一次情報一覧

以下のリンクはいずれも **2026-11-05 参照**、ソースについては**commit SHA 固定**。少なくとも 5 件以上の実装判断を一次資料で検証した。

1. YARA-X のルール取り込みと**部分成功の注意**：[Compiler::add_source](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/mod.rs#L617-L659)、[errors/warnings/ignored_rules](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/mod.rs#L1150-L1175)。
2. YARA-X の **module 依存による無効化**：[ignore_module](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/mod.rs#L995-L1003)、[コンパイラの回帰テスト](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/tests/mod.rs#L931-L977)。
3. **regex / base64 / 演算子の互換差**：[差分マニュアル](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/site/content/docs/writing_rules/differences.md#L34-L145)、[L161-L249](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/site/content/docs/writing_rules/differences.md#L161-L249)。
4. **実走査 API とリソース上限**：[Scanner](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/mod.rs#L201-L396)、[match 上限のテスト](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/tests.rs#L661-L707)、[タイムアウトのテスト](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/scanner/tests.rs#L1333-L1360)。
5. **危険な compiled rules デシリアライズ警告**：[Rules::deserialize](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/rules.rs#L285-L325)。
6. **重いルールへのコンパイル時拒否・include 制御**：[Compiler 設定](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/mod.rs#L1099-L1130)、[巨大 regex テスト](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/lib/src/compiler/tests/mod.rs#L2335-L2365)。
7. **現行依存・MSRV・ライセンス**：[YARA-X Cargo](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/Cargo.toml#L1-L15)、[依存](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/Cargo.toml#L33-L125)、[LICENSE](https://github.com/VirusTotal/yara-x/blob/910a938569a0fa16db5ad7d0d492b18ad8e70d93/LICENSE#L1-L26)、[AegisGuard Cargo](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/Cargo.toml#L1-L15)。
8. **Forge ルール出所とライセンス**：[clone/出所 commit](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/main/rule_collector.py#L78-L111)、[LICENSE 探索](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/main/rule_collector.py#L113-L130)、[rule metadata](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/main/rule_processors.py#L176-L210)。
9. **Forge の YARA 系 QA と package 出力**：[qa/rule_qa.py](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/qa/rule_qa.py#L243-L342)、[出力](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/main/rule_output.py#L153-L195)、[テスト](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/tests/test_rule_output_guardrails.py#L96-L129)。
10. **Forge 公開成果物の生成手順**：[weekly-release workflow](https://github.com/YARAHQ/yara-forge/blob/38825cf1e3cdda6e0112d0bab6a262ea2ea50f89/.github/workflows/weekly-release.yml#L66-L148)、[最新版の公開 release](https://github.com/YARAHQ/yara-forge/releases/tag/20261103)。
11. **AegisGuard への入力/証拠/JSONL接続点**：[scan_file](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/scan.rs#L22-L81)、[script のレイヤ処理](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/script.rs#L441-L563)、[機密文字列の非出力テスト](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/script.rs#L594-L603)、[Report](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/model.rs#L27-L114)。
12. **公式補助文書（バージョン固定ではないため説明用）**：[YARA-X 公式サイト](https://virustotal.github.io/yara-x/)（99% 表示は再現未了）、[Rust crate API](https://docs.rs/yara-x/latest/yara_x/struct.Scanner.html)。動作主張は上記 commit 固定ソース優先。
