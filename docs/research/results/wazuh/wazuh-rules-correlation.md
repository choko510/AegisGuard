# 調査報告：Wazuh / wazuh-rules-correlation

> 担当：wazuh-rules-correlation（ルールエンジン・イベント相関・スコアリング／ローカル運用） / 調査日：2026-11-05 / 調査結果：部分完了（ソース・テスト・ライセンス原文の静的確認は実施、ビルド・実機動作は未実施）

## 0. 結論（3〜5行）

- **取り入れる価値：高い。ただし取り込むのは設計・テストの考え方であってWazuh実装本体ではない。** 4.x のルール相関には「前段デコード→階層ルール→同一キー・時間窓→アラートと根拠保持」という明確な実装がある。[src/analysisd/analysisd.c#L2120-L2204](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/analysisd.c#L2120-L2204)、[src/analysisd/eventinfo.c#L99-L156](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/eventinfo.c#L99-L156)
- **最優先：AegisGuard固有の小さなRustローカル相関器。** 現状のファイル別Reportに、時刻・プロセス識別子・イベント欠損状態と複数イベントの根拠を追加する。[src/model.rs#L4-L110](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/model.rs#L4-L110)、[docs/ARCHITECTURE.md#L11-L30](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L11-L30)
- **Wazuh 5.xと4.xは同一エンジンではない。** 取得した5.1.0-alpha0はC++ Engineのポリシー／デコーダ／前後フィルタ／ルーター構成で、4.xのfrequency/timeframe相当の完全な時系列相関を実装済みと認定できない。[src/engine/source/builder/src/policy/factory.cpp#L387-L504](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/source/builder/src/policy/factory.cpp#L387-L504)
- **見送り：Wazuh Manager/Indexer一式のWindows移植、Wazuhルール・コードの無審査の同梱。** 本体のAGPL-3.0-or-later／GPL-2.0の境界と、大きなネイティブ依存が障害。[LICENSE#L2-L63](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/LICENSE#L2-L63)、[src/engine/CMakeLists.txt#L262-L333](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/CMakeLists.txt#L262-L333)
- **重大な未確認：** 5.x時間窓相関の網羅性、性能・欠損率・再起動復元、配布形態に依存するGPL/AGPLの法的評価。未検証を「実装済み・安全」とみなさない。

## 1. 対象の固定と調査方法

| 要素 | 値 / 根拠 |
|---|---|
| 公式リポジトリ | https://github.com/wazuh/wazuh （リポジトリのデフォルトブランチはmain） |
| 5.x調査固定commit | **2940bdfb5e1a90cd67200fa63579d7eadf679009**、[VERSION.json#L1-L4](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/VERSION.json#L1-L4) の表記は **5.1.0 / alpha0**。これはmain上の開発状態であり、安定版という意味ではない |
| 4.x比較固定commit | **8f892ebe86f07db387b80967cbd7ca69a4517385**、[VERSION.json#L1-L4](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/VERSION.json#L1-L4) は **4.14.12 / alpha0**。歴史的実装の参照であり、5.xのAPI仕様として扱わない |
| AegisGuard比較commit | **83fcf0d150e8d760baff5f971c106deb09c1f8e4**（2026-11-05に確認したmain） |
| AegisGuard現状 | Rust CLIでPE・スクリプト静的検査とC2 IP照合。Sysmon/ETW連動やイベント相関は未実装：[README.md#L1-L25](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md#L1-L25)、[docs/ARCHITECTURE.md#L11-L30](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L11-L30) |
| Wazuhライセンス | 5.x [LICENSE#L2-L63](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/LICENSE#L2-L63)、Engine [src/engine/COPYING-engine#L1-L15](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/COPYING-engine#L1-L15)、4.x [LICENSE#L1-L35](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/LICENSE#L1-L35)。個別ライセンスは後述 |
| 確認範囲 | 4.x: analysisd/decoder, rules, eventinfo, MITRE, JSON出力、XMLルール、ユニット/ルールテスト。5.x: Engine builder/policy, router/worker/orchestrator, filter schema, CMake依存、単体/統合テスト。Aegis: README, SECURITY, ARCHITECTURE, src/model.rs, src/scan.rs, src/main.rs, Cargo.toml |
| 実機・ビルド・テスト | **未実施**。Wazuh実行・未知のコード実行・Windows構成変更はせず、ソースと既存テストの読み取りのみ。テストが存在する事実と実行成功を区別する |
| 確認日・制約 | 2026-11-05。Wazuh mainは変動するため上記SHAを固定。外部Indexer/GUIのソースと法務レビューは今回の担当外 |

### バージョンと責務を混同しない

**4.x：** Windowsを含むEndpoint **Agent** 側で収集したイベントをManagerへ送り、**Managerのanalysisd**がデコードとルール評価・履歴相関を行う。今回読んだ [src/analysisd/analysisd.c#L2120-L2204](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/analysisd.c#L2120-L2204) はWindows端末側に組み込める小型ライブラリではない。デコード部は [src/analysisd/decoders/decoder.c#L19-L110](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/decoders/decoder.c#L19-L110)。

**5.x開発ブランチ：** [src/engine/source/README.md#L11-L46](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/source/README.md#L11-L46) はEngineをポリシー・デコーダ・フィルタ・エンリッチメント・出力・ルーターへ分割し、[src/engine/source/router/src/worker.cpp#L62-L106](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/source/router/src/worker.cpp#L62-L106) が入力キューからパースしルートへ渡す。Windows AgentのソースとManager側Engineの責務を一体化して扱わない。

## 2. 実装アーキテクチャとソース調査

| 機能 | 主要なファイル／シンボルと役割 | SHA固定の一次情報 | 確認状態 |
|---|---|---|---|
| 4.xログデコード | **DecodeEvent**：program名、prematch、親・子decoderを選択しEventinfoへ設定 | [src/analysisd/decoders/decoder.c#L19-L110](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/decoders/decoder.c#L19-L110) | 実装確認 |
| 4.xルール評価 | **OS_CheckIfRuleMatch**：decoder種別、regex、動的フィールド、CDB、子ルールを評価。NO_ALERTを考慮 | [src/analysisd/rules.c#L2598-L2750](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/rules.c#L2598-L2750)、[src/analysisd/rules.c#L3104-L3169](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/rules.c#L3104-L3169) | 実装確認 |
| 4.x履歴相関 | **Search_LastSids / Search_LastGroups / Search_LastEvents**：既出ルールID、グループ、一般履歴を探索 | [src/analysisd/rules.c#L1964-L1997](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/rules.c#L1964-L1997)、[src/analysisd/eventinfo.c#L99-L156](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/eventinfo.c#L99-L156)、[src/analysisd/eventinfo.c#L275-L335](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/eventinfo.c#L275-L335)、[src/analysisd/eventinfo.c#L462-L520](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/eventinfo.c#L462-L520) | 実装確認 |
| 4.x同一キー・時間窓 | agent_idの一致（global frequencyで例外）、ID・IP・動的fieldなどのsame/different、generate_timeと現在時刻の差を評価 | [src/analysisd/eventinfo.c#L142-L165](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/eventinfo.c#L142-L165)、[src/analysisd/eventinfo.c#L205-L269](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/eventinfo.c#L205-L269) | 実装確認 |
| 4.x重大度・抑制・優先 | level 0–16、ルール階層、既出判定の比較、ignore_time抑制とskip、firedtimesを保持 | [src/analysisd/rules.c#L2290-L2345](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/rules.c#L2290-L2345)、[src/analysisd/eventinfo.c#L233-L261](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/eventinfo.c#L233-L261)、[src/analysisd/analysisd.c#L2146-L2199](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/analysisd.c#L2146-L2199) | 実装確認 |
| 4.x履歴保持・破棄 | **OS_CreateEventList / OS_AddEvent**：メモリ上のイベント数上限と古いノードの回収 | [src/analysisd/eventinfo_list.c#L15-L79](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/eventinfo_list.c#L15-L79) | 実装確認（再起動復元までは未立証） |
| 4.x ATT&CK | XMLのmitre idからDBを照会し、出力JSONへID・戦術・技術名を格納 | [ruleset/rules/0595-win-sysmon_rules.xml#L255-L282](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/ruleset/rules/0595-win-sysmon_rules.xml#L255-L282)、[src/analysisd/mitre.c#L17-L144](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/mitre.c#L17-L144)、[src/analysisd/format/to_json.c#L96-L224](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/format/to_json.c#L96-L224) | 実装確認 |
| 4.xアラート根拠 | JSONへrule.id/level/description、frequency、firedtimes、previous_output、必要に応じfull_logを保存 | [src/analysisd/format/to_json.c#L84-L96](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/format/to_json.c#L84-L96)、[src/analysisd/format/to_json.c#L232-L258](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/format/to_json.c#L232-L258)、[src/analysisd/format/to_json.c#L295-L296](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/format/to_json.c#L295-L296) | 実装確認 |
| 5.xポリシー構築 | **Policy / buildExpression**：prefilter → decoder → enrichment → postfilter → outputの式木。decoderの兄弟はOR、outputの兄弟はBroadcast | [src/engine/source/builder/src/policy/policy.cpp#L30-L134](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/source/builder/src/policy/policy.cpp#L30-L134)、[src/engine/source/builder/src/policy/factory.cpp#L387-L504](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/source/builder/src/policy/factory.cpp#L387-L504) | 実装確認 |
| 5.xフィルタ定義 | JSON schemaのenabled、pre-filter/post-filter、check式。時間窓相関を含むとまでは読めない | [src/engine/ruleset/schemas/wazuh-filters.json#L10-L37](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/ruleset/schemas/wazuh-filters.json#L10-L37)、[src/engine/ruleset/schemas/wazuh-filters.json#L104-L150](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/ruleset/schemas/wazuh-filters.json#L104-L150) | 実装確認（相関互換性未確認） |
| 5.xルーティング | **Router::ingest**：有効な複数ルートへイベントを複製・投入、優先順位を表で管理 | [src/engine/source/router/src/router.cpp#L115-L141](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/source/router/src/router.cpp#L115-L141)、[src/engine/source/router/src/router.cpp#L205-L235](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/source/router/src/router.cpp#L205-L235) | 実装確認。**route priority ≠ threat severity** |
| 5.x入力と欠損 | **RouterWorker::start**：イベントを待ち受け、受信時刻/UUIDを付与、例外をログ化。**Orchestrator::postEvent**：容量・バイト使用量・キュー競合・ドロップを監視 | [src/engine/source/router/src/worker.cpp#L62-L106](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/source/router/src/worker.cpp#L62-L106)、[src/engine/source/router/src/orchestrator.cpp#L203-L273](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/source/router/src/orchestrator.cpp#L203-L273) | 実装確認。すべての欠損を復元できる意味ではない |
| 5.x相関・スコア | 4.xのfrequency/timeframeと同等の時間窓相関・severity計算・ATT&CK付与の全経路 | 上記5.xのpolicy/filter/routerを調査した範囲では立証できない | **未確認**。4.xの実装を5.xに帰属させない |

### 4.x評価の具体的データフロー

1. Managerのanalysisdがイベントをキューから処理し、**DecodeEvent**で入力の解釈と抽出フィールドの特定をする。[src/analysisd/analysisd.c#L1795-L1835](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/analysisd.c#L1795-L1835)、[src/analysisd/decoders/decoder.c#L19-L110](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/decoders/decoder.c#L19-L110)
2. **OS_CheckIfRuleMatch**で候補の条件・親子ルールを評価する。XML定義の**if_matched_sid / if_matched_group**に応じてイベント履歴検索関数が接続される。[src/analysisd/rules.c#L1964-L1997](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/rules.c#L1964-L1997)、[src/analysisd/rules.c#L3104-L3155](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/rules.c#L3104-L3155)
3. 履歴相関は**現在時刻とイベントgenerate_time**の差をtimeframeに照らし、通常agent_idが一致した履歴だけを数え、同一IP/動的fieldなどの条件を追加する。到着遅延やイベント欠損に完全対応しているとは読めない。[src/analysisd/eventinfo.c#L127-L165](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/eventinfo.c#L127-L165)、[src/analysisd/eventinfo.c#L205-L261](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/eventinfo.c#L205-L261)
4. 条件が成立すればlevel/ignore_timeや抑制対象を見て、出力を生成する。例：SSH失敗の反復条件を **frequency=8、timeframe=120、ignore=60、same_source_ip、MITRE T1110** と定義している。[src/analysisd/analysisd.c#L2146-L2204](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/analysisd.c#L2146-L2204)、[ruleset/rules/0095-sshd_rules.xml#L109-L117](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/ruleset/rules/0095-sshd_rules.xml#L109-L117)
5. **ルールXMLのfrequencyをそのまま内部カウンタ値と読み替えてはいけない。** パーサーは2–9999の範囲チェック後に内部値から2を引いており、相関実装は別の数え方を行う。AegisGuardの閾値表現は独自に「何イベントを数えるか」を固定すべき。[src/analysisd/rules.c#L2316-L2328](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/rules.c#L2316-L2328)

### 誤検知と相関の意味

4.x Sysmonルール群は、たとえば怪しい名前のプロセス検出の後に「正規親プロセスならlevel 0で抑制」の子ルールを持つ。[ruleset/rules/0595-win-sysmon_rules.xml#L255-L285](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/ruleset/rules/0595-win-sysmon_rules.xml#L255-L285)。ただし親プロセス名だけで安全性が証明されるわけではない。AegisGuardではルール除外を**スコアゼロ＝安全**へ変換せず、原因・範囲・有効期限のある抑制ログとして残す。

**重要な区別：** Wazuhの4.x **level** はルール重大度、**frequency** は繰返し判定、5.x **Routerのpriority** は配信先の評価順序であり、どれもAegisGuardの既存0–100 **score**と同じ尺度ではない。混合して足し算をしてはいけない。[src/engine/source/router/src/table.hpp#L30-L59](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/source/router/src/table.hpp#L30-L59)、[src/model.rs#L90-L107](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/model.rs#L90-L107)

## 3. 具体的な取り込み候補と選択肢

| 候補機能 | 利用方法 | AegisGuard接続先 | 優先度 | 工数 S/M/L | 技術・ライセンス上の阻害要因 |
|---|---|---|---|---|---|
| **1. ProcessGuid単位の時間窓・件数相関** | **独自Rust実装**（4.x設計参考） | 将来のaegis-detection、event ingestion | **P0** | **M** | イベント収集手段未実装、順序乱れ・再起動・時刻揺れ・スコア定義を設計 |
| **2. 正規化イベント・根拠・欠損表現** | **独自Rust実装**（5.x worker/metrics参考） | src/model.rsから分離するaegis-core、JSONL | **P0** | **S** | EventLogアクセス、JSONL PII、既存Reportとの互換性 |
| **3. バージョン付きルールとオフライン再生テスト** | **独自Rust実装**（4.xルールテスト、5.x Tester参考） | 将来のaegis-detection/tests | **P1** | **M** | 署名・原子更新・規則互換性・例外/ロールバック |
| 4.x XMLルール・相関処理を直接組み込む | **不採用**（設計のみ参考） | なし | — | L | GPL-2、Manager用C実装、スキーマと依存関係が一致しない |
| 5.x C++ Engine API/ライブラリに直結 | **不採用**（設計のみ参考） | なし | — | L | AGPL-3-or-later、巨大C++依存、Rust crate/APIを確認できない |
| Wazuh Managerを別サービスとして使う | **外部CLI/サービス**（検証専用・条件付き） | 手動オフライン比較評価 | P3 | L | Windowsローカル単体目標と不整合、配布/データ転送/ライセンス/保守 |
| ATT&CKタグ付け | **独自実装・設計参考** | Signal metadata/検出根拠 | P1 | S | タグを確度・スコアに変換しない、データ再配布条件別途調査 |

### 推奨するRustローカル相関器の仕様案（実装は行わない）

**イベント入力：** 新しい **EventEnvelope v1**（既存Reportを流用して無理に上書きしない）を設ける。最低限 **event_id UUID、schema_version、source_type、host_id、boot/session ID、occurred_at、observed_at、source cursor/bookmark、ProcessGuid（Option）、PID（補助）、parent_guid（Option）、file_hash（Option）、network destination（Option）、normalized fields、payload completeness、source health** を持つ。原文ログをデフォルトで丸ごと保存せず、必要ならACL付きローカル保管を明示設定する。sysmonイベントと静的検査Report/C2照合結果は、ソース種別と**取得根拠**を残す。[docs/ARCHITECTURE.md#L19-L29](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L19-L29)、[src/model.rs#L4-L41](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/model.rs#L4-L41)

**ルール入力：** Rust独自のversioned JSON（初期段階は既存serde_jsonで十分）で **rule_id、revision、enabled、severity_label、predicate、group_by（host_id + ProcessGuid等）、window_duration、min_distinct_events、allowed_lateness、cooldown、max_state_entries、suppression exceptions、attack_techniques、evidence_fields** を定義。Wazuh XML構文やGPLライセンスのあるサンプルを直接コピーしない。コンパイル時に未知フィールド・矛盾するウィンドウ・複雑過ぎる正規表現・禁止されたオブジェクト参照を拒否する。正規表現の悪意ある入力対策と入力サイズ上限を設ける。

**処理：** ①収集→正規化（source cursorを記録）→②厳格なフィールド検証→③ホスト・ProcessGuid・ルールIDをキーにしたbounded window ring/deque→④重複event_id除去と有限の遅延許容→⑤イベント時刻/観測時刻とwatermarkを区別して確定→⑥根拠ID集合、ルールrevision、重大度と不確実性を含むFindingをJSONLへ出力。1イベントでは重症扱いせず、ルールごとの根拠数を報告する。**Wazuh由来のlevelをAegisGuardのscoreに変換しない。**

**出力：** **Finding {rule_id, rule_revision, severity, confidence_status, event_ids, evidence_summary, group_key, window_start/end, source_status, mitre_ids, generated_at}** とする。confidence_statusは例えば **correlated / partial / uncertain** の離散状態で、感染確率ではない。Aegisの既存Signalは静的なcode/reason型なので、将来の互換APIではSignalの**検査結果**をFindingの根拠として引用し、無条件にsumして重複評価しない。既存Reportの**analysis_complete=false**や**not_assessed**を生かす。[src/model.rs#L60-L110](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/model.rs#L60-L110)、[src/model.rs#L119-L143](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/model.rs#L119-L143)

**状態と永続化：** PoCはプロセス内の容量制限付きメモリとTTL、source bookmarkとルールversionのJSONL監査を分離。再起動で時間窓の再構築が保証できない場合、復元直後の履歴は**incomplete**として扱う。実用段階でSQLite WALなどを**依存追加・スキーマ移行・暗号化/ACL・クラッシュ復旧試験を経て**検討。Wazuh 4.xがSQLiteへ同じ相関状態を永続化すると誤認しない。

**失敗動作：** キュー満杯／EventLog購読断／デコード失敗／bookmark不連続／時刻逆行／ルール署名不正／状態DB破損は**欠損カウンタ+原因+影響時間帯**を記録する。到達した既知の根拠に基づく陽性は維持、無検出側は**unknown/partial**に格下げし「クリーン」報告禁止。自動遮断なし・未知の外部スクリプト実行なし。

**最小PoC：** OSログの直接購読もWazuh実行も初期には不要。無害な**架空のSysmon EventID 1 → 3**、静的検査の合成Signal、再送・遅延・欠損メタデータをローカルJSONLから再生し、規則の一致／不一致と根拠をゴールデンテストで確認する。

## 4. ライセンス・再配布・依存関係

| 対象 | 原文で確認した範囲 | 採用への影響 |
|---|---|---|
| **Wazuh 5.x Engine：src/engine/** | **AGPL-3.0-or-later** とLICENSEに明記。個別COPYING-engineも一致。[LICENSE#L2-L9](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/LICENSE#L2-L9)、[src/engine/COPYING-engine#L1-L15](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/COPYING-engine#L1-L15) | コード移植・静的/動的リンク・配布やネットワーク提供について義務を個別検証。直接組み込みは見送り |
| **5.x共通モジュール列挙分** | **GPL-2.0-only OR AGPL-3.0-or-later** と明記。utils等6領域。[LICENSE#L11-L23](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/LICENSE#L11-L23) | ライブラリ単位で提供ライセンスを確認。全体を「全部AGPL」や「全部GPL」とは扱わない |
| **5.x上記以外のWazuhのソース・デコーダ・ルール・データ** | **GPL v2**が原則、個別例外あり。[LICENSE#L25-L26](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/LICENSE#L25-L26)、[LICENSE#L48-L63](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/LICENSE#L48-L63) | 4.x XMLルール、デコーダ、署名・ルールセットの無断同梱をしない。ファイルごとの例外と由来を確認 |
| **4.xソース／ルールセット** | [LICENSE#L1-L35](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/LICENSE#L1-L35) はGPL v2とデコーダ・ルール・データへの適用を明示 | 参考にするのは独立の仕様上の発想。コード片、正規表現、MITREマッピング表、XMLをコピーしない |
| **MITRE ATT&CKデータ、署名、IOCフィード** | Wazuh内にはenterprise-attack.jsonがあるが、そのデータの独立した権利・再配布条件までは確認未了。[LICENSE#L48-L50](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/LICENSE#L48-L50) | ATT&CK IDを単に指す案と、大量の付随データを同梱する案を分ける。法的評価未完了 |
| **サードパーティ依存** | CMakeでRocksDB、fmt、spdlog、yaml-cpp、RapidJSON、curl、protobuf等を参照。[src/engine/CMakeLists.txt#L205-L209](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/CMakeLists.txt#L205-L209)、[src/engine/CMakeLists.txt#L262-L333](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/CMakeLists.txt#L262-L333)。ルートにTHIRD-PARTY-NOTICESが存在 | 個別パッケージの実際のバージョン・ライセンス・SBOMを再確認。Wazuhライセンスだけでは足りない |
| **AegisGuard本体** | READMEでは現時点でコードのライセンス未設定。[README.md#L80-L82](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md#L80-L82) | Aegis側の配布条件も未決定。AGPL/GPLライブラリ転用やルール同梱の是非を現段階で断定しない |

**利用形態の区別：** 「API直リンク」はWazuh C++実装と強く結合しやすく推奨しない。「コード・XMLのコピー」はGPL/AGPL義務および著作権問題の可能性がある。「別プロセスCLI/サービスを**ユーザーが別に導入する**」ことと、「AegisGuardが**同梱・一体インストーラで配布する**」ことは分けて判断する。WazuhのLICENSEは派生物に対し比較的広い見解（実行プログラムの結合・インストーラ等）も記載するため、**「CLI経由なら必ずセーフ」は誤り**。配布態様とGPL/AGPL相互互換の**法的評価未完了**。[LICENSE#L48-L70](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/LICENSE#L48-L70)

**Rust crate/APIの結論：** 調査した5.x Engineのビルド実態はC++/CMakeであり、AegisGuardに簡単に組み込める公式Rust crateや、オフラインの固定ABIをここでは確認できない。無いと断定するのではなく「本調査で未確認・直接採用不可」とする。[src/engine/CMakeLists.txt#L299-L333](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/CMakeLists.txt#L299-L333)

## 5. Defender共存・Windows制約・権限境界

AegisGuardの現在のCLIは非特権の読み取り解析を中心とする。Microsoft Defenderは引き続き主防御であり、停止・除外登録・ポリシー変更をこの調査やPoCで要求しない。[README.md#L1-L25](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md#L1-L25)、[SECURITY.md#L15-L21](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md#L15-L21)

- **Windows 11 x64：** 4.x/5.xのManagerソースはAgentと別。Wazuh Managerのanalysisd/Engineを、Windows上で動くRust DLLだと見なさない。センサー実装時はEvent Log APIのAPI/権限・イベント取得性能をWindows実機で検証する。
- **Sysmon：** 実運用では導入・設定変更・EventID 3/7有効化は管理者権限と承認が必要になる場面がある。イベント購読に必要なChannel ACLを設定・確認し、過剰な全DLLイベントを初期デフォルトにしない。**ProcessGuid**を主キーとしPID再利用を警戒。[docs/ARCHITECTURE.md#L19-L26](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L19-L26)
- **ETW/Windows Event Log：** EventLogブックマーク永続化、Channelクリア、ログローテーション、アクセス拒否、イベント欠損・遅延・時刻変更を失敗状態として記録。必要権限はプロバイダー/チャネルごとに最小化。
- **AMSI：** Defenderと保護機能が重なる可能性がある。AMSIが全ホスト・全言語を自動監視する前提を置かない。重複検知を別々の強い独立証拠として加点しない。[docs/ARCHITECTURE.md#L19-L30](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L19-L30)
- **WFP/Firewall：** この担当は観測のみ。将来の遮断は別担当の権限境界・名前空間付き自分のルールのみ・明示同意・巻戻し・管理者権限を必須にする。検証でネットワークフィルタやDefenderを変更しない。[docs/ARCHITECTURE.md#L31-L39](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L31-L39)
- **プライバシー：** 原文ログにはユーザー名、コマンドライン、IP、パス、場合により秘密情報が含まれる。4.x出力にはprevious_output/full_logを含む経路があるのでコピーしない。規定は最小フィールド・ローカルのみ・ACLと保持期限・任意の詳細記録。[src/analysisd/format/to_json.c#L246-L258](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/format/to_json.c#L246-L258)、[SECURITY.md#L9-L13](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md#L9-L13)

## 6. 性能・堅牢性・誤検知

**実測値：なし。** 後述の受入基準は目標と計測法であってWazuhやAegisGuardで計測した性能値ではない。

- **キュー負荷・欠損：** 5.xのOrchestratorはエントリー数と使用バイト数の両方から競合状態を判定し、特定条件でdropカウンタと警告を出す。キューへのpush失敗が実イベント損失になり得る。AegisGuardではカウンタの単調性・全失敗経路・入力元bookmarkとの比較を追加要件とする。[src/engine/source/router/src/orchestrator.cpp#L203-L273](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/source/router/src/orchestrator.cpp#L203-L273)
- **状態メモリ上限：** 4.xはイベントリスト数の上限超過で履歴を回収。高速イベントで閾値超過やTTLによる情報消失があっても、それを「未検出＝安全」に読み替えない。PoCはキーの最大数、1キー最大イベント数、総バイト数、イベント最大サイズ、CPU予算を定義・計測する。[src/analysisd/eventinfo_list.c#L35-L79](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/eventinfo_list.c#L35-L79)
- **クロック・順序：** 4.xのtimeframe判定は検索時の現在時刻からgenerate_timeを引く。AegisGuardはoccurred_at/observed_atを保持し、watermarkや許容遅延、時刻信頼性を明示する。ログ欠落・プロセス再起動・boot ID変化では不確実性が上がる。[src/analysisd/eventinfo.c#L127-L156](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/eventinfo.c#L127-L156)
- **誤検知：** 正規管理スクリプト、Windows正規プロセス、ブラウザー更新、サービス再起動で一致し得る。単一シグナルでは高リスクへ飛び級させず、**独立性のある根拠**と許可リスト／抑制の理由・期限を記録。4.xの子ルールレベル0は参考になるが完全性の証明にはならない。[ruleset/rules/0595-win-sysmon_rules.xml#L255-L285](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/ruleset/rules/0595-win-sysmon_rules.xml#L255-L285)
- **検査漏れと悪意入力：** 壊れたJSON、極端な深さ、多重エスケープ、正規表現大量照合、フィールド欠損、巨大ログ、時刻逆行を安全な合成データで入力。例外時の黙ったdrop、パーサの無限ループ、rule version混在、レース条件を再現テストする。
- **システム影響：** 初期は観測専用。CPU時間、RSS、ページフォルト、イベント処理速度、キュー待機時間、drop/gap数、JSONL肥大化を「無負荷baseline→合成イベント投入→終了後回復」で測る。測定環境・ルール数・イベントサイズも記録する。

## 7. 推奨する小さなPoCと成功基準

**前提：** ユーザー権限のオフライン実行、Defender有効、ネットワーク不要、実マルウェア実行なし。開発用の合成イベントであり、本番Windowsイベントを収集せずに開始する。ローカルファイルだけを読み込む。

**安全なテストケース：** 
1. **正例**：同じhost_id・boot_id・ProcessGuidで、合成Sysmon ID1の生成後、同じProcessGuidの疑わしいネットワークID3が設定した時間窓内に複数回発生すると、期待した**1件のFinding**を出し、各event_id・ルールrevision・観測時間を根拠として列挙する（件数閾値はPoC仕様で明記する）。
2. **反例**：同一PIDでも異なるProcessGuid、別host、時間窓外、要求フィールド欠落の場合は相関を成立させない。欠落で成立しない場合はunknown/partialとする。
3. **重複・順序**：同一event_idの再送は加算しない。許容遅延内の順序入替では決定的に同じ結果、遅延範囲外では根拠の不足を表示する。開始／終了・再起動後の挙動をテストに固定。
4. **故障注入**：キュー満杯、破損JSON、未対応schema_version、rule parse error、bookmark飛び、時間逆行、キャンセルでクラッシュせず、エラー・drop/gapカウンタ・影響時間範囲が残る。
5. **抑制・重大度**：許可済みの正規管理処理を理由付きで抑制し、抑制元イベントを追跡できる。スコアの自動加算やDefender遮断、未知のコマンド実行は起こらない。

**成功条件・計測：** 定義した正例・反例・欠損ケースがゴールデンJSONLと一致し、同じ入力で決定的な結果を再現できる。メモリ・イベント数の上限を超えてもプロセスの異常終了・無限増大がなく、上限で捨てた件数を計数する。CPU/RSS、p50/p95処理遅延、イベント／秒、ドロップ率、保存容量をWindows 11 x64の安全な検証機で複数負荷条件で計測し、合格値は実測ベースで後日設定する。**数値を現時点で創作しない。**

**失敗・ロールバック：** 観測ルールを無効化し、PoCのローカル出力・一時状態のみ削除。OS、Defender、Sysmon、Firewallの設定は元から変更しない。中止条件は意図しない通信/権限昇格/自動遮断、未追跡のイベント喪失、上限超過による継続的な資源増大、ローカル外へのセンシティブ情報送信。

## 8. 採用しない設計と理由

1. **Wazuh Manager + C++ Engine + Indexer + ダッシュボードのフル移植。** 5.x Engineは多段のC++依存とサービス・ストア・インデクサー結合を持ち、AegisGuardの「軽量なWindows 11ローカルRustエンジン／Defender併用」の目標に過剰。さらにAGPL-3.0-or-laterの配布・統合上の評価が必要。[src/engine/CMakeLists.txt#L262-L333](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/CMakeLists.txt#L262-L333)、[LICENSE#L2-L26](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/LICENSE#L2-L26)
2. **4.xのXML検出ルール・正規表現・C実装をそのままコピー／翻訳する。** WazuhのGPL v2はルールとデコーダにも適用され、AegisGuardのライセンス未設定と整合を判断できない。また4.xのfrequency内部表現やWindows正規プロセス例外ルールを無検証移植すると誤検知・見逃しを生む。[LICENSE#L19-L35](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/LICENSE#L19-L35)、[src/analysisd/rules.c#L2316-L2328](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/rules.c#L2316-L2328)
3. **相関結果だけで自動Firewall遮断・Defender設定変更。** 現時点でイベント完全性・誤検知率・ルール更新の真正性・ロールバックが検証されていない。初回PoCでは実施しない。[docs/ARCHITECTURE.md#L31-L39](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L31-L39)

## 9. 他担当との境界・引継ぎ

- **wazuh-fim-persistence担当：** FIM側のイベント発生源・DB・再起動継続性が担当範囲。相関器はFIMを入力可能なEventEnvelopeとして抽象化するだけに留め、FIM DB設計を今回決定しない。
- **simplewall / Portmaster担当：** WFPでの遮断とルール反映は別担当。ここでのFindingは観測・根拠のみ、権限・遮断可否は後段ポリシーで明示判断。
- **YARA / ClamAV / Loki担当：** 各スキャナーから受け取る結果は**独立したevidence source**として正規化する。検査未完了と脅威検知の区別を統一するが、各エンジンの閾値を共通スコアへ機械的換算しない。
- **Aegis core/sensor担当：** src/model.rsにSignal/Reportと完了状態が既存。EventEnvelope/Finding型を別型として提案し、EventLog bookmark、ProcessGuidの寿命、ACL/監査ログの責任境界はセンサー側実装前に共同確定する。[src/model.rs#L4-L110](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/model.rs#L4-L110)
- **法務／配布判断：** GPL/AGPLコード・ルール・MITREデータ・第三者IOCの同梱条件とAegisGuardライセンスは別途レビューが必要。

## 10. 未確認事項・追加調査項目

| 重要度 | 未確認事項 | 必要な検証 |
|---|---|---|
| **重大** | **5.x Engineの4.x互換の相関（frequency/timeframe、agent別・group別履歴、再起動復元、MITRE付与・severity計算）の全機能** | 5.xルールアセット/バックエンド/導入済みポリシーとテストを個別に網羅し、4.xと差分比較。今回確認済みなのはbuilder・filter・router等の一部。未確認を不在とは断定しない |
| **重大** | AegisGuard配布形態とWazuhコード/ルール再配布のライセンス互換 | コンポーネント別著作権表示・例外・ソース公開義務・AGPLネットワーク条項・外部サービス境界を専門家確認（法的評価未完了） |
| **高** | Windows 11 Sysmon EventLogのACL、ブックマーク継続性、イベント取りこぼし、ETW互換 | Defender有効のWindows検証機で非特権／特権の読取境界・再起動・ログクリア・高負荷を観測 |
| **高** | 4.xの相関イベント履歴がManager再起動時にどの程度復元されるか | in-memory event list以外の保持経路・管理者用DBとルール相関stateの境界を追加追跡 |
| **高** | 5.xキュー失敗・ワーカー例外の監査粒度と実際のevent loss上限 | unit/integration実行と故障注入、drop counterとbookmark不整合の照合 |
| **中** | ルール・MITRE・署名/IOC feed・THIRD-PARTY-NOTICESの個々の再配布条件 | 採用するデータだけ版・出所・NOTICE・権利者を抽出して整理 |
| **中** | Rustローカル相関器の性能・誤検知率・長時間連続稼働 | 安全な合成／許諾済みの無害ログで負荷試験。ベンチマーク数値なし |
| **中** | 5.x開発ブランチの正式リリースへの到達とAPI安定性 | 公開タグ/リリースと主な破壊的変更を追跡。今回のmain=alpha0を固定 |

## 11. 一次情報一覧

以下のリンクは**2026-11-05に取得した該当commit SHAへ固定**。少なくとも主要な実装判断を直接確認できる箇所に限定し、URLを単なるトップページではなくファイル・行にしている。

| 区分 | 固定ソース／該当箇所 | 裏付け |
|---|---|---|
| 4.xデコーダ | [src/analysisd/decoders/decoder.c#L19-L110](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/decoders/decoder.c#L19-L110) | DecodeEventの条件と親子decoder |
| 4.x評価 | [src/analysisd/rules.c#L2598-L2750](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/rules.c#L2598-L2750) / [src/analysisd/rules.c#L3104-L3169](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/rules.c#L3104-L3169) | ルール・相関・子ルール・NO_ALERT |
| 4.x履歴検索 | [src/analysisd/eventinfo.c#L99-L165](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/eventinfo.c#L99-L165) / [src/analysisd/eventinfo.c#L205-L269](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/eventinfo.c#L205-L269) | 同一agent/フィールドの時間窓と件数 |
| 4.x状態上限 | [src/analysisd/eventinfo_list.c#L15-L79](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/eventinfo_list.c#L15-L79) | bounded in-memory event list |
| 4.x具体例 | [ruleset/rules/0095-sshd_rules.xml#L109-L117](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/ruleset/rules/0095-sshd_rules.xml#L109-L117) / [ruleset/rules/0595-win-sysmon_rules.xml#L255-L285](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/ruleset/rules/0595-win-sysmon_rules.xml#L255-L285) | frequency/timeframe/cooldown/MITRE/誤検知抑制 |
| 4.xアラート | [src/analysisd/format/to_json.c#L84-L115](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/format/to_json.c#L84-L115) / [src/analysisd/format/to_json.c#L232-L258](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/analysisd/format/to_json.c#L232-L258) | level・id・MITRE・根拠と前段ログ |
| 4.xテスト | [src/unit_tests/analysisd/test_same_different_loop.c#L93-L184](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/unit_tests/analysisd/test_same_different_loop.c#L93-L184) / [ruleset/testing/ruleset/test_rules.xml#L1-L70](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/ruleset/testing/ruleset/test_rules.xml#L1-L70) | same/different条件と時間窓テスト定義 |
| 4.x MITREテスト | [src/unit_tests/analysisd/test_mitre.c#L54-L143](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/src/unit_tests/analysisd/test_mitre.c#L54-L143) | DB失敗・空応答のテストが存在 |
| 5.xポリシー | [src/engine/source/builder/src/policy/factory.cpp#L387-L504](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/source/builder/src/policy/factory.cpp#L387-L504) / [src/engine/source/builder/src/policy/policy.cpp#L30-L134](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/source/builder/src/policy/policy.cpp#L30-L134) | Filter/decoder/enrichment/outputの式木 |
| 5.xルーティング | [src/engine/source/router/src/router.cpp#L115-L141](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/source/router/src/router.cpp#L115-L141) / [src/engine/source/router/src/router.cpp#L205-L235](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/source/router/src/router.cpp#L205-L235) | priorityとイベント分岐 |
| 5.xキュー管理 | [src/engine/source/router/src/orchestrator.cpp#L203-L273](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/source/router/src/orchestrator.cpp#L203-L273) / [src/engine/source/router/src/worker.cpp#L62-L106](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/source/router/src/worker.cpp#L62-L106) | queue contended、drop、観測タイムスタンプ |
| 5.xテスト | [src/engine/source/router/test/src/unit/worker_test.cpp#L124-L190](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/source/router/test/src/unit/worker_test.cpp#L124-L190) / [src/engine/source/router/test/src/unit/router_test.cpp#L203-L233](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/source/router/test/src/unit/router_test.cpp#L203-L233) | Worker処理・重複priority検査 |
| 5.x統合テスト | [src/engine/test/integration_tests/tester/features/api.feature#L59-L94](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/test/integration_tests/tester/features/api.feature#L59-L94) | デコーダからのtrace/outputの期待値 |
| 5.x依存・ライセンス | [src/engine/CMakeLists.txt#L262-L333](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/CMakeLists.txt#L262-L333) / [LICENSE#L2-L63](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/LICENSE#L2-L63) / [src/engine/COPYING-engine#L1-L15](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/COPYING-engine#L1-L15) | C++依存とAGPL/GPL境界 |
| 4.xライセンス | [LICENSE#L1-L35](https://github.com/wazuh/wazuh/blob/8f892ebe86f07db387b80967cbd7ca69a4517385/LICENSE#L1-L35) | 4.xルール/decoder/dataまでGPL v2の適用 |
| Aegis接続先 | [src/model.rs#L4-L110](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/model.rs#L4-L110) / [docs/ARCHITECTURE.md#L11-L39](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L11-L39) / [Cargo.toml#L1-L23](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/Cargo.toml#L1-L23) | 既存レポート、計画センサー、Rust依存 |

**再現上の制約：** GitHub上のソース/ユニットテスト/ルールテストの**存在と内容を静的に確認**したが、Wazuh 5.1.0-alpha0 / 4.14.12のビルド、ルールエンジン起動、Windows 11上の実行、負荷・誤検知の測定はしていない。設計提案はAegisGuard向けの独自案で、Wazuhで動作検証済みと表現しない。
