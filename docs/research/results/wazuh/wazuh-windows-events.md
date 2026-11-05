# 調査報告：Wazuh / wazuh-windows-events

> 担当：wazuh-windows-events / 調査日：2026-11-05 / 調査結果：ソース調査完了・実機検証未実施  
> 対象：Windows 11 x64、Rust-first、Microsoft Defenderとの併用。調査のみ。実装・マージ・システム設定変更なし。

## 0. 結論（3〜5行）

- **取り入れる価値：高い。ただしコード移植ではなく設計参考。** WazuhのWindows Event Log API購読、チャネル指定/XPath、ブックマーク復旧を参考に、AegisGuard専用の小さなRustローカル収集サービスを独立実装する。
- **最優先候補：** Sysmon OperationalのID 1（プロセス作成）を取得し、ProcessGuidで関連イベントを結び付け、**ディスクへの永続化成功後**にカーソルを進める。ID 3/7は選択的・段階的に導入。
- **見送り候補：** Wazuh Windowsエージェント/マネージャ一式の同梱、GPLv2のイベント購読コードのコピー、全DLLロードの無条件収集。
- **最大の制約：** 調査コミットには、送信失敗後のブックマーク更新、ブックマーク不正時のfuture-onlyフォールバック、有限メモリキューでのdropが実在する。これらを「取りこぼしゼロ」と解釈してはいけない。
- **立場：** 調査したWazuh mainは5.1.0 alpha0表記。コード静読とテスト所在確認までであり、実機のロス率/CPU/メモリ、Windows 11上での動作保証は未確認。

## 1. 対象の固定と調査方法

| 要素 | 値 / 根拠 |
|---|---|
| 公式リポジトリ・commit固定URL | [wazuh/wazuh @ 2940bdfb5e1a90cd67200fa63579d7eadf679009](https://github.com/wazuh/wazuh/tree/2940bdfb5e1a90cd67200fa63579d7eadf679009)。GitHubのデフォルトブランチはmain。 |
| 調査コミットSHA・タグ | 2940bdfb5e1a90cd67200fa63579d7eadf679009（2026-11-05取得）。[VERSION.json:1-4](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/VERSION.json#L1-L4) は「5.1.0 / alpha0」。**リリースタグとは同一視しない**。 |
| AegisGuardの比較先SHA | [choko510/AegisGuard @ 83fcf0d150e8d760baff5f971c106deb09c1f8e4](https://github.com/choko510/AegisGuard/tree/83fcf0d150e8d760baff5f971c106deb09c1f8e4)（main、2026-11-05取得）。 |
| ライセンスファイルと対象範囲 | [LICENSE:1-65](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/LICENSE#L1-L65)、[src/engine/COPYING-engine:1-16](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/COPYING-engine#L1-L16)、[src/shared_modules/utils/COPYING:1-18](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/shared_modules/utils/COPYING#L1-L18)、[THIRD-PARTY-NOTICES:1-96](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/THIRD-PARTY-NOTICES#L1-L96)。 |
| ソース/設定/テスト | read_win_event_channel.c、logcollector.c/state.c、Windows CMake/service/installer、Windows ossec.conf、HTTPS clientのstatelessStream/eventAccumulator/spoolFile、unit tests、Windows向けintegrations、logcollector docs。 |
| 実機・ビルド・テスト | **未実施**。Windows 11/Sysmon動作環境を使用しておらず、未知の外部コードを実行せず静的調査。テストは**実装とアサーションを読んで確認**したのみ。 |
| 対象外 | Wazuh managerの全ルールの実行、Sysmon自身のソース監査、専用カーネルドライバ開発、既存Defenderポリシー変更。 |
| 比較元の状態 | [src/main.rs:1-74](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/main.rs#L1-L74) はscan/C2サブコマンドのみ。[Cargo.toml:1-25](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/Cargo.toml#L1-L25) にはWindowsイベントAPI依存がない。[docs/ARCHITECTURE.md:19-40](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L19-L40) ではWindows sensorが将来予定。[SECURITY.md:12-23](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md#L12-L23) もETW/Sysmon/サービス未実装と明記。 |

**区別：** 以下の「実装確認」は固定SHAのコード分岐を確認した意味であり、その機能が全Windows条件で動作するという試験結果ではない。特に5.x系のリポジトリ内ローカル収集/HTTPSコードと、過去バージョンの既存運用例を混同しない。

## 2. 実装アーキテクチャとソース調査

### 2.1 Windows収集経路（入力→処理→出力）

| 機能 | 主要なファイル/シンボルと役割 | commit固定一次情報 | 確認状態 |
|---|---|---|---|
| Event Channel設定 | Windowsの既定設定はApplication/Security/System、Securityでは多数のノイジーなEventIDをXPathで除外。**Sysmon購読は既定設定にない。** | [src/win32/ossec.conf:15-33](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/win32/ossec.conf#L15-L33) | 実装/設定確認 |
| Sysmonチャネル設定可能性 | 統合テストのWindows locationデータに「Microsoft-Windows-Sysmon/Operational」、Windows Defender/Operationalなどがある。これは**設定受理系のテストケース**であり、各イベントIDの意味解析テストではない。 | [tests/integration/test_logcollector/test_configuration/data/test_cases/cases_basic_configuration_location_win.yaml:1-63](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/tests/integration/test_logcollector/test_configuration/data/test_cases/cases_basic_configuration_location_win.yaml#L1-L63) | テストソース確認 |
| 起動とチャネル購読 | logcollectorのeventchannel分岐がwin_start_event_channelを呼び出す。WinAPIのEvtSubscribeをコールバック方式で実行。 | [src/logcollector/src/logcollector.c:286-321](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/logcollector.c#L286-L321)、[src/logcollector/src/read_win_event_channel.c:424-502](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/read_win_event_channel.c#L424-L502) | 実装確認 |
| XPath/フィルタ | queryをfilter_special_charsおよびUTF-16化し、EvtSubscribeのQuery引数に渡す。正確なエスケープの可否はfilter_special_charsの入力組合せを別途テスト要。 | [src/logcollector/src/read_win_event_channel.c:450-502](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/read_win_event_channel.c#L450-L502)、[docs/ref/modules/logcollector/configuration.md:71-83](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/docs/ref/modules/logcollector/configuration.md#L71-L83) | 実装確認 |
| ブックマーク読込 | UTF-16 XMLをbookmarks/<channel>から読み、EvtCreateBookmarkで復元しEvtSubscribeStartAfterBookmarkを使用。futureフラグ時は利用しない。 | [src/logcollector/src/read_win_event_channel.c:136-193](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/read_win_event_channel.c#L136-L193)、[src/logcollector/src/read_win_event_channel.c:480-503](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/read_win_event_channel.c#L480-L503) | 実装確認 |
| ブックマーク更新 | EvtCreateBookmark→EvtUpdateBookmark→EvtRenderBookmark→ファイル書込。wfopenの書込とfwrite後に終了するが、原子的置換/fsync/データの耐久性確認は見当たらない。 | [src/logcollector/src/read_win_event_channel.c:195-302](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/read_win_event_channel.c#L195-L302) | 実装確認＋耐久性要実証 |
| イベント本体の処理 | EvtRenderEventXmlでXML取得→UTF変換→win_format_event_string→SendMSG(..., EventChannel, WIN_EVT_MQ)。**このコレクタではProcessGuid相関やSysmon EventID別解析を行っていない。** | [src/logcollector/src/read_win_event_channel.c:306-376](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/read_win_event_channel.c#L306-L376) | 実装確認 |
| 購読失効/再接続 | EvtSubscribeActionDeliver以外は一律「eventlog service is down」と警告し、指定reconnect_timeで再購読する。エラーコード別分類や欠損カウントはこの関数にない。 | [src/logcollector/src/read_win_event_channel.c:401-422](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/read_win_event_channel.c#L401-L422) | 実装確認 |
| ブックマーク復旧フォールバック | StartAfterBookmarkでEvtSubscribe失敗時、**何も通知せず**ToFutureEventsで再購読を試みる経路。古い記録が残っていても欠損し得る。 | [src/logcollector/src/read_win_event_channel.c:489-524](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/read_win_event_channel.c#L489-L524) | 実装確認・重大制約 |
| 既存内部キュー | logcollector.queue_sizeは128〜220000の設定範囲。宛先ごとの固定長キューを使い、満杯時にメッセージ破棄＋警告。 | [src/logcollector/src/logcollector.c:1884-1904](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/logcollector.c#L1884-L1904)、[src/logcollector/src/logcollector.c:1944-1995](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/logcollector.c#L1944-L1995) | 実装確認 |
| 状態/ドロップ可視化 | channel単位で処理イベント数/バイト数、target別dropsを保持し、JSON stateへ反映する。 | [src/logcollector/src/state.c:194-225](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/state.c#L194-L225)、[src/logcollector/src/state.c:241-271](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/state.c#L241-L271)、[src/logcollector/src/state.c:381-395](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/state.c#L381-L395) | 実装確認 |
| ローカルキュー→agent | 出力ワーカーはagent宛でキュー再接続を繰り返すが、再接続後にも送信失敗ならdropの状態記録となりメッセージを解放する。**永続WALではない。** | [src/logcollector/src/logcollector.c:2029-2095](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/logcollector.c#L2029-L2095) | 実装確認 |
| 新HTTPS送信経路 | Windowsターゲットにhttps_clientをリンク。stateless経路はEventAccumulatorが容量超過時drop-newest、送信成功でconsume、503/timeoutは次周期まで保持、400等で破棄する分岐を持つ。 | [src/win32/CMakeLists.txt:169-189](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/win32/CMakeLists.txt#L169-L189)、[src/client-agent/https_client/src/eventAccumulator.cpp:33-52](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/client-agent/https_client/src/eventAccumulator.cpp#L33-L52)、[src/client-agent/https_client/src/statelessStream.cpp:138-153](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/client-agent/https_client/src/statelessStream.cpp#L138-L153)、[src/client-agent/https_client/src/statelessStream.cpp:279-358](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/client-agent/https_client/src/statelessStream.cpp#L279-L358) | 実装確認。ただしWindows実機の全経路結合は未検証 |
| 送信用spoolの対象 | StatefulStreamはリクエストのバイト列を一時ファイルに置くが、RAIIのSpoolFileデストラクタはファイルを削除。**stateless Windowsイベントの再起動後スプール保証と混同禁止。** | [src/client-agent/https_client/src/statefulStream.cpp:38-69](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/client-agent/https_client/src/statefulStream.cpp#L38-L69)、[src/client-agent/https_client/src/spoolFile.cpp:68-115](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/client-agent/https_client/src/spoolFile.cpp#L68-L115) | 実装確認 |
| Windowsサービス/ACL | WazuhSvcの作成/削除、サービス自動起動、インストール後のqueue/bookmarksのACL制限がある。 | [src/win32/win_service.c:225-242](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/win32/win_service.c#L225-L242)、[src/win32/win_agent.c:47-58](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/win32/win_agent.c#L47-L58)、[src/win32/InstallerScripts.vbs:761-785](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/win32/InstallerScripts.vbs#L761-L785) | 実装確認 |
| 内部ログローテーション | ossec.log / ossec.jsonは日替わり/サイズ閾値でw_rotate_logを呼ぶ。**収集したWindowsイベントの永続スプール/EVTX保持設定そのものではない。** | [src/client-agent/src/rotate_log.c:23-41](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/client-agent/src/rotate_log.c#L23-L41)、[src/client-agent/src/rotate_log.c:63-90](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/client-agent/src/rotate_log.c#L63-L90) | 実装確認（適用範囲に注意） |

**データ経路の理解：** Windows EventChannel→EvtRender/XML→logcollectorのSendMSG→宛先キュー/agent→（5.x系構成で）HTTPS stateless送信→manager側の分析・保存。最後のWazuh engine/rules/indexerをAegisGuardのローカルMVPの必須構成にしない。Windows向けのリンク構成は[src/win32/CMakeLists.txt:159-189](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/win32/CMakeLists.txt#L159-L189)、外部への送信契約の具体例は[src/client-agent/https_client/src/statelessStream.cpp:248-276](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/client-agent/https_client/src/statelessStream.cpp#L248-L276)。manager側を用いない場合、Event XMLをそのままローカル判定し、別のローカル保存/可視化経路が必要になる。

### 2.2 取りこぼし防止についての重大発見

1. **キュー投入失敗でもブックマークを進める。** send_channel_eventはSendMSGが失敗したときにdropsを計上する一方、その後のupdate_bookmarkは送信結果を条件にしない。結果としてキュー投入前に落ちたイベントが再起動後に再取得されない可能性がある（「可能性」の推定はこの制御フローに基づく）。根拠：[src/logcollector/src/read_win_event_channel.c:357-370](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/read_win_event_channel.c#L357-L370)。
2. **キュー投入成功も耐久完了を意味しない。** メモリキューの溢れ時破棄、後段送信失敗、停止時の未送信バッファの存在。ローカルサービスは「永続ストレージに同期確定してからブックマークを確定」を検討すべき。根拠：[src/logcollector/src/logcollector.c:1948-1994](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/logcollector.c#L1948-L1994)、[src/logcollector/src/logcollector.c:2029-2095](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/logcollector.c#L2029-L2095)。
3. **無効な/古いブックマークはfuture-onlyへ退避。** 起動できることと欠損しないことは別。AegisGuardでは明示的なgapフラグと安全な再走査（残存しているチャネル範囲を探索）、重複許容の処理を優先。根拠：[src/logcollector/src/read_win_event_channel.c:489-523](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/read_win_event_channel.c#L489-L523)。
4. **EvtSubscribeStrict未使用。** MicrosoftのサンプルはEvtSubscribeStrictとERROR_EVT_QUERY_RESULT_STALEによる欠損通知を扱うが、固定SHAのwin_start_event_channelはFuture/StartAfterBookmarkのみでStrictを付加していない。イベント削除/ローテーションの検出が網羅的とは言えない。根拠：[src/logcollector/src/read_win_event_channel.c:424-431](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/read_win_event_channel.c#L424-L431)、[src/logcollector/src/read_win_event_channel.c:489-513](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/read_win_event_channel.c#L489-L513)、[Microsoft Event Bookmark](https://learn.microsoft.com/en-us/windows/win32/wes/bookmarking-events)。
5. **仕様/コード差分に注意。** ドキュメントはonly-future-events=noでWindows channelの全既存イベントを処理すると説明するが、**ブックマークなし**の固定SHA実装は初期flagsがEvtSubscribeToFutureEventsのまま。実機で最初の起動時の読み始め位置を検証必須。根拠：[docs/ref/modules/logcollector/configuration.md:105-113](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/docs/ref/modules/logcollector/configuration.md#L105-L113)、[src/logcollector/src/read_win_event_channel.c:424-431](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/read_win_event_channel.c#L424-L431)、[src/logcollector/src/read_win_event_channel.c:480-503](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/read_win_event_channel.c#L480-L503)。

### 2.3 SysmonのイベントID、ProcessGuid、時刻の区別

**Sysmonがイベント生成元**で、**Wazuhは設定されたWindowsイベントチャネルを収集する側**。Wazuhのread_win_event_channel.cには自前のプロセス生成/DLLフックやProcessGuid生成は見当たらず、WazuhがSysmon 1/3/7のイベントを創出するわけではない。公式仕様：[Sysmon - Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)、[Sysmon event definitions](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)、[Sysmon configuration schema](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-configuration-files)。

| Sysmon Event ID | 主な意味/相関フィールド | AegisGuardの優先扱い |
|---|---|---|
| 1 | ProcessCreate。ProcessGuid、ProcessId、ParentProcessGuid/ParentProcessId、Image、CommandLine、UtcTime、ハッシュ等（イベントスキーマに依存）。 | 最初のPoC対象。親子エッジ作成、静的PE/スクリプト検査結果との結合候補。 |
| 3 | NetworkConnect。ProcessGuid/PID、宛先IP/port/プロトコル。**既定で無効。** | 利用者の明示許可とSysmon側の有効化を前提に、C2 IOCの観測用。WFPによる即時遮断とは別物。 |
| 5 | ProcessTerminate。終了時刻/ProcessGuid/PID。 | プロセス寿命の閉鎖、PID再利用による誤相関の抑制。 |
| 7 | ImageLoad。DLL/EXEイメージ読み込み。**既定で無効・高頻度。** | 最初から全面取得しない。調査対象プロセスなどで限定有効化。 |
| 8 | CreateRemoteThread。別プロセスへのリモートスレッド作成。 | 第二段階、対象プロセスの文脈付き警告。 |
| 10 | ProcessAccess。Source/TargetProcessGuidなどを用いて参照側と被参照側を区別。 | 高ノイズ。対象限定・しきい値と許可リストを設け、単独で悪性断定しない。 |
| 22 | DNSQuery。問い合わせドメインとProcessGuid等。 | 将来のDNS IOC照合に活用、DNS秘匿・プライバシーに注意。 |

**相関キー案（AegisGuard独自設計）：** (machine_id, sysmon_process_guid) を主キーとし、ProcessGuid欠落時のみ(machine_id, PID, process_start_utc, image)を低信頼の代替候補にする。PIDだけで同一プロセス確定しない。EventRecordIDは**チャネル内の継続点/重複排除**に用い、process identityには使わない。TimeCreated(System)とEventData.UtcTimeを別々に保存し、受信時刻/単調処理順序を追加して、遅延イベント・時刻変更・再起動によるズレを観測する。親プロセスの先行イベントが欠けたらorphanと記録し、存在しなかったと決めつけない。Sysmonのイベント項目/時刻がOS/設定/版で異なる可能性は実機検証する。

## 3. 具体的な取り込み候補と選択肢

| 候補機能 | 利用方法（crate/API・外部CLI・独自実装・参考・見送り） | AegisGuard接続先（提案） | 優先度 | 規模 | ライセンス・技術上の阻害要因 |
|---|---|---|---|---|---|
| WinEventLogチャネル購読とXPath | **Rust windows crate/Win32 EventLog API直接利用＋AegisGuard独自実装** | 新規 sensor/windows_eventlog | P0 | M | Windows用ABI/コールバック寿命、安全なHANDLE破棄・ACL・Win11実機が必要。Wazuh GPLコードは非転用。 |
| 原子的チェックポイント/再走査/欠損状態 | **独自実装**（Wazuhは失敗例も参考） | sensor/checkpoint + storage/events | P0 | M | 永続I/O/ジャーナル書込の整合、停電/空き容量/ログ上書き。 |
| Sysmon ID 1/5相関 | **独自実装**（MicrosoftのSysmonを外部サービスとして利用） | sensor/sysmon_normalize + correlation/process_graph | P0 | M | Sysmon未インストール/無効/設定差、ProcessGuid欠損の誤相関。 |
| EventID 3/7/8/10/22の選択的取得 | **EventLog API直接利用＋独自解析** | sensor/sysmon_normalize + detections | P1 | M | 3/7は明示的設定、容量・誤検知の実測が先。 |
| キュー飽和の検出/品質指標 | **独自実装**（Wazuh dropカウンタは設計参考のみ） | telemetry/health + storage/wal | P0 | S | 容量枯渇時は明確にdegraded/gap表示し、無音で捨てない。 |
| Sysmonインストール/設定管理 | **外部サービス連携（利用者が別途導入）** | setup/sysmon_diagnostics（将来） | P1 | M | 管理者承認・配布条件・既存Sysmon設定の所有権。MVPでは勝手に変更しない。 |
| WazuhのHTTPS stateless/manager indexer | **設計参考のみ** | なし（ローカル完結MVP） | P2 | L | サーバー前提、GPL/AGPLとメンテ費用、個人のPII外送要件に非適合。 |
| Wazuh logcollectorのCコード/Rustへの直訳 | **不採用** | なし | — | L | GPLv2のライセンス・復旧上の欠点を持ち込みやすい。 |

**最優先3件：** (1) WinEventLog reader（P0/M、Windows 11・APIアクセス権がブロッカー）、(2) durable cursor + gap検知（P0/M、トランザクション/停電テストがブロッカー）、(3) Sysmon ID1/5相関（P0/M、Sysmonの任意導入とProcessGuid完全性がブロッカー）。上記工数は相対規模で、実際の人日・CPU・件数ではない。

**候補ごとの入出力/失敗：**
- **購読：** 入力は許可されたchannel名、限定XPath、復旧方針。出力はEvtRenderEventXml由来のサイズ制限付きXML、channel、record_id、provider、event_id、event_time、受信時刻、異常状態。WinAPI失敗時はサービスを止めず、種類別の状態通知/再試行。callbackでは重い検査をせず、イベントを有界パイプへ渡す。
- **永続化：** 入力は上記イベントとWindows bookmark XML/record ID。出力はディスク上の(イベント本体、ソース/record_id、checkpoint)一貫スナップショット。保存が成功したイベントだけの連続領域までcursorを進める。中間欠落・ディスク書込失敗なら進めずdegradedに移行。クラッシュ直前重複を許容し、(channel, record_id, provider等)で冪等にする。ブックマークの保存とイベント保存の原子性はPoCで実証。
- **Sysmon相関：** 入力は許可リスト内のEvent IDの構造化データ、出力はprocess_graphのノード・エッジと根拠。未解決のparent GUID/欠落イベントはunknown/orphanを保持。イベントIDだけで即時「悪性」と判定しない。既存の静的scan/C2チェックは別キュー/レート制限付きで呼び、重い検査に引っ張られてイベントcallbackを詰まらせない。
- **診断：** 入力はキュー深度、ディスク残容量、チャネル情報、last_event/last_checkpoint、Windows APIエラー、Sysmon状態。出力はreceived/persisted/parsed/dropped/gap/replayedとlagを区別したローカルhealth JSONL。最大許容容量は**実測で決定**し、ゼロロスと自称しない。

## 4. ライセンス・再配布・依存関係

| 対象 | 原文/ビルドで確認できた条件 | AegisGuardでの判断 |
|---|---|---|
| Wazuh Windowsイベントコレクタ、agent、Windowsサービス | [src/logcollector/src/read_win_event_channel.c:1-9](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/read_win_event_channel.c#L1-L9)、[src/win32/win_service.c:1-9](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/win32/win_service.c#L1-L9) のGPL version 2、[LICENSE:1-30](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/LICENSE#L1-L30) の「その他はGPLv2」。 | 実装をコピー/改変/静的リンクして閉源配布可能と断定できない。**設計参考のみ**とする。 |
| Wazuh engine / manager-analysisd | [src/engine/COPYING-engine:1-16](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/COPYING-engine#L1-L16)、[LICENSE:1-6](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/LICENSE#L1-L6) のAGPLv3 or later。 | ローカルMVPでは不採用。サーバー連携・改造・再配布は別途法務評価。 |
| shared_modules utils/manager_config/keystore/indexer_connector/common/http-request | [LICENSE:7-21](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/LICENSE#L7-L21)、[src/shared_modules/utils/COPYING:1-18](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/shared_modules/utils/COPYING#L1-L18) ではGPL-2.0-only OR AGPL-3.0-or-laterのデュアル。 | コンポーネントごとに選択条件/依存・連結先を再審査。単独でMIT系と見なさない。 |
| Wazuh decoder、rule、設定、データ | [LICENSE:27-55](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/LICENSE#L27-L55) は別途指定がない限りルールやデータにもGPLv2が及ぶと述べる。 | ルール/署名/データを無許可同梱しない。挙動から学んで独立したルールを定義。 |
| 外部依存 | [src/win32/CMakeLists.txt:59-69](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/win32/CMakeLists.txt#L59-L69) のWindows wevtapi/advapi32等、[src/logcollector/CMakeLists.txt:11-30](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/CMakeLists.txt#L11-L30) のcURL/PCRE2/YAML/OpenSSL、[THIRD-PARTY-NOTICES:1-96](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/THIRD-PARTY-NOTICES#L1-L96) の複数の個別ライセンス、[.gitmodules:1-3](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/.gitmodules#L1-L3) のhttp-requestサブモジュール。 | Wazuhバイナリ同梱をする場合はSBOM/第三者告知/サブモジュールまで監査。Windows APIを自分のRustコードから呼ぶ設計ならWazuh製コードは不要。 |
| Microsoft Sysmonの実行ファイルと設定 | [Sysmon公式ドキュメント](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)、[Windows側の組み込みSysmon情報](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)。**WazuhのGPLをSysmon自体へ適用してはいけない。** | WazuhからSysmonバイナリを転載しない。必要ならMicrosoftの現行配布/ライセンス/組み込み機能の条件を別途確認。 |

**利用形態を分ける：** (1) RustからMicrosoft Event Log APIへ直接リンクするのはWazuhコードの直接リンクとは異なる、(2) Wazuhコード転用/静的リンク/データ同梱はライセンス検討が必要、(3) Wazuh外部CLI/サービスを単に別プロセスで起動すれば常に安全という保証はない、(4) 利用者自身がWazuhを別途導入する場合とAegisGuardインストーラへの同梱は区別する。Wazuh LICENSEには派生物解釈として実行プログラム統合にも言及がある。**法的評価未完了**。将来の商用/閉源配布時には専門家への確認が必要。AegisGuard自身の現行ライセンスは[README.md:67-71](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md#L67-L71)で未設定とされるため、現在の移植/再配布適合性は結論不能。

## 5. Defender共存・Windows制約・権限境界

- Windows 11 x64でWindows Event Log API（EvtSubscribe、EvtRender、EvtCreateBookmark、EvtUpdateBookmark）を**読み取り主体**として使用し、Defender Real-time protection、ASR、Windows Firewallを停止/変更しない。[src/logcollector/src/read_win_event_channel.c:14-15](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/read_win_event_channel.c#L14-L15) はWinAPIを使うためのターゲットマクロ。AegisGuardの構想は[docs/ARCHITECTURE.md:1-44](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L1-L44)。
- Sysmonは独立した収集元。Event Log読取はETW providerへの自前リアルタイム登録、WFPフィルタ、AMSIホスト連携、プロセスをブロックするドライバと**同義でない**。Sysmon ID3とWFPネットワーク観測は重複し得るが得られる時点/粒度が異なる。AMSI/Defenderの二重スキャンは、静的解析をイベントごとに無制限に実施しない設計で避ける。
- Wazuh Windowsサービスは[src/win32/win_service.c:225-242](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/win32/win_service.c#L225-L242) でauto start/未指定アカウントとして作成。サービスのinstall/uninstallは[src/win32/win_agent.c:189-210](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/win32/win_agent.c#L189-L210)。Windowsのサービスアカウント/ログのDACLに応じて必要なread権限は異なる。AegisGuardでは**インストール・設定の変更に管理者承認を求める**一方、通常の購読・閲覧UIは権限分離、最小権限/Service SID/ACLを検討し、安易にLocalSystemを前提としない。
- ブックマーク/イベントDBに平文の実行コマンド、ユーザー名、DNS、通信先、ファイルパス、場合によってはユーザー識別情報が含まれる。Wazuhもqueue/bookmarksのACLを制限する（[src/win32/InstallerScripts.vbs:761-785](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/win32/InstallerScripts.vbs#L761-L785)）。AegisGuardはAdministrators/SYSTEM等の限定ACL、保存期間、暗号化の要否、外部転送なし、ユーザーによる削除、プライバシー既定値の明示を推奨。
- Windows Event Logの元ログサイズ/ローテーション/クリア権限はOS側。保存先のディスク容量が十分でも元のEVTXが上書きされたイベントは復旧できない。OS側のイベント保持設定を勝手に書き換えない。Sysmonのインストール・アンインストールや設定変更も独立した同意フローが必要。

## 6. 性能・堅牢性・誤検知

**コードで確認：** logcollectorの出力キューは設定可変な有限キュー（[src/logcollector/src/logcollector.c:1884-1904](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/logcollector.c#L1884-L1904)）。満杯なら破棄し60秒間隔の警告に集約する（[src/logcollector/src/logcollector.c:1944-1995](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/logcollector.c#L1944-L1995)）。5.x HTTPSのstateless bufferはbatchSizeBytes×bufferCapMultiplierを上限に新規イベントを拒否し、カウンタを増やす（[src/client-agent/https_client/src/eventAccumulator.cpp:33-52](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/client-agent/https_client/src/eventAccumulator.cpp#L33-L52)、[src/client-agent/https_client/src/statelessStream.cpp:138-153](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/client-agent/https_client/src/statelessStream.cpp#L138-L153)）。後段は成功でconsumeし、503/通信失敗時は保持、413単一巨大イベントや一部400で破棄（[src/client-agent/https_client/src/statelessStream.cpp:279-358](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/client-agent/https_client/src/statelessStream.cpp#L279-L358)）。

**テストで確認：** cmockaのWindowsコレクタ単体テストはEvtRenderサイズ取得失敗と正常イベント送出を検証（[src/unit_tests/logcollector/test_read_win_event_channel.c:61-127](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/unit_tests/logcollector/test_read_win_event_channel.c#L61-L127)）。ただし本ファイルにブックマーク破損、再起動、接続切断、EvtSubscribeActionErrorの単体試験は見られない。C++ gtestはdrop-newest、consume時のtail保全、413分割、400/404、timeout、503を模擬（[src/client-agent/https_client/tests/unit/eventAccumulator_test.cpp:78-101](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/client-agent/https_client/tests/unit/eventAccumulator_test.cpp#L78-L101)、[src/client-agent/https_client/tests/unit/statelessStream_test.cpp:478-507](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/client-agent/https_client/tests/unit/statelessStream_test.cpp#L478-L507)、[src/client-agent/https_client/tests/unit/statelessStream_test.cpp:610-663](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/client-agent/https_client/tests/unit/statelessStream_test.cpp#L610-L663)）。これは**Windows実機のEnd-to-end欠損ゼロ試験ではない**。一時ファイルのRAII削除も[src/client-agent/https_client/tests/unit/spoolFile_test.cpp:40-54](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/client-agent/https_client/tests/unit/spoolFile_test.cpp#L40-L54)にテストがある。

**要実測：** Sysmon ID7のDLLロードとID10プロセスアクセスはイベント爆発、XMLシリアライズ/文字列変換のCPU・メモリ/バッテリ、DB書込回数、Defenderとの併用時のI/O競合が懸念。性能目標値、MB/日、EPS、ロス率は現時点で断定しない。観測バースト、元チャネル上書き、シャットダウン、ディスク満杯、アクセス拒否、ログサービス一時停止、イベントXML巨大化、壊れたBookmark XML、service restartを故障注入シナリオにする。

**誤検知/検査漏れ：** 通常の管理ソフト/デバッガもID10/8を発行し、DLL署名済みでも悪用され得る。正当なDLLロードを「悪性」としない。一方、Sysmon非導入/設定フィルタ/イベントログ上書き/アクセス不可/停止中/改ざん時には「イベントがない=安全」としない。特権境界をまたぐXMLの長さ・ネスト・不正文字は上限を設け、トリガーした実ファイルの再検査にはTOCTOU・reparse-pointを考慮。既存の[SECURITY.md:1-22](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md#L1-L22)も実行検体/パス競合に注意している。

## 7. 推奨する小さなPoCと成功基準

**前提：** 機能フラグ初期OFF、Windows 11検証VM/スナップショット、Defender ON、Sysmonが利用可能かどうか事前診断、管理者の明示同意。通常環境の保護ポリシーは触らない。検証用にMicrosoft公式Sysmon/組み込みの有無と取得可能なチャネルを確認するが、無断インストールはしない。

**安全な手順（段階的）：**
1. **無効/読取診断：** read-onlyで対象チャネルの存在、ACL、旧い/新しいRecordID、Bookmark復元可否を取得。アクセス拒否/空/未導入を異なる状態コードで出力。イベント本文は永続保存しない。
2. **観測のみ：** Sysmon ID1/5（なければ既存のApplicationテストチャネル）を限定購読し、安全なコマンド（例：標準のメモ帳/計算機の起動終了）を発生させる。SysmonのEID発生有無を別に確認。取得したXMLはサイズ上限を適用しローカルDBへ保存。既存AegisGuard scanの呼出はまだしない。
3. **再開/重複/欠損試験：** 保存→強制終了→再起動、保存途中のクラッシュ、ロック中のDB、権限剥奪、ディスク容量制限、元ログ上書き、購読再接続、ブックマーク破損をVM上で模擬。イベントRecordID列を独立のWindowsログビューア取得結果と比較し、設定フィルタによる意図的欠番と取得失敗を区別する。
4. **限定相関：** ID1/5のProcessGuid/親子を結び、存在しないGUID/PID再利用/順不同/UTC時計変更を合成XMLフィクスチャで検証。次の段階でID3を限定的に選択し、C2は**警告のみ**。

**成功条件：** (a) 明示的に収集対象とした安全イベントのrecord_idと保存/再開結果を突合し、通常の停止/再開経路で未報告の欠損・重複警告漏れがない、(b) 原子的チェックポイント試験で**永続化済み以外へカーソルが進まない**、(c) 強制的な元ログ上書き/不正ブックマーク/ディスク満杯は「成功」扱いせずgap/degradedを記録する、(d) CPU/Private Bytes/Peak RAM/DBサイズ/書込IOPS/キュー深度/イベント遅延をETW/Performance Monitorなどで測定し結果と端末条件を残す、(e) Defender ONのまま運用/巻戻しでき、サービス停止後もOSやDefender設定は元のまま。**性能しきい値は実測後に決定**する。

**失敗時：** 一旦購読OFF、ブックマークを保持してdiagnosticを出し、ディスクの未処理記録は残す。復帰時はOS上に残存するログから再読込＋idempotentな重複排除を実施。ログ消失時は失われた範囲を明示し、黙って未来へジャンプしない。rollbackはサービス停止/自動起動解除/自身のDBとサービスの削除のみ、Defender/Sysmon/既存イベントは変更しない。

**中止条件：** Defender競合・OS不安定化、ログ大量肥大化、無断のPII記録、権限過大要求、処理落ちを検出できない、サービス終了/更新後に復旧不能のいずれか。

## 8. 採用しない設計と理由

1. **Wazuh agent + manager + engine/indexerをAegisGuardに同梱する案：不採用。** Windows単体のread-only MVPに対して過剰で、ネットワーク/サービス/資格情報/運用とGPLv2・AGPLのライセンス整理が増える。[README.md:14-24](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/README.md#L14-L24)、[LICENSE:1-30](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/LICENSE#L1-L30)。
2. **Wazuh read_win_event_channel.cをRustへ機械翻訳して使用：不採用。** GPLコード転用の懸念、SendMSG失敗後もcursorが進む実装、StartAfterBookmark失敗→Futureの暗黙切替を再利用する危険。[src/logcollector/src/read_win_event_channel.c:357-370](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/read_win_event_channel.c#L357-L370)、[src/logcollector/src/read_win_event_channel.c:489-513](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/read_win_event_channel.c#L489-L513)。
3. **Sysmon ID7/10を全プロセス全期間で収集：MVP見送り。** 大量イベント/プライバシー/性能/誤検知が未測定。必要性が証明された対象のみ設定を絞って段階導入。[Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)。

## 9. 他担当との境界・引継ぎ

- **wazuh-fim-persistence担当：** Windowsのwhodataは別購読経路[src/syscheckd/src/whodata/win_whodata.c:1-10](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/whodata/win_whodata.c#L1-L10)であり、SACL/監査ポリシーとFIMデータベース運用はそちらで判定。本稿のEventChannel readerと混同しない。今回の設計では必要なログを読み取るのみで、監査ポリシーは変更しない。
- **Portmaster/simplewall担当：** WFP/Firewallの通信観測・遮断は別途。Sysmon ID3は既存の接続事実の観察であり、ファイアウォールのポリシー決定/自動遮断と統合しない。必要なら統一プロセスIDとイベント時刻の契約を共有。
- **ClamAV/YARA/Rust解析担当：** ID1/7のImage/Hashから任意の**読み取り専用**ファイルスキャンを要求する際、重複検査抑止と最大同時実行数を決める。イベント購読callback内で同期スキャンしない。
- **既存AegisGuard：** [src/model.rs:1-43](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/model.rs#L1-L43) はfile Report構造であり、event_id、source、cursor、gapを持つ汎用イベントモデルは未定義。別個のEventEnvelopeを設け、既存ファイルscan結果と根拠として相関する。LICENSE未設定の取り扱いはリポジトリ責任者/法務判断。

## 10. 未確認事項・追加調査項目

| 重要度 | 未確認内容 | 次の検証 |
|---|---|---|
| **重大** | Windows 11実機でWazuhのbookmark無し初回購読がdocs記述と異なるか、EventLogクリアや古いbookmarkで本当にどの範囲が飛ぶか | Wazuh 5.1 alpha0 Windows VMで再現。APIのGetLastError/ERROR_EVT_QUERY_RESULT_STALEを記録。 |
| **重大** | WazuhのWin32 EventChannel→logcollector queue→Windows HTTPS client→managerまでの欠損数、ACK時点、停止/再開の永続性 | 経路別計数と故障注入。特に「ローカルキュー投入成功」と「サーバー永続化成功」を区別。 |
| **高** | Sysmon（組み込み機能/別途Sysinternals配布、バージョン/構成）によるID 1/3/7/10の可用性と項目差分 | 実機のmanifest/schema/XMLとProcessGuid/ParentProcessGuidを比較。 |
| **高** | 最小サービス権限/チャネルDACL、設定配布/削除/管理者UACの実要件 | 標準ユーザー、専用サービスSID、昇格済み管理者で取得可能イベントを比較。 |
| **高** | Windowsのイベントログローテーションとbookmark回復APIの端点/strict mode | Microsoft Learn確認＋小容量テストログで検証。 |
| **中** | Wazuhライセンス解釈、特殊例外と外部CLI同梱可否 | 再配布方式確定後に法務レビュー。Sysmon/ルール配布条件を別途調査。 |
| **中** | 大量イベント/非常に大きなXML/UTF変換に対するCPU、RAM、電池、ディスク容量、誤検知 | Defender ONのWindows端末で性能測定。 |
| **中** | テスト網羅性：イベント購読コールバック競合、破損bookmark、飽和、サービスクラッシュに対する独立テスト | フィクスチャとproperty/fault-injection tests作成。 |

**調査限界：** Wazuhのmainは開発途中のalpha表記であり、既存安定版のWindowsエージェントと実装差があり得る。本調査ではビルド/実機/テスト実行/ライセンス専門家審査をしていない。OSイベントが元から存在しない状況と取りこぼしを区別する完全な方法は、Sysmon設定/元ログ保持条件/独立計数源を含む設計が必要。

## 11. 一次情報一覧

確認日：2026-11-05。**以下はすべて固定SHAへのpermalink（ファイル・行）。**

1. Wazuh EventChannel購読（EvtSubscribe、future/bookmark失敗時の代替）：[src/logcollector/src/read_win_event_channel.c:424-545](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/read_win_event_channel.c#L424-L545)。
2. Wazuh bookmark読込/更新（永続性・失敗の挙動）：[src/logcollector/src/read_win_event_channel.c:136-302](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/read_win_event_channel.c#L136-L302)。
3. WindowsイベントのEvtRender/XML→SendMSG、送信失敗後のcheckpoint：[src/logcollector/src/read_win_event_channel.c:306-377](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/read_win_event_channel.c#L306-L377)。
4. logcollectorのメモリキュー容量/警告/drop：[src/logcollector/src/logcollector.c:1884-1995](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/logcollector.c#L1884-L1995)。
5. ローカル送信経路の再接続/再送：[src/logcollector/src/logcollector.c:2027-2095](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/logcollector.c#L2027-L2095)。
6. HTTPS statelessの有限バッファ、応答ごとのconsume/drop：[src/client-agent/https_client/src/eventAccumulator.cpp:33-52](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/client-agent/https_client/src/eventAccumulator.cpp#L33-L52)、[src/client-agent/https_client/src/statelessStream.cpp:279-358](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/client-agent/https_client/src/statelessStream.cpp#L279-L358)。
7. Wazuhのイベントドロップ検知テスト/413/503/timeout：[src/client-agent/https_client/tests/unit/eventAccumulator_test.cpp:78-101](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/client-agent/https_client/tests/unit/eventAccumulator_test.cpp#L78-L101)、[src/client-agent/https_client/tests/unit/statelessStream_test.cpp:537-548](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/client-agent/https_client/tests/unit/statelessStream_test.cpp#L537-L548)、[src/client-agent/https_client/tests/unit/statelessStream_test.cpp:610-663](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/client-agent/https_client/tests/unit/statelessStream_test.cpp#L610-L663)。
8. Windows EventChannelのcmockaテスト：[src/unit_tests/logcollector/test_read_win_event_channel.c:61-127](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/unit_tests/logcollector/test_read_win_event_channel.c#L61-L127)。
9. Sysmon Operational/Windows Defender Operational構成データ：[tests/integration/test_logcollector/test_configuration/data/test_cases/cases_basic_configuration_location_win.yaml:1-63](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/tests/integration/test_logcollector/test_configuration/data/test_cases/cases_basic_configuration_location_win.yaml#L1-L63)。
10. Windowsサービス、ACL、依存ライブラリ：[src/win32/win_service.c:225-242](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/win32/win_service.c#L225-L242)、[src/win32/InstallerScripts.vbs:761-785](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/win32/InstallerScripts.vbs#L761-L785)、[src/win32/CMakeLists.txt:59-69](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/win32/CMakeLists.txt#L59-L69)。
11. ルートGPL・engine AGPL・shared modules dual license/依存通知：[LICENSE:1-65](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/LICENSE#L1-L65)、[src/engine/COPYING-engine:1-16](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/COPYING-engine#L1-L16)、[src/shared_modules/utils/COPYING:1-18](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/shared_modules/utils/COPYING#L1-L18)、[THIRD-PARTY-NOTICES:1-96](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/THIRD-PARTY-NOTICES#L1-L96)。
12. Wazuh mainの版：[VERSION.json:1-4](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/VERSION.json#L1-L4)、AegisGuard mainの未実装境界：[src/main.rs:1-74](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/main.rs#L1-L74)、[docs/ARCHITECTURE.md:18-40](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L18-L40)。

**公式Windows/Sysmon API資料（コード外の一次情報、2026-11-05確認）：** [EvtSubscribe](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtsubscribe)、[Bookmarking events](https://learn.microsoft.com/en-us/windows/win32/wes/bookmarking-events)、[Sysmon download/events](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)、[Sysmon event definitions](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)、[Sysmon configuration](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-configuration-files)。

---
**判定:** 小さなローカルWindows Event Logセンサを独自実装することを推奨。WazuhのAPI使用パターンと失敗経路は価値ある一次資料だが、無欠損・耐久スプール・ProcessGuid解析がそのまま提供されているとは評価しない。
