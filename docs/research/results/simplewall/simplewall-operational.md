# 調査報告：simplewall / simplewall-operational

> 担当：simplewall-operational（ルール永続化・運用・ログと例外/ロールバック） / 調査日：2026-11-05 / 調査結果：部分完了（一次コード調査完了、Windows 11実機・ビルド・動作試験未実施）

## 0. 結論（3〜5行）

- **取り入れる価値：高い。** simplewall のWFPオブジェクト所有者識別、個別許可、ログからルール作成、設定バックアップは、AegisGuardの「監査→利用者承認→選択的遮断」に参考となる。
- **最優先：** (1) 遮断理由を伴う監査ログ、(2) 期限付き例外・復旧UX、(3) 自分が作ったルールだけを列挙・巻き戻す所有権モデル。いずれも**AegisGuard独自実装**またはWindows公式APIによる実装を推奨する。
- **見送り：** simplewallのC/C++コード取り込み、全面デフォルト拒否、Windows Firewallの無効化、起動時からの広範なWFP boot-time遮断、WFPエンジンの包括的ACL変更。
- **最大の制約：** AegisGuardは現在読み取り専用Rust CLIで遮断・常駐・権限分離が未実装。simplewallはGPL-3.0であり、実機での復旧・Defender共存・外部ルールデータ許諾も未検証。
- **重要な訂正：** simplewallの「temporary」は**再起動まで有効**であり、「アプリ終了時に必ず消える」動的セッションではない。実際の`FWPM_SESSION0`設定には`FWPM_SESSION_FLAG_DYNAMIC`がない。

## 1. 対象の固定と調査方法

| 要素 | 値 / 根拠 |
|---|---|
| 公式リポジトリ・commit固定URL | [henrypp/simplewall@24bbd2c](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/README.md)（公式[リポジトリ](https://github.com/henrypp/simplewall)、`master`の調査スナップショット） |
| 調査コミットSHA・タグ | `24bbd2ceb7daee9ef308e0b406be5eb039cb30a1`。`VERSION`に`simplewall=3.9.1`、`build.bat`に`build simplewall 3.9.2`があり、開発時の表示差異を確認。両者を同一リリースと仮定しない。[VERSION](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/VERSION) / [build.bat](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/build.bat) |
| AegisGuard比較先SHA | `83fcf0d150e8d760baff5f971c106deb09c1f8e4`（`main`）。[README](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md#L1-L18) / [ARCHITECTURE](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L28-L44) |
| ライセンス | simplewall本体[`LICENSE`](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/LICENSE)はGNU GPL v3原文。`henrypp/routine`も[GNU GPL v3](https://github.com/henrypp/routine/blob/master/LICENSE)。内部ルール/外部ブロックリストの権利関係は別途確認が必要。 |
| ソース・文書 | `src/wfp.c`、`profile.c`、`db.c`、`log.c`、`notifications.c`、`timer.c`、`network.c`、`packages.c`、`uwp.cpp`、`security.c`、`main.c`、`editor.c`、`global.h`、`bin/profile_internal.xml`、`README.md`、`.gitmodules`、`packages.config`、`simplewall.vcxproj`、`.github/workflows/scorecard.yml`、`LICENSE`、ビルドスクリプト、AegisGuardのREADME/SECURITY/ARCHITECTURE/Cargo/src。 |
| テスト・CIの調査 | 固定SHAの再帰ファイルツリーには独立した`tests/`やテスト実行用CIは見つからず、確認した唯一のGitHub Actionsワークフローは[OpenSSF Scorecard](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/.github/workflows/scorecard.yml)解析。テストが全く存在しないと断定しない。 |
| 実機・ビルド・テスト | **未実施。** Windows 11実機・MSVC v145/SDK、管理者WFP環境がないため、バイナリの起動、通信遮断、リブート、修復、性能測定は実施していない。未知のコードや検体の実行は行っていない。 |
| 調査日・対象範囲 | 2026-11-05（日本時間）。このコミットの実装を対象とする静的コード調査。更新後の動作・製品環境・他社FWとの競合は要実測。 |

調査方法：GitHubでcommit SHA固定ファイルの実コードと構成ファイルを読み、関数の呼出しとWFP API引数を突き合わせた。Microsoft Learnの[WFP Object Management](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)、[Filter Arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration)、[Access Control](https://learn.microsoft.com/en-us/windows/desktop/FWP/access-control)を補助一次資料とした。READMEの「共存可能」という説明だけで、既存Firewall設定を一切操作しないとは判断しない。

**AegisGuard現状：** `src/main.rs`のCLIはファイル`scan`と`c2 update/check/status`のみ。[実装](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/main.rs#L24-L75)。`README`はWindows Firewall・常駐・遮断を未実装と明記し、`docs/ARCHITECTURE.md`は観察先行、明示承認と自分の名前空間のルールだけを変更する方針。[README](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md#L7-L18) / [ARCHITECTURE](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L28-L35)。

## 2. 実装アーキテクチャとソース調査

### 2.1 コード根拠付き機能マップ

| 機能 | 主要ファイル/シンボルと役割・意味 | commit固定の一次情報 | 確認状態 |
|---|---|---|---|
| WFPエンジン接続 | `_wfp_getenginehandle` → `FwpmEngineOpen0`。BFE未起動時の`EPT_S_NOT_REGISTERED`を短時間再試行し、それ以外はエラーを記録。セッションは`DYNAMIC`フラグを指定していない。 | [wfp.c 8–65](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L8-L65) | 実装確認 |
| 所有者の分離と永続性 | `_wfp_initialize`が専用`GUID_WfpProvider`/`GUID_WfpSublayer`を登録。一時モード以外では`FWPM_PROVIDER_FLAG_PERSISTENT`と`FWPM_SUBLAYER_FLAG_PERSISTENT`。 | [wfp.c 207–311](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L207-L311) | 実装確認 |
| ルール→実フィルター | `_wfp_createfilter`で固有GUID、action、priority、providerKey、subLayerKey、`FWPM_FILTER_FLAG_PERSISTENT`/`INDEXED`、`FwpmFilterAdd0`。`FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`も利用。 | [wfp.c 715–810](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L715-L810) | 実装確認 |
| アプリ別・IPv4/6フィルター | `_wfp_createrulefilter`で通常exeの`FWPM_CONDITION_ALE_APP_ID`、サービスの`FWPM_CONDITION_ALE_USER_ID`（サービスSD）、Store/UWPの`FWPM_CONDITION_ALE_PACKAGE_ID`（SID）を分岐。`ALE_AUTH_CONNECT`/`ALE_AUTH_RECV_ACCEPT`のv4/v6に展開。**サービス名文字列だけで同じ許可になるとは限らない。** | [wfp.c 918–1032](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L918-L1032) / [wfp.c 1175–1205](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L1175-L1205) | 実装確認 |
| UI・ルール編集 | `src/editor.c`でアクション、方向、プロトコル、リモート/ローカル宛先、アプリ適用範囲を選択。変更はprofileへ保存、WFP再適用。 | [editor.c 430–502](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/editor.c#L430-L502) / [profile.c 1708–1769](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/profile.c#L1708-L1769) | 実装確認 |
| 設定形式 | `_app_db_parse_rule`が`rule`/`rule_local`、`dir`、`is_block`、`protocol`、`version`、`apps`、重みをXMLから読み込む。plain/圧縮/暗号化のプロファイル形式を分岐。 | [db.c 288–458](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/db.c#L288-L458) / [db.c 119–141](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/db.c#L119-L141) / [db.c 519–760](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/db.c#L519-L760) | 実装確認 |
| 永続化・リロード・バックアップ | `_app_profile_load`は通常のプロファイル読み込み失敗時に`.bak`を試し、同梱の内部ルールを追加。`_app_profile_save`はロックして書き込み、時期が来れば`.bak`へコピー。`WM_INITDIALOG`時にも既存フィルターがあれば再適用。 | [profile.c 1619–1769](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/profile.c#L1619-L1769) / [main.c 1991–2004](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/main.c#L1991-L2004) | 実装確認 |
| 内部ルールと更新 | 同梱`profile_internal.xml`でDHCP/DNS/NCSI/Windows Update/SMB等のテンプレートを定義。ファイル版と埋込リソースの更新時刻/バージョンを比較。起動時に内部ルール更新コンポーネントを登録。 | [profile_internal.xml 1–44](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/bin/profile_internal.xml#L1-L44) / [profile.c 1531–1583](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/profile.c#L1531-L1583) / [main.c 2024–2030](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/main.c#L2024-L2030) | 実装確認 |
| 接続/遮断イベント・ログ | `FwpmNetEventSubscribe4/3/2/1/0`をOSに応じて呼び分け、`CLASSIFY_DROP/ALLOW`やIPsec dropから`filterId`/`layerId`、AppID/PackageSID、宛先、ユーザーなどを解決して記録。許可イベント収集は初期設定で除外。 | [log.c 295–465](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/log.c#L295-L465) / [log.c 466–678](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/log.c#L466-L678) / [log.c 690–725](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/log.c#L690-L725) | 実装確認 |
| 通知・時間限定許可 | `_app_notify_command`が通知の「許可」「遮断」を対象アプリに反映し、許可秒数がある場合`_app_timer_set`を使用。ログのリモートIP/portから個別許可ルールを生成。 | [notifications.c 56–118](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/notifications.c#L56-L118) / [notifications.c 1195–1223](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/notifications.c#L1195-L1223) / [timer.c 38–106](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/timer.c#L38-L106) | 実装確認 |
| WSL/サービス/Store | 既存通信一覧でPIDから通常プロセス/StoreのAppContainer SID/サービスを分岐。WSLはWin32パス取得失敗時にNT形式へフォールバック。サービス一覧・UWPパッケージ一覧は別取得。 | [network.c 686–774](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/network.c#L686-L774) / [packages.c 389–457](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/packages.c#L389-L457) / [uwp.cpp 16–79](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/uwp.cpp#L16-L79) | 実装確認。WSLの全通信への遮断精度は未実測 |
| 基盤通信・IPv6例外 | `_wfp_createglobalfilters`がループバック、6to4、ICMPv6の近隣探索、ステルス動作等を生成。`BlockOutboundConnections`/`BlockInboundConnections`は初期値true。 | [wfp.c 1508–1687](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L1508-L1687) / [wfp.c 1789–1836](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L1789-L1836) | 実装確認 |
| ブート時遮断・NAT問題 | `InstallBoottimeFilters`が初期値true、永続モードでのみ`FWPM_FILTER_FLAG_BOOTTIME`。`AllowIpForwarding`初期値falseなら転送v4/v6も遮断。ソースコメントはモバイルホットスポット/ICS/NAT仮想スイッチ破損を明示。 | [wfp.c 1743–1788](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L1743-L1788) | 実装確認 |
| ルール全停止・自己所有フィルター限定削除 | `_wfp_dumpfilters`はフィルターを列挙して`providerKey`が指定GUIDに一致するものだけを配列化。`_wfp_destroyfilters`と`_wfp_uninitialize(..., TRUE)`が削除経路。全フィルター再構成はWFPトランザクション。 | [wfp.c 1933–2004](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L1933-L2004) / [wfp.c 477–595](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L477-L595) / [wfp.c 380–475](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L380-L475) | 実装確認 |
| Windows Firewall設定との相互作用 | **READMEの共存説明と別に**、インストール確認ダイアログにWindows Firewall無効化チェックが存在し、`INetFwPolicy2_put_FirewallEnabled`でDomain/Private/Publicをオン/オフできる。初期`WF_State`はtrueとして読み出される。 | [main.c 43–135](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/main.c#L43-L135) / [wfp.c 2059–2085](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L2059-L2085) | 実装確認（UI操作時の実際の選択状態は要実機確認） |
| CLI操作 | `-install`、`-install -temp`、`-install -silent`、`-uninstall`。アンインストール側は確認ダイアログを要求し、無確認の`-uninstall -silent`は意図的に用意されていない。 | [main.c 3564–3620](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/main.c#L3564-L3620) | 実装確認 |
| WFPセキュリティ設定 | `_app_setenginesecurity`、`_app_setprovidersecurity`などがエンジンと自分のWFPオブジェクトのACLを変更。保護用途だが、BFE全体のACL編集には共存リスク。 | [security.c 151–298](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/security.c#L151-L298) / [security.c 301–379](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/security.c#L301-L379) | 実装確認 |

### 2.2 永続性・設定破損・緊急停止の実際の意味

1. **永続モード：** provider、sublayer、通常フィルターに`PERSISTENT`フラグ。アプリ終了後にもWFPポリシーが残り得る。再起動後も持続する前提で、回復手段は実行中UIから独立させる必要がある。[wfp.c](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L207-L311) / [wfp.c](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L715-L810)。
2. **temporaryモード：** `is_filterstemporary`で`PERSISTENT`付与を外すが、セッション側に`DYNAMIC`は立てない。従って単純なクラッシュ自動復旧とは**別物**。プロセス終了で消える設計が必要ならWFPの動的セッションを別途評価し、[Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)と合わせて実機確認する。
3. **通常プロファイル読込失敗：** ファイル読込エラーは`.bak`を試し、さらに内部ルールの同梱リソースをロードする。ただし`_app_db_parse`の検証失敗時の振る舞い、異常設定を保持したまま再適用する可能性については動作試験未実施。[profile.c](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/profile.c#L1619-L1705)。
4. **バックアップの限界：** 通常プロファイル書込後、時間条件で`.bak`へコピー。永続ルールの原子的コミットと**別個**なので、ファイル保存成功だけで遮断ポリシーの適用成功/復元成功が保証されるわけではない。[profile.c](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/profile.c#L1708-L1769)。
5. **緊急停止：** GUI/`-uninstall`は専用providerのフィルターとsublayer/providerを削除するが`-uninstall`は確認を必須化。管理者がGUIを開けない・リモート接続が遮断された場合に対する独立した復旧経路は、この調査では実証していない。[main.c](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/main.c#L3609-L3619) / [wfp.c](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L380-L475)。
6. **更新と競合：** 内部ルールは同梱版とローカルファイルのメタデータを比較。WFPルール再適用は既存の**自provider**のフィルターを削除し再構築するが、外部providerのルールが無効になるとは書かれていない。[profile.c](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/profile.c#L1531-L1583) / [wfp.c](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L477-L595)。

### 2.3 例外シナリオの監査・受け入れ観点（実測でない）

| シナリオ | 実コードから見える扱い | AegisGuardで確認すべきこと |
|---|---|---|
| 通常EXEのアウトバウンド | AppIDとALE_CONNECTでIP v4/6を分離して登録 | 同じ署名でもパスが更新されたときの識別、必要なら実行ファイルID/署名/パスの複合照合 |
| Store/Windowsアプリ | AppContainer package SIDを`ALE_PACKAGE_ID`で指定 | package更新、同一パッケージ複数プロセス、未取得SIDの「未確認」状態 |
| `svchost`/Windowsサービス | サービスセキュリティ記述子とユーザ条件を使用、内部ルールでDNS/DHCP/NCSIの例外 | サービス共有ホスト、NCSI、DNS、Windows Updateに関する最小権限・障害時通知 |
| IPv6/名前解決 | IPv6 ALE層、ICMPv6ルーター/近隣探索、LLMNR/mDNS/UDP DNSテンプレート | IPv6のDNS・RA/NS/NAとDNS over HTTPSを従来のport 53だけで扱わない |
| VPN/WSL/仮想NIC | WSLパス解決フォールバックあり。`IPFORWARD` boot-time ruleはNAT/ICSを妨げ得る | WireGuard/OpenVPN、VPN再接続、WSL2/Hyper-V/ICS/Hotspot、IPv4/6トンネル別に遮断漏れ・誤遮断 |
| 誤ったIOC/古いルール | simplewallはルール定義から個別適用。AegisGuardはC2リスト鮮度を独立管理 | TTL切れは遮断対象に昇格させない、リスト入替後の巻き戻し、誤検知例外の監査 |
| ログの欠落 | WFPイベントのフィルターID/レイヤーがないイベントは破棄。許可ログは初期で除外 | 「イベントがない=安全/許可」と言わない。パケット・フロー・プロセス発生の整合性を監視 |
| アプリクラッシュ/再起動 | 永続ルールは残存可能、temporaryは再起動まで | AegisGuard UI/サービス障害でも独立の安全復旧、起動時reconcile、残存ルール一覧 |

## 3. 具体的な取り込み候補と選択肢

| 候補機能 | 方法（採用判定） | AegisGuard接続先案 | 優先度 | 工数 S/M/L | ライセンス・技術上の阻害要因 |
|---|---|---|---|---|---|
| **遮断原因・判定根拠を残す構造化監査** | **Rustで独自実装**（将来公式WindowsイベントAPI直接利用） | `sensor/network` → `core/model` → `audit` | **P0** | **M** | WFPイベント収集の権限、欠落、イベント量、PID再利用、機微情報。simplewallコード転載不可 |
| **手動承認・期限付き例外と切れたら復元** | **独自実装**（UIアイデアのみ設計参考） | `policy/approval`、`policy/lease`、UI | **P0** | **M** | 昇格された書込担当、期限切れ後の再起動整合性、誤許可 |
| **自分のルールだけ列挙/更新/削除するjournalと復旧** | **Windows FirewallルールAPIを直接利用→必要時にWFP管理APIを検討**、UIと管理ロジックは独自 | `response/policy`、`response/recovery` | **P0** | **L** | まずAegisGuard計画のWindows Firewall namespaced rules、将来WFP providerの利用時も自分のGUID限定 |
| 監査イベントから1クリックで「この宛先だけ許可」 | **設計参考のみ→独自UI** | `ui/alerts`、`policy/approval` | P1 | M | 意図しない広域許可、IP共有ホスティング、IPv6や多ポート、権限確認 |
| Store/サービス/WSLの識別 | **Windows公式API直接利用** | `sensor/process_identity` | P1 | L | サービス共有プロセス/PackageSID/WSLの識別精度、更新に伴う同一性 |
| XMLプロファイル/バックアップ方式 | **設計参考のみ**。独自のバージョン付きJSON/DB＋チェックサム＋原子的差替を検討 | `policy/store` | P1 | M | ライセンス、再適用の整合性。バックアップそのものは安全な適用を保証しない |
| WFPフィルター・ログ機構 | **Windows SDK公式API直接利用**が候補。`windows` crate等のラッパー採用は別途検証 | `sensor/network` / 将来`response/wfp` | P2 | L | 高権限、WFPレイヤー/サブレイヤーの競合、Windows 11実機試験必須 |
| simplewallのCLIを同梱・自動操作 | **見送り** | なし | — | — | GPL-3.0、他製品ルールの管理、`-uninstall`要確認、恒久フィルターの残存 |
| simplewallのWFP実装をRustへ直訳・統合 | **見送り** | なし | — | — | GPL-3.0義務、プロセス/権限/同居製品の設計差、未試験 |

**採用候補の入出力と失敗処理：**
- 監査：入力＝WindowsのWFP/イベントログ/Sysmon等の観測イベント（process GUID/PID+開始時刻、AppID、package SID、宛先IP/port、protocol、action、filterId、providerKey、時刻、取得元）。出力＝スキーマ化した`NetworkDecision`と`Evidence`、イベント喪失カウンター。ソース不明/欠損は`unattributed`、イベント購読失敗は`sensor_unavailable`として扱い、決して「許可された」と誤訳しない。**最小PoC**はローカルで人工生成したイベントの整形と欠損テストから開始。
- 期限付き許可：入力＝利用者が明示承認した`PolicyRequest`（対象アプリID・宛先範囲・用途・expires_at・request_id・承認者）、出力＝`ProposedRule`/`AppliedRule`とリビジョン、監査履歴。承認失敗、ID不一致、タイムアウトはルールを作らず監査。タイマーだけに依存せず永続期限を起動時reconcile。**最小PoC**はアクションせず期限切れをシミュレーション。
- 所有権・巻き戻し：入力＝期待する`OwnedRuleSet`と現在のシステム状態、出力＝`Diff`/`DryRunPlan`/`ApplyResult`/`RollbackReport`。適用前にpreflight/チェックポイント、適用後再列挙、失敗時は自己所有物だけを戻す。Windows Firewallルール名の固定プレフィックス＋専用識別子を使い、他ソフト設定は触らない。**最小PoC**はDry-run差分計算のみ、実ルール適用は別承認の安全な隔離Windows VMで行う。
- 宛先単位例外：入力＝選択された遮断イベントIDと対象アプリの本人性、出力＝正規化された正確なIP/port/protocol/有効期間の承認画面。ホスト名への過大一般化や全ポート開放を既定にしない。失敗時は既存規則不変。**最小PoC**は録画ではなくダミーイベントを用いたUIテスト。
- 識別/永続化：入力＝プロセス・サービス・package・プロファイルDB、出力＝出典付きID・スキーマversion・完全性検査結果。識別不能/スキーマ不明時は`unknown`として手動確認・適用保留。**最小PoC**は構造化fixtureの移行・破損復旧試験。

**上位3件の実行順：**
1. **P0 / M：証拠付き監査ログ** — ブロッカー：監視経路選択、PII取扱いとイベント欠落可視化。
2. **P0 / M：期限付き・最小範囲の手動例外** — ブロッカー：承認認可/サービス境界/期限切れ復旧。
3. **P0 / L：所有ルールだけのドライラン・復旧ジャーナル** — ブロッカー：Windows 11 VMでの権限・競合・クラッシュ試験。これを通すまで**遮断機能は有効にしない**。

## 4. ライセンス・再配布・依存関係

| 対象 | 確認した内容 | AegisGuardへの判断 |
|---|---|---|
| simplewall C/C++本体 | [GPL v3原文](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/LICENSE)（2026-11-05確認）。`src/`にはHenry++著作権表示がある。 | **コピー/直訳/静的・動的リンク移植を行わない。** 設計アイデアとMicrosoft公開APIの独立実装を分離。AegisGuard本体は現状[ライセンス未設定](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md#L80-L82)であり、GPL混入は将来の配布条件を制約し得る。 |
| 外部`routine`ライブラリ | [.gitmodules](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/.gitmodules)に`../routine`と`../builder`の参照、[vcxproj](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/simplewall.vcxproj#L376-L395)に`routine`のCコードを直接コンパイルする記載。`henrypp/routine`の[LICENSE](https://github.com/henrypp/routine/blob/master/LICENSE)はGPL v3。 | サブモジュールが兄弟ディレクトリを前提とするため再現ビルド手順の確認必須。直接リンク/流用は行わない。 |
| ビルド・SDK | [packages.config](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/packages.config)に`Microsoft.Windows.CppWinRT 2.0.230706.1`、[vcxproj](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/simplewall.vcxproj#L31-L74)にWindows SDK 10.0、MSVC `v145`。 | Windows依存のC/C++/WinRT資産。AegisGuard Rustへ移植済みではない。CppWinRT/SDKなど各依存の再配布条件は個別未確認。 |
| 内部XMLとブロックリスト | [profile_internal.xml](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/bin/profile_internal.xml#L1-L50)にOSサービス例外と外部IPリストを含む。ルールビルド用[bat](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/build_simplewall_rules.bat)は外部builderを実行。 | ルール**アイデア**のみ参照。XMLやIP集合を無条件に複製・同梱しない。元の収集元/規約/更新署名の許諾は**法的評価未完了**。 |
| 署名/バイナリ | [README](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/README.md#L58-L64)はGPG署名`simplewall.exe.sig`を案内。 | バイナリ/署名の検証・再配布・自動ダウンロードの条件は未検証。AegisGuardに組み込まない。 |
| simplewall外部CLI起動 | CLIオプションは[main.c](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/main.c#L3564-L3620)で確認。 | **同梱・操作は見送り。** 別プロセス利用でもライセンス義務が一律に免除されると断定できない。配布/組み合わせ時の法的評価未完了。 |
| 設計参考とWindows API | 公開されたWFP APIそのものは[Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fwp/about-windows-filtering-platform)で規定。 | Windows公式APIを独立して利用することと、GPL実装のコードを転載することを区別。Rust `windows` crate等の具体版/ライセンス/保守状態は別途固定して確認する。 |

**法的評価：未完了。** 内部ルール、外部ブロックリスト、生成物、第三者著作権と配布形態を個別に精査する必要がある。ライセンス表示や既存実装のコメントを直接複製しない。最終判断は必要に応じ法務/権利者へ確認する。

## 5. Defender共存・Windows制約・権限境界

**同じWFP上の複数provider間で「自分が許可したら必ず通信できる」とはならない。** Microsoftの[Filter Arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration)はサブレイヤー優先順位・アクション権限・block vetoを規定する。simplewallの`FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`、独自サブレイヤー重み、永続ルールはDefender、Windows Firewall、VPN、他社セキュリティ製品の結果と競合し得る。[wfp.c 715–784](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L715-L784)。

**特に採用禁止：** simplewall自体はWFPを直接操作するが、`main.c`のインストール確認でWindows Firewall無効化の選択肢があり、`_wfp_firewallenable`はDomain/Private/Publicを切替える。READMEの「Windows Firewallを無効にする必要はない」という説明と両立するのは「選択肢として提供される」という事実である。AegisGuardは保護の低下を許すUIを追加せず、Defenderリアルタイム保護/ASR/AMSIやFirewallの既存設定を維持する。[main.c 79–127](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/main.c#L79-L127) / [wfp.c 2059–2085](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L2059-L2085)。

- **権限：** WFPは[オブジェクト単位のACL](https://learn.microsoft.com/en-us/windows/desktop/FWP/access-control)によるアクセス制御。simplewall READMEは管理者権限が必要と記述しつつ、manifestは[`asInvoker`](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/res/manifest.xml#L9-L18)。したがって一律「普通のユーザーでWFP書込可能」とは扱わない。AegisGuardは低権限GUI/監査クライアントと最小権限の昇格されたpolicyサービスを分離し、昇格・同意を明示する。
- **WFPエンジン全体のACL：** [`_app_setenginesecurity`](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/security.c#L151-L298)のような包括的変更は他のproviderへ影響し得る。AegisGuardは原則実行しない。自己所有ルールだけ編集し、他provider GUIDには触れない。
- **イベント系の重なり：** simplewallはWFP net-eventsとTCP/UDPテーブルを使用。AegisGuard計画のSysmon EventID 1/3/7・ETWはプロセス作成/接続/イメージロードの相関用であり、WFPの「policyによる遮断結果」と同一イベントではない。AMSIもスクリプト検査経路でWFPフィルターの代替ではない。[ARCHITECTURE](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L19-L35)。
- **システム例外：** DNS、DHCP、NCSI、IPv6 ICMPv6、サービス間通信、Windows Update等を無造作に遮断するとOS自身の通信・接続判定を壊す。内部XMLは参考例であってAegisGuard用の普遍的ホワイトリストとみなさない。[profile_internal.xml](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/bin/profile_internal.xml#L1-L44)。
- **仮想化・VPN：** NAT/ICS破損警告が[ソースに存在](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L1743-L1788)。WSLネットワークのパス識別も[フォールバック実装](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/network.c#L749-L756)があるだけで、全フローの帰属と完全遮断は未実証。
- **プライバシー：** ログにはユーザー名、アプリパス、接続元/宛先、ポート、フィルター名が含まれ得る。[log.c](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/log.c#L180-L230)。AegisGuardではACL、保存期間/上限、機微パスのマスキング、ローカル既定、エクスポート同意を指定する。

## 6. 性能・堅牢性・誤検知

**実測：なし。** simplewallのCPU%、常駐メモリ、通知遅延、WFPフィルター数、バッテリー影響の数値を持っていないため、評価値は提示しない。推定として、ログ対象の増大、IP v4/v6/方向別のフィルター展開、アプリ別の許可、WFPイベントごとの`FwpmFilterGetById0`/`FwpmLayerGetById0`はイベント量とAPI呼び出しに依存して負荷が変わる。[log.c 466–555](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/log.c#L466-L555) / [wfp.c 918–1205](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L918-L1205)。

**実装に見える保護：** profile decodeではバッファサイズ制限と復号回数上限（[db.c 728–760](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/db.c#L728-L760））。ログは`LogSizeLimitKb`に達すると**既存ファイルをクリア**するため、永続的な監査保全ではない。[log.c 126–160](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/log.c#L126-L160)。イベント購読はOS互換版へフォールバックするが、加入失敗時は警告/機能無効であり、欠落の補償は別途必要。[log.c 295–396](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/log.c#L295-L396)。

**AegisGuardの性能検証手順（数値は測定後に報告）：**
1. 通常アイドル、ブラウザ更新、Windows Update、VPN接続/再接続、WSL2、DNS大量照会の6条件を同じWindows 11 VM/実機で反復。Defenderは常時有効、比較する`off → audit-only`時点は遮断なし。
2. CPU平均/最大/プロセス別、private bytes/working set、ハンドル、イベント受信/破棄件数とキュー長、ディスク書込/ログ増分、ネットワークRTT/失敗数、バッテリー消費・再起動後状態を測る。処理前後差と分布を保存。
3. ダミーイベント高負荷、遅い書き込み、満杯ディスク、購読切断、権限拒否、ルール数上限、時間逆行、重複ログ、設定破損、IPv6、PID再利用で失敗扱いとバックプレッシャー/安全復旧を検証。
4. 誤検知例：正規ソフトが同一IPをCDNと共有、DNS IP変更、管理アプリのスクリプト通信、Windows Update。誤検知時の救済通知、監査理由、許可期限を記録。検査漏れ例：ログ収集不可、WSL帰属不能、未知パッケージSID、暗号化トラフィック（宛先しか見えない）を区別。

**安全条件：** リングバッファ/キュー上限、レート制限、ログファイル保全の上限とローテーション、ローカル専用データ、WFP provider自己所有確認、ポリシー入力バリデーション、監査利用者と書込者の分離。削除/遮断が必要な処理は未検証状態では走らせない。

## 7. 推奨する小さなPoCと成功基準

**PoC-0：遮断ゼロの設計・監査PoC（まず実施）**
- **前提：** Windows 11 x64の復元可能なVM、ネットワーク復旧用ローカルコンソール、管理者と標準ユーザーのアカウント、Defender/Windows Firewallが有効なスナップショット。AegisGuard既存`main`は変更しない本レポート段階。
- **安全なサンプル/検証：** 無害なローカルTCPクライアント/テストサーバーと人工的なWFP/Sysmon相当JSONイベント。`audit-only`で既知の通信と「未取得」を可視化する。実際のファイアウォール規則を初期PoCで追加せず、疑似`RulePlan`を生成。
- **成功条件：** サンプルイベントが出典・時刻・proc identity・対象宛先・filterId・action・欠落状態とともに再現可能に記録されること。センサー停止は「監視不可」、拒否は「拒否」、判定不明は「不明」に区分。CPU/メモリ/キュー/ログ量をベースラインとともに記録し、過度のログ増大時もUIと既存防御が正常に働く。
- **失敗時・ロールバック：** イベント購読停止、UI非表示、テスト用ローカルデータ削除のみで元の保護状態に戻せる。Windows Firewall/Defenderの設定変更は一切ないことを変更前後で照合する。
- **中止条件：** 意図しない既存セキュリティ設定変更、ログの無制限増加、無断外部送信、クラッシュ、イベント欠落を「許可」と報告する挙動。

**PoC-1：隔離VMでのみ行う将来の「選択式遮断」（別途実装計画/承認後）**
- 初期値off、監査→ドライランの差分提示→利用者承認→**1アプリ・1宛先・短い期限**だけに限定したアウトバウンド規則を追加。AegisGuard専用プレフィックス/IDの所有物だけ変更する。
- 発動前に復元可能なチェックポイント、サービス異常/ログ破損/BFE再起動/Windows再起動/VPN変更時のreconcileと復旧を設計。少なくとも通常通信、DNS、IPv6、Windows Update、VPN、WSL2、ネットワーク切替、ポリシー競合、誤遮断の各ケースを確認。
- **受け入れ基準：** 適用前後のWindows Firewall/Defenderの既存設定が変わらない。未承認宛先への拡張はゼロ。所有ルール以外の作成/更新/削除はゼロ。期限満了・管理者手動解除・強制終了・再起動後に対象ルールを再列挙でき、失敗時は復旧の手順と結果を記録する。DNS/OS基本通信を意図せず遮断しない。合否の測定値は実測後に記録し、現在は合格と判定しない。
- 緊急復旧は**UIと独立**の管理者手段を用意し、通常のアプリ終了のみでは巻き戻ると仮定しない。復旧できなければ試験中止、VMスナップショットへ復元。外部本番端末・データを使わない。

## 8. 採用しない設計と理由

1. **全面的な「全アプリを遮断して一つずつ許可」：見送り。** simplewallの既定`BlockOutboundConnections/BlockInboundConnections`はtrueであり[コード確認](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L1789-L1836)。AegisGuardは現状、Windows 11一般利用者向けの検出・監査ツールで、必要通信の網羅的な例外・復旧UIが未完成。OS更新、名前解決、VPN、Windowsサービスを誤遮断する危険が高い。
2. **Windows FirewallをオフにしてWFPルールを主防御にする：不採用。** [simplewallのチェック付きUI](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/main.c#L79-L127)と[切替コード](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L2059-L2085)は存在するが、Defender/Firewallを弱めないという[AegisGuardの方針](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md#L1-L22)に反する。
3. **simplewallを内蔵し`-install -silent`や`-uninstall`で管理：不採用。** GPL-3.0と使用許諾の問題、他アプリ所有の状態との分離、起動終了とルール寿命のずれ、`-uninstall`の確認ダイアログ必須により、自動緊急復旧APIとして信用できない。[CLI](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/main.c#L3564-L3620)。
4. **boot-timeとIP forwarding遮断を初期有効：不採用。** NAT・ホットスポット・WSL/Hyper-Vの悪影響がソース上でも指摘されている。[wfp.c](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L1743-L1788)。
5. **WFP全体のACLを変更：不採用。** 他社セキュリティ製品/Windowsネットワーク機能との潜在的な競合を増やす。[security.c](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/security.c#L151-L298)。

## 9. 他担当との境界・引継ぎ

- **simplewallのWFPフィルター生成/重みの詳細**を調べる担当へ：本担当は運用・寿命・復旧とUIを主に扱う。`FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`、subLayerの重み、許可/拒否の優先順位は[Filter Arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration)と併せてWindows 11で実験してから決定すること。
- **Portmaster/DNS担当へ：** OS標準DNS（UDP/53）以外のDoH/DoT、proxy、アプリ単位の名前解決例外、SNI/域名帰属はここでは深追いしていない。simplewall内部DNSルールをドメイン監視の証明とみなさない。
- **Sysmon/ETW・Defender担当へ：** WFPの許可/拒否イベント、Sysmon EID3の通信イベント、ETW、AMSIの収集重複/欠落/コスト/プロセスID相関は専任調査へ。AegisGuard側の[予定設計](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L19-L27)に合わせる。
- **IOCフィード担当へ：** 誤検知・期限切れのIPを自動遮断しない。AegisGuard既存[`src/c2.rs`](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L76-L90)のフィード別TTLを遮断前チェックにも引き継ぐ必要がある。
- **ライセンス管理担当へ：** GPL本体、`routine`/`builder`、内部ルールの外部データ源、GPG署名、Windows SDK/CppWinRTを個別確認。**法的評価未完了**とする。

## 10. 未確認事項・追加調査項目

| 重要度 | 未確認点 / 調査アクション |
|---|---|
| **高** | Windows 11で永続/temporaryの実際の終了・クラッシュ・再起動・BFE再起動後の残存状態。`FWPM_SESSION_FLAG_DYNAMIC`不使用と「再起動で消える」は静的コードと公式仕様の読み合わせにとどまる。 |
| **高** | Windows Firewallのインストール確認のチェックボックス初期状態/ユーザーの実際の操作による既存保護の変化。コードの初期`WF_State`がtrueでも実UI挙動は未実施。 |
| **高** | システム復旧（GUI不能、管理者権限喪失、BFEエラー、プロファイル破損、遠隔端末）が本当に可能か、rollback失敗時に残存ルールをどう安全に撤去するか。 |
| **高** | Defender Firewall/Defender、VPNクライアント、Windows Update、DNS、WSL2/Hyper-V、ICS/モバイルホットスポット、IPv6とのWFP競合と誤遮断の実測。 |
| **高** | 内部ブロックリストデータの著作権・再配布許諾、`builder`と第三者依存、GPG署名の検証フロー。**法的評価未完了**。 |
| 中 | 公式`master`の`VERSION`=3.9.1と`build.bat`=3.9.2の差分の理由、同一成果物への対応関係。 |
| 中 | `.bak`の破損時復元、XML parse失敗時の状態、圧縮爆弾耐性、fixed `PROFILE2_KEY_DEPRECATED`の暗号化モードの脅威モデルと第三者改ざん対策。 |
| 中 | WFP net-eventの欠落率、許可イベントのOS版差、ログ保存の最大値・クリアタイミング、フィルターIDの再利用、バッファ負荷、実機CPU/RAM/電池負荷。 |
| 中 | テストの存在範囲：レポジトリツリー内で`tests/`やテストCIを確認できなかったが、外部/private CI・リリース時のテスト有無は不明。ビルド再現性の検証も未実施。 |
| 低 | Storeパッケージ更新/サービスの再起動に伴う識別の変化、WSLパスの多様性、GUI言語・バックアップ復元のユーザビリティ。 |

## 11. 一次情報一覧

いずれも**2026-11-05参照**。GitHubソースは`24bbd2ceb7daee9ef308e0b406be5eb039cb30a1`、AegisGuardは`83fcf0d150e8d760baff5f971c106deb09c1f8e4`で固定。

1. [`src/wfp.c` L8–65: `_wfp_getenginehandle`、セッション初期化](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L8-L65) — 動的セッション不使用・BFE再試行。
2. [`src/wfp.c` L207–311: `_wfp_initialize`](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L207-L311) — provider/sublayer寿命、永続属性。
3. [`src/wfp.c` L477–595, L715–810: `_wfp_installfilters`/`_wfp_createfilter`](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L477-L595) / [filter add](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L715-L810) — 所有者限定再構成とWFPフィルター作成。
4. [`src/wfp.c` L1933–2004: `_wfp_dumpfilters`](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L1933-L2004) — provider一致による列挙。
5. [`src/wfp.c` L1743–1836: boot-time/forwarding/既定拒否](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L1743-L1836) — NATと基盤通信への影響。
6. [`src/main.c` L43–135および`src/wfp.c` L2059–2085](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/main.c#L43-L135) / [firewall切替](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L2059-L2085) — Firewall無効化UIとCOM API。
7. [`src/main.c` L3564–3620: CLI install/uninstall](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/main.c#L3564-L3620) — 復旧時の確認要件。
8. [`src/profile.c` L1619–1769: 読込・バックアップ・保存](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/profile.c#L1619-L1769) / [`src/db.c` L288–458: XML规则](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/db.c#L288-L458) — ポリシー永続化。
9. [`src/log.c` L295–465・L466–678: WFP event subscriptions/callback](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/log.c#L295-L465) / [callback](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/log.c#L466-L678) — 監査項目とイベント欠落の意味。
10. [`src/notifications.c` L56–118・L1195–1223、`src/timer.c` L38–106](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/notifications.c#L56-L118) / [dest rules](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/notifications.c#L1195-L1223) / [timers](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/timer.c#L38-L106) — UI承認と期間限定許可。
11. [`src/network.c` L686–774、`src/packages.c` L389–457、`src/uwp.cpp` L16–79](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/network.c#L686-L774) / [services/UWP](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/packages.c#L389-L457) / [WinRT](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/uwp.cpp#L16-L79) — 通信帰属とAppContainer/WSL。
12. [`bin/profile_internal.xml` L1–44](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/bin/profile_internal.xml#L1-L44) — OSサービス・DNS・IPv6等の内部ルール。
13. [`LICENSE`](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/LICENSE)、[`.gitmodules`](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/.gitmodules)、[`packages.config`](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/packages.config)、[`simplewall.vcxproj`](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/simplewall.vcxproj)、[`scorecard.yml`](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/.github/workflows/scorecard.yml) — ライセンス、依存、CI。
14. [AegisGuard `README.md`](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md#L1-L18)、[`SECURITY.md`](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md#L1-L22)、[`ARCHITECTURE.md`](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L28-L44) — 実装済み機能と非干渉・将来設計。
15. Microsoft Learn: [Object Management](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)、[FwpmEngineOpen0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0)、[Filter Arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration)、[Access Control](https://learn.microsoft.com/en-us/windows/desktop/FWP/access-control)、[About WFP](https://learn.microsoft.com/en-us/windows/win32/fwp/about-windows-filtering-platform) — セッション寿命、重み、権限、他providerとの共存。

**注：** 上記はコード・設定ファイルの静的観察であり、単一コミットについての調査。未実行の動作・性能・復旧の成功を保証するものではない。
