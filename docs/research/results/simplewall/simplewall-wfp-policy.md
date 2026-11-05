# 調査報告：simplewall / simplewall-wfp-policy

> 担当：simplewall-wfp-policy / 調査日：2026-11-05 / 調査結果：静的ソース調査完了・Windows実機検証未実施

## 0. 結論（3〜5行）

- **取り入れる価値：高い（設計・API選択のみ）**。simplewallはWFP管理APIを利用した、provider/sublayer所有・ALE条件・トランザクション・ログ購読の具体例であり、AegisGuardの将来のC2通信遮断の判断材料となる。
- **最優先候補：監査可能なIOC→期限付きアウトバウンドポリシー変換と、所有ルールだけの安全なrollback**。本番導入前にWindows Firewall API経由の最小実装と、直接WFPを使う実験的バックエンドを比較する。
- **見送り：simplewallのコード直接移植、全通信を既定で遮断する動作、Windows Firewall/Defender無効化、boot-time/calloutフィルタ**。
- **最大の制約：WFPは他製品と共通の判定基盤**。サブレイヤ内外の優先順位、管理者権限、BFE停止、永続オブジェクト残留、Microsoft Defenderとの共存をWindows 11実機で検証していない。
- GPL-3.0のsimplewallをコピーせず、Microsoft公開仕様を根拠としたRust独自実装を推奨する（互換性の法的最終評価は未完了）。

## 1. 対象の固定と調査方法

| 要素 | 値 / 根拠 |
|---|---|
| 公式リポジトリ・固定URL | [henrypp/simplewall](https://github.com/henrypp/simplewall/tree/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1)、既定ブランチ master |
| 調査コミットSHA・タグ | 24bbd2ceb7daee9ef308e0b406be5eb039cb30a1（master、コミット日時2026-11-03 UTC）。確認できた公開リリースは [v.3.8.7](https://github.com/henrypp/simplewall/releases/tag/v.3.8.7)（2025-08-08公開）。**masterをリリース版と同一視しない** |
| AegisGuard比較先SHA | 83fcf0d150e8d760baff5f971c106deb09c1f8e4（2026-11-05取得時点のmain、[AegisGuard README.md:1-22](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md#L1-L22)） |
| ライセンス | [simplewall LICENSE:1-20](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/LICENSE#L1-L20) はGPL version 3。[simplewall src/wfp.c:1-5](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L1-L5) の著作権表記も確認。依存する[henrypp/routine/LICENSE](https://github.com/henrypp/routine/blob/master/LICENSE)にもGPLv3全文 |
| 調査範囲 | simplewallのwfp.c/h、security.c、db.c、main.c、log.c、timer.c、global.h、manifest、Visual Studioプロジェクト、packages.config、.gitmodules、内蔵XML規則、LICENSE、README、.github/workflows/scorecard.yml。AegisGuardのREADME/SECURITY/ARCHITECTURE/Cargo.toml/src/main.rs/src/c2.rsおよびmainのsrc一覧 |
| 実機・ビルド・テスト | **未実施**。Windows 11の隔離VM・管理者権限環境は本調査に提供されておらず、他人のWFPやDefender設定を変更しない。静的コード・依存関係・テスト配置を確認 |
| 日付・限界 | 2026-11-05。WFPドライバ、実行挙動、OSビルド別相性、AV併用時のフィルタ優先関係、実測性能は未確認。静的ソース確認は通過テストを意味しない |

比較先AegisGuardは、[AegisGuard src/main.rs:1-78](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/main.rs#L1-L78) がscanとc2 update/check/statusのみを公開し、[AegisGuard src/c2.rs:15-25](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L15-L25) がフィード上限と48時間TTLを管理する。[AegisGuard docs/ARCHITECTURE.md:22-44](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L22-L44) と[AegisGuard SECURITY.md:1-21](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md#L1-L21) は遮断・サービス・WFP/ETW等を**未実装**と明記する。既存の検出・照合と、将来の強制遮断を混同しない。

## 2. 実装アーキテクチャとソース調査

| 機能 | 主要シンボル / 動作 | commit固定の一次情報 | 確認状態 |
|---|---|---|---|
| エンジン接続・BFE失敗 | _wfp_getenginehandle：FwpmEngineOpen0でユーザーモード管理セッションを開始。EPT_S_NOT_REGISTERED時は短い再試行、最終失敗はプロセス終了 | [simplewall src/wfp.c:8-65](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L8-L65) | 実装確認 |
| 所有権とサブレイヤ | GUID_WfpProvider/GUID_WfpSublayerで個別識別しFwpmProviderAdd0・FwpmSubLayerAdd0。設定可能なsublayer weightの既定値は0xFFFF | [simplewall src/wfp.h:6-29](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.h#L6-L29)、[simplewall src/wfp.c:207-300](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L207-L300) | 実装確認 |
| フィルタ作成・優先度 | _wfp_createfilter：個別GUID、providerKey、subLayerKey、FWP_UINT8 weight、action、条件群をFWPM_FILTER0に設定しFwpmFilterAdd0。block等にCLEAR_ACTION_RIGHT、永続型にPERSISTENT | [simplewall src/wfp.c:715-809](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L715-L809) | 実装確認 |
| IP/ポート/プロトコル | _wfp_createrulefilter：リモート/ローカルアドレス、IPv4/IPv6マスク・範囲、IP_REMOTE_PORT/IP_LOCAL_PORT、IP_PROTOCOL条件をFWPM_FILTER_CONDITION0へ変換 | [simplewall src/wfp.c:1035-1187](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L1035-L1187) | 実装確認 |
| アプリ別識別 | 通常のEXE等はFWPM_CONDITION_ALE_APP_ID。サービスにはALE_USER_ID（セキュリティ記述子）、UWPはALE_PACKAGE_ID（SID）。アプリパス変換は独自_FwpmGetAppIdFromFileName1 | [simplewall src/wfp.c:918-1037](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L918-L1037)、[simplewall src/wfp.c:2093-2203](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L2093-L2203) | 実装確認 |
| レイヤ配置 | outboundはALE_AUTH_CONNECT_V4/V6、inboundはALE_AUTH_RECV_ACCEPT_V4/V6。通常のアプリ許可はFWW_APP（0x09）、ルールblocklistは0x0D、ユーザーblockは0x0C | [simplewall src/wfp.c:1182-1213](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L1182-L1213)、[simplewall src/db.c:345-357](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/db.c#L345-L357)、[simplewall src/wfp.h:18-29](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.h#L18-L29) | 実装確認 |
| プロファイル→適用 | XMLのdir/is_block/protocol/version/remote/local/appsをパースし、アプリ/サービス別の許可・遮断フィルタへ変換 | [simplewall src/db.c:288-366](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/db.c#L288-L366)、[simplewall src/wfp.c:1217-1400](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L1217-L1400) | 実装確認 |
| 更新・削除 | _wfp_installfiltersで自身のprovider所属フィルタを列挙し、トランザクションで削除→再構築。_wfp_destroyfilters_array はfilterKeyによる削除を使用 | [simplewall src/wfp.c:477-595](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L477-L595)、[simplewall src/wfp.c:851-917](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L851-L917)、[simplewall src/wfp.c:1932-2004](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L1932-L2004) | 実装確認 |
| 期限とセッションの区別 | インストール時のtemporaryは単にPERSISTENTを付けない方式。アプリのタイマーはThreadpoolTimerと期限時filter削除。**FWPM_SESSION_FLAG_DYNAMICはこのエンジン開始ではセットされない** | [simplewall src/wfp.c:8-35](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L8-L35)、[simplewall src/wfp.c:759-770](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L759-L770)、[simplewall src/timer.c:28-112](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/timer.c#L28-L112) | 実装確認 |
| 例外規則・boot-time | 既定のoutbound/inbound一括遮断、loopback/特定アドレス許可、特殊callout参照、FWPM_FILTER_FLAG_BOOTTIMEを含む | [simplewall src/wfp.c:1590-1660](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L1590-L1660)、[simplewall src/wfp.c:1743-1878](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L1743-L1878)、[simplewall src/wfp.c:1880-1919](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L1880-L1919) | 実装確認・採用非推奨 |
| セキュリティ記述子 | engine/provider/sublayer/filterのACLと所有者を調整し、フィルタ更新時は保護解除→再設定を実施 | [simplewall src/security.c:151-232](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/security.c#L151-L232)、[simplewall src/security.c:301-460](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/security.c#L301-L460)、[simplewall src/wfp.c:477-506](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L477-L506) | 実装確認・転用非推奨 |
| ログ | WFPネットイベント収集をEngineSetOptionで有効化し、FwpmNetEventSubscribe0〜4を動的選択。provider別の表示判別がある | [simplewall src/wfp.c:319-353](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L319-L353)、[simplewall src/log.c:295-417](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/log.c#L295-L417)、[simplewall src/log.c:470-548](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/log.c#L470-L548) | 実装確認 |
| Windows Firewallとの関係 | WFPのフィルタ機構はWindows FirewallルールAPIとは異なるが、インストールダイアログでWindows Firewall有効/無効を選び、INetFwPolicy2_put_FirewallEnabledを呼び出す経路が**実在** | [simplewall src/main.c:43-130](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/main.c#L43-L130)、[simplewall src/wfp.c:2037-2085](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L2037-L2085) | 実装確認・README説明の注意点 |
| ビルド依存・テスト | MSVC/Windows SDK、外部../routineのCソース、CppWinRT NuGet。ツリー内で独立したunit/integration testプログラムは特定できず、確認できたワークフローはScorecard中心 | [simplewall simplewall.vcxproj:379-429](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/simplewall.vcxproj#L379-L429)、[simplewall packages.config:1-4](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/packages.config#L1-L4)、[simplewall .gitmodules:1-7](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/.gitmodules#L1-L7)、[simplewall .github/workflows/scorecard.yml:1-55](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/.github/workflows/scorecard.yml#L1-L55) | 構成確認、試験網羅性は未確認 |

**WFPとWindows Firewallは同一ではないが、相互に独立した判定基盤でもない。** Microsoftの[WFP概要](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)は、Windows Firewall with Advanced Security（WFAS）自体がWFPを利用し、WFP APIとWFAS APIのポリシーが共通のarbitrationに参加すると明示する。simplewall READMEの「Windows Firewall UIではない」という主張は正しい一方、「全くinteractionしない」は上記の明示的なFirewallEnabled操作まで含めると厳密ではない。AegisGuardはWindows Firewallを無効化しない。

**優先順位は単一の整数値では決まらない。** simplewallはサブレイヤに0xFFFF、フィルタに0x08〜0x0Fを設定する。しかしMicrosoftの[Filter Arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration)によれば、レイヤ→サブレイヤの重み→同一サブレイヤ内のフィルタ重みに加え、block/permitとaction right、calloutによるvetoの規則がある。したがって0xFFFFならDefenderや他社製品より必ず優先される、特定のpermitで全てのblockを覆せる、などとは断定できない。

**静的レビューでの重大な失敗経路：** _wfp_createrulefilterは複数の_wfp_createfilter呼び出しの戻り値を検査せず、最後にis_success=TRUEを返す箇所がある（[simplewall src/wfp.c:1182-1217](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L1182-L1217)）。下位FwpmFilterAdd0のエラーはログに残るが、呼び出し元のis_haveerrorsへ伝播しない可能性がある。_wfp_installfilters側でも再構築中の個々の追加エラーを集約せずコミットしている（[simplewall src/wfp.c:531-584](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L531-L584)）。さらに一部の個別変更処理ではトランザクション開始の否定値をフラグへ代入する経路があり（[simplewall src/wfp.c:1235-1275](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L1235-L1275)）、開始エラーと「他の処理で開始済み」を分離しないと意図しない非原子的変更を招きうる。**実害発生は未実測**だがAegisGuardは「全API成功→commit／一つでも失敗→abort」を必須にする。

## 3. 具体的な取り込み候補と選択肢

| 候補機能 | 利用方法 | AegisGuard接続先（提案） | 優先度 | 工数 S/M/L | 阻害要因・前提 |
|---|---|---|---|---|---|
| ① IOC→安全なポリシー・dry-run・有効期限 | **独自実装**（Rust、既存c2出力を入力） | 将来のaegis-core/policy、c2とresponseの間 | P0 | M | フィード鮮度、public-IP検証、ユーザー許可リスト、監査、期限 |
| ② Windows Firewall APIでのアウトバウンド限定遮断 | **RustからWindows API直接利用**（INetFwPolicy2/INetFwRule等。単独ルール所有） | response/windows-firewall（新規案） | P1 | M | 管理者/組織ポリシー、ルール競合、反映状態照会、rollback |
| ③ WFPユーザーモードの独立providerと限定フィルタ | **RustからMicrosoft WFP API直接利用**（windows/windows-sysバインディング採否は実装時検証） | response/wfp（実験的な別バックエンド案） | P1・VMのみ | L | BFE、FWPM ACL、トランザクション、WFP arbitration、誤遮断 |
| ④ 既存フィルタの列挙と自分のルールの照合・cleanup | **独自実装**（WFP/FWASそれぞれの公開API） | response/reconcile、audit | P1 | M | GUID/名前空間保護、他製品削除禁止、異常終了時の残留 |
| ⑤ WFPネットイベントの観測 | **設計参考のみ→必要ならWindows API** | 将来のsensor/network | P2 | L | グローバル収集設定・ログ権限・PII・負荷。まずSysmon/ETWとの重複を比較 |
| ⑥ simplewall.exeを外部CLIとして実行 | **見送り** | なし | 不採用 | — | GPL同梱/利用条件、全体的なフィルタ所有、デフォルトdeny、CLIが限定的、設定競合 |
| ⑦ simplewallのWFP管理・ルールパーサをコピー | **見送り** | なし | 不採用 | — | GPL-3.0、既存のC/ネイティブ依存、独自失敗処理の継承 |
| ⑧ ブート時フィルタ・既存callout/自作callout | **見送り（当面）** | なし | 不採用 | — | 起動/通信破壊リスク、ドライバー署名・運用の追加コスト |

**① ポリシー変換：** 入力は（フィード名・IPv4/IPv6・取得時刻・失効時刻・根拠・承認状態）を持つ型。出力は「適用候補一覧・除外理由・適用期限・差分・rollback対象ID」を含むJSON/監査ログ。C2Intelは既存設計どおり調査目的だけ、Feodoもユーザー承認済みかつfreshなIPのみ候補とする。public-IP、上限、署名/ソース来歴、時刻逆行、重複、空更新、誤フィードを検証し、問題があれば遮断を行わない。[AegisGuard src/c2.rs:76-151](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L76-L151) と [AegisGuard src/c2.rs:198-258](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L198-L258) の鮮度検証を活用しつつ、永続化した「ブロックした事実」を単なるキャッシュとは分離する。

**② Windows Firewallバックエンド：** 管理者が承認したrule planを入力に、明示的に名前空間化したAegisGuard専用のoutbound blockルールだけを作成/照合/削除し、反映結果とルール識別子を返す。他者ルールやDefender設定は更新しない。実際に有効かを照会できない場合は成功扱いしない。障害時は追加前のスナップショットに基づき自己所有ルールだけを戻す。サービス停止後のcleanupと期限切れ検知は別の回復処理で保証する。Microsoft [INetFwPolicy2](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwpolicy2) を参照。

**③ WFPバックエンド：** 将来の最小API呼び出し系列はFwpmEngineOpen0→専用Provider/SubLayer作成→FwpmTransactionBegin0→ALE_AUTH_CONNECT_V4/V6に必要なREMOTE_ADDRESS等のBLOCKフィルタだけを追加→戻り値検証→Commit→FilterGet/Enumで照合。アプリ限定ならOS提供のFwpmGetAppIdFromFileName0でAPP_IDを取得する（独自パス正規化をコピーしない）。テスト時はFWPM_SESSION_FLAG_DYNAMICでプロセス停止時に自動消去、恒久運用へ切り替える前には期限・起動回復・所有物の列挙削除の設計を完成させる。失敗はAbortして結果をエラーとして返し、部分成功を禁止する。[Microsoft: App ID](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0)、[Object management](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)。

**④ reconciliation：** 起動時に「期待する承認済み有効期限内のルール」と「専用provider/ルール名前空間で実在するオブジェクト」を突き合わせ、不明なルールは勝手に削除せず高優先度警告。期限切れ・失効・取り消しの場合は自分のルールのみ撤去。BFE再起動・RPC切断時はunknownと表示し、無限リトライや他社製品の列挙総削除はしない。

**⑤ イベント購読：** 監視入力（WFPネットイベント）、出力（正規化された時刻・アプリ/通信先・フィルタID・判定・データ取得状態）を設計し、Sysmon EventID 1/3/7のProcessGuid相関やETWと比較。ログにはアプリパス・IP・ユーザー情報が含まれうるためACL・保持期間・上限・バックプレッシャーが先決。WFPログをAMSIやカーネルメモリ検査と同一視しない。

## 4. ライセンス・再配布・依存関係

| 対象 | 確認と扱い |
|---|---|
| simplewall本体のCソース | GPL-3.0原文を確認（[simplewall LICENSE:1-20](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/LICENSE#L1-L20)）。wfp.c、db.c、security.c等のコードや固有定数/実装をAegisGuardへコピー・リンクしない。GPLに従った再利用案は可能でもAegisGuard全体の配布条件との整合を専門家判断する必要がある |
| routine（ビルド必須の兄弟リポジトリ） | [simplewall .gitmodules:1-7](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/.gitmodules#L1-L7) と [simplewall simplewall.vcxproj:379-406](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/simplewall.vcxproj#L379-L406) から依存を確認。外部の[LICENSE](https://github.com/henrypp/routine/blob/master/LICENSE) はGPLv3。ビルド依存でありAegisGuardへの統合対象外 |
| Windows SDK・Fwpuclnt.dll・FWP公開定義 | Microsoft提供のOS/SDK APIとして利用（[simplewall src/global.h:1-29](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/global.h#L1-L29)）。simplewall固有コードをコピーせずMicrosoft Learnを設計根拠にする。SDK配布/リンク条件は必要に応じて確認 |
| Microsoft.Windows.CppWinRT（NuGet） | [simplewall packages.config:1-4](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/packages.config#L1-L4) に2.0.230706.1を確認。パッケージの個別配布ライセンスは**本調査で未確認**。AegisGuardのRust PoCでは不要なら依存させない |
| 内蔵ルールXMLと外部ブロックリスト | [simplewall bin/profile_internal.xml:1-39](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/bin/profile_internal.xml#L1-L39) にOSサービス規則・後続のblocklistがある。READMEが外部WindowsSpyBlocker規則を紹介するが、**収録各IPの原作・更新権限・データライセンス・提供元の署名・鮮度は一括確認できていない**。転用/再配布しない |
| アプリ配布バイナリ・署名 | READMEはGPG署名と公開鍵を案内するが、実際の署名検証・署名対象バイナリの来歴・Windowsコード署名の確認は未実施。独自AegisGuardの証明にはならない |
| AegisGuard本体 | [AegisGuard README.md:80-110](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md#L80-L110) のライセンス欄は「未設定」。将来の配布・サードパーティ組み込みの最終法的評価は未完了 |

外部CLI起動を選ぶ場合でも「プロセスを分ければGPLの法的問題が必ず解消する」は誤り。同梱・通信の結合度・配布態様を個別評価する。ルール/署名/データの権利をソースコードのGPL表示から推定しない。

## 5. Defender共存・Windows制約・権限境界

- **原理：** WFPはネットワークの共通基盤で、Windows FirewallもWFP上に構築される。[Microsoft WFP概要](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)。標準Firewall APIは通常のユーザーフレンドリーなルール管理向け、直接WFPは任意のprovider/sublayer/レイヤや低水準フィルタ管理が可能な分、所有・優先順位・復旧に責任が生じる。
- **管理権限：** エンジンを開く権限とフィルタを追加/削除する権限は異なる。[Access control](https://learn.microsoft.com/en-us/windows/win32/fwp/access-control) のFWPM_ACTRL_OPEN/ADD/ADD_LINK/DELETE等と各ACLで決まる。simplewall READMEは管理者を要求し、ソースはACLも変更する。AegisGuardは非特権UI/スキャナと、ユーザーが明示的に承認した特権バックエンドを分離する。一般ユーザーが無条件にWFPへ追加できるとは扱わない。
- **BFE障害：** FwpmEngineOpen0がRPC/EPT_S_NOT_REGISTERED等で失敗する可能性（[simplewall src/wfp.c:8-65](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L8-L65)）。BFEを故意に停止する実験はせず、接続失敗と再接続状態を「適用状態不明」として記録。永続ルールは自動消失しない場合がある。停止時のWFP分類の全挙動はWindows 11の保護機能やネットワーク構成によって異なり、**未実測**。
- **一時・永続・boot-time：** [Microsoft Object Management](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management) によればdynamic=session終了で削除、static=BFE停止/OS停止まで、persistent=明示削除まで、boot-time=BFE初期化時に切り替わる。simplewallの「temporary」はstatic（非persistent）であり、UIプロセス終了による自動rollbackと同義ではない。AegisGuard PoCはdynamic、正式な永続遮断は厳格な期限付きreconcileを条件とする。
- **calloutの境界：** 一般的なIP/ポート/APP_IDのBLOCK/PERMITはユーザーモード管理APIと既存のWindowsフィルタエンジンで足り、AegisGuard専用カーネルドライバーは不要。[Microsoft Callout considerations](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/callout-driver-programming-considerations)。simplewallが既存システムcallout GUIDを参照する箇所（[simplewall src/wfp.c:1849-1908](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L1849-L1908)）は自作ドライバーの存在を示さない。独自のパケット内容変更/ストリーム再注入等にはcalloutドライバー・署名・別途設計が必要。
- **Defender/他社製品：** Microsoft Defenderを無効化せず、Windows Firewallプロファイル・ASR・AMSI・Sysmon・ETW設定も変更しない。WFPのBLOCK/PERMIT調停は製品ごと・サブレイヤごとで決まるためVPN/EDR/Windows Firewallとの相互運用性は未検証。従来のTCP/UDP以外、DNSの別経路、IPv6、QUIC、IPsec、WSL/NATは期待どおり遮断できない可能性を個別検証する。
- **最小権限/プライバシー：** フィード更新は低権限プロセスで行い、特権側は署名/出所と厳格なスキーマを再検証する。WFPログとルール名には通信先、実行パス等の個人情報が含まれ得る。外部自動送信せずACL付きのローカル監査だけに限定する。

## 6. 性能・堅牢性・誤検知

**実測はゼロ。CPU/メモリ負荷、導入所要時間、ネットワーク遅延、誤検知率に数値の根拠はない。** simplewallのFWPM_FILTER_FLAG_INDEXED利用（[simplewall src/wfp.c:759-770](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L759-L770)）は性能最適化の意図を示すのみで、AegisGuardにおける計測結果ではない。

- 大量ルール：単一IPごとのfilter増加はWFP管理時間、BFEメモリ、再起動/reconcile時間を増やし得る。AegisGuardの1フィード最大50,000件（[AegisGuard src/c2.rs:12-18](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L12-L18)）をそのまま最大50,000〜100,000以上のフィルタに変換してはならない。初期PoCは数件、上限を明示し、段階的に制限内で測る。
- 誤検知：C2 IPの再割当、共有IP/CDN、プロキシ、既知正常サービスと重複する宛先、プロセスのパス差し替え、誤フィード。適用前に期限・許可リスト・プロセス/用途・人間の承認を確認し、誤遮断をすぐ戻せるようにする。
- 見逃し：DNS/DoH/DoT、別IP・IPv6、VPNトンネル、アプリが別プロセス/サービスを使う通信、UDP/QUIC、既存接続の維持、IP以外のC2、プロセスPID再利用などはIPのALE_AUTH_CONNECT単体では包括できない。PIDだけで許可/遮断の帰属を固定しない。
- 失敗封じ込め：FwpmFilterAdd0/Commit/Lookup/Deleteは全てステータスを検査。部分適用時は成功と表示せずAbort/リカバリ。BFE切断・ACL拒否・組織ポリシー・ルール重複・OS再起動・設定破損をエラー種別として保持する。
- ログ保護：WFPイベント購読は大量イベントや全体のエンジンオプション変更を伴う（[simplewall src/log.c:295-419](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/log.c#L295-L419)、[simplewall src/wfp.c:319-370](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L319-L370)）。センサー実装時はイベント上限、バッファ、サンプリング/集約、欠落カウンタ、保持期間、ACLを測定・設計し、検査やネットワークを塞ぐまで待たせない。
- 取り込み時の試験：AegisGuardの既存C2ユニットテスト（[AegisGuard src/c2.rs:426-572](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L426-L572)）は期限切れ・不正入力・部分更新失敗などをカバーするが、**WFP操作やrollbackのテストではない**。simplewallツリーには独立したテストファイル/テスト用CIが見当たらず、Scorecardの存在は機能試験合格を意味しない。

## 7. 推奨する小さなPoCと成功基準

**段階0：オフライン・読取専用。** 実在C2ではない文書用IPを用いた合成フィードでPolicyPlanを生成。IPの正規化、public-only判定、重複、TTL超過、時刻逆行、巨大/HTML入力、未知source、ユーザーallowlist、1件単位の差分、最大件数、手動承認の単体テストを実施。既存Defender設定やWFPには触れない。合否：期限切れ/不正/承認なしの全ケースで適用候補がゼロ、なぜ除外したか機械可読な監査が残る。

**段階1：隔離したWindows 11 VMでdry-run・現状確認。** 管理者/非管理者の権限差、BFEサービスの状態を読み取り、ルール計画と自分が所有する予定のprovider/名前空間が未使用であることを確認。既存Windows Firewall/DefenderとVPN/AVの有無を記録。合否：dry-runでフィルタ/Firewall/Defenderの差分ゼロ。

**段階2：明示承認・限定有効化。** ローカル隔離VM内の管理者操作に限り、1〜数個の安全なテスト宛先でoutboundだけを試す（実通信試験はネットワーク的に隔離したテスト用対向ホストを使用。privateアドレスを使う特例はテスト専用に分離し、本番のpublic-IP検証を緩めない）。初手はWindows Firewall APIの専用ルールで低リスクな操作性を比較。直接WFP試験は別バックエンドかつFWPM_SESSION_FLAG_DYNAMICで行い、専用provider/sublayerとALE_AUTH_CONNECT_V4/V6のBLOCK条件のみ。意図したアプリ/宛先だけ拒否され、別アプリ/別宛先、DNS、IPv6、Defender保護が不変であることを観察。API成功・実際の遮断・ルール一覧の三者を照合する。

**段階3：rollback/故障注入。** フィルタ追加2件目のエラー、権限拒否、トランザクション失敗、プロセスクラッシュ、ネットワーク断、再起動のシナリオをVMで安全に再現する（BFE/Defenderサービスの故意停止は**しない**）。合否：失敗時に成功表示ゼロ、トランザクションAbort、dynamicセッション終了時は追加したWFPオブジェクトゼロ、Firewallバックエンドは所有したルールだけ削除、無関係なprovider/rules/Defender設定の差分ゼロ、期限切れ・再起動時は未解消のルールを検出して復旧可能。

**性能と観測：** 追加/削除/照合のレイテンシ、WFPオブジェクト数、管理プロセスCPU/RSS、ネットワーク往復、ログイベント数/欠落数を、遮断前・遮断中・解除後で比較し測定手順と生データを保存する。**閾値はデバイス/VMの基準値を測ってから決定**。障害時に元の通信を復元できない、他製品のルールが変化する、サービスを無効化する必要が出る、操作結果が不明なまま継続する場合は即中止。

## 8. 採用しない設計と理由

1. **simplewallのデフォルトdeny・system/loopback例外・boot-timeフィルタの移植：** AegisGuardの目的は厳選したC2アウトバウンドの選択的遮断であり、全通信遮断はWindows Update/DNS/WSL/VPNなどを壊す。[simplewall src/wfp.c:1743-1919](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L1743-L1919) のboot-time仕様を最小構成に持ち込まない。
2. **simplewall.exeの自動インストール/CLI制御：** READMEの-install/-uninstallは所有フィルタ集合を大きく操作する。AegisGuardの単一IOCと一対一で独立した期限/rollbackが保証されない。Windows Firewallを無効にする選択肢まで含むため不採用。
3. **simplewallのWFP C実装のRustへのコピーペースト：** GPL-3.0との整合性が未確定で、外部routine依存と戻り値未伝播の失敗経路も持ち込む。公式WFP仕様からRust FFI/バインディングで独自に作る。
4. **独自callout.sys/高優先度sublayerで強制的に他製品へ勝つ設計：** 単純なIP blockの必要条件でなく、署名・パッチ追従・相互運用性・ネットワーク切断の危険が高い。Defender共存を優先する。

## 9. 他担当との境界・引継ぎ

- **simplewall-operational担当：** インストール/アンインストール、サービス運用、GUI操作、ユーザー承認、Windows Firewallの状態変更、実際のログ挙動と権限昇格の分析を引き継ぐ。本担当はWFP管理APIと安全な差分設計まで。
- **portmaster-wfp-driver / portmaster-policy-dns担当：** callout/ドライバーが必要となるパケット操作・DNS/ドメイン制御、他製品間の競合と専用サービスの機能分担を比較してもらう。直接WFPの単純IP blockだけでDNSまで解決したとみなさない。
- **IOC/脅威フィード担当：** フィードの鮮度、信頼度、ASN/CDN誤遮断、期限、データ再配布条件は政策適用の上流責務。本担当は入力が妥当と判定された後の強制操作境界を定める。
- **Windowsセンサー/Defender担当：** Sysmon EventID 1/3/7、ETW、AMSI、ASR、WFP NetEventsの観測重複・パフォーマンス・Defender共存検証を引き継ぐ。WFPのイベントだけで実行ファイルの悪意を断定しない。

## 10. 未確認事項・追加調査項目

1. **高：Windows 11 x64実機でのDefender/Windows Firewall/VPN/EDR共存**と、条件別のフィルタ調停・既存接続への適用・IPv6/QUIC/WSL/NAT挙動（未実測）。
2. **高：BFE障害・再起動・部分コミット失敗・OS更新後の復元保証。** 現状の静的指摘は再現試験未実施。AegisGuardが「常に復旧できる」とは主張できない。
3. **高：Rust Windowsバインディングの採用crate/version/featuresとFWPM構造体・union・callbackのABI確認。** Microsoft SDK直接呼び出しの安全なラッパ設計は実装段階で選定。
4. **高：ルール所有権の形式的保証と組織ポリシー、複数ユーザー・複数サービス同時更新。** Windows Firewallバックエンドの適用可否とWFPベースの設計境界を検証。
5. **中：simplewallのリリースv.3.8.7とmasterの差、および機能試験の有無。** リポジトリ内で明確なテストスイートを特定できず、実機ビルド未実施。
6. **中：XML内蔵ルール/外部blocklistとNuGet依存の個別ライセンス、GPG署名の真正性。** 法的評価未完了、コード/データ同梱は行わない。
7. **中：大規模IPリストによるフィルタ数・分類レイテンシ・メモリ・ネットイベント増加。** 数値測定・上限設計は未完了。

## 11. 一次情報一覧

調査日：2026-11-05。以下のsimplewall/AegisGuardリンクは取得時SHAで固定したファイル・行範囲（README要約だけではない）。Microsoft文書は公開仕様として確認し、版差の再確認を前提とする。

1. [simplewall src/wfp.c:8-65](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L8-L65) — BFE/RPC接続と失敗時の終了処理。
2. [simplewall src/wfp.c:207-310](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L207-L310) — provider、sublayerの作成、永続フラグとACL。
3. [simplewall src/wfp.h:6-29](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.h#L6-L29) — GUIDとweightの具体的定義。
4. [simplewall src/wfp.c:715-809](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L715-L809) — filterKey/条件/weight/actionとFwpmFilterAdd0。
5. [simplewall src/wfp.c:918-1217](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L918-L1217) — APP_ID/USER_ID/PACKAGE_ID、IP/port/protocol、ALEレイヤー。
6. [simplewall src/db.c:288-365](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/db.c#L288-L365) — XML規則からaction、protocol、priorityへ変換。
7. [simplewall src/wfp.c:477-595](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L477-L595) — 既存providerフィルタの再構築トランザクションと削除。
8. [simplewall src/wfp.c:598-669](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L598-L669) — Begin/Commit/Abort/Deleteのエラー処理。
9. [simplewall src/wfp.c:1182-1217](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L1182-L1217) — filter add失敗の戻り値が伝播しない可能性。
10. [simplewall src/wfp.c:1743-1919](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L1743-L1919) — boot-time、default deny、既存calloutの参照。
11. [simplewall src/main.c:43-130](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/main.c#L43-L130)、[simplewall src/wfp.c:2037-2085](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/wfp.c#L2037-L2085) — Windows Firewall有効/無効という例外的連携。
12. [simplewall src/log.c:295-417](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/log.c#L295-L417) — ネットイベント購読/解除と互換APIの選択。
13. [simplewall src/timer.c:28-112](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/src/timer.c#L28-L112) — アプリ単位のタイマーと期限撤去。
14. [simplewall simplewall.vcxproj:379-429](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/simplewall.vcxproj#L379-L429)、[simplewall packages.config:1-4](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/packages.config#L1-L4)、[simplewall .gitmodules:1-7](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/.gitmodules#L1-L7) — MSVC/SDK/CppWinRT/routine依存。
15. [simplewall LICENSE:1-20](https://github.com/henrypp/simplewall/blob/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1/LICENSE#L1-L20) と [henrypp/routine/LICENSE](https://github.com/henrypp/routine/blob/master/LICENSE) — GPL-3.0一次資料。
16. [AegisGuard src/main.rs:24-78](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/main.rs#L24-L78)、[AegisGuard src/c2.rs:12-18](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L12-L18)、[AegisGuard src/c2.rs:426-572](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L426-L572) — 現行CLI、IOC件数上限、鮮度のユニットテスト。
17. [Microsoft Learn: WFP全体とWFASの共通基盤](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)、[Filter Arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration) — フィルタ層と裁定。
18. [Microsoft Learn: Object Management](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)、[FWPM_FILTER0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0) — 動的/static/persistent/boot-timeの寿命。
19. [Microsoft Learn: Access Control](https://learn.microsoft.com/en-us/windows/win32/fwp/access-control)、[FwpmEngineOpen0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0)、[FwpmGetAppIdFromFileName0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0) — 権限とアプリ識別。
20. [Microsoft Learn: Callout Driver Programming Considerations](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/callout-driver-programming-considerations)、[INetFwPolicy2](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwpolicy2) — ドライバーの要否とFirewall API。

### 導入候補上位3件と阻害要因（意思決定用）

1. **P0 / M：期限付きPolicyPlan・dry-run・自己所有rollback** — ブロッカー：承認/allowlist/古いIOCの整合とルール数上限。WFPを操作しない単体テストから開始。
2. **P1 / M：Windows Firewall APIによるAegisGuard名義の最小アウトバウンド遮断** — ブロッカー：管理者権限、組織ポリシー、反映確認、失敗後の撤去。既存ARCHITECTUREの初期方向と一致。
3. **P1（VM限定）/ L：Microsoft WFP APIによるdynamic provider/sublayerとALE_AUTH_CONNECT IP block** — ブロッカー：厳密なWFP arbitration/ACL/BFE/reconcile/失敗時の完全削除。simplewall実装は設計参考のみ。

**見送り2件：** (A) simplewall GPLソース・CLIの取り込み、(B) 既定全通信遮断・boot-time/callout方式。いずれも最小C2ブロックに必要な範囲を超え、共存性・保守性・ライセンスに追加の負担を生む。
