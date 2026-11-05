# 調査報告：Portmaster / portmaster-wfp-driver

> 担当：portmaster-wfp-driver / 調査日：2026-11-05 / 調査結果：**ソース静的調査完了・実機検証未完了**
>
> 対象：Windows 11 x64・Rust-first・Microsoft Defenderとの共存を前提とするAegisGuard。以下の「実装確認」は特定commitのコード読解であり、実機動作保証を意味しない。

## 0. 結論（3〜5行）
- **取り入れる価値：高い（設計・帰属・復旧手順）**。PortmasterはGoユーザーモード制御とRust製WFPカーネルドライバーを組み合わせ、接続の最初の判定・継続パケット処理・サービスへの帰属まで実装している。
- **最優先候補：** Windowsイベント/Sysmonからのアプリ別通信監視（通知は原則事後）、次に所有権を限定したWindows Firewallの明示承認付きアウトバウンド遮断、PID・サービス帰属の堅牢化。
- **見送り候補：** WFP callout・パケット再注入・独自カーネルドライバーのコピー/移植、および無条件の未知通信停止。両方とも現MVPの安全性・運用上の負担に見合わない。
- **最大の制約：** WFPの他製品との優先順位と署名配布、異常終了時のpending/queue、PID/ドメイン帰属の不確実性、GPL-3.0コード再利用条件。法的評価未完了。

## 1. 対象の固定と調査方法

| 要素 | 値 / 根拠 |
|---|---|
| 公式リポジトリ・commit固定URL | [safing/portmaster](https://github.com/safing/portmaster/tree/bffef134cd709d2a74295cd8450cf0c6231bd60d)（公式リポジトリ、default branch: development） |
| 調査コミットSHA・タグ | **bffef134cd709d2a74295cd8450cf0c6231bd60d**（development）。確認時の最新リリースは **v2.2.8**。タグと調査commitは同一と仮定しない |
| AegisGuard比較先SHA | [main @ 83fcf0d150e8d760baff5f971c106deb09c1f8e4](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md#L1-L15)。Rust CLIの静的検査/C2 IP照合のみ |
| ライセンス原文 | [ルートLICENSE = GPL-3.0本文](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/LICENSE#L1-L22)、[ドライバーINFのGPLv3-or-later表記](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/PortmasterKext64.inf#L1-L18)。独立ライセンスとデータの例外は個別確認が必要 |
| 調査対象コード | windows_kext/driver、windows_kext/wdk、windows_kext/kextinterface、service/firewall/interception、service/network、service/process、packaging/windows、Go/Rust manifest、テスト/CI |
| AegisGuard現状確認 | [README](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md#L1-L18) / [SECURITY](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md#L1-L25) / [ARCHITECTURE](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L1-L49) / [Cargo.toml](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/Cargo.toml#L1-L30) / [src/main.rs](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/main.rs#L1-L78) / [src/c2.rs](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L1-L16) / [src/model.rs](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/model.rs#L27-L43) |
| 実機・ビルド・テスト | **未実施**：Windows 11実機、WDK、テスト署名済みドライバーを起動していない。悪性検体なし。ソース/テストコードの静的レビューのみ。 |
| 日付・制限 | 2026-11-05時点。GitHubコードとMicrosoft Learnを閲覧。HVCI/Secure Boot互換、Driver Verifier、Defenderとのレース、障害復旧、負荷は未実測 |

### 観察上の境界
Portmasterの現行Windows経路は単なるOS標準Firewallルール操作ではない。[interception_windows.go: startInterception](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/interception/interception_windows.go#L18-L46) が更新バイナリの portmaster-kext.sys を読み、サービスとして起動する。[kext v1/v2選択](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/interception/interception_windows.go#L35-L64) には旧プロトコル互換経路もあるため、v2 Rustドライバーと旧実装を混同しない。

## 2. 実装アーキテクチャとソース調査

### 2.1 機能マップ（実装確認・文書のみ・推測を区別）
| 機能 | 主要ファイル/シンボルと処理 | commit固定の一次資料 | 確認状態 |
|---|---|---|---|
| WFP登録・全体構成 | Rust DriverEntry → Device::new → FilterEngine::commit。GoのサービスがKextを起動・停止 | [entry::driver_entry](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/entry.rs#L29-L80) / [Device::new](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/device.rs#L28-L70) / [Go側の起動](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/interception/windowskext2/kext.go#L27-L51) | 実装確認 |
| サブレイヤ・管理API | カーネル側から動的BFEセッションを開き、sublayer weight 0xFFFF、filter weight 15、条件0（同層の全トラフィック）でcallout登録。トランザクションでcommit | [FwpmEngineOpen0/サブレイヤ](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/wdk/src/filter_engine/ffi.rs#L28-L68) / [filter条件/重み/flag](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/wdk/src/filter_engine/ffi.rs#L166-L204) / [登録順](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/wdk/src/filter_engine/mod.rs#L62-L114) | 実装確認 |
| ALEアウトバウンド判定 | IPv4/IPv6 ALE_AUTH_CONNECTでprocess_id、5-tuple、reauthorizeを読む。TCP/UDPの新規接続を保留しInfoをGoへ通知。policy verdict後に再注入・cache更新 | [ALEとPID取得](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/ale_callouts.rs#L68-L105) / [保留/送出](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/ale_callouts.rs#L234-L283) / [判定受信](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/device.rs#L156-L204) | 実装確認 |
| TCP/UDP以外・受信・fragment | IP packet calloutでIPv4/v6を処理。fragmentは無条件blockのコード。ICMP等はALEではなくpacket layerで扱う | [packet layer](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/packet_callouts.rs#L99-L125) / [ネットワーク層判定](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/packet_callouts.rs#L156-L255) | 実装確認（副作用要評価） |
| 帯域統計 | STREAM TCP、DATAGRAM UDP calloutが方向別のバイト数を記録し、Goが定期取得 | [stream_callouts](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/stream_callouts.rs#L6-L45) / [Go 1秒ポーリング](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/interception/interception_windows.go#L64-L82) | 実装確認 |
| 終了/キャッシュ | ALE_ENDPOINT_CLOSURE / resource releaseで終了通知。ConnectionCacheが判定を保存し、明示的にfilterリセット可能 | [callout登録](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/callouts.rs#L32-L91) / [connection cache](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/connection_cache.rs#L17-L128) / [ClearCache](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/device.rs#L261-L266) | 実装確認 |
| PID→ユーザーモード | カーネルのprocess_idとpacket情報をプロトコルに入れてGo側でPacketInfoへ変換。0は未定義PID | [IdCache::build_info](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/id_cache.rs#L79-L130) / [Go handler](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/interception/windowskext2/handler.go#L50-L102) | 実装確認 |
| 未帰属の補完 | PID hintは短時間キャッシュ。未知PIDではWindows IP HelperのTCP/UDP owner-PID tableを照合、失敗は「不明/unsolicited」へ降格 | [PID hint](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/network/pidhint.go#L13-L84) / [state::Lookup](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/network/state/lookup.go#L27-L67) / [IP Helper tables](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/network/iphelper/tables.go#L14-L84) / [process::GetPidOfConnection](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/process/find.go#L52-L105) | 実装確認 |
| サービス帰属 | svchost.exeについて tasklist /svc を呼びPIDごとのサービス名をタグ化する。**1 PIDに複数サービスなら一意な送信サービスまで特定したとは限らない** | [サービス名取得](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/base/utils/osdetail/svchost_windows.go#L16-L66) / [svchostタグ化](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/process/tags/svchost_windows.go#L53-L80) | 実装確認（粒度に限界） |
| 旧/新カーネルプロトコル | Kextメジャー版を確認し旧windowskextか新windowskext2を選択 | [version互換分岐](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/interception/interception_windows.go#L33-L63) | 実装確認 |
| WFP状態可視化 | GoのGetWFPStateは netsh wfp show state を実行しXMLを解析。WFP管理の本体ではなく**診断** | [GetWFPState](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/compat/wfpstate.go#L19-L59) | 実装確認 |
| Windows 11実機互換/Defender共存 | 最新Windows 11 + HVCI + Defender + 他社製callout同時動作は実機テストが必要 | [開発前提README](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/README.md#L16-L34) | **未確認** |

### 2.2 ドライバー固有の役割とユーザーモードの役割
- **カーネルRust側：** WFP callout関数、ALEでの保留とパケット吸収、ネットワーク層コピー/書換え/再注入、接続cache、event queue、device I/O、通信量集計。[callouts.rs](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/callouts.rs#L10-L168) / [packet_callouts.rs](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/packet_callouts.rs#L99-L255)
- **Goサービス側：** driver.serviceの作成/起動、デバイスからイベント読取、アプリ/サービス帰属、接続ポリシー評価、verdict返送、統計/UI、停止時の手順。[Go service管理](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/kextinterface/kext.go#L87-L160) / [handler](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/interception/windowskext2/handler.go#L34-L76) / [verdict更新](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/interception/windowskext2/kext.go#L120-L176)
- **WFPオブジェクト管理（FWPM_* API）：** サブレイヤ/フィルター追加・削除自体はユーザーモードからも可能。ただし**当該calloutの実際のclassify処理、pending、パケット再注入はカーネル側**。Portmasterは管理APIもカーネルから呼ぶが、「管理APIにドライバーが必須」という意味ではない。Microsoftの [WFP概要](https://learn.microsoft.com/en-us/windows/win32/fwp/about-windows-filtering-platform)、[オブジェクト管理](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)、[FWPM条件](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/filtering-condition-identifiers)。

### 2.3 優先順位・競合と停止挙動（重要）
1. [filter設定](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/wdk/src/filter_engine/ffi.rs#L183-L201) は **sublayer=0xFFFF / weight=15 / FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT / 条件0**。WFPのフィルター裁定はsubLayer優先順位とaction right等で決まり、**Defender Firewallや他社AVとの共存を「優先順位が高いから安全」と断定できない**。Microsoft [Filter Arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration)。
2. [ALE::clear_write_flag](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/ale_callouts.rs#L190-L213) は自プロセスのアウトバウンド許可時にwrite flagを落として後続他社フィルターの上書きを抑制するとコメントしている。**他社Firewallのブロック方針を弱め得るためAegisGuardでは採用不可**。MS [filter裁定](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration)で別途検証。
3. **正常停止：** Go側はShutdownを送り、ファイルハンドルを閉じ、SCMサービスを止め削除。[Stop()](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/interception/windowskext2/kext.go#L64-L90)。Rustはshutting_downフラグを立て、未決着packetのverdictをPermanentBlockにしてpending操作を完了させ、その後フィルター解除。[Device::shutdown/drop](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/device.rs#L321-L373) / [FilterEngine::drop](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/wdk/src/filter_engine/mod.rs#L167-L193)。**「停止時すべて即許可」ではない**（既存の保留接続はblockされ得る一方、停止フラグ後の新規ALE/packetはpermit）。[ALE shutdown](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/ale_callouts.rs#L234-L243) / [packet shutdown](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/packet_callouts.rs#L222-L228)。
4. **異常終了：** GoがクラッシュしShutdownが届かず、カーネルdriverの動的BFEセッションが残ると判定待ち通信が滞留する**可能性**。driver側のユーザーモード死活監視・verdictタイムアウト・自動アンロードを、この調査範囲のソースでは確認できない。これは「必ず遮断が続く」という実測ではなく**高優先度の検証仮説**。実機障害注入は禁止し、専用VM設計で後日確認。
5. **IN/OUTの通信遮断差：** outbound TCP/UDPはALE最初の許可/拒否を同期的に制御できる一方、packet layerでのfragment抑止やpending失敗時のdropはアプリケーションを壊し得る。[ALE default block](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/ale_callouts.rs#L107-L115) / [IP packet fragments](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/packet_callouts.rs#L99-L114)。

## 3. 具体的な取り込み候補と選択肢

| 候補機能 | 利用方法（crate/API・外部CLI・独自実装・参考・見送り） | AegisGuard接続先 | 優先度 | 工数 S/M/L | ライセンス・技術上の阻害要因 |
|---|---|---|---|---|---|
| 通信イベント+プロセス相関・未知接続の**事後**通知 | **独自実装**：Windows Event Log / Sysmon EID 1,3、必要に応じWFP net events閲覧。PortmasterのpidHint/unknown分岐は**設計参考** | planned Windows sensor / EventStore / UI | **P0** | **M** | EID 3は明示有効化が必要、欠損/遅延/PID再利用/権限、既存ログの負荷。[Process fallback](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/process/find.go#L52-L105) |
| アプリ別IP・IP:portの明示承認ブロック | **独自実装**：Windows Firewall API/PowerShellでAegisGuard専用命名規則のアウトバウンドルールを作成。必要時のみ管理者サービス | response/firewall-policy | **P1** | **M** | ACL/管理者承認、OSのルール上限、設定の持続性、IPv4/v6、状態回復と競合。[AegisGuardの方針](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L29-L42) |
| PID・5-tuple+ProcessGuid/開始時刻・サービス帰属 | **独自実装**＋Portmaster設計参考：未帰属を保留、IP Helperは補助、Sysmon ProcessGuidを主軸 | Windows sensor / correlation | **P0** | **M** | svchost複数サービス、socket/プロセス終了のレース、VPN/NAT/共有PID、個人情報。[svchost tag](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/process/tags/svchost_windows.go#L53-L80) |
| DNS→ドメイン→IP候補のアプリ別相関 | **独自実装**（ドメインは観測・助言を先行）/ portmaster DNS処理は別担当の設計参考 | DNS event correlator / IOC | P2 | L | DoH/DoT、共有CDN IP、TTL/CNAME、プロキシ、複数アプリ共有IP、誤遮断 |
| WFP管理APIからのフィルター監視・診断 | **直接Win32 API**またはWindows標準netshによる**読取診断のみ**。Portmasterのwfpstate XML解析は参考 | diagnostics | P2 | S/M | アクセス権・イベント監査の前提、XML変更、ロギング負荷。[wfpstate.go](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/compat/wfpstate.go#L19-L59) |
| カーネルALE/packet calloutの再利用 | **見送り**。Rust crate直接リンクは不可（カーネル静的ライブラリ + WDK固有、汎用crateではない） | 対象外（将来の独立検討） | 非採用 | L | GPLの条件、Microsoft署名、HVCI/BSOD、優先順位、運用負担。[driver Cargo](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/Cargo.toml#L8-L25) |
| Portmaster Goサービス/CLIを統合 | **見送り（外部プロセス方式も）**。導入/更新/権限/競合が新たな依存になり、目的と責務が重なる | 対象外 | 非採用 | L | GPLと配布境界を含む法的評価未完了、独立ドライバー常駐を前提 |

**ユーザーモードだけで可能な範囲と差分：**

| 目的 | Windows Firewall/イベント読取のみ | WFP管理APIのみ（独自calloutなし） | Portmaster型kernel callout |
|---|---|---|---|
| EXEパス/リモートIP/ポート単位の許可・遮断 | 標準Firewallルールで**可能**。動的プロセス実体の完全識別は別問題 | ALE_APP_ID/REMOTE_ADDRESSなどを条件とする静的フィルターで**可能**（権限が必要） | 可能 |
| 接続の観測と未知接続通知 | **事後通知**は可能。ログ有効化と欠損対策が必要 | WFP net events購読等、イベント種別・有効化条件に依存 | 判定前にイベントを通知して**保留**も可能 |
| 未知通信を一旦止めユーザーの判定を待つ | **不可**（事前定義したdefault-denyは別物） | 静的ポリシー以外に任意の同期判定/holdは**困難** | ALE pending等で可能、stall/timeout対策必須 |
| packet内容の書換え/再注入、接続ごとの逐次payload判定 | 不可 | 不可 | packet callout・injectorが必要 |
| TCP/UDP帯域統計 | 代替監視方式は検討可能だがPortmasterと同じ粒度/正確性は保証不可 | フィルター管理だけでは逐次バイト集計不可 | stream/datagram calloutで実装 |

Microsoft一次資料：[WFP条件一覧](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/filtering-condition-identifiers)、[各層で可能な条件](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/filtering-conditions-available-at-each-filtering-layer)、[FwpmNetEventSubscribe0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmneteventsubscribe0)、[WFPアクセス制御](https://learn.microsoft.com/en-us/windows/win32/fwp/access-control)。

### 採用候補のI/O・失敗時処理・最小PoC
- **P0 通信監視：** 入力はSysmon EID1/3（ProcessGuid、PID、開始時刻、exe path、src/dst、protocol、timestamp）、OSイベントログのbookmark。出力は connection-observation {source, timestamp, process_guid?, pid?, image?, remote_ip, remote_port?, protocol, confidence, incomplete_reason?} のJSONL/UI表示。フィードの新IPなど「未知」を判定し、**接続許可状態を変更せず**事後通知。権限/ログ欠損/フィード期限切れなら「帰属不明/検査不足」と表示し、無通知=安全にしない。PoCは既知の無害なローカル接続で EID1⇄EID3 を突合、イベント欠損カウンタを確認。
- **P1 Firewall：** 入力は検証済みpublic IP・exe絶対パス・プロトコル/port・失効時刻・管理者承認済みpolicy ID。出力は rule-id/GUID・作成前後差分・適用結果・監査ログ。**名前空間（例 AegisGuard/）で自分のルールだけを追加/削除**。dry-run→承認→適用→読戻し→再起動後復元→期限切れ削除。書込み失敗は成功扱いにせず、設定を戻す。Windows Firewallルール操作に関わる管理者権限をUIへ常時与えない。IPからdomainへ逆引きして自動遮断しない。
- **P0 帰属：** 入力はイベント+プロセス開始/終了+IP Helper snapshot+サービス名/ユーザーSid（取得可能時）。出力は確度付き attribution {process_guid?, pid, start_time?, image?, services[], ambiguity}。不一致はunknownにし**強制遮断の条件にしない**。PoCは同PID再利用の合成イベント、IPv6、短命プロセス、svchost複数serviceを模したfixtureで誤帰属なしを確認。

## 4. ライセンス・再配布・依存関係

| 対象 | 調査結果 | AegisGuard判断 |
|---|---|---|
| Portmaster本体Go | ルートにGPL Version 3原文がある（[LICENSE](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/LICENSE#L1-L22)）。全ファイルが同一条件と断定せず、個別例外を要監査 | **設計参考のみ**。コードコピー/リンクは法的評価未完了のため行わない |
| windows_kext Rust driver / wdk / protocol | 独立したwindows_kext/内のLICENSEは調査ツリーで発見できず、[INF原文](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/PortmasterKext64.inf#L1-L18) はGPLv3-or-later。crate群は[driver Cargo](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/Cargo.toml#L1-L25)、[wdk Cargo](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/wdk/Cargo.toml#L1-L21)、[protocol Cargo](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/protocol/Cargo.toml#L1-L15) を確認 | kernel code/ABIの直接転用・組込みは**不可判断**（許諾条件・派生物性の法的評価未完了） |
| Go↔Rust wire protocol | 独自packed構造とバイナリfixture/相互読取テスト（[Rust protocol test](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/protocol/src/command.rs#L78-L115) / [Go protocol test](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/kextinterface/protocol_test.go#L11-L86)） | コードは転用せず、**失敗時のバージョニング・互換テスト設計だけ参考** |
| 第三者依存 | driverはsmoltcp 0.10、num系、ローカルwdk/protocol、特定windows-sys Git rev。Go側は多数の依存（[driver dependencies](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/Cargo.toml#L13-L25)、[Go dependencies](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/go.mod#L1-L55)） | 各依存のSPDX表記とライセンス原文・再配布義務は**個別未監査**。OSSの許諾自動継承とみなさない |
| 署名/driver.sys/CAB | [リリース手順](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/release/README.md#L1-L38) はWDK/Visual Studio、CAB、Microsoft hardware dashboard申請を記載。[INFとCAT](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/PortmasterKext64.inf#L20-L60) も確認 | AegisGuardでは署名済みdriver等を同梱しない。仮に将来行うなら署名・SBOM・更新/ロールバックと保守を別プロジェクトとして監査 |
| ドメイン/ルール/IOC・表示データ | 今回の調査対象Windows driverから「特定ルール/署名/IOCデータを再配布可能」と判断できる根拠は得られない。assets/fonts等には個別LICENSEがある | ドメインフィード担当で利用規約、署名・更新、著作権、再配布を別途判断 |
| AegisGuard現状 | [README末尾](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md#L79-L91) はソースライセンス未設定を明記（現段階で独立OSSライセンスはない） | PortmasterのGPLコードを複製して組み合わせる判断は**法的評価未完了**。CLI別プロセスなら常に安全、という一律判断も不可 |

GPLv3の条件に基づくコード複製・リンク・改変配布・バイナリ同梱と、単なる公開APIへの独自呼出しは区別する。技術的分離はライセンス義務を免除する保証にはならない。法律上の最終評価ではない。

## 5. Defender共存・Windows制約・権限境界

- **Defender併用：** AegisGuardはDefenderの常駐監視/Firewall/ASRを停止しない。Sysmon/ETWは観測層、AMSIは対応スクリプトホストのスキャン境界、WFPはネットワークフィルター/裁定層。これらは代替関係ではなく、ログ重複・順序ずれ・ポリシー競合を分離して扱う。[現設計](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L23-L48)
- **WFP priority：** Portmasterの0xFFFF sublayerおよびclear action-rightは他のFirewall/EDRとの競合調査が必要。第三者の許可を無断上書きしない。**AegisGuard PoCではPortmaster方式を再現しない**。Microsoft [裁定](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration)。
- **権限：** Windows Firewallのrule変更やWFP filter追加には適切な管理者権限/ACLが必要。閲覧・subscribeも各objectのBFE ACLに従う。読み取りが成功したから書き込み可能と仮定しない。[カーネルデバイスSDDL](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/c_helper/helper.c#L31-L57) は管理者/SYSTEM用のdevice controlを用意する。Microsoft [WFP access control](https://learn.microsoft.com/en-us/windows/win32/fwp/access-control)。
- **署名：** Windows 11 x64の本番kernel driverは適切な署名、Secure Boot/HVCI、driver loading policyとの互換が要件。Portmasterの[開発ガイド](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/README.md#L18-L34) はx64とテスト署名を扱い、[release guidance](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/release/README.md#L12-L38) はMicrosoft署名を扱う。**AegisGuardの実機で互換確認したわけではない**。Microsoft [Driver Signing Options](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings) / [Driver Signing](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing)。
- **ロード/アンロードと更新：** PortmasterのユーザーモードGoではSCMを開きkernel-driverのDEMAND_START serviceを作成し、Stop/Delete後に再作成する。[CreateKextService](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/kextinterface/kext.go#L209-L250) / [Stop](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/interception/windowskext2/kext.go#L64-L90)。古いINFテンプレートのBOOT_START記載（[INF StartType](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/PortmasterKext64.inf#L54-L60)）を、現在のGo経路の起動形態と混同しない。
- **認証情報・プライバシー：** packet payloadやURL/DNS/プロセスパスを無制限に保存しない。PID/ProcessGuid/ServiceName/ドメインなど必要最小限の情報に限定し、ユーザーごとのACL、保存期間、ログローテーションを設定。管理者権限を持つバックエンドは最小APIで分離する。
- **初期機能差：** app path + IP/port blockなら標準Firewallで十分。一方、WFPのcalloutを使わない初期AegisGuardでは「ユーザー回答まで最初の接続を停止」やpacket redirection/逐次payload filteringはできない。通知は**接続開始後に届き得る**ことをUIで明記。

## 6. 性能・堅牢性・誤検知

- **実測は全て未実施。** CPU%、RAM MB、イベント処理速度、ドライバー起動時間、ネットワーク遅延について根拠のない数値は置かない。PoCではWindows 11の標準的なノートPCで、baseline/観測有効/限定rule有効を同じ接続発生パターンで比較し、CPU、working-set、event/sec、p50/p95通知遅延、失われたイベント、ネットワーク正常性を実測する。
- **backpressure:** Goは接続packet queueを100件の固定チャネルとし、満杯ならDropする。[connection handler](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/network/connection_handler.go#L19-L29) / [overflow](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/network/connection_handler.go#L70-L92)。Rust IdCacheは1000件の初期容量で、push時に件数上限/期限切れ退避が見当たらない（[IdCache](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/id_cache.rs#L12-L60)）。**高負荷時の滞留メモリと停止**を安全要件に入れる。
- **fault domain:** [driver panic handler](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/lib.rs#L40-L81) はkernel panic時にbugcheckを呼び、通常ユーザーモードの単純なpanicと違いOS停止を起こし得る。AegisGuard初期版にkernel codeを置かない強い理由。
- **未知接続：** PID不明、ログ欠落、通信先IP再割当、共有CDN、DNS暗号化/プライベートDNS、VPN/プロキシ、IPv6、QUIC、同じ5-tupleの再利用で誤判定の可能性。[5-tuple cache](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/connection_cache.rs#L72-L95)。アプリ/サービス/ドメイン帰属にconfidenceを付け、低確度では自動遮断しない。
- **攻撃者入力：** 偽C2フィード、広域IPレンジ、プライベート/ループバック/リンクローカル、DNS rebinding、サイズ過大、同一IP共用、短時間の多量接続、遅延イベントを考慮。[既存C2検査上限](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L129-L167) を運用ポリシーから迂回させない。
- **観測による見逃し：** Sysmon EID3未設定、Windows Firewall/WFP net events未有効化、イベント喪失、ETWセッション断、開始前の接続は観測されない可能性。AVスキャンの結果と通信判定を混同しない。Windows 11の負荷・イベント可用性は要検証。
- **可用性：** 拒否ルールの異常な残存を防ぐため適用前バックアップ/owner特定/期限・再起動復元・監査を設計。既存Windows Defender Firewall設定を一括削除/無効化しない。
- **テスト証拠の限界：** [Rust↔Go protocol tests](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/protocol/src/command.rs#L78-L137) / [Go protocol tests](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/kextinterface/protocol_test.go#L11-L86) は互換フォーマット確認に有用。[test_protocol.sh](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/test_protocol.sh#L1-L9) はRust/Go test起動。[kext CI](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/.github/workflows/kext.yml#L1-L41) はEarthly +kext-ciを実行するが、その時点のWindows 11 Defender共存/HVCI/Driver Verifier合格を証明しない。[driver test README](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/test/README.md#L1-L14) は開発用と明記。今回はテスト実行していない。

## 7. 推奨する小さなPoCと成功基準

- **前提：** 第1段階は**監査のみ**。Windows 11 x64 + Defender/Firewallを有効に保ち、管理者権限なしでも可能な閲覧範囲を確認。テスト専用端末/VM（既存利用者のネットワーク・Firewallは変更しない）。Sysmonを新たに有効化する作業は別途管理者承認と復元計画を要する。
- **安全なサンプル/検証方法：** ループバックの単純なHTTP/TCP接続、無害なDNS、IPv4/IPv6、イベントの合成入力、長寿命/短寿命プロセス、複数サービス名称のfixture。フィードには偽の実害IOCを入れない。マルウェアやtest-signingによる実OS設定弱化は行わない。
- **フェーズA（dry-run観測）：** 接続元・アプリ名・ProcessGuid・日時・PID・src/dst・confidence・ログ欠落を保持し、ユーザーに「事後の未知通信通知」と明示。EID3が無い場合は明確にinactiveを返し、接続をblockしない。
- **フェーズB（限定policy、承認が得られた検証環境のみ）：** 事前に設定を読み取りAegisGuard専用owner GUIDの**単一のテスト用アプリ/外部IP**の候補ruleをdry-runで表示。承認後に適用、ルール読戻し、同アプリ/別アプリの挙動確認、失効/rollbackの確認。DNSベースの自動IP展開は行わない。
- **成功条件：** (1) 同じProcessGuidの観測が適切に相関し、PID再利用の合成ケースで誤帰属しない (2) IPv4/IPv6・欠損・未許可・権限不足を明示 (3) 既存Defender Firewallや他社ruleを一切変更しない (4) 作成したruleだけを消して元のrule集合へ戻せる (5) 再起動/サービス再起動後も中途半端なruleを検知・回復 (6) 途中失敗、feed stale、期限切れは確実に警告 (7) CPU/メモリ/ログ量/欠損/通知p95をベースラインと比較して結果を記録。
- **失敗時の扱い・rollback：** monitorをオフにしても元のOSルールは不変。block PoCは保存済みowner GUID一覧に限定してルール削除→読戻し→通信確認。中断で削除できない場合はUIに**復旧失敗**を明示、管理者向けの限定復旧手順を出す。OSのFirewallサービスやDefenderは停止しない。
- **中止条件：** OS通信障害/ログ欠損増大、意図しない既存rule差分、Defender異常、プロセス誤帰属、ルール復旧失敗、起動/停止不安定、検査不完全を正常扱いした場合。
- **kernel calloutのPoCは今回対象外：** 将来どうしても必要になった場合だけ独立した脅威モデル、署名、Driver Verifier、BFE復旧、仮想NIC/VPN/Defender/他社製品、panic・異常終了、fail-open/closedをVMで安全性審査する。

## 8. 採用しない設計と理由

1. **PortmasterのRust WFP kernel driverをAegisGuardへ直接リンク/コピー**：no_std/staticlibで専用WDK、callout、IRQL、再注入、署名が必要。kernel panicでOSを停止し得る。GPL原文とAegisGuardライセンス未設定の法的評価未完了。[driver manifest](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/Cargo.toml#L8-L25) / [panic→bugcheck](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/lib.rs#L40-L81)。
2. **Portmaster型の最高優先度/全パケットcalloutと自プロセス通信の特別permit**：sublayer最大値と条件0で全トラフィックを受け、他社フィルターを妨げる可能性。AegisGuard初期目的（IOC照合と選択的ブロック）に過剰。[weight/condition](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/wdk/src/filter_engine/ffi.rs#L60-L68) / [action right](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/ale_callouts.rs#L198-L203)。
3. **未知接続を既定で全てhold/denyし、UI回答まで待機**：通知遅延・UI不在・ユーザー離席・サービス障害で正規ネットワークを停止。初期は観測通知と、明示承認された静的ruleへ分割。
4. **ドメイン名を現在のIP群へ無条件変換してアプリ別ブロック**：DoH、TTL/CDN/共有IPによる過剰遮断。最初はdomain相関と根拠表示のみ。

## 9. 他担当との境界・引継ぎ

- **portmaster-policy-dns担当：** DNSに対する自前リゾルバ、DoH/DoT、DNSフィルタリング、アプリprofile、DNS→IPの帰属精度とdomain block可否を担当。ここではWFP/ドライバーとサービス帰属の境界のみ結論。
- **Sysmon/Windows sensor担当（該当する場合）：** EID1/3の取りこぼし・ProcessGuid寿命/権限/ログローテーションとイベント相関に引継ぐ。
- **Defender/Firewall共存担当：** 既存ルールの読み取り、allow/deny precedence、ASR、通知の重複抑止、復旧時の権限分離を連携評価する。
- **ライセンス担当：** PortmasterルートGPLv3、INF GPLv3-or-later、third-party Rust/Go依存、配布ドライバー・ルール/署名/データのライセンス原文を個別に追跡。AegisGuard側ライセンス未設定を前提に法務確認する。
- **WFP無関係のnetwork inspection/ClamAV/PE担当：** 静的ファイル判定やDefender経由の検査とは分離し、重複スキャンや通信遮断を勝手に連結しない。

## 10. 未確認事項・追加調査項目（重大順）

1. **重大：Goプロセス異常終了/電源断/Windows更新でkernel pendingとFWPM dynamic sessionがどう残るか**。driver側watchdog、queue timeout、BFE restart、SCM recovery、再起動時ルール処理。失敗注入は本番機で禁止、専用VM/将来の安全審査で確認。
2. **重大：Defender Firewall、VPN、IPsec、他社WFP calloutとの順序/高優先度/clear-write-flagの実挙動**。WFP裁定は仕様だけで製品間の安全保証不可。
3. **重大：Windows 11のSecure Boot/HVCI/Memory Integrity、EV/HLK/attestation署名、更新/ロールバック時の互換性**。Portmasterの公式配布済みbinaryそのものの署名チェーンまでは検証していない。
4. **高：device I/Oのアクセス境界とGoサービス停止中にOSがブロックされる可能性**。コードのSDDLは管理者/SYSTEM対象だが、脅威モデルと全IRPの長さ検証・TOCTOU等を網羅監査していない。
5. **高：プロセス/サービス帰属**。PID reuse、5-tuple再利用、svchost複数サービス、低権限/保護プロセス、短命接続、shared socket、NAT/IPv6/QUIC/Loopback、DNS暗号化でどこまで誤帰属を防げるか。
6. **高：OS標準Firewallアプリ別remote-IP/port ruleの全パターンとOS管理者権限/ACL/ドメイン参加GPOとの衝突**。Windows 11実機が必要。
7. **中：負荷/可用性の実測**。Rust IdCache/Go packet queueサイズ、pending許容時間、CPU/メモリ、netevent欠損、ログ肥大化、ネットワーク遅延、断続的サービス再起動時の回復。
8. **中：ライセンス詳細**。各ファイル・Rust crates・Go modules・生成コード・バイナリ配布・データとルール/署名の条件を法的レビュー。現時点では互換性判定不可。
9. **中：テストcoverage**。Rust↔Go protocol fixtureやCIは確認したが、各WFP layerの負荷/競合/Driver Verifier/Windows 11実機合格レポート・脆弱性監査結果は確認していない。
10. **中：最新release v2.2.8とdevelopment SHAの差分**。最新default branch実装の調査であり、ユーザー配布済みrelease binaryとの1:1対応は未保証。

## 11. 一次情報一覧（2026-11-05参照）

| # | 実装判断と参照範囲 | 固定permalink |
|---|---|---|
| 1 | DriverEntry→Device初期化・WFP登録 | [entry.rs L29-80](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/entry.rs#L29-L80) / [device.rs L28-70](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/device.rs#L28-L70) |
| 2 | 動的WFP session、最大sublayer、全条件0、filter重み/flags | [ffi.rs L28-68](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/wdk/src/filter_engine/ffi.rs#L28-L68) / [ffi.rs L166-201](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/wdk/src/filter_engine/ffi.rs#L166-L201) |
| 3 | ALE認証、PID/5-tuple、新規接続pended、既存verdict | [ale_callouts.rs L68-105](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/ale_callouts.rs#L68-L105) / [L139-283](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/ale_callouts.rs#L139-L283) |
| 4 | Packet layerのdefault absorb/fragment、packet判定/再注入 | [packet_callouts.rs L99-114](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/packet_callouts.rs#L99-L114) / [L156-255](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/packet_callouts.rs#L156-L255) |
| 5 | Goサービスのversion選択/worker、Stop/Service lifecycle | [interception_windows.go L18-120](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/interception/interception_windows.go#L18-L120) / [windowskext2/kext.go L33-90](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/interception/windowskext2/kext.go#L33-L90) |
| 6 | 正常停止時の未決着packetとFWPM cleanup | [device.rs L321-373](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/device.rs#L321-L373) / [filter_engine Drop](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/wdk/src/filter_engine/mod.rs#L167-L193) |
| 7 | kernel PID→Go info、PID hint、unknown fallback | [id_cache.rs L79-130](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/id_cache.rs#L79-L130) / [pidhint.go L13-85](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/network/pidhint.go#L13-L85) / [process/find.go L52-105](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/process/find.go#L52-L105) |
| 8 | Windows IP Helper TCP/UDP owner-PIDとsvchost service | [iphelper/tables.go L14-84](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/network/iphelper/tables.go#L14-L84) / [svchost_windows.go L16-66](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/base/utils/osdetail/svchost_windows.go#L16-L66) |
| 9 | Go↔Rust protocol tests とCIの検証範囲 | [Rust test](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/protocol/src/command.rs#L78-L137) / [Go test](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/kextinterface/protocol_test.go#L11-L86) / [kext CI](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/.github/workflows/kext.yml#L1-L41) |
| 10 | kernel panicがbugcheckへ移行する設計 | [driver/src/lib.rs L40-81](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/lib.rs#L40-L81) |
| 11 | サービス名付与と誤帰属の限界 | [tags/svchost_windows.go L53-80](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/process/tags/svchost_windows.go#L53-L80) / [connection_cache.rs L70-95](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/connection_cache.rs#L70-L95) |
| 12 | ライセンス・依存・driver release | [GPL-3.0](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/LICENSE#L1-L22) / [INF GPLv3+](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/PortmasterKext64.inf#L1-L18) / [driver Cargo](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/Cargo.toml#L13-L25) / [release](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/release/README.md#L1-L38) |
| 13 | AegisGuard現MVP、将来のresponse設計 | [architecture](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L8-L49) / [c2.rs](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L129-L167) |

Microsoft一次資料（公式仕様）：[WFP概要](https://learn.microsoft.com/en-us/windows/win32/fwp/about-windows-filtering-platform)、[Filter Arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration)、[Object Management / dynamic session](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)、[Filtering Conditions](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/filtering-conditions-available-at-each-filtering-layer)、[FwpmNetEventSubscribe0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmneteventsubscribe0)、[WFP Access Control](https://learn.microsoft.com/en-us/windows/win32/fwp/access-control)、[Driver Signing Options](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings)。

### 最終判定
**導入候補上位3件：** (1) P0/M: 読取専用の通信イベント・未知通信の事後通知（blocker: EID3設定・欠損/権限・ProcessGuid） (2) P0/M: ProcessGuid+PID+サービス帰属（blocker: shared PID・PID reuse・未知扱い） (3) P1/M: 承認付きアプリ別IP Firewall rule + 自動rollback（blocker: 管理者分離、GPO、IPv6、復旧保証）。

**見送り2件：** (1) Portmaster WFP kernel driverの転用 (2) 全通信hold/未知接続のfail-closed既定運用。どちらもAegisGuardの初期段階で採用しない。

**安全な最小PoC受け入れ基準：** Defender/Firewall変更なしで帰属付き観測、欠損を明示すること。その後の別PoCでユーザーが明示したAegisGuard専用ルールのみが適用/全回収できること。どちらも障害時のログと復元可能性を示すこと。
