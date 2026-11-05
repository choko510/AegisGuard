# 調査報告：Portmaster / portmaster-policy-dns

> 担当：portmaster-policy-dns / 調査日：2026-11-05 / 調査結果：ソース・テストの静的調査は完了、実機・法的評価は未完了

## 0. 結論（3〜5行）
- **取り入れる価値：高。** とくに「通信のプロセス帰属 → アプリ別設定 → 理由付き優先順位判定」「DNS観測の確度付き相関」「期限・失敗を管理するフィード更新」はAegisGuardのC2検知に適合する。
- **最優先候補：** Portmasterの判断順序を参照した、AegisGuard独自Rustの**監査専用**ポリシー評価器（S〜M）。次点はDNSとIPの**証拠付き**相関（M）、IOC更新の検証・ロールバック強化（M）。
- **見送り：** PortmasterのGoコアとGPL-3.0コードを直接リンク/移植すること、WFPカーネルドライバーまたはDNS横取りをMVPへ導入すること。
- **最大の制約：** DNSの名前と通信IPは一意対応ではない。さらにIntel更新インデックスの署名検証は、調査した起動設定では明示的に有効化されていない（後述）。これを「署名付きルール更新が保証される」と見なしてはならない。
- Defenderとの共存を前提に、**非特権・観測のみ → 計測・例外検証 → 管理者が明示承認した可逆的遮断候補**の順とする。現時点でブロックは実装しない。

## 1. 対象の固定と調査方法

| 要素 | 値 / 根拠 |
|---|---|
| 公式リポジトリ・commit固定URL | [safing/portmaster](https://github.com/safing/portmaster/tree/bffef134cd709d2a74295cd8450cf0c6231bd60d)、GitHubでデフォルトブランチ development と確認 |
| 調査コミットSHA・タグ | bffef134cd709d2a74295cd8450cf0c6231bd60d。このコミットへ全コード参照を固定。リリースタグとの同一性は未確認 |
| AegisGuardの比較先SHA | [choko510/AegisGuard](https://github.com/choko510/AegisGuard/tree/83fcf0d150e8d760baff5f971c106deb09c1f8e4) / main / 83fcf0d150e8d760baff5f971c106deb09c1f8e4 |
| ライセンス原文 | [Portmaster LICENSE GPL v3](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/LICENSE)（冒頭で GNU GENERAL PUBLIC LICENSE Version 3）。AegisGuardは [README.md L64-79](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md#L64-L79) で未設定 |
| ソース/ドキュメント確認範囲 | Portmaster README、Go依存、policy/profile/process/tags、DNS/resolver/cache、filterlists/geoip/updates、WFP Rustドライバー定義、複数の *_test.go、AegisGuard README/SECURITY/ARCHITECTURE/Cargo/src |
| 実機・ビルド・テスト | **未実施**。GitHubの固定ソースとテスト実装の静的確認のみ。Windows 11 VM、署名済みドライバー、Portmaster実行環境なし。外部の不明な実行物・悪性検体は実行していない |
| 調査日・制限 | 2026-11-05。実行時の真正性、DNS観測範囲、署名済みフィード、実際の通信遅延・負荷は要実測 |

**比較先の実態：** AegisGuardはRust CLIの静的PE/スクリプト検査と**手動更新・オフラインC2 IP照合**まで。[src/main.rs L1-80](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/main.rs#L1-L80)、[src/c2.rs L13-50](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L13-L50)。フィード状態はソースごとの成功日時と48時間の有効期限を持ち、更新失敗時に既存情報を保持する [src/c2.rs L60-170](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L60-L170) [src/c2.rs L215-330](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L215-L330)。プロセスイベント購読・DNS監視・Firewallルール作成は未実装 [docs/ARCHITECTURE.md L13-48](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L13-L48) [SECURITY.md L1-28](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md#L1-L28)。

## 2. 実装アーキテクチャとソース調査

### 2.1 コード根拠付き機能マップ

| 機能 | 主要ファイル/シンボルと入力 → 出力 | commit固定の一次情報 | 確認状態 |
|---|---|---|---|
| アプリ識別 | process.GetProfile → profile.GetLocalProfile。パス、MatchingPath、コマンドライン、環境変数、タグのフィンガープリントからプロファイルを選ぶ。複数候補はスコア競合通知 | [service/process/profile.go L17-42](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/process/profile.go#L17-L42) / [service/profile/fingerprint.go L12-102](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/profile/fingerprint.go#L12-L102) / [service/profile/get.go L191-250](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/profile/get.go#L191-L250) | 実装確認 |
| svchostとDNSサービス | svchost.exeのPIDからサービス名を読みタグ化。Dnscache特別扱い。複数サービス・識別失敗時の完全性は非保証 | [service/process/tags/svchost_windows.go L52-111](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/process/tags/svchost_windows.go#L52-L111) / [service/process/profile.go L62-106](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/process/profile.go#L62-L106) | 実装確認 |
| Storeアプリ識別 | WindowsAppsパスを分割し、アプリ名・Publisher IDをタグ化。ただしプロファイル構築は主にアプリ名タグであり真正な署名認証とは異なる | [service/process/tags/winstore_windows.go L60-118](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/process/tags/winstore_windows.go#L60-L118) | 実装確認 |
| 階層ポリシー | LayeredProfile.MatchEndpoint/MatchServiceEndpoint、DefaultAction。個別レイヤーを順に評価し、判断がなければグローバルへ | [service/profile/profile-layered.go L317-362](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/profile/profile-layered.go#L317-L362) | 実装確認 |
| ルール順序 | defaultDecidersを順に実行。最初の決定が勝つ。DNSRequestの最終デフォルトは許可 | [service/firewall/master.go L28-128](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/master.go#L28-L128) | 実装確認 |
| endpoint式 | Endpoints.Match は指定順に最初の非NoMatchを採用。domain/IP/CIDR/country/ASN/port/scopeのパーサーとテストあり | [service/profile/endpoints/endpoints.go L18-29](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/profile/endpoints/endpoints.go#L18-L29) / [service/profile/endpoints/endpoints.go L90-127](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/profile/endpoints/endpoints.go#L90-L127) / [service/profile/endpoints/endpoint_test.go L1-67](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/profile/endpoints/endpoint_test.go#L1-L67) | 実装・テスト確認 |
| OSレベル遮断 | WindowsはPortmasterのportmaster-kext.sysを取得、kext1/2起動、ドライバーへ判定を伝達。ALE v4/v6でプロセスID等を扱う | [service/firewall/interception/interception_windows.go L17-119](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/interception/interception_windows.go#L17-L119) / [windows_kext/driver/src/ale_callouts.rs L68-140](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/ale_callouts.rs#L68-L140) | 実装確認、動作未検証 |
| DNS横取り | 通常DNSの宛先ポート53、条件付きでPortmaster nameserverへreroute。**HTTPS上の任意DoHを解読する実装ではない** | [service/firewall/packet_handler.go L475-546](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/packet_handler.go#L475-L546) | 実装確認 |
| DNS/DoH/DoT | resolver URLの dns/dot/doh/tcp を解析。DoH はHTTPS GETでDNSメッセージを転送し、DoTはTLS付きTCP resolver | [service/resolver/resolvers.go L98-136](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/resolver/resolvers.go#L98-L136) / [service/resolver/resolver-https.go L58-135](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/resolver/resolver-https.go#L58-L135) / [service/resolver/resolver-tcp.go L89-115](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/resolver/resolver-tcp.go#L89-L115) | 実装確認 |
| IP ↔ DNS | DNS応答の A/AAAA、CNAME、HTTPS/SVCB hint を収集し、profileID別IPInfoに紐付け。DNS要求コンテキスト・期限・resolver情報を格納 | [service/firewall/dns.go L228-342](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/dns.go#L228-L342) / [service/resolver/ipinfo.go L32-75](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/resolver/ipinfo.go#L32-L75) / [service/resolver/ipinfo.go L103-190](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/resolver/ipinfo.go#L103-L190) | 実装確認 |
| DNSレコード削減・rebinding | DNS応答IPをスコープにより検査しブロック候補を除去。グローバルresolverがLAN/localhostを返す場合の判定あり | [service/firewall/dns.go L20-105](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/dns.go#L20-L105) / [service/firewall/master.go L450-472](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/master.go#L450-L472) | 実装確認 |
| ブロックリスト照合 | ドメイン、IPv4/IPv6、ASN、国をBloom filterで前段選別しDBレコードのsourcesを参照 | [service/intel/filterlists/bloom.go L15-120](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/intel/filterlists/bloom.go#L15-L120) / [service/intel/filterlists/lookup.go L11-120](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/intel/filterlists/lookup.go#L11-L120) | 実装確認 |
| フィード更新 | base/intermediate/urgent の適用順を解決。更新後の旧データ掃除が失敗するとoverblocking警告を発行 | [service/intel/filterlists/updater.go L65-175](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/intel/filterlists/updater.go#L65-L175) / [service/intel/filterlists/updater.go L179-240](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/intel/filterlists/updater.go#L179-L240) / [service/intel/filterlists/updater_test.go L10-118](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/intel/filterlists/updater_test.go#L10-L118) | 実装・テスト確認 |
| 更新の署名・整合性 | インデックス署名はtrustStore != nilの場合のみ検証。artifactはSHA256照合、**展開後ハッシュ照合の前に解凍** | [service/updates/index.go L151-179](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/updates/index.go#L151-L179) / [service/updates/downloader.go L198-221](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/updates/downloader.go#L198-L221) | 実装確認 |
| GeoIP | maxminddb-golangでIPv4/IPv6 DBを読み、国情報を付加。国/ASNによる自動遮断は精度・データ権利を別検証すべき | [service/intel/geoip/lookup.go L1-39](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/intel/geoip/lookup.go#L1-L39) / [service/intel/geoip/database.go L152-199](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/intel/geoip/database.go#L152-L199) | 実装確認 |
| DoH迂回対策 | port 53/853、既知DNSリゾルバーリスト、Firefox canary名を利用。全てのDoH/QUICを識別するわけではない | [service/firewall/bypassing.go L10-104](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/bypassing.go#L10-L104) | 実装確認、網羅性未証明 |

### 2.2 ポリシーの**実際の**決定順序と例外

[service/firewall/master.go L28-128](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/master.go#L28-L128) の defaultDeciders は次の順番で最初に判定できたものを採用する。

1. Portmaster自身、ブロードキャスト応答などの特例
2. 接続タイプ（P2P/Inbound等）、接続スコープ（Internet/LAN/localhost）
3. endpointルール（外向き MatchEndpoint、内向き MatchServiceEndpoint）
4. 不正IP、リゾルバーのスコープ、接続性確認用ドメイン
5. DNS迂回抑止、通常フィルターリスト、カスタムリスト
6. ドメイン・ヒューリスティクス、関連ドメインの自動許可
7. 該当なしなら既定動作。**DNS要求だけは特別に既定許可**（DNS応答等で追加チェックを行う前提）

これは「アプリの許可はすべてのブロックより優先」ではない。例えばInternetスコープ遮断は個別endpoint許可より先に評価され、一方endpoint許可は後続リスト遮断より先に評価される。グローバル/個別の同一設定では個別レイヤーが先にマッチし、該当なしの場合のみグローバルに落ちる [service/profile/profile-layered.go L330-346](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/profile/profile-layered.go#L330-L346)。**フィルターリスト集合は単純な和集合ではなく、最初に明示設定されたレイヤーが採用される** [service/profile/profile-layered.go L430-455](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/profile/profile-layered.go#L430-L455)。同じ規則集合内は**記述順優先** [service/profile/endpoints/endpoints.go L90-127](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/profile/endpoints/endpoints.go#L90-L127)。

**例外とfail behavior：** 未識別プロセス・プロファイルは deny [service/firewall/master.go L46-57](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/master.go#L46-L57)。endpoint評価エラーもdeny [service/firewall/master.go L203-236](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/master.go#L203-L236)。system resolverのDNS要求は要求元が分からないためローカルプロファイルのendpointのみ先に確認し、元プロセスが分かる段階で追加フィルタする設計 [service/firewall/master.go L238-270](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/master.go#L238-L270)。更新に伴う判定revisionの再評価あり [service/firewall/master.go L57-84](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/master.go#L57-L84)。Portmaster由来の許可やpre-authenticated接続もある [service/firewall/packet_handler.go L475-520](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/packet_handler.go#L475-L520)。これらの例外を単純コピーすると監視漏れを作るため、AegisGuardでは必ず「理由」と「確度」を残す。

### 2.3 DNS相関の限界・誤遮断シナリオ

- **DNSキャッシュとCDN：** IPInfoは「直近にそのIPを引いた名前」を保持するが、同一IPが複数ドメインをホストする。[service/resolver/ipinfo.go L103-147](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/resolver/ipinfo.go#L103-L147) の MostRecentDomain は悪性ドメインの**証明ではない**。接続先IPだけで名前を確定して一括遮断しない。
- **TTLの違い：** RRCache.Cleanは応答中のTTLを17へ書き換え、別途cache期限を計算 [service/resolver/rrcache.go L53-105](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/resolver/rrcache.go#L53-L105)。IPInfoはDB保持期限を最低1日+1時間の余裕として計算 [service/resolver/ipinfo.go L181-208](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/resolver/ipinfo.go#L181-L208)。**DBに残っている事実と現在も有効なDNS対応であることは別**。AegisGuardはDNS応答TTL、観測時刻、IOC TTLを個別管理し、古い対応は確度を落とす。
- **A/AAAA/HTTPS/SVCB：** IPv6/HTTP service binding のヒントも収集している [service/firewall/dns.go L250-301](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/dns.go#L250-L301)。ヒントは実際に当該名前へ接続した証拠ではない。Happy Eyeballs、CNAME、DNS先行取得、ブラウザーキャッシュの例外を考慮。
- **DoH・DoT・QUIC/ECH：** ポート53の横取りや53/853の防止策では、443経由の独自DoH・HTTP/3上の暗号化通信、ECHの内部ホスト名は一般に見えない [service/firewall/bypassing.go L10-104](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/bypassing.go#L10-L104)。**「観測なし」≠「DNS利用なし」**。TLS SNIや宛先IPからドメイン断定しない。
- **リバインディング/スプリットDNS：** resolverのネットワークスコープと返却IPのスコープが矛盾する場合を扱う [service/firewall/master.go L450-470](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/master.go#L450-L470) が、企業VPNの社内DNS・NRPT・Split Horizonを一律危険視すると正規通信を壊す。
- **プロセス帰属：** system DNS resolverは複数アプリの問い合わせを扱い、元プロセス不明の事象がある [service/firewall/master.go L238-270](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/master.go#L238-L270)。DNSの観測を通信元EXEの確定的証拠に変換しない。
- **ローカル通信：** HostLocalをIPInfoに保存しない [service/firewall/dns.go L312-342](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/dns.go#L312-L342)。ループバック/LinkLocal/LAN/multicastをC2パブリックIP候補と混同しない。

### 2.4 更新・署名・フィード相互作用の重要な発見

1. **署名の有無：** [service/updates/index.go L151-165](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/updates/index.go#L151-L165) の ParseIndex は trustStore が非nilの時だけ署名検証する。起動入口 [cmds/portmaster-core/main.go L93-109](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/cmds/portmaster-core/main.go#L93-L109) は VerifyBinaryUpdates に信頼ストアを設定する一方、**VerifyIntelUpdatesを設定していない**。[service/config.go L16-28](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/config.go#L16-L28) [service/config.go L126-155](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/config.go#L126-L155) でIntelのVerifyにはその未設定値が渡る。従って**調べた標準起動経路ではIntelインデックス署名が必須とは読み取れない**。別の起動方法・配布時補強は未確認。バイナリ署名の存在をIntelフィードへ外挿しない。
2. **ハッシュは署名の代替ではない：** [service/updates/downloader.go L198-221](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/updates/downloader.go#L198-L221) のSHA256は取得したインデックスが指定する値と一致するかを調べる。インデックスを信頼できない場合、配布物の出所認証にはならない。しかも解凍はハッシュ照合より先で、解凍サイズ・メモリ上限の実測/監査が必要。
3. **旧リストの誤遮断対策：** base更新後に旧エントリをpurgeし、失敗すると「Filter Lists May Overblock」警告を発行してDBバージョン更新を止める [service/intel/filterlists/updater.go L133-174](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/intel/filterlists/updater.go#L133-L174)。AegisGuardでも「更新成功・鮮度正常」だけでなく**データ移行完全性**を別ステータスにする。
4. **実効ポリシー競合：** 先にendpointが許可するとリスト拒否へ到達しない [service/firewall/master.go L203-236](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/master.go#L203-L236) [service/firewall/master.go L422-449](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/master.go#L422-L449)。unbreakフィルターはリストのブロックを無効化できる [service/firewall/master.go L422-449](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/master.go#L422-L449)。AegisGuardではC2 IOC、個別allowlist、プロセス識別不確実性を監査証跡で同時表示する。
5. **GeoIP/リストの権利：** [service/intel/filterlists/index.go L43-83](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/intel/filterlists/index.go#L43-L83) は外部SourceごとのURLとLicenseフィールドを持つ。ソース自体がGPLという意味ではない。実際の配布index・フィード個別利用規約・GeoIP DBの契約は未取得のため**同梱可否は未確認**。

## 3. 具体的な取り込み候補と選択肢

| 候補機能 | 利用方法（crate/API・外部CLI・独自実装・参考・見送り） | AegisGuard接続先 | 優先度 | 工数目安 | ライセンス・技術上の阻害要因 |
|---|---|---|---|---|---|
| **①監査専用ポリシー評価器** | **独自実装（Rust）＋設計参考** | 将来の aegis-core/policy、JSONL監査 | **P0** | **M** | 優先順位の仕様化、例外テスト、誤判定 |
| **②DNS→IP相関（確度付き）** | **独自実装（Rust）＋設計参考** | 将来の windows-sensor / dns-correlation | **P1** | **M** | Windowsイベント取得の可否、ブラウザーDoH不可視、プライバシー |
| **③フィード更新トランザクション** | **独自実装（Rust）＋設計参考** | 現在の src/c2.rs → 将来の intel-store | **P1** | **M** | フィード個別ライセンス、署名鍵管理、DB移行 |
| Windowsアプリ識別改善 | **独自実装（Rust）** | windows-sensor/process-identity | P1 | M | Authenticode/API、サービスPID帰属、Package Family Name |
| WFP ALE read-only診断 | **Windows OS APIの利用検討**（Portmaster crateではない） | windows-sensor/net-observe | P2 | L | 管理者権限とドライバー設計/Defender共存の検証 |
| PortmasterのGUI/APIから観測値を受け取る | **外部サービス連携**、参考段階 | オプション連携 adapter | P3 | M | APIの契約・認証・永続性未検証、Portmaster導入依存 |
| PortmasterのGoロジックをRustから直接呼ぶ | **crate/API直接利用：不採用** | なし | — | L | PortmasterはGoモジュール、Rust crateとして提供されない。GPL-3.0、密結合 |
| Portmaster WFPドライバーの再利用/改変 | **見送り** | なし | — | L | GPL-3.0確認・WDK/署名・カーネル攻撃面・Defender競合 |
| DNS53強制転送 / DoH一律遮断 | **見送り** | なし | — | L | VPN/NRPT/企業DNS/独自DoH/QUICとの互換性、誤遮断 |

**採用候補の入出力・失敗時の扱い：**

**① policy/evaluate：** 入力は process_identity{pid,process_start_time,process_guid?,image_path,sha256?,signer?,package_family_name?,services[],identity_confidence}、destination{ip,port,protocol,direction,scope,domain_evidence[]}、policy_revision、now。出力は decision{action: audit_allow|audit_flag|block_candidate|unknown, matched_rule_ids[], overridden_rule_ids[], reason_codes[], confidence, policy_revision}。初期は**監査専用**でOSへ遮断を返さない。データ欠損/帰属失敗は unknown+reason として明示。PoCは合成のルール競合・scope・無効ルール・更新中のrevision変更を決定論的に単体試験する。

**② dns-correlation：** 入力は dns_observation{timestamp,query_name,rrtype,answers,cnames,svcb_hints,ttl,resolver,process_identity?,source} と net_event{time,process_identity?,dst_ip,dst_port,protocol}。出力は domains_with_evidence[]{domain,source,first_seen,last_seen,expires_at,confidence,shared_ip_ambiguity}、warnings[]。タイムウィンドウ内の同一プロセス・resolver条件が成立する場合だけ強い関連とし、DNS不明なら**IP IOCの照合のみ**継続。悪性通信の確定・自動遮断に使わない。PoCはA/AAAA、CNAME循環、TTL切れ、DNS未取得、CDN共有IP、IPv6をsynthetic fixtureで検証する。

**③ intel/update：** 入力は feed_manifest{source_id,url,revision,published_at,ttl,license,expected_sha256,signature?,signing_key_id?,format} とIP/ドメインIOC。出力は staged_snapshot{validation_results,per_source_last_success_at,expiry,hash,record_count}、active_snapshot_revision、rejected_reason。**HTTPSだけではなく**署名済みマニフェストと鍵ピンニングの採否を別途設計、未署名ソースは監査用のみに区分。空HTML・異常件数・欠落・タイムスタンプ逆行・重複・高頻度更新は旧状態保持し、更新失敗を新規成功として扱わない。PoCはオフラインの固定フィードから一時DBへ書いて検証後に切替、故障注入で旧状態復元。

**既存AegisGuardとの接続契約（提案スキーマ、未実装）：**

~~~json
{
  "schema_version": 1,
  "event_id": "opaque-id",
  "observed_at_utc": "ISO-8601",
  "process": {
    "pid": 1234,
    "start_time_utc": "ISO-8601",
    "process_guid": null,
    "image_path": "C:\\Program Files\\Example\\app.exe",
    "image_sha256": null,
    "signer": null,
    "package_family_name": null,
    "service_names": [],
    "identity_confidence": "unknown"
  },
  "destination": {
    "ip": "203.0.113.8",
    "port": 443,
    "protocol": "tcp",
    "direction": "outbound",
    "network_scope": "documentation",
    "domains": []
  },
  "indicators": [
    {
      "type": "ip",
      "value": "203.0.113.8",
      "source_id": "example-only",
      "observed_at_utc": "ISO-8601",
      "expires_at_utc": "ISO-8601",
      "fresh": false
    }
  ],
  "assessment": {
    "status": "unknown",
    "action": "audit_only",
    "reason_codes": ["synthetic_fixture"],
    "policy_revision": "draft-1",
    "confidence": "unknown",
    "block_candidate": false
  }
}
~~~

上記は**架空データのスキーマ例**でIPは文書用予約範囲。実測観測値ではない。JSONLにする場合、ローカルのパス・サービス・DNS名称は個人情報になり得るためアクセス制御、保持期間、匿名化、サイズ上限が必要。将来のSysmon ProcessGuidが取得できなければPID+開始時刻+イベント時刻で相関し、PIDだけの一致は強い根拠にしない [docs/ARCHITECTURE.md L24-40](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L24-L40)。

## 4. ライセンス・再配布・依存関係

| コンポーネント | 一次情報・確認結果 | AegisGuardへの判断 |
|---|---|---|
| Portmaster Goコア・一般ソース | ルート [LICENSE L1-40](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/LICENSE#L1-L40) はGPL-3.0原文。Go本体は [go.mod L1-95](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/go.mod#L1-L95) 参照 | **設計のみ参考**。Goロジックのコピー、静的/動的リンク、変換移植、同梱は権利・義務の法的評価未完了。原則行わない |
| Portmaster Rust WFPドライバー | [windows_kext/driver/Cargo.toml L1-25](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/Cargo.toml#L1-L25) はRust staticlib、ローカルWDK/protocolと固定windows-sysに依存。ルートLICENSE以外の独立許諾は今回未確認 | **移植・配布しない**。Rust製＝組込み可という意味ではない。署名/WDK依存も大きい |
| DNS/政策/フィルターのソース部分 | 同リポジトリにありGPL-3.0の対象と扱うのが保守的（個別例外の探索は未完了） | API概念/アルゴリズム案を参考に**クリーンな独自設計**。一行単位のコード転用をしない |
| リスト配布物・カテゴリ/ルール | [service/intel/filterlists/index.go L43-84](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/intel/filterlists/index.go#L43-L84) のSource.Licenseは**ソース別に可変**。実際の配布インデックスと一次提供元契約は今回未取得 | **同梱・再配布しない**。個々の許諾と更新署名、商用可否、改変再配布範囲を調査するまで参考のみ |
| GeoIP DB | [service/intel/geoip/lookup.go L1-39](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/intel/geoip/lookup.go#L1-L39) はmaxminddb-golangで読んでいるが、DB自体の権利・提供元条件はこのファイルから確定できない | データをコピーしない。DB提供者・契約・更新元・保持条件を別確認 |
| AegisGuard | [README.md L69-79](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md#L69-L79) にライセンス未設定と記載 | **GPL互換を前提とした結合を決めない。法的評価未完了**。外部CLI/サービス分離も「常に安全」ではなく個別評価が必要 |

依存関係：Portmaster中核はGo 1.26、主な関連直接依存は miekg/dns、maxminddb-golang、safing/jess、tannerryan/ring、sqlite等 [go.mod L1-85](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/go.mod#L1-L85)。Windowsドライバーは別Rust staticlib + WDK/protocol + smoltcp + pinned windows-sys。これらをまとめて「Rust crate/API直接利用」と評価できない。第三者依存やフィード提供者の個別ライセンス、実際のビルドSBOM、パッケージ内の著作物は別途監査する。

## 5. Defender共存・Windows制約・権限境界

- **現行AegisGuardはDefender併用CLI**で、ネットワーク遮断機能は存在しない [SECURITY.md L1-30](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md#L1-L30)。Defender、AMSI、ASRの権限・設定を変更しない。
- PortmasterはWFPカーネル拡張からパケット/コネクションへ介入する [service/firewall/interception/interception_windows.go L17-119](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/interception/interception_windows.go#L17-L119)。ALE識別はプロセスIDとv4/v6アドレス等 [windows_kext/driver/src/ale_callouts.rs L68-140](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/ale_callouts.rs#L68-L140)。WindowsのWFP ALEはアプリケーションIDとユーザーIDでフィルターできることがMicrosoft公式で説明される（[ALE](https://learn.microsoft.com/en-us/windows/win32/fwp/application-layer-enforcement--ale-), [WFP overview](https://learn.microsoft.com/en-us/windows/win32/fwp/about-windows-filtering-platform)）。Windows Firewall/Defender Firewall等の既存WFPポリシーとの裁定・優先順位はOSが扱うため**独自レイヤーが「必ず最終許可」とは限らない**。
- Windows 11 x64ではサービス登録・ドライバー読み込み・ポリシー変更には適切な管理者権限と署名/インストール要件が必要。Portmaster Windowsドライバーは実際に[WDKとテスト署名に関する開発要件](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/README.md#L16-L65)を記す。**本調査ではドライバーをインストール・起動しない**。
- AegisGuardで最初に使うのは読み取り専用Sysmon Event 1（プロセス）/3（ネットワーク、構成依存）やETW/WFP由来イベントの可能性を比較する段階。AMSIはスクリプト側の別レイヤーでDNSやWFPの代替ではない。SysmonとETWのイベント欠落・権限・初期設定/有効化状況は他担当が確認する。
- **VPN/WSL2：** トンネル化、NAT/仮想NIC、名前空間やプロセス帰属のずれがあるため、ゲストアプリの通信をホスト上のVPN・vmmem・svchostへ誤帰属し得る。WSL2・Hyper-V・VPN併用の網羅的テストは未実施。直接アクセス不能な場合はprocess_identity=unknownとしてログし、ドメイン由来の自動遮断をしない。
- **Windows Store：** WindowsAppsのフォルダ名タグはコード上存在するが、パッケージ・署名の真正性までは示さない。Windows公式WFPにはPackage Family Name等の条件もある（[filtering conditions](https://learn.microsoft.com/ja-jp/Windows/Win32/fwp/filtering-conditions-available-at-each-filtering-layer)）。AegisGuardはパッケージIDと署名検証を別情報として保持。
- **svchost：** 同一PIDに複数サービスが存在し得る。Portmasterは列挙したサービス名タグを付ける [service/process/tags/svchost_windows.go L52-111](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/process/tags/svchost_windows.go#L52-L111)。単一サービスを通信発生源と断定しない。
- **ローカル通信：** loopback、LAN、DNS Proxy、mDNS、企業NRPT、DNSリバインディングを区別。許可や可視性の欠落について別ステータスを残す。WindowsクライアントのDoH/NRPT設計は[Microsoft DNS DoH/NRPT](https://learn.microsoft.com/ja-jp/windows-server/networking/dns/doh-client-support)参照。
- **失敗時：** AegisGuardは常時保護者ではなく調査ツール。将来のセンサーが停止してもDefenderと既存Firewallを残し、AegisGuard独自の拒否候補は期限切れ・異常時に自動反映しない。管理者承認のFirewall変更は名前空間、ルール上限、復旧ログ、期限と一括巻き戻しが必須。

## 6. 性能・堅牢性・誤検知

| リスク | ソース・根拠 | AegisGuardの緩和案 |
|---|---|---|
| ルール照合/プロファイル探索 | [service/profile/get.go L192-230](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/profile/get.go#L192-L230) には全プロファイル走査が高コストかもしれないというTODO。[service/intel/filterlists/bloom.go L15-116](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/intel/filterlists/bloom.go#L15-L116) はBloom前段選別 | ルールをコンパイル済み構造へ、インデックス・キャッシュ上限、更新時差し替え、ベンチ必須 |
| DNS→IP誤帰属 | [service/resolver/ipinfo.go L103-147](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/resolver/ipinfo.go#L103-L147) はIPごと複数ドメインと直近を保持 | IP共有/CDN/TTL失効/欠損なら弱証拠。DNS名を使う遮断を禁止 |
| DNSキャッシュの長期保持 | [service/resolver/ipinfo.go L181-208](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/resolver/ipinfo.go#L181-L208) はDBの最短保持がDNS応答TTLより長い | TTL内の観測と履歴保存を別フィールドにする |
| フィード更新の差分不整合 | [service/intel/filterlists/updater.go L133-174](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/intel/filterlists/updater.go#L133-L174) は古いエントリ残存の過遮断警告を持つ | 原子的なスナップショット、有効期間、検証後切替、旧版復元 |
| フィード改ざん | [service/updates/index.go L151-160](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/updates/index.go#L151-L160) は検証用信頼ストアを任意にできる | 強制署名/鍵ピンニングを将来のブロック候補ソースへ、未署名は監査用途 |
| 展開前検証の欠如 | [service/updates/downloader.go L198-221](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/updates/downloader.go#L198-L221) に解凍してからSHA検証するTODOあり | 入力バイト・展開バイト・比率・CPU時間・entry件数を上限付きに |
| 誤許可/誤遮断 | [service/firewall/master.go L28-128](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/master.go#L28-L128) は順序と例外で決まる | 決定順序に加えて全一致候補を監査ログへ保存。allowlistを過度に信用しない |
| 暗号化DNS/通信 | [service/firewall/bypassing.go L10-104](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/bypassing.go#L10-L104) はポートと既知リスト方式 | 443/HTTP3/ECHを解析済みと誤表示しない。unknownを保持 |
| CPU/メモリ/ディスク | パケットごとの処理、リストDB、GeoIP、DNS保存等が発生 | シミュレーション時の入力件数・p95/p99評価時間、最大RSS、JSONL増分を記録。**数値目標/実測値は未設定・未取得** |
| プライバシー | プロセスpath, DNS domain, CMD line, remote IPが機微情報になる | ローカル限定、既定で外部送信なし、ACL、保持期間、コマンドライン既定非収集 |

**テストを実際に読んだ範囲：** [service/profile/endpoints/endpoint_test.go L1-70](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/profile/endpoints/endpoint_test.go#L1-L70) にIPv6/CIDR/ドメイン/ポートのパース事例、[service/profile/fingerprint_test.go L1-57](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/profile/fingerprint_test.go#L1-L57) にフィンガープリント順序を並べ替えても同じIDを導く確認、[service/intel/filterlists/updater_test.go L10-117](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/intel/filterlists/updater_test.go#L10-L117) に更新順序のテーブル駆動テスト、[service/updates/index_test.go L1-65](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/updates/index_test.go#L1-L65) にパストラバーサル/NTFS ADSを含むartifact名テスト、[service/firewall/preauth_test.go L1-63](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/preauth_test.go#L1-L63) に一回限りのpre-authポート、[service/intel/geoip/database_test.go L1-83](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/intel/geoip/database_test.go#L1-L83) にDBファイル置換、[service/resolver/rrcache_test.go L1-47](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/resolver/rrcache_test.go#L1-L47) にキャッシュ読み書きのテストを確認。**テストの存在と成功は同義ではない**。go test、Rust driver build、Windows実機は未実行。特に完全なdecider順序×VPN/WSL×DoH迂回の結合テストが十分かは未確認。

## 7. 推奨する小さなPoCと成功基準

**上位3件（優先度／工数／ブロッカー）**
1. **P0 / M：純Rust・監査専用ポリシー評価器**。ブロッカー：仕様に明文化した判定順・プロセス識別・例外テストが必要。既存Firewallへの書込みなし。
2. **P1 / M：DNSとIPの証拠付き相関モジュール**。ブロッカー：Windows 11での安全な観測経路、帰属失敗、DNS暗号化時の欠損処理。自動遮断なし。
3. **P1 / M：IOCの署名/検証/原子的更新の監査モデル**。ブロッカー：データソースのライセンスと鍵管理、アクティブ/ステージング切替の回復設計。

**前提：** Windows 11でDefender有効のまま開発用VMを使用（ただし本PRではまだ実機実験しない）。本体の管理者設定変更、ドライバー導入、DNSリダイレクト、Firewall変更なし。RustでPoCを実装するのは**後続タスク**。

**安全なサンプル/検証方法：** 予約ドメイン（example.com、.test）と文書用IPv4/IPv6、合成プロセス・サービス・PID再利用・DNS応答・期限付きフィードを使う。外部通信や危険検体を必要としない。ルールの順序、scope blockとendpoint allowの競合、個別/グローバル優先、filterlist上書き、CNAMEループ、再割当IP、古いDNS証拠、壊れたマニフェスト/署名、更新失敗を試す。

**受け入れ基準（測定可能、未達/達成は本調査で未判定）：**
- 同じ入力と設定revisionから常に同じ監査判定が得られ、理由コード・適用/見送り規則・不明理由を復元可能。
- データ不足/PID再利用/共有IP/DoH不可視は「安全」「悪性確定」に丸めず unknown/confidence lowered を出す。
- AegisGuardによるOS側の遮断・DNS経路変更・ドライバー起動が**0件**で、Defender/Windows Firewall設定が実験前後で不変。
- フィード検証失敗/TTL失効/署名異常時に活性スナップショットが不正に新しくならず、stale/partial/invalidを判別可能。
- 監査イベントで失われた件数・欠落理由、イベント処理時間（p50/p95/p99）、RSS、JSONL容量、CPU、復旧時間を実測で提出。**現段階で性能数値を捏造しない**。
- CIは少なくとも合成テストでIPv4/IPv6、DNS、ルール競合、ライフタイム、リスト更新失敗、限界入力を再現できる。

**失敗時の扱い・ロールバック：** PoC機能は無効が初期値。観測モジュール異常時は停止して明示アラートを出し、元のC2 CLI機能を維持。更新中の異常は旧スナップショットを保持。将来有効化するFirewall機能は別PR・管理者承認・名前空間限定・期限付き復旧試験を要する。

**中止条件：** Defender/他社ネットワーク製品が阻害される、取得権限が想定外に増える、DNS漏洩や企業VPN障害、誤遮断、観測データ欠落を検知できない、更新データの真正性を保証できない、ライセンス未解決でコード同梱を要する場合。

## 8. 採用しない設計と理由

1. **Portmaster Goコア/Windows WFP RustドライバーをそのままAegisGuardへ移植・直接組み込み：不採用。** Go+カーネル拡張への依存、GPL-3.0の再配布上の検討、署名・権限・保守負担がAegisGuardのRust-first/Defender共存MVPに不適切 [windows_kext/README.md L16-65](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/README.md#L16-L65)。Portmasterと別サービスで接続する案は**読み取り専用かつ安定APIと権利条件の確認後**の参考評価に限る。
2. **DNS53透過リダイレクト、DoH/DoTの無条件遮断、IP⇔ドメインの単一確定をMVPへ採用：不採用。** VPN/企業DNS/WSL/ローカルサービスや共有CDN IPを壊し得る。Encrypted DNS/ECH/QUICについて過大な検知保証も生む [service/firewall/packet_handler.go L495-546](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/packet_handler.go#L495-L546) [service/firewall/bypassing.go L10-104](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/bypassing.go#L10-L104)。
3. **GeoIPの国単位拒否をC2確定判定に利用：見送り。** CDN/Anycast/VPN/地理DB誤差と権利条件が未解決。GeoIPは文脈データとしてのみ保持。
4. **Portmaster配布のブロックリストを無条件でAegisGuardに同梱：見送り。** sourceごとのLicense未確認、配布index署名設定の未確認が残る。

## 9. 他担当との境界・引継ぎ

- **Windowsイベント担当：** Sysmon Event 1/3、ETW/WFPの正確なプロセス帰属、PID再利用・サービス・Package Family Name、イベント欠落と権限。こちらでは取得センサーのコード/ドライバーは実装しない。
- **C2/IOCフィード担当：** Feodo/C2Intelの配布条件、sourceごとの失効・信頼レベル・Allowlist、署名鍵/更新失敗の横断仕様。既存 [src/c2.rs L13-50](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L13-L50) から拡張。
- **Firewall/レスポンス担当：** 管理者承認、WFP/Windows Firewallルール所有権、復旧・rollback、Defender共存、ログ。こちらは候補までで強制執行しない。
- **DNS/ネットワーク担当：** DoH/DoT/HTTPS/SVCB、NRPT/企業VPN、WSL/Hyper-V、IPv6、QUIC/ECH、レコード相関の確度実測。
- **ライセンス/サプライチェーン担当：** Portmaster GPL-3.0、intelhub/source-list/GeoIPの個別許諾、配布indexの実際の署名とコード入口以外の構成、更新時の署名強制を確認。

## 10. 未確認事項・追加調査項目

1. **重大：** Intelインデックスが実配布物では署名必須なのか。[cmds/portmaster-core/main.go L93-109](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/cmds/portmaster-core/main.go#L93-L109) と [service/config.go L145-155](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/config.go#L145-L155) だけでは標準起動経路で必須と認められない。公開Intel indexの実バイト・署名検証・代替entrypoint等は未確認。ハッシュのみで出所認証したと主張しない。
2. **重大：** PortmasterルートGPL-3.0以外のサブコンポーネント、third-partyデータ/source-license、GeoIP原データ、Intel listの同梱/再配布権。法的評価未完了。
3. **高：** Windows 11 x64 + Defender有効 + Windows Firewall + WFPドライバー同居時の性能・競合・失敗復旧。実機/CI実行なし。
4. **高：** Windows Storeアプリとsvchost同居サービス、WSL2、VPN/NRPT、仮想NIC、プロセス消滅直後の帰属精度。実環境証跡なし。
5. **高：** DNS53以外、ブラウザーDoH、DoT、QUIC/HTTP3、ECH、CDN・共有IP、IPv6の観測漏れ・偽陽性・失敗時の扱い。完全網羅は保証できない。
6. **中：** 正式タグ/リリースとdevelopment SHAの差分、実際のテスト成功状況（go test/ドライバーcargo test未実施）、実装全体のファジング/性能測定。
7. **中：** Portmaster APIの契約・認可・安定性、外部連携が製品利用規約上適切か。選択的連携は候補に留める。

## 11. 一次情報一覧

参照日：**2026-11-05**。以下はすべてPortmaster bffef134cd709d2a74295cd8450cf0c6231bd60d またはAegisGuard 83fcf0d150e8d760baff5f971c106deb09c1f8e4 の**コミット固定**permalink。主要判断と根拠は各節の近傍にも添付。

1. アプリ識別重み・マッチ：[service/profile/fingerprint.go L12-102](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/profile/fingerprint.go#L12-L102)、[service/profile/get.go L191-250](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/profile/get.go#L191-L250)、テスト [service/profile/fingerprint_test.go L1-57](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/profile/fingerprint_test.go#L1-L57)
2. Windowsサービス/Store特殊識別：[service/process/tags/svchost_windows.go L52-111](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/process/tags/svchost_windows.go#L52-L111)、[service/process/tags/winstore_windows.go L60-118](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/process/tags/winstore_windows.go#L60-L118)
3. 判定器の順序とfail behavior：[service/firewall/master.go L28-128](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/master.go#L28-L128)、[service/firewall/master.go L203-270](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/master.go#L203-L270)
4. レイヤー/リスト優先：[service/profile/profile-layered.go L317-362](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/profile/profile-layered.go#L317-L362)、[service/profile/profile-layered.go L430-455](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/profile/profile-layered.go#L430-L455)、[service/profile/endpoints/endpoints.go L90-127](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/profile/endpoints/endpoints.go#L90-L127)
5. DoH/DoTと迂回対策：[service/resolver/resolver-https.go L58-135](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/resolver/resolver-https.go#L58-L135)、[service/firewall/bypassing.go L10-104](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/bypassing.go#L10-L104)、[service/firewall/packet_handler.go L475-546](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/packet_handler.go#L475-L546)
6. DNSレコード・IP関連・期限：[service/firewall/dns.go L228-342](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/dns.go#L228-L342)、[service/resolver/ipinfo.go L103-208](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/resolver/ipinfo.go#L103-L208)、[service/resolver/rrcache.go L53-105](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/resolver/rrcache.go#L53-L105)
7. Intelフィルター/GeoIP：[service/intel/filterlists/lookup.go L11-120](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/intel/filterlists/lookup.go#L11-L120)、[service/intel/filterlists/index.go L43-84](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/intel/filterlists/index.go#L43-L84)、[service/intel/geoip/lookup.go L1-39](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/intel/geoip/lookup.go#L1-L39)
8. 更新順序・異常復旧・テスト：[service/intel/filterlists/updater.go L65-174](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/intel/filterlists/updater.go#L65-L174)、[service/intel/filterlists/updater_test.go L10-117](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/intel/filterlists/updater_test.go#L10-L117)
9. インデックス署名の条件と実際の入口：[service/updates/index.go L151-179](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/updates/index.go#L151-L179)、[cmds/portmaster-core/main.go L93-109](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/cmds/portmaster-core/main.go#L93-L109)、[service/config.go L126-155](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/config.go#L126-L155)
10. SHA256/解凍順・安全テスト：[service/updates/downloader.go L198-221](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/updates/downloader.go#L198-L221)、[service/updates/index_test.go L1-65](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/updates/index_test.go#L1-L65)
11. Windowsカーネル構成：[service/firewall/interception/interception_windows.go L17-119](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/service/firewall/interception/interception_windows.go#L17-L119)、[windows_kext/driver/src/ale_callouts.rs L68-140](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/src/ale_callouts.rs#L68-L140)、[windows_kext/driver/Cargo.toml L1-25](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/windows_kext/driver/Cargo.toml#L1-L25)
12. 依存・GPL-3.0原文：[go.mod L1-85](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/go.mod#L1-L85)、[LICENSE](https://github.com/safing/portmaster/blob/bffef134cd709d2a74295cd8450cf0c6231bd60d/LICENSE)
13. 比較先：[src/c2.rs L13-50](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L13-L50)、[src/c2.rs L215-330](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/c2.rs#L215-L330)、[src/model.rs L1-75](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/model.rs#L1-L75)、[docs/ARCHITECTURE.md L12-66](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L12-L66)、[SECURITY.md L1-30](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md#L1-L30)
14. Windows一次資料：[Microsoft WFP](https://learn.microsoft.com/en-us/windows/win32/fwp/about-windows-filtering-platform)、[ALE](https://learn.microsoft.com/en-us/windows/win32/fwp/application-layer-enforcement--ale-)（いずれも2026-11-05閲覧）、[DoH/NRPT](https://learn.microsoft.com/ja-jp/windows-server/networking/dns/doh-client-support)。

**確認状態の総括：** コードの関数・制御順・テスト定義・ライセンス原文は静的確認済み。テスト結果、Windows実機、更新indexの署名強制、外部データ権利、誤遮断率と負荷の数値は**未確認**。