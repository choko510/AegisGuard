# 調査報告：ConfigureDefender / configuredefender-asr

> 担当：`configuredefender-asr`（Defender設定監査・ASR/クラウド保護・設定の安全性） / 調査日：2026-11-05 / 調査結果：**部分完了**（旧版の実コードと現行配布・公式資料は確認。現行4.1系の圧縮ソースとWindows実機は未検証）

## 0. 結論（3〜5行）

- **取り入れる価値は高いが、ConfigureDefenderのバイナリ・AutoItコードを直接組み込む案は採らない。** Defender設定の読み取り専用健全性監査、ASRルールとイベントの対応付け、設定の管理主体と変更リスクの可視化が中心となる。
- **最優先は`Get-MpComputerStatus` + `Get-MpPreference`による状態スナップショット（P0/S）、Defender OperationalログのASR/CFAイベント相関（P0/M）、Microsoft一次情報に基づくルール/設定カタログと差分表示（P1/M）。**
- 旧版の実ソースには、**設定画面の初期化時にもレジストリ変更、ASR除外のポリシーキー削除**を行いうる経路が存在する。製品の「監査」と「防御設定の変更」は厳格に分離する。
- 現行4.1.0.0の配布元`License.txt`は**無改変・非販売の再配布**を記載するが、自由な改変・コード転用許諾ではない。歴史的な第三者ミラーのMIT表記は原著作者の許諾を証明しない。**法的評価未完了**。
- Windows 11実機、現行ソース、既存ポリシーとの競合、性能・誤検知率は未検証。防御設定を勝手に変更せず、将来の変更機能もユーザーの明示承認・監査モード・原状復帰可能性を前提にする。

## 1. 対象の固定と調査方法

| 要素 | 値 / 根拠 |
|---|---|
| 公式配布リポジトリ・commit固定 | [AndyFul/ConfigureDefender @ `04163467957211587914f993f0799681e98d9b57`](https://github.com/AndyFul/ConfigureDefender/tree/04163467957211587914f993f0799681e98d9b57)（デフォルト`master`、2026-11-05確認）。ルートには`ConfigureDefender.exe`、ヘルプPDF、`License.txt`、`README.md`、変更履歴など。**展開済みAutoItソースは含まれない**。 |
| 公式ソース置場・commit固定 | [AndyFul/Hard_Configurator @ `cd2c28bd34a979b7bf9b523a5db47297db360242`](https://github.com/AndyFul/Hard_Configurator/tree/cd2c28bd34a979b7bf9b523a5db47297db360242)。[ビルド説明](https://github.com/AndyFul/Hard_Configurator/blob/cd2c28bd34a979b7bf9b523a5db47297db360242/src/How2build_H_C.txt#L1-L19)が`src/Hard_Configurator.zip`のパスワードと`ConfigureDefender/ConfigureDefender.au3`のビルド先を明記。ZIPはバイナリかつパスワード付き。 |
| 比較用の実ソース・commit固定 | [第三者ミラー szepeviktor/ConfigureDefender @ `c4615b3c374b0a3bc013509007a23b5c435c94d8`](https://github.com/szepeviktor/ConfigureDefender/tree/c4615b3c374b0a3bc013509007a23b5c435c94d8)。`src/ConfigureDefender.au3`の内部表記は**2.1.1.1**。現行4.1系の実装と同一とは扱わない。 |
| 調査コミットSHA・リリース | 公式READMEは**stable 4.1.0.0（2025年12月）**、変更履歴は4.1.0.0の新しい証明書とanti-tampering改善、4.0.1.1のASR追加を記載。[README](https://github.com/AndyFul/ConfigureDefender/blob/04163467957211587914f993f0799681e98d9b57/README.md#L1-L31) / [変更履歴](https://github.com/AndyFul/ConfigureDefender/blob/04163467957211587914f993f0799681e98d9b57/What_is_new.txt#L1-L24)。実行ファイルの署名・ハッシュ照合は未実施。 |
| AegisGuard比較先SHA | [`83fcf0d150e8d760baff5f971c106deb09c1f8e4`](https://github.com/choko510/AegisGuard/tree/83fcf0d150e8d760baff5f971c106deb09c1f8e4)（`main`）。`src/main.rs`のサブコマンドは`scan`/`c2`のみ。Defender監査・Windowsセンサーは未実装。[実コード](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/main.rs#L24-L75) |
| ライセンス原文 | [配布側`License.txt`](https://github.com/AndyFul/ConfigureDefender/blob/04163467957211587914f993f0799681e98d9b57/License.txt#L1-L13)、[公式ソース格納側`License.txt`](https://github.com/AndyFul/Hard_Configurator/blob/cd2c28bd34a979b7bf9b523a5db47297db360242/License.txt#L1-L13)、[第三者ミラーの`LICENSE`](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/LICENSE#L1-L21)を別々に確認。 |
| 読んだ範囲 | 公式2リポジトリのファイルツリー・README・License・ビルド手順・変更履歴、第三者ミラーのAutoIt主ファイル/ASR除外/CFA除外/CFAフォルダー/Defenderイベント/ライセンス・変更履歴、AegisGuard README/SECURITY/ARCHITECTURE/Cargo/src/CI、Microsoft Learn複数記事。 |
| ソース確認の限界 | **公式`Hard_Configurator.zip`の展開・4.1.0.0版`.au3`への直接アクセスは未実施。** GitHub連携のテキスト取得はZIPバイナリの復号・展開をサポートせず、調査環境からの直接ダウンロードも利用不可。旧版ミラーで検証した挙動を現行版の既知バグと断定しない。 |
| 実機・ビルド・テスト | **未実施**。Windows 11/AutoIt環境なし。未知の配布実行ファイル、パスワード付きアーカイブ、マルウェア検体を実行せず、ソース静的読解のみ。調査した公式配布/ソース格納リポジトリの表示されたGitツリーに専用テスト群・CI構成は見つからず、ZIP内部の有無は**未確認**。 |

**証拠の格付け**：`[現行配布]`＝公式4.1系文書・配布物の存在、`[旧版コード]`＝第三者ミラー2.1.1.1の具体的実装、`[MS一次情報]`＝現行OS API/制約、`[提案]`＝AegisGuard向け新規設計。これらを混ぜない。

## 2. 実装アーキテクチャとソース調査

**データフロー（旧版コード）**：管理者権限でAutoIt GUI起動 → PowerShellの`Get-MpPreference`で設定を取得し一時レジストリへ書く → GUIの個別コンボ/プリセット操作から`Set-MpPreference`/`Add-MpPreference`およびレジストリ操作を実行 → Windows Defender/Operationalイベントの`wevtutil`表示。アンチウイルスエンジンや独自スキャンエンジンではなく、**Windows側の保護機能の設定フロントエンド**である。

| 機能・入力→出力 | 主要なファイル/シンボル・作用 | commit SHA固定の一次情報 | 確認状態 |
|---|---|---|---|
| 管理者権限・プラットフォーム | `#RequireAdmin`、PowerShell 5系とAutoIt標準GUI、旧コードは`@OSVersion="WIN_10"`判定。旧版そのもののWindows 11対応は立証できない。 | [`ConfigureDefender.au3` L1-L40, L103-L115](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/ConfigureDefender.au3#L1-L115) | **旧版コード** |
| 設定取得 | `CheckBoxDefender`内部で`Get-MpPreference`を実行、一時HKLMポリシーキーへ`New-ItemProperty`。取得エラーはレジストリ値を見て画面表示・終了。**単に画面を開く処理でも書込みがある**。 | [`ConfigureDefender.au3` L209-L229](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/ConfigureDefender.au3#L209-L229) | **旧版コード** |
| ASRの設定/読出し | GUIDをWindows Defender/ASRの通常キー・Policyキーから読み、`0/1/2`を表示。想定外値では`Add-MpPreference`でDisabledに**補正**するGUI初期化経路あり。個別変更は`ASRAddRule`→`Add-MpPreference`（Disabled/Enabled/Audit）。 | [`ConfigureDefender.au3` L581-L608](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/ConfigureDefender.au3#L581-L608) / [L1477-L1511](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/ConfigureDefender.au3#L1477-L1511) | **旧版コード**。現行ではWarn/追加ルールがある旨は変更履歴のみ。 |
| ASR除外の管理 | `ManageASRExclusions`は通常/Policyの両方を列挙。`AddASR_FileExclusion`/`RemoveASR_Exclusions`で`Add-/Remove-MpPreference`とポリシー値削除。除外は保護力を弱める場合がある。 | [`ASRExclusions.au3` L19-L45](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/ASRExclusions.au3#L19-L45) / [L83-L120](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/ASRExclusions.au3#L83-L120) | **旧版コード** |
| **起動時の副作用** | `OptimizeASRExclusions()`が画面初期化から呼ばれ、Policyキー内のASR除外を**確認なしに削除する分岐**がある。その他の除外入替え分岐にはダイアログがある。読み取り専用監査に流用できない決定的根拠。 | [呼出 L219-L230](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/ConfigureDefender.au3#L219-L230) / [`OptimizeASRExclusions` L1773-L1835](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/ConfigureDefender.au3#L1773-L1835) | **旧版コード**。4.1で存続しているか未確認。 |
| CFA（保護フォルダー） | `ControlledFolderAccess`→`Set-MpPreference -EnableControlledFolderAccess`、旧UIはDisabled/Audit/ON。保護フォルダー・許可アプリの追加削除は別`.au3`。 | [`ConfigureDefender.au3` L1522-L1528](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/ConfigureDefender.au3#L1522-L1528) / [`CFA_Folders.au3` L80-L105](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/CFA_Folders.au3#L80-L105) / [`CFAExclusions.au3` L78-L102](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/CFAExclusions.au3#L78-L102) | **旧版コード**。現行のBDMO追加は[公式変更履歴](https://github.com/AndyFul/ConfigureDefender/blob/04163467957211587914f993f0799681e98d9b57/What_is_new.txt#L15-L26)のみ。 |
| クラウド/MAPS/サンプル | `MAPSReporting`/`SubmitSamplesConsent`/`DisableBlockAtFirstSeen`、`MpCloudBlockLevel`はレジストリのDWORD 0/2/4/6、`MpBafsExtendedTimeout`は追加0〜50秒を操作。試料送信には**プライバシー上の副作用**がある。 | [`ConfigureDefender.au3` L1353-L1371](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/ConfigureDefender.au3#L1353-L1371) / [L1390-L1412](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/ConfigureDefender.au3#L1390-L1412) | **旧版コード** |
| SmartScreen | `SmartScreenForExplorer`/`Edge`/`IE`は旧版固有ポリシーのレジストリを操作。**Defender AVのASRとは別の制御面**。旧Edge/IEキーを現行Windows 11対応のまま転用しない。 | [`ConfigureDefender.au3` L1426-L1475](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/ConfigureDefender.au3#L1426-L1475) / [MS SmartScreenポリシー](https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/available-settings) | **旧版コード** + **MS一次情報** |
| DEFAULT/HIGH/MAX | `DefaultDefender`はASR全ルール削除・Policyキー削除を含む。`DefenderHighSettings`はASRを一括`Set-MpPreference`、`DefenderChildProtection`はCFA/SmartScreen/クラウドを強制し、Windows SecurityのUI非表示も設定。 | [`ConfigureDefender.au3` L1651-L1680](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/ConfigureDefender.au3#L1651-L1680) / [L1684-L1720](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/ConfigureDefender.au3#L1684-L1720) / [L1723-L1769](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/ConfigureDefender.au3#L1723-L1769) | **旧版コード**。INTERACTIVEの実実装は未確認。 |
| Defenderイベント表示 | `DefenderSecurityLog`→`wevtutil qe Microsoft-Windows-Windows Defender/Operational`の**最新300件**取得、テキストのEvent ID/GUIDを説明文字列へ置換してNotepadで表示。**イベント継続購読/カーソル永続化はない**。 | [`DefenderEvents.au3` L6-L24](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/DefenderEvents.au3#L6-L24) / [L35-L80](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/DefenderEvents.au3#L35-L80) | **旧版コード** |
| 変更反映の成否 | 多くの`RunWait`/`RegWrite`後に終了コード、実効設定、GPO反映、Tamper Protectionを再確認する処理は該当旧版関数で見当たらない。GUI表示を成功の証明としない。 | [`ASRAddRule` L1477-L1511](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/ConfigureDefender.au3#L1477-L1511) / [`SetProtectionLevelOptions` L1873-L1962](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/ConfigureDefender.au3#L1873-L1962) | **旧版コードからの静的判断**。全関数網羅・現行版は未確認。 |

**現行版の確認可能な追加**：公式変更履歴ではWindows 11対応、ASR Warn、INTERACTIVE、CFAのBDMO、イベントID 1120、後続版でASR 2ルール追加を宣言しているが、**最新4.1.0.0のAutoItソースとの差分を検証できていない**。[公式変更履歴](https://github.com/AndyFul/ConfigureDefender/blob/04163467957211587914f993f0799681e98d9b57/What_is_new.txt#L1-L40)。

**ASRの仕様照合**：Microsoftの現在のモードは無効`0` / ブロック`1` / 監査`2` / 警告`6`（MDMの`5`は未構成）。`Warn`非対応ルールがあり、ルール別にWindows/Defender/AMSI/Cloudの前提が異なる。`AttackSurfaceReductionRules_Ids`と`_Actions`は順序対応の配列で、**GUIDの種類・重複・長さ不一致・欠損を検証すること**。[Microsoft: ASRルールと除外](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-configure) / [ルールごとの差異](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)。

## 3. 具体的な取り込み候補と選択肢

| 候補機能 | 利用方法（crate/API・外部CLI・独自実装・参考・見送り） | AegisGuard接続先（**すべて新規案**） | 優先度 | 工数目安 | ライセンス・技術上の阻害要因 |
|---|---|---|---|---|---|
| **① Defender健全性と設定の読み取り専用スナップショット** | **独自実装**：当初はOS標準`Get-MpPreference`/`Get-MpComputerStatus`を限定的に呼び構造化JSONで受ける。将来CIM/WMIのAPI直接利用も評価。 | `windows/defender_audit`、`model/defender` | **P0** | **S** | Windows専用、PowerShell実行不可/権限制限時に取得失敗。設定値と**実効保護状態**は別。原著コードはコピーしない。 |
| **② ASR/CFA/Defenderイベント読み取り** | **Rust/Windows Event Log API直接利用候補**（`windows` crate等の採用はPoC後判断）、代替として`wevtutil`の**読み取り専用CLI**でPoC。 | `windows/defender_events`、`correlation` | **P0** | **M** | ログ閲覧ACL、イベント欠損/ローテーション、PID再利用、個人情報、ブックマーク復旧。 |
| **③ ASR GUID→名称・要求前提・モード差異カタログ** | **AegisGuard独自データ/実装**。Microsoft公開仕様を手で確認し、バージョン管理。 | `windows/asr_catalog` | **P1** | **M** | ルール・対応OS・Warn可否の更新追従。ConfigureDefenderのルール配列を複製しない。 |
| **④ クラウド保護・サンプル送信・CFA除外/SmartScreen監査** | **独自実装**。設定と状態だけ取得、標準UIやポリシーの出所を表示。 | `windows/defender_audit` | **P1** | **M** | SmartScreenはDefender AV外。企業管理・Tamper Protection・利用者同意・機微な除外パス。 |
| **⑤ 設定変更提案のプレビュー（読み取るだけ）** | **設計参考のみ＋独自実装**。必要な前提、影響するアプリ、差分/根拠/監査期間、復旧計画を提示。 | `policy/advisor` | **P1** | **M** | 誤った推奨による業務停止/誤検知。ユーザー承認前に書込処理を持たない。 |
| **⑥ 限定的なASR監査モード変更** | **独自実装・将来のみ**。明示承認後に昇格した限定プロセスでMicrosoft公式cmdletを実行、実効値を再確認。 | `response/defender_policy`（現時点なし） | **P2** | **L** | ポリシー優先順位・所有権・Tamper Protection・ロールバック・多ルール破壊的上書き・管理者権限。 |
| ConfigureDefender EXEのGUI/CLI組込み | **外部CLI/サービスとしては見送り**。ポータブルGUIで、安定した非対話・読出しAPIは確認できない。 | なし | **見送り** | — | 非販売/無改変ライセンス。GUI起動の副作用、無人動作の保証なし、実行前ハッシュ/署名未検証。 |
| 旧AutoItソースからのRust移植、MAX/HIGH一括適用 | **直接移植・一括設定は見送り**。意味・UXを参考にするのみ。 | なし | **見送り** | — | ソースライセンス未解決、グローバル変更、除外削除・一括上書き、誤検知、ポリシー衝突。 |

**上位3件と具体的I/O・失敗時**：

1. **① 健全性監査（P0/S）**。入力：端末ID（ローカル匿名識別子）、取得時刻、任意の監査スコープ。出力：`DefenderSnapshot { queried_at, platform_version, running_mode, real_time, cloud_reporting, sample_consent, cloud_block_level, asr: [{guid, action}], cfa_mode, exclusions_count, tamper_state, origin, errors[] }`程度の**新規スキーマ案**。保護状態と希望設定を分け、`null/unknown/access_denied`を明示。取得できなくても絶対に「保護中」または「安全」と出さない。PoC：一般ユーザー環境で`Get-MpPreference`/`Get-MpComputerStatus`を**照会だけ**行い、PowerShellを使用できない場合の`unavailable`を確認する。
2. **② Defenderイベント相関（P0/M）**。入力：Windows Event Log`Microsoft-Windows-Windows Defender/Operational`のRecordId、TimeCreated、EventID、EventData。出力：`DefenderFinding { event_id, record_id, timestamp, rule_guid?, process_path?, mode, correlation?, data_redacted, completeness }`の新規スキーマ案。API未対応時は取得不能/欠落を記録し、既存AegisGuardのJSONL出力へ接続。イベント1121（ASRブロック）/1122（ASR監査）/1129（Warn override）、1123/1124（CFAブロック/監査）、1127/1128（CFAのディスクセクタ）、5007（設定変更）などを優先。[MSイベントID](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-windows-events)。PoC：**既に存在する正常なログ/匿名化した合成イベントのみ**でパーサを検証。
3. **③ 設定カタログ（P1/M）**。入力：上記`guid/action`、OSビルド・Defenderプラットフォーム版・AMRunningMode。出力：`AsrRuleAssessment { guid, name?, configured_action, supported?, prerequisites, policy_conflict?, evidence_version, status }`の新規スキーマ案。未知GUIDは削除せず`unknown_rule`、配列不整合は`incomplete`。Win11対応表と設定・実効値の優先度解決を別テスト。PoC：Microsoftの既知GUID例と未知/重複/配列不一致の合成ケースを通す。

**その他の候補I/O**：④はCFAモード・保護フォルダ/許可アプリ・サンプル送信設定・SmartScreenポリシーを列挙するが、既定で**パスとサンプル内容を外部送信しない**。⑤は「推奨値」「現在値」「副作用」「権限」「管理元」「取り消しの可否」の**差分JSONだけ**を生成。⑥の将来PoCは隔離したVMで、単一GUIDに対する`AuditMode`変更を権限境界を通じて試し、変更前スナップショットと原状復帰が成立した場合だけ先へ進む。管理元ポリシー下では変更を拒否する。

## 4. ライセンス・再配布・依存関係

| 対象 | 確認した条件・依存 | AegisGuard側の扱い |
|---|---|---|
| **公式ConfigureDefender EXE/ドキュメント** | [`License.txt`](https://github.com/AndyFul/ConfigureDefender/blob/04163467957211587914f993f0799681e98d9b57/License.txt#L1-L13)：「無料で再配布可、販売不可、改変なし」を記載。`NOASSERTION`相当で自由な修正・再配布・内部コード利用を包括的に許諾していない。NSISの別途ライセンスにも言及。 | **再配布・改変・組込みはせず、設計のみ参照**。バイナリ署名・ハッシュ・来歴を未検証。 |
| **公式`Hard_Configurator.zip`内のAutoItソース** | [ビルド説明](https://github.com/AndyFul/Hard_Configurator/blob/cd2c28bd34a979b7bf9b523a5db47297db360242/src/How2build_H_C.txt#L1-L19)はAutoIt 3.3.14.2でのコンパイル、パスワード付きZIP、複数`.au3`を説明。[`Hard_Configurator/License.txt`](https://github.com/AndyFul/Hard_Configurator/blob/cd2c28bd34a979b7bf9b523a5db47297db360242/License.txt#L1-L13)は無改変・非販売の配布条件。AutoIt、含まれるライブラリ、Sysinternals/NirSoft/7-Zip/NSIS等について追加の条件を示唆。 | **コード転用の許諾未確認。法的評価未完了**。ZIP内部の著作権表示・サードパーティ依存の版と条件は未確認。 |
| **第三者ミラーのAutoItソース** | [`LICENSE`](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/LICENSE#L1-L21)にはViktor Szépe名義のMITがある一方、コードはConfigureDefender名義・AutoIt由来。**原著作権者がMITへの変更を許諾した証跡なし**。 | 行動観察・構造理解に限定。**MITだから転用自由とは判断しない**。 |
| **ASRルールID/名称、CFAイベントID、クラウド保護値** | Microsoft Learnの公開技術仕様。[ルール参照](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)等。個々のGUIDは製品API識別子。リポジトリ独自のルール署名ファイルを利用するわけではない。 | Microsoft一次情報で**独自のマッピング**を作成。ドキュメントの文章・図表を大量複製しない。更新ごとに照合する。 |
| **AV署名/検体/クラウドデータ** | ConfigureDefenderはDefender設定フロントエンドであり、Defenderの署名DB・クラウド判定ロジックを再配布するものではない。 | **署名、ルール配布物、サンプルを同梱・再配布しない**。AegisGuardのC2フィードとは別系統で扱う。 |
| **Windowsネイティブ機能** | `Get-MpPreference`、`Get-MpComputerStatus`、`Set-/Add-/Remove-MpPreference`はWindows/Defender標準cmdlet。`wevtutil`とWindows Event Log APIもOS提供。旧版はAutoIt GUI、レジストリ、PowerShell呼出に依存。 | 標準APIへの呼出を**独自実装**し、サードパーティのEXE/ソースへの依存を設けない。既存[`Cargo.toml`](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/Cargo.toml#L1-L25)にはWindows API用crateの採用はない。追加時は別途crateのライセンス/セキュリティ監査が必要。 |

**境界**：原著のコードをリンク/コピーしてRustへ翻訳することと、独立にWindows標準PowerShell/Windows APIを呼ぶことは別。外部GUIを別プロセスにしただけでライセンス条件が消えるわけではない。パッケージへ同梱、ユーザーに外部ダウンロードを案内、起動して自動操作する、の各行為を別途法的・セキュリティ評価すること。

## 5. Defender共存・Windows制約・権限境界

- **Windows 11 x64 / Defender共存**：AegisGuard`main`はファイル静的検査+C2キャッシュのみで、Windows常駐センサー・Firewall変更は未実装。[`main.rs`](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/main.rs#L24-L75)、[設計方針](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md)。新監査はDefenderを無効化せず、二重のAVエンジンを常駐させない。Defenderの`AMRunningMode`がNormal/Passive等のどれかにより**設定値と強制保護の実効性が違う**ため、`Get-MpComputerStatus`結果を併記。[Microsoft cmdlet](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus?view=windowsserver2025-ps)。
- **権限**：旧AutoItは`#RequireAdmin`。Microsoftは`Set-/Add-/Remove-MpPreference`の変更に**昇格PowerShell**を要求。[Microsoft ASR設定](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-configure)。読み取りcmdletやDefender Operationalイベントへのアクセスは非管理者でも環境/ACLによって差があり得るためPoCで確認。通常のUIと権限を持つ変更プロセスを分離し、引数の固定ホワイトリスト・署名済み操作要求・監査ログが必須。**ファイル名/パス/IOCをPowerShell文字列へ連結しない**。
- **管理ポリシーの優先順位**：ローカル`Set-MpPreference`は最下位。GPO・Intune/MDM・Configuration Managerの優先順位と競合・再適用で、実行直後に成功風に見えても変更が無効化され得る。[MS設定優先順位](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-configure)。GPOの存在を根拠なしに「解除可能」とみなさず、管理主体不明なら変更を拒否。旧コードの`RegDelete`でPolicyキーを消す設計は採用しない。
- **Tamper Protection**：保護対象設定の変更やレジストリ変更を遮断し、管理ツールの操作が成功に見えても防がれる場合がある。**回避、無効化を前提にしない**。`IsTamperProtected`および（提供されれば）`ControlledConfigurationState`/`TamperProtectionSource`を読み、`unsupported`/`unknown`も表現。[Microsoft Tamper Protection](https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection)、[構成保護の確認](https://learn.microsoft.com/en-us/defender-endpoint/secure-controlled-configuration)。
- **ASR/AMSIとの役割分担**：ASRはOS/Defenderが実施するブロック・監査であり、AegisGuardの静的スクリプト評価の代替ではない。難読化スクリプトASRはDefender/AMSI/Cloudを要するルールもある。AMSIは対応するホストからの検査であって、全言語に万能ではない。[Microsoft ASRルール参照](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)。
- **ETW/Sysmon/WFPの重なり**：Defender Operationalの1121/1122等は「防御機能の判断イベント」、将来のSysmon EventID 1/3/7やETWはプロセス/通信の観測。WFPは将来の通信制御候補で、**設定監査ではWFPドライバー/フィルターに触れない**。Sysmon ProcessGuidを使った相関は将来機能であり、イベントだけでC2通信を決めつけない。[AegisGuard設計](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md)。
- **CFA/SmartScreen**：CFAの`Disabled/Enabled/AuditMode/BlockDiskModificationOnly/AuditDiskModificationOnly`は別物で、Windows Security UIは一部のみ変更可能。[MS CFA](https://learn.microsoft.com/en-us/defender-endpoint/enable-controlled-folders)。SmartScreenはアプリ評価/ブラウザ等のポリシーであってASRの1ルールではない。[MS SmartScreen](https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/available-settings)。旧IE・旧EdgeのポリシーキーをWindows 11へそのまま移植しない。
- **クラウド/機微情報**：`MAPSReporting`、`SubmitSamplesConsent`、`CloudBlockLevel`、`CloudExtendedTimeout`などを**状態表示のみ**。MicrosoftはクラウドのHigh/HighPlus/ZeroToleranceを区別し、上位ほど誤検知・待ち時間/性能の影響があり得る。[MSクラウド](https://learn.microsoft.com/en-us/defender-endpoint/enable-cloud-protection-microsoft-defender-antivirus)、[ブロック待機](https://learn.microsoft.com/en-us/defender-endpoint/configure-cloud-block-timeout-period-microsoft-defender-antivirus)。サンプルの自動送信同意をAegisGuardが変更しない。除外パス・イベントのユーザーフォルダ名はJSONLで必要に応じて秘匿する。

## 6. 性能・堅牢性・誤検知

**実測値：なし。以下は検証すべきリスクであり測定結果ではない。**

- **負荷/効率**：頻繁なPowerShell起動は起動負荷を生む可能性、CIM/WMI連続照会はOSサービス負荷を生む可能性。読み取りの定期間隔・差分取得・失敗時バックオフ・同時実行数制限を設ける。CPU、RSS/Private Bytes、I/O、起動時間、イベント遅延、バッテリー影響は**Windows 11 x64実機で測定**。根拠のないミリ秒/MBを記さない。
- **ログの完全性**：旧版`wevtutil /c:300`は過去300件の閲覧用途で、取りこぼしを検出しない。[実コード](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/DefenderEvents.au3#L6-L24)。本番候補はEvent RecordId・ブックマーク・イベントログクリア/ローテーション検知・有限キュー・ディスク上限・再起動復元を備える。読めないイベント・GUID未知・Win11版差異は`unknown`/`incomplete`で出す。
- **ASR誤検知**：業務アプリ/管理ツールの正常動作をブロックする可能性。特にOfficeの子プロセス、WMI永続化、署名のない実行ファイル、クラウドのZeroTolerance、CFAの書込み制限を一律有効化しない。Microsoftも個別ルールによって例外・Warn未対応・監査ノイズの差を明記。[MSルール参照](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)、[監査から始める推奨](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-deployment-test)。
- **検査漏れ/False negative**：ASR未設定/サードパーティAVによるDefenderパッシブ動作/OS非対応/ログ消去/権限不足/クラウドへの接続不可/除外/未知ルール/ポリシーの再適用で、**設定済み=実効的にブロック中**と断定できない。監査の`healthy`判定にはデータの出典・鮮度・実効モードが必要。
- **攻撃者入力耐性**：イベントの文字列/プロセスパス/Policyの除外値は信頼できないデータ。サイズ上限、UTF-16文字、改行、制御文字、ログ汚染、JSONLエスケープ、長大パス、想定外イベントスキーマ、タイムスタンプ逆行を処理する。外部通信は不要、Defenderイベントのプロセスパス/ユーザー名の外部送信は行わない。
- **ロールバック安全性**：`Set-MpPreference`のASRルール配列は**他ルールまで上書きし得る**。[MSルール設定](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-configure)。将来は差分適用する`Add/Remove`も既存設定と競合し得るため、変更時は保護された設定履歴・所有権・before/afterの再読取り・多重変更競合検出・戻せないケースの警告が必要。

## 7. 推奨する小さなPoCと成功基準

**安全な最小PoCは「読み取りのみ」で完結させる。**

| 段階 | 前提/操作 | 定量値を捏造しない受け入れ基準 |
|---|---|---|
| **A: 初期監査（P0）** | Defender有効の隔離Windows 11 x64 VM。`Get-MpComputerStatus`/`Get-MpPreference`を参照するだけ。試料提出・除外・ポリシー変更・昇格を要求しない。 | 実機の取得前後で監査対象`MpPreference`およびポリシーキーが不変。Defender無効/Passive/権限なし/PowerShell失敗を合成入力または隔離環境で`unknown`等として報告し「正常」と誤表示しない。 |
| **B: イベントパーサ（P0）** | 公式イベントID表に沿った、匿名化済み合成XML/EVTX相当データだけを使用。イベント閲覧権限のみ。 | 1121/1122/1129、1123/1124/1127/1128、5007、未知ID、欠損フィールド、重複/逆行RecordIdを区別。イベントが0件の時は「イベントなし」であり「保護が働いている」とはしない。個人情報や原始イベントを外部送信しない。 |
| **C: ルールカタログ（P1）** | Microsoft公開GUIDと、未知GUID・配列要素数不一致・Warn非対応・サポート外OSのフィクスチャ。 | 入力GUIDが欠落/重複/未知でもpanicせず全件の可視化ができ、異常を`incomplete`として報告。Microsoft公開情報への参照版/更新日を残す。 |
| **D: 変更の検討（今回のPoC外）** | 別の隔離VM、ユーザーによる明示承認、管理者境界、バックアップ、1ルールだけ監査モードを試行。 | 管理主体が不明/管理下/Tamper Protectionで変更が阻まれる場合は中止。作業前後の実効値一致確認、ロールバック一致確認、監査ログ保全がない限り強制ブロックへ進まない。 |

**性能測定方法**：アイドル時と監査中のCPU/RSS、プロセス起動回数、イベント取得遅延、ディスクI/O、JSONL容量、ログ肥大時の欠落数・回復時間を同じVM/同じルールセットで記録。基準値は初回ベンチで定め、未測定の具体値は受入基準にしない。

**失敗時**：監査結果に`unavailable/partial`とエラー区分を残し、既存`scan`/`c2`の結果を汚染しない。変更を伴わないA〜Cのロールバックは「監査プロセス停止・生成したログ削除のみ（Defender設定変更なし）」。**中止条件**：権限要求/設定変更/Policyキー削除が発生した時、ログへ検体・資格情報が混入した時、Defender動作が変わった時。

## 8. 採用しない設計と理由

1. **ConfigureDefender EXEをバックグラウンドで起動して状態取得/設定適用**：現行配布はポータブルGUIであり、安定した読取り専用CLI/APIを確認できない。旧版は`#RequireAdmin`、画面初期化のレジストリ書込・自動的なASR Policy除外削除がある。[旧版根拠](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/ConfigureDefender.au3#L209-L230)、[自動補正](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/ConfigureDefender.au3#L1773-L1835)。**「起動しただけで監査完了」にはならない**。
2. **HIGH/MAX/DEFAULT/INTERACTIVEをAegisGuardから一括適用**：旧版`DEFAULT`は除外やルール、Policyキーを削除し、`MAX`はCFA/SmartScreen/クラウドを強制しWindows Securityの一部UIまで隠す。[旧版根拠](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/ConfigureDefender.au3#L1651-L1769)。環境・ポリシー・業務アプリとの相性を確認せず一般ユーザーへ適用するのは危険。
3. **レジストリのPolicy領域を強制書換え/削除してGPOやTamper Protectionを突破**：設定の管理主体と競合し、短時間の表示だけでは実効性を保証できない。防御機能の保護を弱める運用はAegisGuardの目的に反する。[MSポリシー優先度](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-configure)、[MS改ざん防止](https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection)。
4. **第三者ミラーMIT表示を理由にAutoItをRustへ丸ごと移植**：原著作者のライセンスと矛盾するように見えるため、**法的評価未完了**。設計知識だけを参照しMicrosoft公式APIから独立実装する。

## 9. 他担当との境界・引継ぎ

- **Windowsイベント/Sysmon/ETW担当**：Defender Operationalの1121/1122/1129/1123/1124/5007等とSysmon ProcessGuidをどう突合するか、Event LogのBookmarkと保持期間、ログ ACL、競合/ギャップを引継ぐ。**ASRのブロックはDefender自身の機能**であり独自WFP遮断と混同しない。
- **AMSI/スクリプト担当**：難読化スクリプトASRとAMSIによる重複/カバレッジ/誤検知を別途評価。Windows PowerShell/PowerShell 7/Python等の宿主差を要検証。
- **ポリシー・Firewall/レスポンス担当**：ユーザー承認、管理者分離、適用所有権、監査モード、差分、復旧・UI表示を共通契約に。既存Defender、GPO、Intune、Tamper Protectionの**無断変更は禁止**。
- **ライセンス/サプライチェーン担当**：公式ZIP内部の著作権/AutoIt同梱ライブラリ、NSIS配布条件、第三者ミラーMITとの権利関係、署名とリリース真正性を調べる。確認まで移植/同梱しない。
- AegisGuardの既存`src/model.rs`は`Report`（ファイル検査前提）で、Defender監査のスキーマとは異なる。[現行モデル](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/model.rs#L27-L57)。独立した`DefenderSnapshot`/`DefenderFinding`を設計し、JSONLの共通メタ情報だけを連携させる。

## 10. 未確認事項・追加調査項目

1. **[重大/法務・ソース]** 公式`Hard_Configurator.zip`を安全な隔離環境で取得・署名/ハッシュ検証・解凍し、現行`ConfigureDefender.au3`と関連`.au3`を実読、コミットとの来歴を固定する。今回**不可能**だったため、旧版の初期化副作用/ASR除外変更が4.1.0.0にも存在するかは未確認。
2. **[重大/法務]** 現行ソース内の権利表記、AutoItライブラリ、第三者ミラーのMIT権限の根拠、公式「無改変・非販売」がソース利用・翻訳を許諾するか。**法的評価未完了**。
3. **[重大/安全]** Windows 11最新ビルド/Defenderプラットフォーム版別の`Get-MpPreference`、`Get-MpComputerStatus`、Tamper Protection下の戻り値と管理者/一般ユーザー権限差。**未実測**。
4. **[重大/安全]** GPO/Intune/Configuration Manager/Defender portalの混在時のポリシー優先順位と「希望設定 vs 実効設定」、パッシブAV時の実効ASR。**未実測**。
5. **[中/互換]** Microsoftの現行ASR規則全件、Warn非対応、OS/AMSI/Cloud依存、CFA BDMO/ADMO、クラウドブロックレベル、SmartScreenのEdge/Explorerポリシー差をOS実機で検証。
6. **[中/品質]** 公式アーカイブ内部のテスト/CIの有無、旧版AutoIt処理でのPS終了コード/エラー処理、現在のイベントログ取得の実装差、バイナリ署名/ハッシュ。ツリー上のテスト不在だけでは品質を断定しない。
7. **[中/運用]** CPU/RAM/IO/電池、イベント欠落/ログローテーション、Defenderと同時監査した際のオーバーヘッド、誤検知と業務アプリ影響。測定値・母集団とも未取得。
8. **[低/調査]** 公式バイナリの最新タグ/過去リリース、`ConfigureDefender_4112_PM.exe`とREADMEの4.1.0.0表記の関係。特定バイナリを「4.1.2」と推定しない。

## 11. 一次情報一覧

すべて**2026-11-05参照**。GitHubはcommit SHA固定。`M`はMicrosoft公式文書（ページ自体は随時更新）、`C`は現行配布文書、`H`は原著者のソース格納・ビルド説明、`S`は**旧版の第三者ミラー実コード**、`A`はAegisGuard現行実コード。

| ID | 一次資料（ファイル/シンボル/該当行） | 支持する判断 |
|---|---|---|
| C1 | [AndyFul/ConfigureDefender README L1-L31](https://github.com/AndyFul/ConfigureDefender/blob/04163467957211587914f993f0799681e98d9b57/README.md#L1-L31) | 現行の公開版、GUI、配布先 |
| C2 | [AndyFul/ConfigureDefender License.txt L1-L13](https://github.com/AndyFul/ConfigureDefender/blob/04163467957211587914f993f0799681e98d9b57/License.txt#L1-L13) | 無改変・非販売配布、NSIS別途条件 |
| C3 | [What_is_new.txt L1-L40](https://github.com/AndyFul/ConfigureDefender/blob/04163467957211587914f993f0799681e98d9b57/What_is_new.txt#L1-L40) | 新版の宣言機能（コード検証とは別） |
| H1 | [How2build_H_C.txt L1-L19](https://github.com/AndyFul/Hard_Configurator/blob/cd2c28bd34a979b7bf9b523a5db47297db360242/src/How2build_H_C.txt#L1-L19) | パスワード付きZIP、AutoItビルド、ソースの場所 |
| H2 | [Hard_Configurator License.txt L1-L13](https://github.com/AndyFul/Hard_Configurator/blob/cd2c28bd34a979b7bf9b523a5db47297db360242/License.txt#L1-L13) | 公式ソース格納側の配布条件 |
| S1 | [ConfigureDefender.au3 L1-L115](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/ConfigureDefender.au3#L1-L115) | 旧版の2.1.1.1表記、管理者要求、依存`#include`、Win10判定 |
| S2 | [ConfigureDefender.au3 L209-L229](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/ConfigureDefender.au3#L209-L229) | 初期取得が一時レジストリを変更 |
| S3 | [ConfigureDefender.au3 L581-L608](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/ConfigureDefender.au3#L581-L608) | ASR初期表示からの設定補正 |
| S4 | [ConfigureDefender.au3 L1477-L1528](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/ConfigureDefender.au3#L1477-L1528) | ASR/CFA/Network Protectionの書込み |
| S5 | [ConfigureDefender.au3 L1773-L1835](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/ConfigureDefender.au3#L1773-L1835) | 起動時のASR除外削除/変更 |
| S6 | [ConfigureDefender.au3 L1651-L1769](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/ConfigureDefender.au3#L1651-L1769) | プリセットの破壊的・広範な変更 |
| S7 | [DefenderEvents.au3 L6-L80](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/DefenderEvents.au3#L6-L80) | `wevtutil`、イベントID、最新300件 |
| S8 | [ASRExclusions.au3 L83-L120](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/src/ASRExclusions.au3#L83-L120) | ASR除外の追加・削除 |
| S9 | [第三者ミラー LICENSE L1-L21](https://github.com/szepeviktor/ConfigureDefender/blob/c4615b3c374b0a3bc013509007a23b5c435c94d8/LICENSE#L1-L21) | 原著の配布条件と異なるMIT表記（権利帰属は未確認） |
| A1 | [AegisGuard main.rs L24-L75](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/main.rs#L24-L75) / [model.rs L27-L57](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/model.rs#L27-L57) | 現MVPにDefender監査がない、JSONLモデルの境界 |
| A2 | [AegisGuard Cargo.toml](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/Cargo.toml) / [SECURITY.md](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md) | Rust依存とDefender共存・設定無変更の方針 |
| M1 | [Microsoft: Get-MpComputerStatus](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus?view=windowsserver2025-ps) / [ASR構成と優先度](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-configure) | 監査API、管理権限、配列、ポリシー競合 |
| M2 | [Microsoft: ASR規則参照](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference) / [イベントID](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-windows-events) | ルール依存・Audit/Warn・検出イベント |
| M3 | [Microsoft: CFA](https://learn.microsoft.com/en-us/defender-endpoint/enable-controlled-folders) / [SmartScreen](https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/available-settings) | CFAモード、SmartScreen管理 |
| M4 | [Microsoft: クラウド保護](https://learn.microsoft.com/en-us/defender-endpoint/enable-cloud-protection-microsoft-defender-antivirus) / [クラウド待機時間](https://learn.microsoft.com/en-us/defender-endpoint/configure-cloud-block-timeout-period-microsoft-defender-antivirus) | 誤検知・待機時間・サンプル同意 |
| M5 | [Microsoft: Tamper Protection](https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection) / [構成保護](https://learn.microsoft.com/en-us/defender-endpoint/secure-controlled-configuration) | 保護状態を尊重し、設定変更成功を誤認しない |
