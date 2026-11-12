# Canary File / Honeyfile 検出設計（P11）

> 状態：**設計・調査のみ。実装・Windows 11実機検証は未実施**  
> 2026-11-12 JST。対象：AegisGuard `main` の Rust core / Windows Service / egui GUI。  
> この文書は今後の実装契約と承認ゲートであり、OS監査設定・Defender・Firewall・既存ファイルの変更を許可するものではない。

## 1. 目的・判定境界

攻撃者が実ファイルと誤認し得る**完全に架空のローカルファイル**をユーザーの明示同意に基づき設置し、ファイルに対して使用された読み取り権限を Windows Security 4663 から観測する。既存の Sysmon プロセス生存期間・通信イベント・Defender アラートと結び付け、根拠を失わず、誤警告を抑えて表示する。

- 脅威モデル：MITRE [T1552.001 Credentials in Files](https://attack.mitre.org/techniques/T1552/001/)・[T1005 Data from Local System](https://attack.mitre.org/techniques/T1005/) に相当する探索・読み取りの**兆候**。
- 守れること：当該デコイを対象とした監査可能な ReadData 権限の使用、複数デコイへのアクセス、時間的に整合する別の不審行動。
- **守れないこと**：デコイを無視するマルウェア、メモリ/ブラウザ API を通じる窃取、監査イベントを生成しない経路、カーネル権限の敵、ログを消せる管理者、OS監査不能状態。
- **断定禁止**：4663 は読み取り権限の**使用**を示すが、ファイル全体のコピー、データの外部送信、感染確定を示さない。ネットワーク接続を同じプロセスへ結び付けても送信内容は証明できない。
- 初期実装は**観測・警告のみ**。自動削除、隔離、通信遮断、Defender除外、実秘密情報の設置、クラウドへの送信を行わない。

利用者が機能を明示して有効化するまでは**すべて無効**。初回セットアップ、追加監査、アンインストールは各段階で可逆性と権限を検証する。

## 2. 2026-11-12時点の調査根拠と方式決定

| 候補 | 観測できるもの | 注意点 | 判断 |
| --- | --- | --- | --- |
| Security 4663（監査 SACL） | SACL に合致するファイル上の ReadData (0x1) 等の権限使用 | Audit File System の成功監査・対象ファイルの SACL・Security ログ読取権限が必要。4663 は成功イベントのみ | **第1選択** |
| Security 4656 | オブジェクトハンドルへのアクセス要求と失敗 | 読み取り完了を示さない。4656 単独で読取検出とみなさない | 補助証拠のみ |
| Sysmon 11 / FIM / FileSystemWatcher | 作成・更新・削除など | 読み取りそのものは検出できない | タンパー検出のみ |
| ETW File I/O | I/Oイベント（設計上の候補） | 特権・ボリューム・ノイズ・帰属・停止時の損失を別実証要 | 第2段階の比較実験 |
| ファイルシステム Minifilter | カーネル I/O 経路 | 署名・互換性・安定性・故障時のリスクが大きい | 初期段階では**導入しない** |

Microsoft 一次情報：
- [4663: An attempt was made to access an object](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4663) ― SACL が必要、4663 に Failure イベントはない、`ReadData=0x1`。
- [4656: A handle to an object was requested](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4656) ― 要求と実行の区別。
- [Audit File System](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-file-system) ― 過剰な SACL はログを圧迫。
- [Sysmon Events](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) ― Event 11 は作成/上書き。
- [AuditQuerySystemPolicy](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy) / [AuditSetSystemPolicy](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-auditsetsystempolicy) ― 現在状態取得・変更には権限が必要。
- [GetNamedSecurityInfoW](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getnamedsecurityinfow) / [SetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo) ― SACL 取得・ハンドルベース設定、`SeSecurityPrivilege`。
- [FILE_ID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info) ― VolumeSerialNumber + FileId による同一性確認。
- [Windows Security 1102/1104](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/other-events) ― ログ消去・満杯。
- [System audit policy GUID 一覧](https://learn.microsoft.com/en-us/windows/win32/secauthz/auditing-constants) ― `Audit_ObjectAccess_FileSystem = {0CCE921D-69AE-11D9-BED3-505054503030}`。
- [T1552.001](https://attack.mitre.org/techniques/T1552/001/) は具体的な標的候補を説明するが、**特定名のデコイが全Infostealerに読まれる証拠ではない**。

## 3. 現行 AegisGuard の再利用と設計上の差分

2026-11-12 の `main` 実ファイルから確認：
- `src/events/process.rs`: `FileRead`、`OBJECT_ACCESS=4663`、`READ_DATA=0x1` が存在するが、`file_reads` は **最大4,096件**であり、専用Canary検出には直接流用できない。`SubjectUserSid`/`SubjectLogonId` は現行正規化で保存されていない。
- `src/events/browser_rules.rs`: `AG-B004` が既存ブラウザー認証情報ストアへの 4663 アクセスを扱い、Sysmon と通信の相関も実装。
- `src/events/mod.rs`: 4663 の `ObjectType`/`ObjectName`/`AccessMask`/`ProcessName` を正規化対象としている。
- `src/service/mod.rs`: `ServiceConfig.channels` の既定値は **Sysmon と Defender のみ**。Security の持続収集は自動で有効化されない。
- `src/service/collect.rs`: チャンネル別スプール・ブックマーク・上限・空き容量閾値を備える。ただし `src/events/collector.rs` の連番RecordIDチェックは**フィルタされたSecurityログに適用不可**。共有の相関窓も20万件上限があり、専用の前段選別とcoverageが必要。
- `src/service/ipc.rs`: Named Pipe APIはread-only。ただし現行の `may_read_findings()` はactive-console-session条件で別SIDを通すため、**Canary詳細にはユーザートークンSID照合を追加**し、GUIから昇格操作を直接受け付ける設計に変更しない。
- `src/events/correlate.rs`: `Finding`/`RuleStatus` に欠損ソースの表現がある。`apps/aegis-ui/src/views.rs` は観測不能を安全表示にしない。

**特に重要**：`observed_security_event_ids[4663]` が存在しても「ある物体の4663を観測した」だけで、**各デコイの SACL と監査パイプラインの正常動作の証明にはならない**。デコイ別の coverage/self-test が必要。

新規候補モジュール（実装PRで最終調整）：`src/canary/{model,plan,registry,windows_audit,rules,health}.rs`、必要時 `src/service/canary.rs`、GUI の専用ビュー。既存 `AG-B004` をコピーせず、既存 `FileRead` 正規化と `ProcessTable` から型を再利用する。変更するシリアライズ/APIにはバージョンと旧データの読み取り規則を設ける。

### 3.1 P1-1：Security監査の高頻度イベント、絞り込みと欠損検知（D2/D3の必須ゲート）

現行 `src/events/process.rs` の `MAX_FILE_READS=4096` は **全Security 4663で共有**し、`src/service/correlate.rs` には `MAX_WINDOW_EVENTS=200_000`、各tickの読み取り量にも上限がある。`src/events/winevt.rs` の `EvtQuery` は現状チャンネルの全イベントを読む。したがって「現行 `FileRead` / `ProcessTable` を再利用する」だけでは、10万件の無関係な4663の後に来たデコイアクセスを確実に相関へ渡せない。

**入出力契約**
1. **収集時点で独立した経路**を作る。Securityログの `4663` を **逐次・有界**にパースし、`ObjectType=File`、`AccessMask & 0x1 != 0`、登録デコイへの厳密マッチを満たすイベントだけを **Canary専用の持続可能なイベントストリーム**へ流す。単なるイベントIDのフィルタだけでは、無関係な4663が多数ある場合の処理遅延を解決しない。`ProcessTable.file_reads` の上限4,096件と、共有相関窓20万件はCanaryの**入場・保持・検出**に使わない。`ProcessTable` はプロセス・ネットワーク帰属に限り利用し、特定デコイの検出証拠は別の `canary_event_uid` から結合する。
2. **保存成功前にカーソルを進めない**。デコイ対象かどうかを判定できない（XML不正、フィールド欠落、パス正規化失敗、台帳一時不可、上限到達）場合はその区間を `degraded` とし、エラー件数・原因・範囲を記録する。判定できないイベントを黙って陰性扱いしない。
3. 無関係なイベントの**全文をメモリ/スプールへ無制限に保存しない**。軽量な前段抽出（OS側の `EvtQuery` XPath またはストリーミングフィルタ）と、Canary専用の耐久キュー/固定サイズの相関状態を分離する。OS側のパス条件付きXPathは文字列エスケープ・Windows版別の対応を**実機検証してからのみ**採用し、未対応なら逐次読み取りの保守的経路へ戻す。未登録デコイは常に無効として扱う。
4. **フィルタ付きクエリでは EventRecordID の非連番は正常**。`src/events/collector.rs` の `previous+1` 欠損ロジックをフィルタ適用後のストリームに流用しない。`query_version`/フィルタの指紋/チャンネル/ブックマークを保存し、変更時は同じ履歴を継続とみなさない。`EvtSeek` での厳密な再開可能性を検証し、フィルタされたイベントが無くても古いイベントが保持されているか・ログ世代が変わっていないかを別に確認する。**連続IDの比較は無フィルタの元チャンネルでのみ有効**。Filtered/Unfilteredそれぞれのチェックポイント契約を分ける。
5. **保存元での欠損と相関側の取りこぼしは別**。チャネルの最古・最新の保持範囲、ブックマーク喪失、Securityログ消去/満杯、パーサー失敗、耐久キューの容量上限、相関tail遅延、イベント重複除去/期限切れを独立した `SensorHealth` 指標で示す。元チャンネルの範囲から「全対象イベントが必ず届いた」と推定しない。無関係イベント10万件を処理中でもデコイ検出は黙って破棄しないが、未処理バックログがあれば `active` の鮮度条件を満たさず `degraded` とする。検出遅延SLAはWindows実測が終わるまで未定。
6. Canary専用ストリームにも明示的な件数・ディスク容量・処理時間・古い記録の保持上限を設ける。上限に到達したら **`overflow` / `coverage_gap` を永続記録して `degraded`** にし、監視を続けているように表示しない。長時間高負荷時にメモリを膨張させず、少なくとも最後の確定チェックポイントまで再開可能にする。新旧状態の切替はサービスの既存スプール/ジャーナル方式に準じ、原文ファイルや資格情報の内容は保存しない。

**保守的な初期実装選択**：先にフィルタ前段+専用Canary証拠保存+監視健全性の純粋なテストを作る。OSクエリでのXPathパス照合を高信頼な必須依存にせず、仕様確認と Windows 11 VM試験を通してから最適化。

## 4. デコイのプロファイル・配置・被覆の限界

候補は「探索されやすさ」と「既存アプリを壊さないこと」の両立で選ぶ。**初期状態で勝手に設置しない**。

| プロファイル | 例 | 初期設定 | 制約 |
| --- | --- | --- | --- |
| `documents` | ユーザー Documents 内の `Accounts-backup.txt`、`passwords.txt` のどちらか1点 | 推奨・明示同意後 | Known Folder API から実パスを取得。既存ファイルがあればスキップ。OneDrive等同期中は既定拒否 |
| `developer` | 管理された空の専用テスト作業領域内の `.env`、`credentials` | オプトイン | **既存プロジェクト、実際の `.aws`/`.ssh` は変更しない**。探索されない可能性を表示 |
| `wallet` | 管理下の非アプリ用ディレクトリ内の `wallet.dat` | オプトイン | ブロックチェーンウォレット形式の「有効な秘密鍵」は絶対に生成しない |
| `application-compat` | Chrome/Firefox/FileZilla等の**隔離したテスト用プロファイル** | 実験段階のみ | 既存プロファイルへ注入しない。アプリ誤動作と検索対象外を検証してから別承認 |

デフォルトのファイル名・配置は固定仕様ではなく、匿名化した安全な合成サンプルで正規ソフトへの影響とファイル探索率を検証して決定。登録数の初期上限はユーザーあたり 8、ファイルごとの初期上限 16 KiB、総量 128 KiB（**提案値**、負荷測定前に確定値と呼ばない）。

- 中身は**明確に無効な架空のデータ**のみ。実サービスに受理される形式の鍵、機能するセッショントークン、実ウォレット seed、個人情報を含めない。ネットワークビーコンや実サービスへの認証試行はしない。
- デコイは実ユーザーの標準的なファイル権限を超えて「全員読み取り可」にしない。ユーザー権限で動くマルウェアが自然に読むことを前提とする。
- Documents を無差別走査する攻撃への誘引は成立し得るが、アプリ固有の決め打ちパスを狙うものには**デフォルト配置がヒットしない**。UI に補足する。
- 端末が共有・多ユーザーの場合、他ユーザーの実ディレクトリに一切設置しない。対象 SID・ユーザープロファイル・ログオンセッションを登録する。

## 5. 登録データ契約（案）

レジストリを端末上の信頼できるローカルストアに保存（ユーザー所有のデコイとは分離、DACL で保護、原子的更新と二世代復旧）。

```json
{
  "schema_version": 1,
  "canary_id": "random-128-bit-id",
  "owner_sid": "S-1-5-21-... (local only)",
  "profile": "documents",
  "path": "expanded-local-path (local only)",
  "identity": {"volume_serial": "...", "file_id": "..."},
  "content_sha256": "...",
  "size_bytes": 128,
  "created_at_unix_ms": 0,
  "state": "planned|installed_unverified|active|degraded|tampered|removing|removed|needs_manual_repair",
  "audit": {
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4663,
    "object_type": "File",
    "required_access_mask": "0x1",
    "sacl_entry_fingerprint": "...",
    "policy_readonly_snapshot": "...",
    "last_selftest_at_unix_ms": null,
    "last_verified_event_uid": null
  },
  "generation": 1
}
```

- 読取イベントには `canary_id`/`event_uid`/時刻/ProcessId/ProcessName/`ObjectName`/`AccessMask`/帰属信頼度/`missing_sources` を記録。本文・疑似パスワード・ユーザーの実秘密情報は収集しない。
- UI/IPC に表示するパスは既定で `%USERPROFILE%\...` 等へ伏せ、管理権限と同一ユーザー条件を満たす時のみ詳細を出す。
- `canary_id` は乱数で推測困難にし、削除権限の証明として**単独では使わない**。
- 既存のイベント原本スプールは保護された端末ローカルのまま。デコイ機能で追加収集するフィールドは最小限。イベント遅延・欠損の判断に元のイベントIDを保持。

### 5.1 P1-2：複数ユーザー・ログオンごとの情報隔離

**監査イベントの主体とデコイ所有者は別人の場合がある**。4663 の `SubjectUserSid` はアクセスを実行した主体、`SubjectLogonId` はそのログオンセッション、デコイの `owner_sid` は**保護対象ユーザー**であり、3つを混同しない。異なるSIDのプロセスがデコイを読んでも観測結果は捨てないが、詳細を閲覧できるのはデコイ所有者か、独立に承認された管理者に限る。

- `src/events/mod.rs` のフィールド許可リストは現状 `SubjectUserSid` / `SubjectLogonId` を保持しない。D2では **Security 4663専用**のパースに両フィールドを型付き追加（有効SID検証、HexInt64検証、長さ上限、欠落/不正の区別）。ユーザー名/ドメイン名・トークン/秘密情報は収集せず、SID/LogonIdも**Canaryのマッチしたイベントに必要な範囲でのみ保持**する。既存の一般イベントスプールを流用するなら、不要なSIDの蓄積・表示を防ぐスキーマ分離と移行テストが必要。
- `SubjectUserSid` が `owner_sid` と異なる場合でも、`canary_id` + 監査主体SID + ProcessId + LogonId の記録を残し、**別ユーザーからのアクセス**として表示する。SID/ログオンIDが欠けていれば `actor_unknown`、ProcessGuidが確定できなければ `process_identity_uncertain` とし、強い相関による昇格はしない。
- IPC の**Canary専用エンドポイントは要求元トークンから取得したSID**と対象 `owner_sid` をサーバー側で比較し、**不一致は拒否**。ユーザーが送ったSID、PID、セッション番号、`canary_id` だけでは認可しない。ImpersonateNamedPipeClient または等価の検証済みトークン取得でクライアントの一次トークン/偽装トークン境界を固定し、トークンを取得できない場合は fail-closed。所属グループ/ログオンセッションだけでは所有者の代用にならない。
- 現行 `src/service/ipc.rs` の `may_read_findings()` は「active console session」を満たす別SIDでも真になり得る。**既存 `findings` / `status` / `hello` の公開範囲をCanaryへそのまま流用しない**。Canaryのファイル名/パス/件数/プロセス名/最終アクセス時刻/詳細なcoverage/総件数/ページングメタデータはすべてユーザー単位で認可・フィルタし、未認可側には `not_authorized` または内容を漏らさない汎用状態のみ返す。statusの共通チャンネル健康値からも他SIDの活動を推定させない。
- 管理者の広域閲覧は当然の例外にせず、専用の明示的な管理モード・管理者トークン検証・監査記録を別ゲートとする。通常ユーザーの見える範囲は自分が所有するデコイのみ。ユーザー切替、RDP、UAC、同一コンソールで異なるSID、別SIDの権限昇格、別ユーザーのログオフを反例としてテスト。
- **自己診断の発信主体は所有ユーザーと同等のアクセス権**にする。LocalServiceやSYSTEMで読み取っても所有者コンテキストでの監査を証明できない。明示起動の通常ユーザー権限プローブ（同SID・目的に合うログオンセッション）を認可し、サービスはその結果を当該SID/ファイルの4663と照合する。ユーザートークン利用不可時は `installed_unverified` / `degraded` であり、サービス権限へのフォールバックは禁止。

## 6. セットアップのトランザクションと境界

1. `canary plan` は**完全な read-only**：ユーザープロファイル/既存ファイル/ディスク/NTFS/再解析ポイント/OneDrive同期/現在の監査ポリシー/Securityログ権限を調べ、配置候補・予想差分・リスクを表示。
2. 明示承認を受ける。デコイ追加は**通常ユーザー権限**の別処理。SACL または監査ポリシー変更は別途昇格プロセス（後述）で、最小権限・範囲限定・再確認する。
3. **第6.1節の信頼できるディレクトリハンドル基準の相対操作**で、終端ファイルはCREATE_NEW相当の排他的作成。**検査したパスを後から絶対パスで再解決して作成しない**。親を含めたreparse/symlink/junction/UNC/想定外ボリュームを拒否。ハードリンクを作らず、`FileIdInfo`・リンク数・最終パス・内容ハッシュを記録する。競合で存在したらスキップして上書きしない。
4. DACL を広げず、既存の権限設計を尊重する。非実行の偽データを書いてフラッシュし、作成と同一性確認が完了したものだけ登録。
5. 4663 の設定を希望する場合、**対象デコイファイルのみ** ReadData 成功監査の SACL ACE を設定。親フォルダを再帰監査せず、既存 ACE/所有権/DACL/継承を変更しない。既存 SACL を保存し、追加した ACE・SACL フィンガープリントを台帳化する。
6. File System 監査サブカテゴリ (GUID `{0CCE921D-69AE-11D9-BED3-505054503030}`) の Success 状態を照会。無効なら **`needs_audit_policy` と表示し、自動変更しない**。有効化は別の明示操作・管理者承認でのみ可能とする。GPO/MDM に管理されている場合は変更禁止。
7. Security チャンネルへの**読み取り権限を証明してから**監視対象へ追加。サービスは現状 LocalService 想定であり、Security チャンネル読取可と仮定しない。権限付与が必要なら別の最小権限・明示承認フローで検討する（管理者権限で常時サービスを動かす、Securityログを消す権限を与える、全OSログを無差別収集する設計は避ける）。
8. インストール完了と `active` は異なる。**対象所有者SID相当の通常ユーザー権限**で初回 `self-test` を行い、該当4663の**イベントUIDを一意に結び付けられ**、別枠のCanary証拠ストリームが健全であることを確認したときだけ第7.2節の有効期限内 `active` にする。届かない/曖昧/過負荷は `installed_unverified`/`degraded`。
9. どこで中断しても原子的なジャーナルと再試行で「ユーザーファイルを消さず、設定の一部だけ残っている」ことが分かる状態へ復帰。特権作業と通常ユーザー作業は一つの信頼された一括操作として扱わない。

**重要なセキュリティ境界**：既存 `src/service/ipc.rs` は読取専用のままとし、GUIから「指定パスを書き換える」「任意コマンドを管理者として実行する」RPCを生やさない。昇格ヘルパーはユーザーの独立した承認で起動し、固定プロファイル・既知IDだけを処理する。任意パスや任意ACEの指示、セッション越境は拒否。

### 6.1 P1-3：パス再解決の競合を許さないファイル作成・管理

`CREATE_NEW` は末尾ファイルの上書き防止にしかならない。親フォルダの **検査後のジャンクション置換**で作成先が変わる可能性があるため、絶対パスを検証してから絶対パスで `CreateFileW` するだけのD1実装は**受け入れ不可**。

- 通常ユーザーのD1処理は、検証済みの**信頼起点ディレクトリハンドル**からパスを1コンポーネントずつ**相対オープン**し、各ディレクトリハンドルのファイルシステム種別、VolumeSerialNumber / FileId、再解析ポイント、リンク状態を検証しながら進む。Windowsでの候補は `NtCreateFile(ObjectAttributes.RootDirectory)` の相対名・reparse制御と `FILE_OPEN_REPARSE_POINT` 等。APIのサポート・フラグの組合わせ・初期の信頼起点取得は **Windows 11 VM で実証して固定**し、公開API仕様が保証していない原子性を保証したと表現しない。信頼起点自体が安全に確保できなければ設置拒否。
- 親の検証と生成の間でパスが置換されても、操作対象は**検証済みハンドルからの相対子要素**で決める。作成後に最終ファイルハンドルから `FileIdInfo` / `GetFinalPathNameByHandleW` 等の同一性を再確認。登録時の親ハンドル・パス・FileIdを再検証し、移動/リネーム/入替え/ボリューム変更が疑われたら `install_failed_unsafe_path` として**`active` にしない**。意図しない場所に作った可能性があっても、**ファイルID等の所有証明ができないものを自動削除しない**。
- 初期対応はローカルNTFSに限定（対応状況をVMで確認）。UNC、ネットワーク/仮想ドライブ、OneDrive等のリダイレクト先、reparse/symlink/junction、実アプリの設定ディレクトリ、未知のファイルシステム、ボリュームを跨ぐ移動は **fail-closed**。名前の比較だけで許可しない。
- D3の昇格ヘルパーも**受け取った任意の絶対パスを開かない**。保護台帳上の `canary_id` と対象所有者SIDに紐づく記録からハンドルを開き、`volume_serial + FileId + expected owner SID + expected parent identity` を**設定直前**に照合。SACL変更は対象のハンドルにだけ行い、同一性不一致・再解析・リンク数異常・競合を検出したら拒否して監査証拠を残す。
- 同一ユーザーの悪意あるプロセスが継続的にパス名前空間を変更できる限り、ユーザーモード手順だけで**すべての並行操作への完全な耐性は保証できない**。特権ヘルパーを通常ユーザー管理ディレクトリへ向けて任意操作させないことが主な防御境界。必要な安全性を満たせない操作経路は機能を提供しない。

一次資料：[NtCreateFile / RootDirectory](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile)、[Reparse Point Operations](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points-and-file-operations)、[FILE_ID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info)。

## 7. 自己診断と coverage（「アクセス0件≠安全」）

監視の前提条件を**デコイごと**に評価する。

- `configured`：対象ファイル・本人の SID・FileId・期待内容・対象 SACL ACE を確認。
- `policy_enabled`：Audit File System / Success の有効化を確認。読み取れない場合 `unknown`。
- `source_accessible`：Security ログが指定サービス実行主体から読み取り可能。
- `self_test_seen`：各デコイを AegisGuard が読んだ直後に、**その対象の**4663 (`ObjectType=File`、`AccessMask & 0x1 != 0`、指定のプロセス/時刻) が規定時間内に到達したことを確認。
- `stream_fresh`：ブックマーク・遅延・最終成功時刻・スプール容量・ディスク空き・ログ切れ/消去・サービス停止・対象ファイル変更の状態が正常。

提案：初回と再設定後は必須の自己診断、稼働中は端末負荷に配慮した定期試験（暫定30分）。実データで頻度を校正する。**所有ユーザー相当の権限**で実施し、`trusted_probe` は第7.1節の通り**一意に対応付けた具体的な `event_uid` に限って抑制**する。実行パス・署名・PID・時刻窓だけでそのプロセスの全イベントを抑制しない。

`coverage_state` は最低限 `active / installed_unverified / degraded / disabled / tampered / unknown` を区別。**有効期限と強制失効の規則は第7.2節**に従い、古い成功イベントだけで `active` を維持しない。ログ消去 (1102)、満杯 (1104)、監査ポリシー変更 (4719)、ブックマーク飛び、専用キューのoverflow、ファイルID不一致、SACL変更、ヘルパー拒否を区別して保存し、`degraded/tampered/unknown` へ落とす。可視性は時間範囲を伴う。**記録されない読み取りがあっても不感染とは扱わない**。

### 7.1 P2-1：自己診断イベントの**一意照合**と抑制範囲

既存の「実行パス・署名/ハッシュ・PID・起動時刻・短い時間窓」は**候補絞り込み**に過ぎず、同じプロセスが同時に行った別のアクセスを抑制する理由にはならない。

1. 自己診断開始時に `probe_id`（乱数・使い回し不可）、対象 `canary_id`、検証済み `owner_sid`、ユーザー権限の実行主体、PIDと**プロセス起動時刻**、開始/終了タイムスタンプ、期待する監査アクセスを登録する。診断プロセス専用の小さな実行単位として、別の通常処理を混在させない。
2. **保存済みの特定の4663イベントの `event_uid`** と、File/ReadData/登録ファイル/主体SID・LogonId/確定PID-生存区間/狭い時刻範囲を**一意に対応付けた場合だけ** `trusted_probe` とマーク。診断の実行結果や対象プロセス名のみでまとめて抑制しない。診断前後・同じPIDの他イベントは通常の `AG-H001` 候補として残す。
3. 候補がゼロ、複数で区別不能、別SID、ログが欠落、クエリに遅延/未処理が残っている場合、**診断不成立**（`self_test_unverified`）とする。曖昧な候補を「診断成功」や「正規アクセス」に振り分けない。正規診断が複数の4663を生成し得る場合も、各イベントUIDを個別に帰属できたものだけ除外し、それ以外は通常観測・要確認に残す。
4. 抑制の台帳は `probe_id -> verified event_uid` のみ（時刻・主体・理由付き）を永続化し、重複再生では同じUIDを再分類する。同一プロセスの他UIDや同時に読んだ別デコイは抑制しない。

### 7.2 P2-2：coverageの有効期限・強制失効

`30分間隔` はあくまで実行周期の案で、**監視有効期限とは別**。初期提案は **最大45分**（VM負荷・正常系の遅延データで再調整）。`active` の必要条件は次の**すべて**：

- 最後に**一意照合された**セルフテスト成功の時刻が最大45分以内。現在のサービス実行世代・監査設定世代・デコイFileId/所有者SIDが同一で、Security取り込みと専用キューが最新のチェックポイントまで処理できている。
- サービス起動/再起動、スリープ復帰、ユーザーログオン状態の変化、監査ポリシー/SACL変更、Securityログ世代変更/消去/容量上限、ファイルID変更、フィルタ/クエリ変更、永続化エラー、未処理バックログ閾値超過、システム時刻の巻戻り/大幅ジャンプを検出したら **直ちに `degraded`（証明不能なら `unknown`）へ失効**。新しいセルフテストとパイプライン再確認が完了するまで `active` に戻さない。
- 時刻比較は一時的な壁時計だけに依存せず、OSの単調時計による現在実行世代内の経過時間・永続化したブート/サービス世代を照合する。再起動後の前世代テスト結果、古い成功イベント、将来時刻のイベントを有効な証明として再利用しない。
- 期限切れ、監査状態不明、所有ユーザートークン未使用、イベント未到達、センサ停止・スプール/専用キューの過負荷では `active` を**fail-closed** にし、通知に「最後に正常と確認できた日時」と「未観測区間」を表示する。Self-testが一度成功しても以後のすべてのアクセス検出を保証しない。

UIの`active` は「**直近の限定的な監査可視性が確認された**」という意味に限る。すべての窃取経路を監視できるとの意味を与えない。

## 8. イベント正規化と確実な帰属

1. 取り込みでは `channel=Security`、`provider=Microsoft-Windows-Security-Auditing`、`EventID=4663`、`ObjectType=File`、`AccessMask` の ReadData ビット `0x1` をチェック。属性読取り (0x80) やディレクトリの ListDirectory (同じ0x1) を誤認しない。
2. `ObjectName` は登録済みデコイの**完全一致相当**のパスのみ。大文字小文字・`\\?\`・DOS/NT volume・Unicode・8.3短縮名・renameを安全なハンドル/ボリューム情報で扱う。末尾一致/ファイル名一致だけでは採用しない。変換不能は `path_unresolved`、陰性にしない。
3. 登録時の `FileIdInfo` をイベント観測時のファイルIDと比較する。ただし 4663 自体は FileId を持たないため、**イベント時点のファイル同一性は完全に証明できない**。イベントと確認の間にファイルが入替われば `identity_uncertain` とする。
4. `ProcessId` は Security 4663 では 16 進表現の可能性を含め厳密に解析する。Sysmon の `ProcessGuid` がない場合、PID単独で過去/未来を通じて同一視しない。`PID + Image + 監査時刻が生存区間内` を満たしたときだけ候補帰属し、曖昧な場合は `process_identity_uncertain`。
5. `ProcessName` は OS 提供の画像パスの**観測値**にすぎない。名前だけの除外・allowlistをしない。正常なセキュリティ製品/バックアップソフトでもアクセスし得る。署名や親子関係、分離実行文脈で抑制候補を決める。
6. 重複 `event_uid` は重複集約。大量アクセスは同一 `canary_id + process_key + 60 秒窓` を1件に集約し、件数と根拠を上限付きで保存。イベントが欠けた場合は `missing_sources` を保持。
7. 既存の `AG-B004` は実ブラウザ資格情報ストア検出用。新ルールは **`AG-H001/H002/H003`** とし、既存の判定境界を混同しない。

### 8.1 追加の相関・監視不能契約（P1-1/P1-2）

- `AG-H001` の入力は `src/events/process.rs` の共有 `file_reads` をそのまま走査した結果ではなく、**デコイ対象を先に選別して永続化した証拠ストリーム**でなければならない。後から `ProcessTable` を作るときは、対象デコイUIDを独立して保持し、プロセス・ネットワーク補助イベントの共有窓が欠けていても `H001` 自体は取りこぼさない。
- Securityイベントの `SubjectUserSid`/`SubjectLogonId` は「アクセス主体」の確証に使い、閲覧認可は「デコイ所有者SID」と「IPCの実トークンSID」で行う。**イベント主体SID＝デコイ所有者SIDであることは発火条件ではない**。
- フィルタされたSecurityのレコードIDの飛びは `gap` としないが、CursorLost、世代不一致、チャンネル最古保持イベントより古いチェックポイント、書込み未完了、マッチ判定不能、証拠キュー溢れは `coverage_gap`。この区間の無検出は検査不能として扱い、 `RuleStatus.evaluable=false` / `missing_sources` に出す。
- ルール条件に必要な履歴が存在する時だけ `H002/H003` を評価する。共有20万件窓が溢れてプロセス/通信の帰属を失ったとき、既知の `H001` は維持するが、**勝手にH002/H003を昇格または陰性判定しない**。

## 9. 相関ルール・レベル（提案）

| ルール | 発火条件 | 最小出力 / 判定 |
| --- | --- | --- |
| `AG-H001` | 監視対象に対する有効な 4663 ReadData。`trusted_probe` ではない | `observed`。デコイID・event UID・時刻・プロセス帰属と不確実性 |
| `AG-H002` | 同一の**確定したプロセス生存期間**で 5 分以内に異なるデコイ2点以上を読む | `review`。対象数・時間窓・重複統合を添付 |
| `AG-H003` | `H001/002` と既存の新鮮なC2 IOC接続、またはその他の独立した強い根拠が同一の確定プロセスに 10 分以内で共起 | `review`（高優先度の調査）。ネットワーク可視性/IOC期限/帰属根拠が欠ければ昇格しない |
| `AG-H004`（別案） | デコイ削除・改変・SACL剥離または入替え | `tamper`。感染の確定ではない。FIM/監査・スナップショットで説明 |

- `H001` の単発は**侵害確定ではない**。実際のリスクに応じて通知は集約、正常バックアップ等を低優先にする。ただし検出根拠を捨てない。
- `H002/H003` の確信度と調査優先度は別の軸。確認できない通信は「なし」ではなく `not_observed`、収集元が無ければ `unknown`。
- `H003` の相関窓は既存C2/ブラウザー相関の設定と整合させて固定・版管理し、同じ結果をオフライン再生と継続実行で再現する。
- 一切のルールで「窃取完了」「外部流出確定」「検出なし＝安全」の文言を出さない。

## 10. 監査ポリシー / SACL の責任とロールバック

最初の実装PRでは監査ポリシー/SACLの**読み取りと事前検証だけ**を実装し、変更コードは次PRの明示ゲートとする。理由：Windows のセキュリティ監査は端末全体の共有資源で、GPO/MDM/別ソフトの設定変更と競合する。

後続の「設定可能」PRで必要な契約：
- 管理者が明示した時だけ `Audit_ObjectAccess_FileSystem` の**Success ビット**を追加。Failure や他サブカテゴリを変更しない。管理対象ポリシーで上書きされる場合は有効化したと偽らない。
- SACL は**デコイ本人のファイルだけ**をハンドルベースで操作し、既存ACE・継承フラグを保つ。自己管理ACEの識別が曖昧、第三者の変更が検出された場合は**上書きして復元しない**。
- 変更前後の政策状態・SACLフィンガープリント・ファイルID・変更者・時刻を保護ストアでジャーナル化。クラッシュ中断・復元試行を再開可能にする。
- 削除時に元の状態を無条件に書き戻してはならない。**後から管理者/GPOが変更した場合は競合扱い**とし、AegisGuard の管理下と証明できるものだけ戻す。
- グローバル監査を初めから有効にしていた機械では絶対に無効化しない。AegisGuard が有効化した場合も、他ソフトの依存があるか判定できなければ無効化せず管理者に案内する。
- ファイル削除は `FileId`・内容ハッシュ・登録したパス・所有者・リンク数・reparse属性のすべてが一致した**自己所有ファイルのみ**。ユーザーが編集したファイルはデータ保護のため残し `needs_manual_repair`。デコイでない親ディレクトリ・他ファイルは削除しない。
- 通常アンインストールのほか、監査ポリシー有効化失敗、権限喪失、クラッシュ、ディスク満杯、競合中断、復元失敗をテストする。
- LocalService に広範な管理者権限や `SeSecurityPrivilege` を常時付与しない。Securityログの読み取り権限は最小化し、監査・SACL変更は独立した昇格ワンショットヘルパーに限定する。

## 11. CLI・型・UI の予定契約（すべて未実装）

CLI 候補：
```text
aegisguard canary plan --profile documents
aegisguard canary install --plan <plan-id> --confirm
aegisguard canary status
aegisguard canary self-test --id <canary-id>
aegisguard canary events --since 24h
aegisguard canary remove --id <canary-id> --confirm
aegisguard canary audit status
# OS監査の有効化は後続の別PRでのみ追加。初期段階は「設定案内」だけ。
```

`canary status` の例（仕様説明用）：
```json
{
  "schema_version": 1,
  "feature_state": "degraded",
  "canaries": [
    {
      "canary_id": "example",
      "profile": "documents",
      "state": "installed_unverified",
      "coverage": {
        "file_identity": "verified",
        "policy": "enabled",
        "sacl": "present",
        "security_log": "permission_denied",
        "self_test": "not_verified",
        "last_verified_unix_ms": null
      }
    }
  ]
}
```

UI は **「おとりファイル」** 画面を独立させ、監視中の個数、各ファイルの有効状態、最終セルフテスト、発火履歴、理由、表示可能な範囲のプロセス情報を示す。失敗時は `監視できていません` と明示。初期のGUIは**読み取り専用**で、確認したプランや管理者向けコマンドを案内するだけ。将来の設定画面も既存 read-only IPC を勝手に変更せず、承認済みの独立ヘルパーを経由する。

API は既存 `src/api.rs` の追加互換性を優先する。スキーマ増分、未知フィールドの安全読込み、古いクライアントへの影響とページング・上限を各PRで検証する。

## 12. 実装PRの分割と依存ゲート

| PR | 作業範囲 | 書換え対象候補 | 完了条件 |
| --- | --- | --- | --- |
| **D0：本設計** | OS仕様調査、責任境界、失敗モデル、インクリメンタル実装計画 | この文書、ロードマップのリンクのみ | 技術判断・実装チェックリストがレビュー可能。**機能はまだ提供しない** |
| **D1：登録と安全な設置** | 純粋プラン、ランダム/無効コンテンツ、排他生成、保護台帳、safe-remove、Mockテスト | `src/canary`、`src/main.rs` | 既存ファイル/リンク/同期先を壊さない、失敗時再開 |
| **D2：監査の読み取りと模擬イベント検出** | `4663` 正規化、厳密マッチ、`H001`、型・合成 fixture。SACL/Policyは**変更しない** | `src/events/*`、`src/canary/*` | PID再利用/hex PID/パス別名/ログ欠落を誤帰属しない |
| **D3：明示承認付き監査設定＋健康状態** | 権限分離ヘルパー、対象限定 SACL、ポリシー状態確認・オプトイン、Security 収集、self-test、可逆なジャーナル | `src/canary/windows_audit.rs`、`src/service/*` | VMで設定前後・失敗復旧を確認するまでデフォルト無効 |
| **D4：相関・GUI・通知** | `H002/H003/H004`、継続/オフライン一致、トレイ/画面、ログの上限・重複抑制 | `src/events/correlate.rs`、`apps/aegis-ui/*` | 正常操作を感染と断定しない、テストとUI文言が一致 |
| **D5：実機負荷とリリースゲート** | 実際のWindows 11 x64で監査可視性・CPU/ディスク・再起動・OneDrive・別ユーザー検証 | テスト手順と結果、`RELEASE_GATE.md` | 未確認項目を VERIFIED/PRODUCTION_READY と呼ばない |

D1〜D4は**互いに競合する共通ソースへの並列実装を禁止**し、必要なAPI契約・順序を確定させる。D0では `Cargo.toml`、OS設定、ソース、実機に手を触れない。

## 13. 受け入れテストと反例

単体・合成 fixture（Linux/Windows GitHub Actions で可能な範囲）：
1. 実在の同名ファイル・別ユーザーのファイル・リンク/ジャンクション/ハードリンク・親フォルダの reparse・UNC・OneDrive 同期先・ネットワークマウントがあっても無断上書き/削除しない。
2. `ObjectType=File` かつ `AccessMask & 1 != 0` の 4663 だけを `H001` とし、`4656`、ReadAttributes-only、ListDirectory、Sysmon11 単独では発火しない。
3. Security 4663の hex PID、同名異パス、Unicode/大文字小文字、`\\?\`、NT device、ファイル入替え、PID再利用、Sysmon ProcessGuid が不在のときを区別する。
4. セキュリティ製品・正規バックアップ・本人の手動オープンを `observed` に残し、感染確定と通知しない。`trusted_probe` のみ確実に識別して抑制する。
5. Security ログが無い・読めない・途中から切れた・ディスク満杯・SACLが変わった・ポリシーが無効/不明のときは `degraded/unknown` で可視化する。
6. `H002` は異なる2ファイルを同一生存期間で読んだ場合のみ。複数ユーザー同時実行、PID再利用、古い/重複イベントで不当な昇格なし。
7. `H003` はC2 IOCの鮮度、有効な ProcessGuid 帰属、観測された通信の組合わせが必要。IPのみ一致・古いIOC・通信未観測で感染確定を出さない。
8. 故障注入（書込み途中クラッシュ、ストア破損、復元失敗、競合する管理者操作）で台帳が壊れても実ファイルが失われない。
9. 旧JSONL/`api.rs`/read-only IPCとの互換、未知フィールドと新 schema、100/1000/100000 イベントで有界メモリ・件数集約。
10. 読み取り専用既存サービスへ任意ファイル書換え/任意管理者命令を注入できない。権限昇格・別セッション・偽装SIDを拒否。

**PR #68 再レビュー P1/P2 の追加必須テスト（合成fixtureで先行、Windows 11で同種の再現）**：

11. **無関係なSecurity 4663を100,000件→登録デコイの4663を1件**（さらに共有 `MAX_FILE_READS=4096` を超えるケース）で `AG-H001` が**正しく1件残る**。共通相関窓20万件が埋まってもH001は取りこぼさず、無関係イベントを無制限保存しない。backlog・専用キュー容量オーバーでは健康状態が `degraded/coverage_gap` になり、`active` のままにならない。
12. XPath等のOS側フィルタ後にレコードIDが `100, 500, 1000` と飛ぶ正常イベントでは **gap誤報なし**。実際のログ上書き/ブックマーク喪失/クエリ定義変更/保存失敗は **確実にgap/unknown**。永続化を挟んだ再起動、bookmark重複、パーサーエラー、マッチ不確定の境界条件を再生する。
13. デコイ所有者SID A、監査アクセス主体SID B、IPCクライアントSID C（同一コンソール）、管理者・別RDP・トークンなりすましを組み合わせ、**B≠Aでもイベントを記録**し、**C≠Aにはstatus/件数/パス/プロセス名を含め情報が漏れない**。`SubjectLogonId` のhex/欠損と通常ユーザーでしか成功しない自己診断を検証する。
14. **親ディレクトリ検証直後にジャンクションへ置換**、別ボリューム化、信頼起点不明、ハンドル・パス・FileId不一致、昇格ヘルパーへ偽 `canary_id`/任意パス注入を行い、**誤配置/誤SACL更新/他者ファイル削除が発生しない**。回避できない競合経路はインストール拒否・手動復旧扱い。
15. 1回のself-test直前・直後に**同一プロセスが別の通常アクセス**を行った場合でも、**一意なテスト `event_uid` 以外は除外されない**。複数候補・UID不一致・プローブ別SID・ログ未到達・遅延では `active` にならない。サービス再起動・スリープ復帰・時計巻き戻り・監査/SACL変更・テスト成功から45分超・処理滞留で `active` が直ちに失効し、再検証前に戻らない。



Windows 11 実機（**未実施、Codex CLI または人手で実施**）：
- VMスナップショット・通常ユーザー/管理者別・Defender有効の環境で、事前 `auditpol`・SACL・イベントログ設定を保存。監査を OFF/ON にした場合の self-test、有効化不能と復元を検証。
- 同じファイルに対し「実バイト読み取り」「属性のみ」「別名パス」「削除/入替え」を行い、4663の実 XML、プロセスID・正規化結果を記録。`H001` の誤検知・検出漏れを数える。
- Security 収集権限を持たない LocalService、監査 GPO 管理、別のプロセスが SACLを変更した場合、ログ上書き/消去、サービス再起動、スリープ/復帰、サインアウト、端末の突然停止を確認。
- Defenderと正規バックアップ/インデクサの共存、OneDrive/リダイレクトされたDocuments、複数ユーザープロファイルで負荷と誤通知を比較する。
- CPU、メモリ、Security Event件数/日、p50/p95検出遅延、欠損・ドロップ・ローテーション、ディスク利用を測定。**閾値はベースライン実測で決定**し、合格前に「軽量」「リアルタイム保護」と宣言しない。
- 実マルウェアの実行を受け入れテストの必須条件にしない。Mockイベントと無害な読み取りスクリプトで実装品質を検証する。

## 14. 未決事項・レビューで固定すべき判断

1. デコイをどの程度実アプリの探索先に近づけるか。**安全優先の既定：既存アプリ領域に書かず、専用テスト領域+Documentsのみ**。検出カバレッジを誇張しない。
2. Securityログ収集主体の具体的なWindows SID/ACL設定：LocalService に読取が許可されることを**実機で確認するまで未確定**。広権限でごまかさない。
3. グローバル監査の有効化/復帰は他製品と共有されるため、導入を第二ゲートとする。**デフォルトは変更しない**。
4. SACL の自己追加 ACE を安全に除去できない競合では、勝手に元全体を書き戻さず手動復旧を促す。
5. UIでいう「異常あり」と「侵害確定」は別。リスク表現は `observed / review / unknown` と coverageを併記する。
6. ETW/Minifilter の導入は、4663 の観測率・負荷・実機検証で課題が明らかになってから判断する。

## 15. この設計PR自体の完了条件

- [x] 現行の読み取り監査・常駐サービス・IPC境界と差分を特定
- [x] Microsoft一次資料とMITREから方式の根拠/限界を整理
- [x] 実認証情報や既存プロファイルを傷つけないファイル生成・削除契約
- [x] SACL/ポリシーの同意、権限分離、監視欠損、プロセス帰属の設計
- [x] 模擬イベント/実機テストと段階的PR分割
- [x] PR #68 再レビュー：P1-1容量・フィルタ付きRecordID、P1-2ユーザーSID隔離、P1-3ハンドル相対生成、P2-1UID単位probe抑制、P2-2coverage TTL・強制失効を仕様化
- [ ] Windows 11実機で 4663 を観測（**このPR対象外**）
- [ ] 実装・CI・性能・誤検知・復旧の検証（**このPR対象外**）

**このPRは仕様書のみ**。マージしてもおとりファイルは自動設置されず、サービスやOS設定にも影響しない。
