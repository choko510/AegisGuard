# 調査報告：Wazuh / wazuh-fim-persistence

> 担当：wazuh-fim-persistence / 調査日：2026-11-05（JST） / 調査結果：**部分完了（一次ソース・既存テストの静的調査完了、Windows実機試験未実施）**  
> 対象：Windows 11 x64・Rust-first・Microsoft Defender併用のAegisGuard。担当範囲：FIM、ファイル改ざん、レジストリ・永続化監視。**コードの取り込み・実装・PRマージは行っていない。**

## 0. 結論（3〜5行）

- **取り入れる価値：高い。** Wazuhの「定期ベースライン＋変更通知＋ローカル状態DB＋失敗時の再照合」はAegisGuardの静的スキャンを継続的な改ざん検知へ拡張する設計参考になる。
- **最優先候補：**（1）少数の重要パスのSHA-256・属性ベースラインと再照合、（2）WindowsのReadDirectoryChangesWによる変更通知と取りこぼし復旧、（3）レジストリの限定的な定期差分監視。
- **見送り候補：** Wazuh FIM本体のRust移植・コードコピー、全ファイルのアクセス監査/SACL自動変更、FIMをブラウザ認証情報の読み取り防止とみなす設計。
- **最大の制約：** FIMは「書換え・作成・削除などの状態差分」を主に検出するもので、Chromeの資格情報DBの**読み取り・持ち出しを直接検知/遮断しない**。ライセンスとWindowsの権限境界も分離して扱う。

## 1. 対象の固定と調査方法

| 要素 | 値 / 根拠 |
|---|---|
| 公式リポジトリ・commit固定URL | [wazuh/wazuh @ 2940bdfb5e1a90cd67200fa63579d7eadf679009](https://github.com/wazuh/wazuh/tree/2940bdfb5e1a90cd67200fa63579d7eadf679009)。2026-11-05取得時のデフォルトブランチは \`main\`。直近コミットはFIM sync queueのメモリ・WAL/チェックポイント関連の改善を含む。 |
| 調査コミットSHA・タグ | **2940bdfb5e1a90cd67200fa63579d7eadf679009**（2026-11-04 UTCのコミット）。タグの網羅的な対応付けは未確認。特定リリースの動作保証を意味しない。 |
| AegisGuard比較先SHA | [choko510/AegisGuard @ 83fcf0d150e8d760baff5f971c106deb09c1f8e4](https://github.com/choko510/AegisGuard/tree/83fcf0d150e8d760baff5f971c106deb09c1f8e4)。2026-11-05に取得した \`main\`。 |
| ライセンスファイルと対象範囲 | [Wazuh LICENSE](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/LICENSE#L1-L75)：原則GPL v2、\`src/engine/\` はAGPL v3-or-later、指定 \`src/shared_modules/\` はGPL-2.0-only **OR** AGPL-3.0-or-later。他の同梱データ・外部依存は別確認が必要。AegisGuardには[現時点でコードライセンスが未設定](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md)。 |
| ソース/ドキュメント確認範囲 | Wazuh \`src/syscheckd/{src,include}\`（file/registry/realtime/whodata/recovery/DB）、\`src/logcollector/src/read_win_event_channel.c\`、\`src/win32/ossec.conf\`、\`src/deps.lock.mk\`、\`src/syscheckd/CMakeLists.txt\`、\`src/unit_tests/syscheckd/\` と \`tests/integration/test_fim/\` の構成、ライセンス、公式FIM文書。AegisGuard README/SECURITY/ARCHITECTURE/Cargo/main/model/scan。 |
| 実機・ビルド・テスト | **未実施**。Windows 11実機、監査権限、Wazuh Manager、依存ツールチェーンを伴う動的検証は実行していない。上流のテスト**コードの存在と内容を閲覧**しただけで、成功とは判定しない。 |
| 日付・未検証制限 | 2026-11-05。GitHub検索での「不一致」はリポジトリ全域での非存在証明にはならない。性能・欠落率・誤検知率は未測定。 |

**比較先の現在地：** AegisGuardは\`src/main.rs\`の\`scan\`/\`c2\`サブコマンドだけを持つCLIであり、\`src/scan.rs\`は手動起動時に対象ファイルを読み、SHA-256をJSONLへ出す。FIMの常駐監視、イベント購読、永続ベースライン、Windowsサービス、ブロック機能はまだない。[main.rs](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/main.rs#L1-L78) / [scan.rs](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/scan.rs#L24-L111) / [ARCHITECTURE](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md#L8-L46)。

## 2. 実装アーキテクチャとソース調査

### 2.1 コード根拠付き機能マップ

| 機能 | 主要なファイル/シンボルと役割 | commit SHA固定の一次情報 | 確認状態 |
|---|---|---|---|
| 定期全走査とベースライン | \`fim_scan()\` → \`fim_file_scan()\`、Windowsでは \`fim_registry_scan()\`。初回と次回走査を区別する。 | [fim_scan.c L43-L119](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/fim_scan.c#L43-L119) | 実装確認 |
| 収集属性・ハッシュ | \`fim_get_data()\` がサイズ・ACL・Windows属性・mtime・所有者・MD5/SHA-1/SHA-256・inode/deviceを構成に応じ取得する。 | [file.c L815-L914](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/file/file.c#L815-L914) | 実装確認 |
| 変更内容の分類 | \`fim_checker()\` とDB transaction callbackで現在状態とDB状態を照合し、イベントをadded/deleted/modifiedに正規化。属性変更の種類をJSONへ追加。 | [file.c L34-L44](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/file/file.c#L34-L44)、[file/events.c L25-L175](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/file/events.c#L25-L175) | 実装確認 |
| 削除/移動/名前変更 | \`fim_realtime_event()\` が存在時は再検査、存在しないとき \`fim_process_missing_entry()\` へ送る。DB上のパス消失やディレクトリ配下の削除を扱う。 | [fim_scan.c L142-L159](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/fim_scan.c#L142-L159)、[file.c L1272-L1367](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/file/file.c#L1272-L1367) | 実装確認。**Windowsでrenameを単一の旧名→新名イベントとして相関する実装は未確認** |
| Windowsリアルタイムファイル監視 | \`realtime_win32read()\` が\`ReadDirectoryChangesW\`で名前/サイズ/最終書込/属性/セキュリティ変更を要求。\`realtime_adddir()\`でディレクトリハンドル作成。 | [run_realtime.c L561-L574](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/run_realtime.c#L561-L574)、[L640-L685](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/run_realtime.c#L640-L685) | **Windows API使用をソースで確認** |
| 変更通知の変換と欠落 | \`RTCallBack()\`は\`FILE_NOTIFY_INFORMATION\`のファイル名をパスに直し\`fim_realtime_event()\`へ渡す。**\`pinfo->Action\`によるrenameペア結合はこの関数にない**。\`dwBytes==0\`は警告、\`dwerror!=SUCCESS\`はエラーで戻る。 | [run_realtime.c L425-L517](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/run_realtime.c#L425-L517) | 実装確認。通知消失後の全回復動作は**要実測** |
| Linux/Windows方式の違い | Linuxは\`inotify_init()\`と\`IN_Q_OVERFLOW\`を利用。Windowsブランチは別の\`ReadDirectoryChangesW\`。 | [run_realtime.c L32-L58](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/run_realtime.c#L32-L58)、[L210-L230](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/run_realtime.c#L210-L230)、[L425-L574](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/run_realtime.c#L425-L574) | 実装確認 |
| レジストリFIM | \`fim_registry_scan()\`がトランザクションを開始。\`fim_open_key()\`は\`RegOpenKeyExW\`/\`RegQueryInfoKey\`/\`RegEnumKeyExW\`で再帰列挙し、\`fim_read_values()\`で\`RegEnumValueW\`を照合。WOW64 32/64ビューを区別。 | [registry.c L1877-L2025](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/registry/registry.c#L1877-L2025)、[L2051-L2195](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/registry/registry.c#L2051-L2195) | 実装確認。**即時RegNotifyChangeKeyValue方式は本担当の探索範囲で確認できず** |
| レジストリの比較・除外 | \`fim_registry_validate_ignore()\`で明示パス/正規表現を除外。\`registry/events.c\`はmtimeや値ハッシュ差分をJSON化。 | [registry.c L1259-L1312](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/registry/registry.c#L1259-L1312)、[registry/events.c L31-L162](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/registry/events.c#L31-L162) | 実装確認 |
| Windows who-data（変更主体） | \`set_winsacl()\`が\`SeSecurityPrivilege\`を調整しSACLへ監査ACEを設定。Windows Securityの4656/4663/4658/4719等を絞る。maskは書込/削除/ACL変更であり一般的な読取監視ではない。 | [win_whodata.c L27-L32](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/whodata/win_whodata.c#L27-L32)、[L198-L327](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/whodata/win_whodata.c#L198-L327)、[L1338-L1393](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/whodata/win_whodata.c#L1338-L1393) | 実装確認。監査ポリシーへの介入はAegisGuard初期段階で不採用 |
| ローカルFIM DB | \`DB::init()\`が\`DBSync\`を\`DbEngineType::SQLITE3\`、\`DbManagement::PERSISTENT\`で起動。FIMDBはローカル状態を保持する。 | [db.cpp L40-L57](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/db/src/db.cpp#L40-L57) | 実装確認 |
| 更新同期・再送・回復 | \`persist_sync_documents()\`が差分を永続キューへ記録。\`fim_recovery_persist_table_and_resync()\`はDataClean後DELTA再同期、失敗時は通常周期のキュー送信へ回す。 | [syscheck.c L303-L397](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/syscheck.c#L303-L397)、[recovery.c L106-L143](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/recovery/recovery.c#L106-L143)、[L294-L321](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/recovery/recovery.c#L294-L321) | 実装確認。**Manager連携の設計でありローカル製品にはそのまま不要** |
| イベントログ/Sysmon接続口 | FIM本体とは別の\`logcollector\`がWindows \`EvtSubscribe\`とbookmarkを使って任意に設定したEvent Channelを収集する。Sysmonのテスト設定は\`Microsoft-Windows-Sysmon/Operational\`。 | [read_win_event_channel.c L425-L526](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/read_win_event_channel.c#L425-L526)、[テスト設定](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/tests/integration/test_logcollector/test_configuration/data/test_cases/cases_basic_configuration_location_win.yaml) | 収集API実装確認。**FIMとSysmonのProcessGuid自動結合は未確認** |
| Windows既定の監視対象 | \`ossec.conf\`はStartupフォルダをrealtimeで監視し、\`HKLM\...\Services\`、Run/RunOnce、Winlogon等を列挙。既定Security EventChannelの通常クエリは4663等を除外。 | [ossec.conf L14-L35](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/win32/ossec.conf#L14-L35)、[L59-L139](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/win32/ossec.conf#L59-L139) | 設定確認。構成ファイルでありWindows 11上の検出成功は未検証 |

### 2.2 取りこぼし・rename・ハードリンク・USNの評価

1. **renameは注意。** Microsoftの\`FILE_NOTIFY_INFORMATION\`には\`FILE_ACTION_RENAMED_OLD_NAME\`/\`NEW_NAME\`があるが、確認したWazuhの\`RTCallBack()\`は\`Action\`を読まず、各パスを独立に再検査している。結果を「必ず1件のrenameイベント」と説明できない。AegisGuardでは候補として旧名/新名を短期間保持するが、ペアリング不確実な場合は\`remove+create\`と記録する。[Wazuh callback](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/run_realtime.c#L478-L508) / [Microsoft FILE_NOTIFY_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-file_notify_information)。
2. **オーバーフローはデータ欠落。** WazuhのWindows callbackは転送0バイトなら警告後に読み直す。Linuxには\`IN_Q_OVERFLOW\`フラグがあるが、Windows側で同等の「直ちに整合性再走査を確実に予約する」経路は上記callbackだけからは立証できない。Microsoftは0バイト/\`ERROR_NOTIFY_ENUM_DIR\`時にディレクトリの再列挙を指示している。AegisGuardは**欠落フラグ＋再走査**を設計上の必須条件とする。[Wazuh callback](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/run_realtime.c#L438-L516) / [Microsoft ReadDirectoryChangesW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw)。
3. **ハードリンク：未確認/要検証。** Wazuhは\`statbuf->st_ino\`/\`st_dev\`を保持するが、inodeを用いた欠落パス検索は確認箇所では\`#ifndef WIN32\`分岐。Windowsの同一実体を複数パスが指す時、1パスの通知が全別名のベースラインを更新する保証は得られない。AegisGuardではパスとは独立の\`volume ID + file ID\`等をハンドルから取得して同一実体として扱うか、PoC時点ではハードリンクを\`unsupported/incomplete\`と明示する。[file.c L899-L914](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/file/file.c#L899-L914) / [fim_scan.c L172-L194](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/fim_scan.c#L172-L194)。
4. **Windows USN Journal：採用実装は未確認。** 調査コミットのGitHubコード検索で\`USN_JOURNAL\`/\`FSCTL_READ_USN_JOURNAL\`は該当なし、実際に確認できたWindows経路は\`ReadDirectoryChangesW\`。ただし検索索引・探索範囲の制約上「Wazuh全体で絶対に使用しない」とは断定しない。USN自体はAegisGuardの将来案（初期PoCでは不要）。
5. **検出に関する重要な落とし穴：** \`fim_get_data()\`はサイズ0や\`file_max_size\`以上のファイルなどでハッシュ計算をスキップし、初期化済みの空ファイル用ハッシュ文字列が残り得る。大容量・読み取り失敗・シンボリックリンクの扱いは「ハッシュがある＝内容確認済み」としない。AegisGuard側では\`hash_status={computed,skipped_size,unreadable,unsupported,changed_during_read}\`を明示し、欠落を安全判定しない。[file.c L874-L908](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/file/file.c#L874-L908)。

### 2.3 永続化ポイントと「監視していないもの」

- **レジストリ:** 既定設定には\`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\`/\`RunOnce\`、\`HKLM\SYSTEM\CurrentControlSet\Services\`、\`...\Winlogon\`がある。前者はユーザーログオン起動、後者はサービス設定に対応するが、FIMはレジストリ**状態差分**であり、サービスが実際に起動した事実の代替ではない。[ossec.conf](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/win32/ossec.conf#L81-L106)。
- **スタートアップ:** 既定の\`%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`は共通Startupフォルダの監視。ユーザーごとの\`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`は別途対象化が必要。ユーザーSIDごとの\`HKU\<SID>\...\Run\`/\`RunOnce\`も追加候補であり、読み込まれていないユーザーハイブは監視できない。
- **スケジュールタスク:** 既定設定の\`schtasks.exe\`監視は**実行ファイル自体**の改ざん確認であり、登録されたタスクの変更検出とは異なる。タスク定義\`%WINDIR%\System32\Tasks\`の限定監視、Task Scheduler Operationalログ、Task Scheduler APIによる差分照合を別機能とする。これらをWazuh FIMで包括実装済みとは扱わない。
- **Sysmon:** イベント11（FileCreate）、12–14（RegistryEvent）、1（ProcessCreate）、19–21（WMI永続化）等は別データソース。\`logcollector\`の\`EvtSubscribe\`経由で取り込める構成と、Windows FIM自身の差分処理を混同しない。イベントが無効化/未導入/ローテーション済みなら空白が生じる。[Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)。

## 3. 具体的な取り込み候補と選択肢

| 候補機能 | 利用方法（crate/API・外部CLI・独自実装・参考・見送り） | AegisGuard接続先 | 優先度 | 工数目安 S/M/L | ライセンス・技術上の阻害要因 |
|---|---|---|---|---|---|
| **① 限定ファイルベースライン・差分** | **独自Rust実装**（既存sha2、Windows API/ファイルハンドル、ローカルSQLite crateを評価）。Wazuhの状態遷移だけ参考 | 将来\`aegis-fim\`→\`core/model\`/JSONL | **P0** | **M** | Wazuh GPLコード転用なし。TOCTOU、ACL、reparse/hardlink、初期状態への信頼、DB保護 |
| **② ディレクトリ変更通知＋欠落時再走査** | **Windows API直接**（\`windows\`/\`windows-sys\`の採用可否を別途確認）、監視ロジック独自 | 将来\`aegis-windows-sensor\`→\`aegis-fim\` | **P1** | **M** | バッファ溢れ、監視停止、rename相関不定、再起動後のギャップ |
| **③ レジストリ持続化点の定期差分** | **Windows Registry API直接＋独自実装**。まず読み取りのみ、\`RegNotifyChangeKeyValue\`は別途検証 | 将来\`aegis-persistence\`→\`core/model\` | **P1** | **M** | HKLM/HKU権限、WOW64ビュー、ユーザーごとのHive、正規変更による誤検知 |
| Sysmonイベント補助相関 | **設計参考＋Windows Event Log API直接**（他担当のSysmon/ETW計画と調整） | 将来\`windows-sensor\`のイベントバス | P2 | M | Sysmon未導入・設定不足、イベントの欠落、同一プロセスの相関不確実 |
| Wazuh全体（agent/manager/indexer）のサービス連携 | **外部サービス/CLI候補として評価した結果、AegisGuard内への同梱は見送り** | 製品内部には接続しない | P3 | L | Agent/Manager構築、リソース・運用負荷、ライセンス、製品目的のずれ |
| Wazuh \`win_whodata\`のSACL/監査ポリシー変更 | **設計参考のみ／初期導入見送り** | 将来の特権センサー候補 | P3 | L | 管理者/\`SeSecurityPrivilege\`、システム監査変更、復旧責務、機密情報 |
| USN Journalベースの巻き戻り補填 | **将来の独自実装案（現時点は採用保留）** | 将来\`aegis-fim\` | P3 | L | ボリューム/ファイルシステム差、Journal無効・削除・wrap時の扱い |
| ファイルを「読んだ」主体の検出をFIMだけで行う | **不採用** | なし | — | — | FIM変更通知・属性比較では一般的な\`ReadFile\`を見ない |

### 採用候補の入出力・失敗処理・最小PoC

**① ローカルベースライン。** 入力＝ユーザー承認済みの少数のディレクトリ/ファイル、対象のファイルハンドル、除外ルール。出力＝\`path, canonical identity, size, mtime, attrs/ACL digest, sha256, hash_status, scan_generation, observed_at\`のスナップショットと、\`added/modified/deleted/incomplete\`の差分。**まずは実行ファイル・スタートアップ設定の限定フォルダだけ**。初回は\`baseline_created/untrusted\`を記録して警報と区別し、次回から差分を報告。ファイルの途中変更、アクセス拒否、巨大ファイル、再解析点は「未評価」として保存し、DB更新をトランザクションで原子的に確定する。現状の\`src/scan.rs\`の読み取り結果を再利用する場合も\`symlink_metadata\`→\`File::open\`間の置換競争が残るため、先にハンドル同一性の安全性を強化する。[AegisGuard SECURITY](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md#L5-L16)。

**② リアルタイム通知。** 入力＝監視対象ディレクトリハンドルと\`ReadDirectoryChangesW\`イベント、ファイル操作の境界にある観測時刻。出力＝\`path_hint, action_hint, received_at, watch_id\`を持つ変更候補→①の再評価。イベントは完全な証拠ではないため、同パス変更はデバウンスし、watch失敗・0バイト・エラー・起動時に\`reconcile_required\`へ遷移。通知のみに頼って\`deleted\`を確定しない。PoCは一時フォルダのcreate/modify/rename/deleteと監視停止・復旧を検証する。

**③ レジストリ差分。** 入力＝\`HKCU\Software\AegisGuardFIMPoC\`等の安全な検証キー、のち承認済みRun/RunOnce、Services等のキー（キー/値名・型・正規化値・最終書換時刻・32/64ビュー）。出力＝差分イベント、\`permission_denied/hive_unloaded\`等の未評価状態。バイナリ値・資格情報そのものはログに出さず、内容をハッシュまたは伏字化。読み取り専用、専用検証キーの作成/削除だけをPoCで行う。正規ソフトの更新は署名・実行主体・既知の更新プロセスと相関するまで自動悪性判定しない。

**補助相関（P2）。** Event Log APIによる\`Microsoft-Windows-Sysmon/Operational\`購読を、他担当のWindowsセンサー設計と一本化。イベントIDの種類・ProcessGuid・規則・ブックマークを保持し、\`FIM差分とイベントの観測時間が近い\`程度の仮説から開始する。Sysmonイベントが見つからなかったことは安全証明ではない。EventChannelが存在しなければ\`not_configured\`としてFIM単体へ縮退。

## 4. ライセンス・再配布・依存関係

| 構成要素 | 一次資料 | 判断・制約 |
|---|---|---|
| \`src/syscheckd/\`（FIM C/C++）、\`src/logcollector/\` | [LICENSE 冒頭](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/LICENSE#L1-L67)、[file.cのヘッダー](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/file/file.c#L1-L9)、[logcollectorヘッダー](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/read_win_event_channel.c#L1-L10) | 原則 **GPL v2**。Rustへの逐語的移植・翻訳・コードコピーはライセンス義務を回避しない。**仕様・設計原理のみ参考**とする。 |
| \`src/engine/\` | [LICENSE 冒頭](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/LICENSE#L1-L18)、[COPYING-engine](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/engine/COPYING-engine) | **AGPL v3-or-later**。FIM単体の根拠と混ぜない。AegisGuardへの組み込みは不採用。 |
| \`src/shared_modules/{utils,manager_config,keystore,indexer_connector,common,http-request}\` | [LICENSE 冒頭](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/LICENSE#L10-L32) | 指定範囲は **GPL-2.0-only OR AGPL-3.0-or-later**。Wazuhのほかの共有モジュールすべてがこの例外ではない。 |
| Wazuh本体同梱のルール・デコーダ・データ | [LICENSEの適用範囲](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/LICENSE#L37-L76)、[ruleset/README](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/ruleset/README.md) | **別途指定がなければ原則GPL v2**との原文。Wazuhが同梱するMITRE ATT&CK由来\`ruleset/mitre\`等は上流データの利用条件を追加確認要。**ルール/署名/データをコピー・同梱しない**。 |
| 外部依存 | [src/syscheckd/CMakeLists.txt](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/CMakeLists.txt#L1-L125)、[src/deps.lock.mk](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/deps.lock.mk#L1-L51)、[DB実装](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/db/src/db.cpp#L38-L55) | C/C++17、cJSON、DBSync、SQLite、OpenSSL系、agent sync protocol、schema validatorなどの依存。lockではSQLite 3.53.1、cJSON 1.7.18、OpenSSL 3.6.2等が指定。**依存ライブラリごとの独立ライセンスは網羅監査未了**。Rust側でWazuhをリンクしない。 |
| AegisGuard自身 | [README末尾](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/README.md)、[Cargo.toml](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/Cargo.toml) | 本体のライセンス**未設定**。当面外部コードをコピーせず、既存のRustクレート（\`sha2\`等）を使い、追加クレートを採用する時は個別のSPDX/再配布条件を監査する。 |

**リンク/プロセス境界の判断：** GPL/AGPLコードを直接静的・動的リンクして再配布する場合と、別プロセスで外部Wazuhを動かす場合と、実装思想だけ参考に独立コードを書く場合では法的論点が異なる。WazuhのLICENSE本文は、同社が**Wazuhを再配布する際**の派生物解釈について、Wazuhコード・データの統合、同梱インストーラ、リンク、プログラム実行を含む広い見解を明記する。これは自動的に最終的な法的結論となるものではない。**外部CLI/サービスなら常にGPLの適用を免れる、とは判断しない。法的評価未完了。** 製品同梱・再配布の前に専門家確認が必要。

## 5. Defender共存・Windows制約・権限境界

- **Defender最優先：** FIMは可視化・差分通知のみ。Defenderのリアルタイム保護/ASR/AMSIをオフにしない。自動隔離、ファイル削除、スキャン時の保護除外作成、監査ポリシー自動変更を行わない。DefenderによるファイルアクセスやWindows Updateの正常変更も大量検知し得るため、最初から広い\`C:\Windows\`再帰監視はしない。
- **権限：** 自分のPoCフォルダとHKCU検証キーは一般ユーザー権限で行う。HKLMの一部・System32等・他ユーザーHive・Security/SACLの読み取りには権限昇格が必要な場合がある。拒否を\`not_assessed/access_denied\`としてレポートし、黙って空状態と扱わない。将来のサービスは最小権限、読み取りと特権操作の分離、ログ・DBのACL保護が条件。
- **SACL who-dataの副作用：** 上流\`win_whodata\`は監査ACEだけでなく監査ポリシーのバックアップ/リストアを扱うため、Defenderや既存セキュリティ製品との運用上の衝突余地がある。AegisGuard PoCでは**有効化しない**。[win_whodata.c L24-L32](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/whodata/win_whodata.c#L24-L32) / [L198-L327](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/whodata/win_whodata.c#L198-L327)。
- **WFP/ETW/Sysmon/AMSIとの重なり：** WFPはネットワーク通信許可/遮断、AMSIは対応ホストのスクリプト内容検査、Sysmon/EventLogは構成されているイベントの収集、FIMはディスク/レジストリの状態差分。FIMはWFPやAMSIの代替でない。汎用ファイルRead監査を目指すならカーネルETWやminifilter等の別権限・高負荷設計が必要であり、この調査では採用判断しない。
- **Chrome等の認証情報窃取対策との関係：** \`Login Data\`、\`Cookies\`等のDBに\`ReadFile\`しただけでハッシュやmtimeは変わらないことがある。Wazuhの\`ReadDirectoryChangesW\`はファイル**変更**通知であり、who-dataの\`criteria\`も書込・削除関連。**FIMで「読み取りイベントを検出できた」と主張しない**。ブラウザの資格情報DBを常時ハッシュ走査するのは通常更新が多く、プライバシー/ロック競合/ログ肥大化を招くため**既定監視対象にしない**。防止を目的とするならOSの保護機構、プロセス挙動・不審な接続等との相関を別担当で検討する。
- **具体的な低ノイズ対象：** 自分のPoCフォルダ、承認済みの自動起動用ショートカット/実行ファイル、\`hosts\`、重要ツールの設定ファイル、最小限のRun/RunOnce・Servicesレジストリキー。対象ごとに理由/更新頻度/期待される正規変更/除外/所有者を定義。システム全体、ブラウザDB、Temp/Cache、Defender定義フォルダは初期段階で対象外。

## 6. 性能・堅牢性・誤検知

| 論点 | Wazuhの確認済み根拠 | AegisGuardの検査計画・失敗意味 |
|---|---|---|
| ハッシュコスト | ハッシュ取得は\`file_max_size\`とファイル種類の条件付き。全ファイルを常時SHA-256にはしていない。[file.c L874-L908](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/file/file.c#L874-L908) | ファイル数・総バイト数・実行時間・CPU・I/O・電池を計測。上限に達したら\`incomplete\`、次回に再試行。ハッシュ省略を空ファイルハッシュで代用しない。 |
| 同時変更/TOCTOU | Wazuhはメタデータとファイルハッシュを別経路で取得する。[file.c L815-L914](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/file/file.c#L815-L914) | ハンドルベースの同一性・前後サイズ/mtime確認、置換とreparse-pointの検査。競争で変化した場合は確定判定せず再試行する。 |
| イベント急増 | Windows \`ReadDirectoryChangesW\`の0バイトcallbackは警告。[run_realtime.c L425-L517](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/run_realtime.c#L425-L517) | 高速create/rename、巨大ツリー、watch切断を合成して欠落を計測。キュー上限・デバウンス・バックプレッシャー・優先度を持つ。欠落後は必ずディスク再照合。 |
| DB/同期上限 | \`file_entry_limit\`とRegistry上限、\`sync_flush_batch_size\`、\`sync_flush_interval_ms\`、\`sync_wal_autocheckpoint_pages\`、\`sync_cache_size_kib\`等がある。[fim_scan.c L70-L108](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/fim_scan.c#L70-L108) / [syscheck.c L88-L97](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/syscheck.c#L88-L97) | ローカルのみの小さなSQLiteストアを想定。テーブル件数、WALサイズ、checkpoint、再起動、電源断想定、ディスク満杯、破損時の再構築を測る。上流Manager同期は初期PoCで不要。 |
| 復旧・再同期 | \`recovery.c\`はDataClean＋DELTA、切断時のキュー再送。[recovery.c L106-L143](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/recovery/recovery.c#L106-L143) / [L294-L321](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/recovery/recovery.c#L294-L321) | ブックマーク/scan generationと「最終走査が成功したか」を記録。DBがない場合は新規untrusted baseline、破損時は高重大度の\`integrity_state_lost\`。 |
| false positive | Windows既定のStartup/レジストリ監視と除外が明示。[ossec.conf L70-L131](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/win32/ossec.conf#L70-L131) | 正規アップデート・インストール・同期ツール・テンポラリファイルを区別。警報は許可/禁止でなく\`review\`中心、抑止ルールに有効期限・スコープを設定。 |
| false negative | 除外・未スキャン・サイズ上限・アクセス拒否・イベント欠落・マウント/ネットワークFSがあり得る | "変化なし"は観測対象・観測期間に限る。短時間に戻された改変は定期スキャン単独では見逃す。見逃しテストを明記。 |
| プライバシー | Windows SecurityログとFIM経路はファイルパス・ユーザー/プロセスを含む。[win_whodata.c L67-L82](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/whodata/win_whodata.c#L67-L82) | ブラウザ内容、鍵、資格情報、全文差分を収集しない。ユーザー名・パス・値データの最小化、暗号化/ACL/保存期間、外部送信なし。 |

**定量評価：** 上記の\`50 max_eps\`や\`43200 frequency\`等はWazuh Windows設定の**初期値**でありAegisGuardの実測値・推奨保証値ではない。CPU%・メモリMiB・秒・欠落率・誤検知率の測定値は**存在しない**。受け入れ閾値は対象ハードウェアとテスト規模を定めた後に決定する。

**テスト根拠（実行結果ではない）：**
- Windows API通知：[\`test_run_realtime.c\` L1381-L1409](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/unit_tests/syscheckd/test_run_realtime.c#L1381-L1409)（\`ReadDirectoryChangesW\`成功/失敗）、[L1786-L1917](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/unit_tests/syscheckd/test_run_realtime.c#L1786-L1917)（callbackエラー、0バイト、変化イベント）。
- レジストリ：[\`registry/test_registry.c\` L896-L1108](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/unit_tests/syscheckd/registry/test_registry.c#L896-L1108)（baseline、定期再走査、RegOpenKey/QueryInfo失敗）、[L1512-L1915](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/unit_tests/syscheckd/registry/test_registry.c#L1512-L1915)（値種類、未終端文字列、ignored、WOW64）。
- who-data：[\`whodata/test_win_whodata.c\` L538-L1642](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/unit_tests/syscheckd/whodata/test_win_whodata.c#L538-L1642)（SACL失敗/成功）、[L4712-L6015](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/unit_tests/syscheckd/whodata/test_win_whodata.c#L4712-L6015)（4656/4663/4658監査イベント）。
- 同期復旧：[\`test_fim_sync_limits.c\` L172-L385](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/unit_tests/syscheckd/test_fim_sync_limits.c#L172-L385)（昇格/降格/欠損データ）、[\`test_recovery.c\` L713-L1136](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/unit_tests/syscheckd/test_recovery.c#L713-L1136)（agent ID変更や停止中の再同期）。上流には[\`tests/integration/test_fim/\`](https://github.com/wazuh/wazuh/tree/2940bdfb5e1a90cd67200fa63579d7eadf679009/tests/integration/test_fim)にWindows固有のケース等もあるが、**実行・結果検証未実施**。

## 7. 推奨する小さなPoCと成功基準

- **前提：** Defenderを有効のままWindows 11の隔離された検証VMまたは検証用ユーザーで実施。通常ユーザー権限。監視対象は新規作成した\`%TEMP%\AegisGuard-FIM-PoC\`と\`HKCU\Software\AegisGuardFIMPoC\`だけ。実際のRun/RunOnce、サービス、ブラウザDB、SACL、Sysmon設定は変更しない。
- **フェーズA（無効・観測）:** 対象/除外/ACLの列挙だけ行い、\`baseline_untrusted\`を明示してスナップショット作成。操作ログとベースラインDBの整合性を検証。
- **フェーズB（読み取り監査）:** テスト用の\`*.exe\`ダミーファイル（**実行はしない**）とテキストを用意し、追加→内容変更→mtimeのみ変更→ACL変更（テスト範囲内）→リネーム→削除→再作成の差分を確認。ハードリンク/シンボリックリンク/サイズ上限/アクセス拒否/途中更新を別ケースとして扱う。レジストリは専用HKCUキーの\`REG_SZ\`、\`REG_DWORD\`、\`REG_BINARY\`の値変更と削除を検証。
- **フェーズC（限定通知）:** 監視開始後に変更通知→差分再評価。多数の合成ファイルを一時フォルダに作成し、イベントキュー飽和/通知停止/プロセス再起動/DB使用不可を人工的に再現、復旧時の**全体再走査**で最終状態へ到達することを検証。破壊的サンプル・ランサムウェア・実環境のタスク/サービス登録は使用しない。
- **受け入れ条件：** (1) 2度目の変更なし走査では差分0、(2) 既知の追加/変更/削除を正しいパスで記録、renameを確信できないときは\`remove+create\`として誤断定しない、(3) 欠落/権限拒否/サイズ超過/破損/途中変更で\`clean\`と出さず\`incomplete\`、(4) 故障・再起動後は\`reconcile_required\`→全再走査→整合性確認、(5) DB破損時は失われた基準を明示、(6) Defender設定/SACL/Firewallは変更されない、(7) ブラウザ秘密データや実データ本文がログにない。
- **性能測定方法：** 固定のファイル件数・サイズ分布と操作トレースを用意し、前/後でCPU時間、ピークRSS、読み取りバイト数、ファイルI/O、キュー深さ、DB/WALサイズ、イベント遅延、検出漏れ件数、正規変更誤検知件数を記録。許容値はその測定とユーザー環境で設定する。**架空の数値基準を置かない。**
- **失敗時の扱い・ロールバック：** 監視を停止→自分の専用テストフォルダ/HKCU検証キーだけ削除→ベースラインDBは必要に応じ退避して削除。Windows監査ポリシー、Defender設定、Firewall、他者のファイルには触れない。
- **中止条件：** Defenderや通常業務に顕著な干渉、予期せぬ権限昇格要求、監視対象外への書込み、個人情報の収集、永続的なwatch停止を自動検知できない状態、復旧不能なDB不整合。

### 導入候補上位3件（確定提案）

| 順位 | 優先度/規模 | 機能 | 先行ブロッカー |
|---|---|---|---|
| 1 | P0 / M | 限定パスのSHA-256・属性ベースラインと原子的差分DB | ハンドル安全性、未評価表現、初期ベースライン信頼性、DB保護 |
| 2 | P1 / M | \`ReadDirectoryChangesW\`＋欠落時再走査 | 非同期watch、rename、overflow、watch再開/停止のテスト |
| 3 | P1 / M | Run/RunOnce等を対象とするRegistry差分 | 権限/WOW64/HKUユーザー別ビュー、正規変更の抑制、機密値の抑止 |

## 8. 採用しない設計と理由

1. **Wazuhの\`syscheckd\`/Managerを丸ごと同梱、またはC/C++を逐語的にRustへ移植する案を見送る。** Rust-firstの小型・ローカルMVPとは依存関係/サービス/同期モデルが異なり、GPL等の再配布義務・独自ライセンスが未定という問題もある。FIMの設計だけ利用し、実装は新規に作る。
2. **Windows全域へのwho-data/SACL監査の自動設定を見送る。** 特権と監査ポリシー変更を要求し、イベント量・既存監査ルールとの衝突・復旧失敗リスクが高い。まず一般権限で読み取り専用の限定FIMを実証する。
3. **FIMをChrome等の認証情報窃取に対する「読み取り遮断/検出」と位置付ける案を見送る。** 単純な読取だけではディスク内容が変わらず、変更監視は反応しない。別センサーによる読取・プロセス・ネットワークの相関は将来課題。
4. **USN Journalを初期PoCの必須条件にしない。** Volume/USN連続性、アクセス権、journal wrapや削除への対応が必要で、少数ディレクトリの\`ReadDirectoryChangesW\`＋整合性再走査で最初の価値を検証できるため。

## 9. 他担当との境界・引継ぎ

- **Sysmon/ETW担当：** ProcessGuidによる主体相関、EventID 1/11/12–14/19–21、イベント購読の共通インターフェース、LogChannel/bookmark/権限を決める。Wazuh FIM単独でProcessGuid連携済みと扱わない。
- **Windowsサービス/WFP担当：** FIMは観測専用。実行ファイル隔離、Windows Firewall遮断やWFPルールは本担当の範囲外。通知失敗時に特権センサーが安全に停止する設計を共有。
- **Defender/AMSI担当：** 既存保護を弱めず、二重解析の頻度/契機と自動除外を作らない運用を調整。
- **静的解析担当：** \`modified\`されたEXE/DLL/PS1のハッシュと\`Report\`へ接続する一方、更新失敗/サイズ超過/再解析点を\`low_signal\`にしない。署名検証やYARA-Xで悪性を確定したかのように見せない。
- **UI担当：** \`baseline_untrusted\`、\`incomplete\`、\`watch_lost\`、\`reconcile_required\`、\`access_denied\`、\`last_verified_at\`を区別。私有パス/ユーザー名の露出は抑制する。
- **ライセンス監査担当（将来）：** サードパーティ依存、rules/CTI/データと外部Wazuhサービス配布の法的条件を別途審査。

## 10. 未確認事項・追加調査項目

1. **高：Windows 11実機での通知喪失後の復旧**。Wazuhの0バイトcallback警告や\`dwerror\`発生時の監視継続、ネットワークドライブ/OneDrive/非NTFS、rename、ハードリンク、Unicode/長いパスの実動作を**未実証**。特にcallbackで\`WideCharToMultiByte(CP_ACP)\`を使うため非ACP文字のパスが正しく扱えるかは実測要。[run_realtime.c L478-L515](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/run_realtime.c#L478-L515)。
2. **高：ベースラインの安全性。** 初回スキャン時点の改ざんを見逃す問題、ハンドルのTOCTOU、reparse/ハードリンク、署名/信頼済みインストーラとの照合、DBの改ざん対策を未検証。
3. **高：権限・ポリシー・相互作用。** Defender有効状態でのI/O、管理者でないユーザーのHKLM/HKU範囲、実際のSACL副作用、他セキュリティ製品との二重監査を未評価。
4. **中：USN Journal／Registry即時通知。** コード検索で\`FSCTL_READ_USN_JOURNAL\`/\`USN_JOURNAL\`/\`RegNotifyChangeKeyValue\`は見つからなかったが全リポジトリの非使用証明は未完了。採用前にWindows APIの妥当性と必要権限を別途比較する。
5. **中：スケジュールタスク/サービス/ユーザーStartupの完全性。** 既定Wazuh設定の監視範囲を、Task Scheduler API/Operational・SCM・HKCU/HKUへ広げたときの負荷/権限/誤検知は未検証。
6. **中：性能・整合性の定量値。** Windows 11ノート環境でのCPU/RSS、I/O、キュー/DB上限、WAL checkpoint/失敗復旧、ランサムウェア相当の**安全なファイル更新負荷**下での通知欠落率を未測定。
7. **中：ライセンス法的評価。** WazuhのGPL v2/AGPL v3/dual licenseと外部依存、Wazuh以外のデータセット、AegisGuard未設定ライセンスの関係を最終審査していない。
8. **低：タグ/リリース対応とCI。** 調査commitがどの正式リリースに含まれるか、Windowsビルド/既存単体・統合テストのCI成功状態は未確認。

## 11. 一次情報一覧

> 参照日：**2026-11-05**。GitHubソースリンクは全てWazuh \`2940bdfb5e1a90cd67200fa63579d7eadf679009\` / AegisGuard \`83fcf0d150e8d760baff5f971c106deb09c1f8e4\` に固定。以下は、機能判断を支えた一次ソース・シンボル/行。実行検証済みという意味ではない。

1. **定期走査:** [\`fim_scan()\`, \`fim_file_scan()\`, \`fim_registry_scan()\`, fim_scan.c L43-L119](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/fim_scan.c#L43-L119)。
2. **属性/ハッシュ:** [\`fim_get_data()\`, file.c L815-L914](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/file/file.c#L815-L914)。
3. **Windows通知API:** [\`realtime_win32read()\`, run_realtime.c L561-L574](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/run_realtime.c#L561-L574)。
4. **通知イベント処理・rename/overflow:** [\`RTCallBack()\`, run_realtime.c L425-L517](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/run_realtime.c#L425-L517)。
5. **削除・移動後の差分:** [\`fim_realtime_event()\`, fim_scan.c L142-L159](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/fim_scan.c#L142-L159)。
6. **レジストリ列挙:** [\`fim_open_key()\`, registry.c L1877-L2025](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/registry/registry.c#L1877-L2025)。
7. **レジストリ差分/除外:** [\`fim_registry_validate_ignore()\`, registry.c L1259-L1312](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/registry/registry.c#L1259-L1312)、[\`fim_calculate_dbsync_difference_value()\`, registry/events.c L110-L164](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/registry/events.c#L110-L164)。
8. **SACL権限:** [\`set_winsacl()\`, win_whodata.c L198-L327](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/whodata/win_whodata.c#L198-L327)。
9. **監査イベントと書込mask:** [\`set_subscription_query()\`, win_whodata.c L1338-L1393](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/whodata/win_whodata.c#L1338-L1393)。
10. **SQLite保持:** [\`DB::init()\`, db.cpp L40-L55](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/db/src/db.cpp#L40-L55)。
11. **同期と復旧:** [\`persist_sync_documents()\`, syscheck.c L303-L397](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/syscheck.c#L303-L397)、[\`fim_recovery_persist_table_and_resync()\`, recovery.c L106-L321](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/src/recovery/recovery.c#L106-L321)。
12. **EventLog収集:** [\`EvtSubscribe\`/bookmark, read_win_event_channel.c L425-L526](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/logcollector/src/read_win_event_channel.c#L425-L526)。
13. **既定永続化対象:** [Windows \`ossec.conf\` L59-L139](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/win32/ossec.conf#L59-L139)。
14. **既存テスト:** [Windows realtime単体](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/unit_tests/syscheckd/test_run_realtime.c#L1381-L1917)、[registry単体](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/unit_tests/syscheckd/registry/test_registry.c#L896-L1108)、[復旧単体](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/unit_tests/syscheckd/test_recovery.c#L713-L1136)、[FIM統合テスト構成](https://github.com/wazuh/wazuh/tree/2940bdfb5e1a90cd67200fa63579d7eadf679009/tests/integration/test_fim)。
15. **ビルド依存とライセンス原文:** [\`src/syscheckd/CMakeLists.txt\`](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/syscheckd/CMakeLists.txt)、[\`src/deps.lock.mk\`](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/src/deps.lock.mk)、[\`LICENSE\`](https://github.com/wazuh/wazuh/blob/2940bdfb5e1a90cd67200fa63579d7eadf679009/LICENSE)。
16. **比較先AegisGuard:** [\`src/main.rs\`](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/main.rs)、[\`src/scan.rs\`](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/src/scan.rs)、[\`SECURITY.md\`](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/SECURITY.md)、[\`docs/ARCHITECTURE.md\`](https://github.com/choko510/AegisGuard/blob/83fcf0d150e8d760baff5f971c106deb09c1f8e4/docs/ARCHITECTURE.md)。
17. **公式設計/Windows API（実装と区別）:** [Wazuh FIM how-it-works](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/how-it-works.html)、[Registry monitoring](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/windows-registry-monitoring.html)、[who-data](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)、[ReadDirectoryChangesW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw)、[FILE_NOTIFY_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-file_notify_information)、[Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)。

**最終判定：** WazuhのGPL等に従うソース/ルール/署名の直接流用は実施せず、Windowsの標準APIを使ったRustでの**独立した小規模FIM**を、Defender有効・観測専用・失敗は未評価とする方針でPoCへ進む価値が高い。実機試験とライセンス審査が終わるまで、本番利用可能・完全検知と記載しない。
