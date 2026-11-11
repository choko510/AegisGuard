# 技術調査: Windows永続化監査

- 担当: persistence-audit
- 一次情報・ソース確認日: **2026-11-05**
- 対象: Windows 11、Rust独立CLI、読み取り専用
- 検証状況: **Windows 11実機未確認、Windows向けRustビルド未確認。Cargoコマンドも実行不可の環境で執筆。**
- 実装ファイル: src/collector.ps1、src/windows.rs、src/lib.rs、src/main.rs。外部プロジェクトのコードのコピーなし。

## レビュー指摘への対応（2026-11-05）

1. Microsoftの[CommandLineEventConsumer公式仕様](https://learn.microsoft.com/en-us/windows/win32/wmisdk/commandlineeventconsumer)はExecutablePath=NULLでCommandLineTemplateの先頭から起動先を決める構成を認める。テンプレート本文は収集側に留め、静的先頭トークンか動的な実行先の疑いかを識別する。
2. Process間のパイプに秘密引数を含むraw_targetを渡していた点を修正。PowerShell内でターゲットを限定抽出し、Rustでも無効なレコードを拒否する。疑わしい入力はnullとする。
3. 列挙順による#1/#2は破棄し、秘密鍵付きHMACで同一登録を追跡。鍵なしではnull、識別不能を成功扱いにしない。

## 1. Registry Run / RunOnce とWOW64

**一次情報**
- Microsoft: RegistryKey.OpenBaseKey(RegistryHive, RegistryView): https://learn.microsoft.com/en-us/dotnet/api/microsoft.win32.registrykey.openbasekey
- Microsoft: 32-bit and 64-bit Application Data in the Registry: https://learn.microsoft.com/en-us/windows/win32/sysinfo/32-bit-and-64-bit-application-data-in-the-registry
- Microsoft: Accessing an Alternate Registry View: https://learn.microsoft.com/en-us/windows/win32/winprog64/accessing-an-alternate-registry-view
- Microsoft: Registry Key Security and Access Rights: https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights

**実装**
- .NET Framework Microsoft.Win32.RegistryKey.OpenBaseKey、RegistryHive.CurrentUser/LocalMachine、RegistryView.Registry32/Registry64を固定的に指定。
- OpenSubKey(path, false)、GetValueNames、GetValue(DoNotExpandEnvironmentNames)だけを呼び出し、値を変更しない。
- Software\Microsoft\Windows\CurrentVersion\Run、RunOnceの4つのビュー組合せを観測する。名前・引数は出さず、文字列型値から実行先候補を抽出。
- Microsoftの説明どおり、共有されるキーではWOW64フラグは別のデータを意味しない。**32/64ビューの重複は端末の複数件感染を意味しない**。互換性のため両方を試みる。
- 未定義キーは列挙ゼロ、アクセス拒否はpermission_denied、列挙に失敗した項目は部分成功。HKCUは現在のユーザーだけ。他ユーザーのユーザーハイブやポリシー由来の追加のAutoRunキーは網羅しない。

**代替案**
- reg.exe / reg query: 標準出力がローカライズされ、値と秘密の生引数を扱う。安全にパースする契約を定めづらいので不採用。
- Win32_StartupCommand: Registryの全ビュー・RunOnceを明示的に列挙したことの根拠にならないので不採用。
- Rust Win32 RegOpenKeyExW / RegEnumValueW直呼び: 将来的な純Rust実装候補。ただし既存のWindows PowerShell 5.1経由の.NET RegistryKeyが明示ビュー選択と読取専用権限を持ち、独立MVPでは依存を減らすため採用。これはネイティブAPIの直接呼び出しではない。

## 2. Startupフォルダー

**一次情報**
- Microsoft: KNOWNFOLDERID — FOLDERID_Startup / FOLDERID_CommonStartup: https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid

**実装**
- Environment.SpecialFolder.Startup / CommonStartupによりOSの既知フォルダーを取得する。固定の英語パス文字列を前提にしない。
- Directory.EnumerateFilesでファイル名を列挙し、lnkはWScript.Shell COM のCreateShortcut経由でTargetPathのみを読む。Argumentsは読まない。
- ショートカット解決に失敗すればtarget_path=nullでunknown。位置のみで不正と断定しない。

**制約**
- 現在のユーザーと共通Startupだけが対象。別ユーザー、ログオンスクリプト、ジャンクション、リンク先の実在、ファイルACLは検査しない。
- リンク解決でCOMコンポーネントが利用できない環境もあり得る。未確認。
- WScript.Shellの権限・存在・挙動はWindows 11実機で確認が必要。リンク対象は実行しない。

## 3. Task Scheduler **2.0** COM

**一次情報**
- Microsoft: Task Scheduler: https://learn.microsoft.com/en-us/windows/win32/taskschd/about-the-task-scheduler
- Microsoft: ITaskService::GetFolder: https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itaskservice-getfolder
- Microsoft: ITaskFolder::GetTasks、TASK_ENUM_HIDDEN: https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itaskfolder-gettasks
- Microsoft: ITaskFolder::GetFolders: https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itaskfolder-getfolders
- Microsoft: IExecAction::get_Path / ExecAction.Path: https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-iexecaction-get_path
- Microsoft: IExecAction::get_Arguments（**取得しない**）: https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-iexecaction-get_arguments

**実装**
- Windows PowerShellのCOMアクセスから Schedule.Service = ITaskServiceを接続し、ルートフォルダーからGetFolders(0)で幅優先走査、GetTasks(1)で隠しタスクを含む登録タスクを列挙。
- 登録タスクDefinition.ActionsのExecAction (Type 0)のPathだけを取得。Arguments、WorkingDirectory、XML、Principal、ユーザー名、タスク名、パスは読み出さず、レポートにも載せない。
- 非ExecActionは実行先不明として残す。タスクフォルダー最大128、全ソース合計最大2000エントリ、時間制限15秒（WMI時25秒）。
- フォルダー・タスクが途中で消えた場合や閲覧できない場合はenumeration_errorとする（完全列挙と報告しない）。

**不採用**
- Task Scheduler 1.0 (ITaskScheduler / .job): Windows Vista以降の2.0の全機能を列挙できず、古いAPIなので不採用。
- schtasks.exe /query /xml: タスクXMLにはArgumentsやユーザー識別子等が含まれ、不必要な機密収集と巨大文字列の原因になるので不採用。
- 監視や登録・削除API: 今回はread-onlyの棚卸しなので不採用。

## 4. WMI永続イベントサブスクリプション（任意）

**一次情報**
- Microsoft: Receiving Events at All Times: https://learn.microsoft.com/en-us/windows/win32/wmisdk/receiving-events-at-all-times
- Microsoft: CommandLineEventConsumer: https://learn.microsoft.com/en-us/windows/win32/wmisdk/commandlineeventconsumer
- Microsoft: __FilterToConsumerBinding: https://learn.microsoft.com/en-us/windows/win32/wmisdk/--filtertoconsumerbinding
- Microsoft: Implementing Cross-Namespace Permanent Event Subscriptions: https://learn.microsoft.com/en-us/windows/win32/wmisdk/implementing-cross-namespace-permanent-event-subscriptions
- Microsoft: Get-CimInstance (Windows PowerShell 5.1): https://learn.microsoft.com/en-us/powershell/module/cimcmdlets/get-ciminstance?view=powershell-5.1

**実装**
- オプトイン時だけ、Get-CimInstance -Namespace root/subscriptionで__EventFilter、CommandLineEventConsumer、__FilterToConsumerBindingを個別に問い合わせる。
- 権限がなければcoverage=permission_denied、不明なCIM例外はunavailable扱い。CIM操作ごと8秒、子プロセス全体で25秒タイムアウト。
- CommandLineEventConsumerのExecutablePathがある場合は実行先パスの候補だけをPowerShell内で抽出・匿名化。ExecutablePathがNULLでもCommandLineTemplateが有効な登録を見落とさず、テンプレート先頭の静的実行先だけを安全に抽出できる場合に限り報告する。
- CommandLineTemplate本文、引数、WQL、SID、filter名、binding実参照は**PowerShellプロセスのstdoutに出さない**。代わりにtemplate_present / template_dynamic_target / target_sourceの有限のメタデータのみ出力する。
- テンプレート先頭にWMIイベント変数の可能性がある場合はtarget_path=nullで、unknown + mediumの調査優先度を維持する。これは動的な実行先の可能性であって感染の断定ではない。
- __EventFilter / Bindingはメタデータの存在だけで、実行先や危険度を判断しない。

**未実装（特に重要）**
- filter・consumer・bindingを関連付ける相関判定、ActiveScriptEventConsumer等の他種別、他名前空間で作成されたサブスクリプション、ACLや権限の確認。
- CommandLineTemplateのみの設定でも**静的な実行先は限定抽出**する。ただし埋め込み変数/曖昧なパスはtarget_path=nullでunknown・medium、変数解決やWMIイベントの実行は行わない。
- Microsoftはroot\subscription配置を推奨するが、すべての永続化がそこに限られると保証されるわけではない。

## 5. Windows CLIの実装方法

**一次情報**
- Microsoft: GetSystemDirectoryW: https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemdirectoryw
- Microsoft: Windows PowerShell 5.1 Get-CimInstance: 上記リンク

**選択**
- WindowsのみGetSystemDirectoryWで実システムディレクトリを取得し、WindowsPowerShell\v1.0\powershell.exeを**フルパス指定**で非対話・プロファイルなしで起動。
- 呼び出すスクリプトはsrc/collector.ps1に固定し、引数経由で可変のシェルコードやパスを挿入しない。指定値は厳密に検証した数値上限とWMIの真偽値だけ。
- stdin=null、stderr=null、stdoutのみ最大2 MiB読み取り、子プロセスを期限内に終了できなければkill。テスト時に本物のレジストリへ書き込まない。
- 将来的にP5 APIへ接続するならDTO変換を別PRで実装する。今回はルートCargo/workspaceへ統合しない。
- **修正後**：生のRunコマンド文字列はPowerShell側だけで扱い、安全な実行先候補以外は標準出力へ渡さない。Rustパーサは旧raw_targetレコードを拒否し、target_pathに疑わしい引数・生のユーザー名があればnullに落とす。

**未確認**: WDAC/AppLocker/Constrained Language ModeとPowerShellの失敗経路、COM列挙時の細かいAccessDenied HRESULT、WOW64上の別アーキテクチャ、変更中のタスク、遅いWMIでのOS側中断タイミング。

## 6. 評価ルール、誤検知とプライバシー

- 出力はschema_version=2（v1のraw_target入力廃止に伴う破壊的変更）。statusはcomplete、partial、unavailable、permission_denied、error。coverageはソース単位でcomplete / not_collected / permission_denied / unavailable。エントリゼロは安全を意味しない。
- PersistenceEntry相当のkind、scope、location_redacted、entry_id、target_path、signature_status、evidence、assessmentを持つ。位置はセクション名のみで連番を廃止。entry_idは登録識別子から鍵付きHMACで計算し、元の値名/タスク名を標準出力へ出さない。
- observedは典型的なインストール場所の観測、reviewは調査の優先度、unknownは未評価。**悪性かどうかの真偽を表さない**。Program FilesやSystem32でも署名/ACLを見ない限り安全ではない。
- 「ユーザー書込可能な場所」「cmd/powershellなどのランナー」を中程度の調査候補とするが、正規アップデーターと管理スクリプトも該当するので偽陽性がある。
- Authenticode署名検証の負荷・チェーン検証・失効確認はMVPの範囲外。signature_status=not_checked。
- 値名、タスク名、WQL、WMI名、コマンド引数、環境変数の展開結果、SID、ユーザー名は出力しない。Users配下のユーザー名をredact。UNC/URLや秘密引数らしき文字列はtarget_pathをnullに落とす。ローカル実行先自体にも機密が残る可能性があり、報告書の公開は利用者による確認を要する。
- CLIの生データは最大2 MiB、1行8 KiB、10000行、2000エントリ。パーサは値の最大長を制限し、入力の任意キーやエラーメッセージをエコーしない。

### 継続追跡IDの技術判断（2026-11-05追記）

- 公式資料: [Microsoft HMACSHA256 (.NET Framework)](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmacsha256.-ctor?view=netframework-4.8.1)。
- 単純なSHA-256(登録名)は推測可能なレジストリ値名・タスク名の辞書攻撃に弱いため不採用。列挙順の連番も継続比較に不向き。
- オプトインの32バイト乱数鍵（環境変数AEGISGUARD_PERSISTENCE_ID_KEY_B64）をPowerShell側で読み、セクション名と正規化した登録識別子をHMAC-SHA-256でハッシュ化。`entry_id=h1:<64 hex>`とする。同じ鍵・識別子では走査間でも同じIDで、順序に依存しない。
- Registry: セクションと値名。Startup: ショートカット/ファイルの元パス。Task Scheduler: タスクのフルパス + Action番号。WMI: Filter/Consumer名またはBindingの両端参照をローカルでハッシュ。
- 鍵の自動保存はread-only設計に反するため行わず、未設定・不正時はentry_id=nullで明示する。同じ鍵を安全に再設定する責任は利用者側にある。鍵が漏れれば推測耐性を失う。
- 入力の正規化はFormC + ToUpperInvariant。Windowsの大文字小文字を無視する代表的な名前の扱いを想定するが、すべてのWMI名前空間での識別子の一意性は実機未確認。
- 完全なエントリ同一性保証ではない。タスクのAction順序変更やリネームは別IDになる。鍵変更も別IDになる。スコープをまたぐID同値にはしない。

## 7. 依存ソースとライセンス

- Rust標準ライブラリ + serde_json 1.0.154 (MIT OR Apache-2.0) だけをCargo依存に指定。serde_jsonはserde、serde_core、itoa、memchr、zmijに推移依存する。
- serdeソース/ライセンス: https://github.com/serde-rs/serde
- serde_jsonソース/ライセンス: https://github.com/serde-rs/json
- Microsoft.Win32.RegistryKey、WindowsPowerShell 5.1、Windows COM Task Scheduler、WMI CimCmdletsはOSコンポーネント。ソースコードをコピーしていない。
- GPL/AGPLプロジェクト由来のコード、外部YARAルール、第三者の永続化データベースは取り込まない。
- AegisGuard本体のREADMEには現時点のコードライセンス未設定とある。これに勝手なライセンス表記を追加しない。上記依存パッケージの実際のインストール状態およびロック再現性はCargo未実行のため未検証。

## 8. テスト計画と実行結果

**用意したテストコード**
- 合成fixture: HKCU/HKLM、Run/RunOnce、WOW64のカバレッジ、一般的なアップデーター、匿名化済みUnicodeパス、環境変数、起動ホスト、ターゲット未定義。合成HMAC書式の例を含む（実鍵によるHMAC計算の検証ではない）。
- ユニット/統合: 重複、安定ID書式・ID重複・列挙順変更、ID欠損、旧raw_target拒否、コマンド引数や秘密情報の非出力、WMIテンプレート静的/動的/評価不能、上限、JSON不正、UTF-8不正、権限拒否、欠落したWMIソース、収集途中停止の不完全扱い。
- 権限拒否・WMI遅延・消えたタスクはWindows実機では未再現。Windows用の処理が動くかも未確認。テストのために実端末へ永続化項目を作成しない。

**未実行**: cargo fmt --all -- --check、cargo clippy --all-targets -- -D warnings、cargo test、Windows cargo build --release、Windows 11実機read-only scan。実行環境にcargoとrustcが存在しないためであり、**合格済みとは記載しない**。

**残課題**: Windowsでのビルド・シェル実行テスト、PowerShellの例外/HRESULT分類、ACL/署名による誤検知検証、タスク/Registryの読取権限差分、WMI相関と他のイベントコンシューマ種別への拡張、増分走査・再現可能な継続テスト。
