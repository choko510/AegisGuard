# 調査＋実装担当C：Windowsの防御状態診断

あなたは **choko510/AegisGuard の独立Rustモジュール開発担当** です。外部仕様の調査・技術選定・コード実装・テスト・日本語PRまで**この作業で完遂**してください。P5〜P10と同時進行中なので、対象外の既存実装は変更しないでください。

**担当ID：** windows-posture
**リポジトリ：** https://github.com/choko510/AegisGuard
**編集可能なパス：** `standalone/windows-posture/` **以下だけ**
**作業ブランチ：** `standalone/windows-posture`（最新mainから作成。衝突する場合は一意な別名）
**提出PRタイトル：** `調査・実装: Windowsの防御状態診断`
**作業条件：** **PRを作成するがマージしない**。他の6担当のディレクトリにも触れない。

## 0. まず読み込む

**`docs/parallel-agents/PROTOCOL.md` の全文**、このプロンプトの全文、最新のルート`README.md`/`SECURITY.md`/`docs/ARCHITECTURE.md`、現在のオープンPRと担当パスの重なり。共通プロトコルの書込禁止・read-only・安全テスト・PRルールは絶対条件です。プロンプトを読み飛ばしたまま実装しないこと。

## 1. 目標

Microsoft Defender/ASR監査と重ならない領域で、Windows 11のOS/ハードウェア保護状態を読み取り専用で診断する。

## 2. 調査で突き止めること

- Microsoft公式の[デバイスセキュリティ](https://support.microsoft.com/ja-jp/windows/security/windows-security/device-security-in-the-windows-security-app)、Secure Boot、TPM 2.0、BitLocker/デバイス暗号化、VBS/HVCI/メモリ整合性、UAC/LSA保護の状態照会API（WMI/Windows Security APIs/レジストリ読取など）を比較。
- `supported / enabled / disabled / unknown / not_applicable / permission_denied`を混同しない。企業管理、ハードウェア非対応、UEFIでないPC、Home/Pro差、リモートセッションやVMの差を調べる。
- BitLockerの**回復キー・鍵保護情報・シークレット**を取得しない。既存`src/defender.rs`のGet-MpPreference/ASR監査は再実装しない。

各技術選択について、Microsoft等の**一次情報URL、確認日、採用したAPI/関数/型と制約、代替案と不採用理由**を`standalone/windows-posture/RESEARCH.md`に残してください。Windowsで実行していないものは「実機未確認」とすること。

## 3. 実装を完了する内容

- CLI：`windows-posture audit --format json`、`windows-posture inspect-fixture <file>`。機能ごとに`PostureControl {id,availability,state,source,checked_at,warnings}`を返す。
- 初期MVPはSecure Boot・TPM・HVCI/VBS・BitLockerの安全な状態照会と、その失敗時の未知判定。LSA/UACは裏付けがある場合にのみ追加。
- OS設定の推奨/手動案内は可能。ただし設定適用、再起動、レジストリやGPOの変更、Defender管理、`manage-bde`の変更系コマンドは禁止。

**リポジトリの既存モジュールをimportしてコンパイルさせない。** 単独`Cargo.toml`で構築し、`README.md`にCLI使用例とJSON出力例、権限、非対応、統合先となる将来の型を記載。少なくとも動作するMVPと安全なfixture経路を完成させること。広範囲な機能で全件が実装できなければ、どこまでが実装済みか明示し、未完了を成功扱いしない。

## 4. テストすべき条件

- 有効/無効/非対応/権限拒否/値未定義/矛盾する複数情報源/Windowsエディション差を合成fixtureで検証。
- 最小権限のテスト、回復キーが出力に含まれない検証、WMI/コマンド遅延やタイムアウトを測定する。

安全なfixtureとWindows/APIのモックを用意し、入力異常・時間/件数/ファイルサイズ上限・権限拒否・誤判定を明示的に検証。Linux上でWindows APIの実機成功を捏造しない。`cargo fmt --all -- --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test` を専用フォルダーから実行し、失敗は直す。

## 5. 提出条件

- 追加/編集：`standalone/windows-posture/` 内の`src/`・`tests/`・`Cargo.toml`・`Cargo.lock`・`README.md`・`RESEARCH.md`などのみ。
- 出力はversion付きJSON。診断不能/権限なし/部分成功と空・安全を区別。危険入力、誤検知、秘密の漏出を見逃さない。
- **最新mainからPR**、日本語タイトル/説明。PR本文には使った公式仕様/ライセンス、達成した機能、未実装、テスト実績、Windows実機有無、リスク、将来のP5 typed APIへの接続案を記載。
- PR前に`git diff --name-only origin/main...HEAD`を確認して**自分の専用フォルダー外の変更ゼロ**を保証。
- **PRはマージしない**。最後にPR URL・成果物・重要な技術判断・テスト結果・残課題を報告。コネクタが書けない場合はその事実を述べ、作成したファイルを引き渡す。

**調査報告だけで作業を終えないこと。実装と検証まで責任を持って進めること。**
