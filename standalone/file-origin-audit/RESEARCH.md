# ダウンロードファイルの出所監査：調査と採否判断

**確認日: 2026-11-05（JST）**。以下は Microsoft の公開仕様の記述を根拠とし、Windows 11実機での確認を意味しません。本独立CLIのRust実装はWindows APIへの手書きFFIとRust標準ライブラリのみで構成します。外部ソースコードの転用・サードパーティークレート導入はありません。

## 仕様の根拠と制約（一次情報）

| 根拠 | 確認できる点 | 設計への反映 |
| --- | --- | --- |
| [IAttachmentExecute::Save](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-iattachmentexecute-save) | Attachment Servicesは保存時にNTFS ADSへ出所情報を付加する場合がある。Saveはウイルス検査等の副作用があり得る。 | **呼び出さない**。既存メタデータだけを読み取る。 |
| [IAttachmentExecute](https://learn.microsoft.com/en-us/windows/desktop/api/shobjidl_core/nn-shobjidl_core-iattachmentexecute) | SetSource/SetReferrerで出所情報を関連付ける。 | 保存者によるヒントであり、暗号学的な真正性ではない。 |
| [Microsoft 365: Internet macros blocked](https://learn.microsoft.com/en-us/microsoft-365-apps/security/internet-macros-blocked) | `Zone.Identifier` の `[ZoneTransfer]`、`ZoneId` の0=My Computer/1=Local intranet/2=Trusted sites/3=Internet/4=Restricted sites。 | 0〜4だけを認識し、いずれも「安全」を返さない。 |
| [AttachmentManager Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-attachmentmanager) | ユーザー設定でゾーン情報の保存を抑止可能。FAT32では保存が正常に機能しない。 | 不在をローカル起源・安全とはみなさない。設定を読み書きしない。 |
| [MS-FSCC 5.1: NTFS Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c54dec26-1551-4d3a-a0ea-4fa40f848eb3) | 名前付きストリームは `filename:streamname:$DATA`、通常ストリームは `filename::$DATA`。 | 読取専用 `filename:Zone.Identifier` を開く。 |
| [GetVolumeInformationByHandleW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationbyhandlew) | `FILE_NAMED_STREAMS` (0x00040000) はボリュームの名前付きストリーム対応。 | ストリームを開く前に判定し、非対応は `not_supported`。 |
| [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew) | `OPEN_EXISTING`、`FILE_FLAG_OPEN_REPARSE_POINT`、共有フラグ等のオープン動作。 | Rust `OpenOptionsExt` 経由で読み取り、通常のreparse解決を回避。 |
| [Reparse Point Operations](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-point-operations) | 再解析ポイントの属性とオープン時の注意点。 | 祖先/対象の `FILE_ATTRIBUTE_REPARSE_POINT` を拒否。変更APIは使わない。 |
| [GetFileInformationByHandleEx](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex) / [FILE_ID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info) | `FileIdInfo=18`、128-bit FileIdとボリュームシリアルでファイル識別。 | ベースとADSを照合し、再オープンで差し替え検出。 |
| [GetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandle) | 従来の64-bit FileIndexはReFSで十分に一意と限らない。 | 旧64-bit方式は採用しない。 |
| [FindFirstStreamW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirststreamw) / [WIN32_FIND_STREAM_DATA](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-win32_find_stream_data) | ADSを列挙可能。非対応時のERROR_INVALID_PARAMETER等。 | MVPは対象名を直接開く。不要なstream名を列挙しない。 |
| [GetDriveTypeW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdrivetypew) | ドライブ種別を取得できる。 | REMOTE/不明種別を除外し意図しないネットワークI/Oを抑制する。 |
| [GetFinalPathNameByHandleW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew) | オープン済みハンドルの最終パスを `\\?\` 形式で取得可能。シンボリックリンク解決後の最終パス取得ができる。ただし経路全体の原子的な固定は保証しない。 | 対象ハンドルの開封直後と事後の再オープン時に最終パスを取得し、指定されたローカル絶対パスと照合。不一致・取得不能はエラー。 |

**実装のAPI/型**: `std::fs::OpenOptions` + Windows `OpenOptionsExt::{share_mode,custom_flags}`、`MetadataExt::file_attributes`、`GetVolumeInformationByHandleW` (`FILE_NAMED_STREAMS`)、`GetFileInformationByHandleEx` (`FileIdInfo`の`FILE_ID_INFO`レイアウト)、`GetFinalPathNameByHandleW` (`FILE_NAME_NORMALIZED` / `VOLUME_NAME_DOS`)、`GetDriveTypeW`。FFIの定数は上記Microsoft API仕様に対応。ハンドルはRust `File` が閉じる。

## 出所の信頼限界

- MOTWは一部のダウンロード/添付処理が保存する**ローカルな来歴ヒント**であり、第三者証明書による署名やダウンロード先の真正性検証ではない。出所を偽った `HostUrl`、`ReferrerUrl`、`ZoneId` は作成可能である。URL中のuserinfo、query、fragmentに資格情報を含み得る。認証トークンの検出・マスクは難しいため、**URL全文・ドメイン・ハッシュを出力せず存在フラグのみ**採用。
- ZIPからの展開は展開ツール・版・設定・アーカイブのMOTW・個別ファイルの扱いに依存する。コピーも、NTFS間か、ADS非対応のFAT/exFATか、コピーアプリがstreamを保持するかで変化する。クラウド同期はクライアント実装依存。**すべてでMOTW伝播するという保証はない**。これらは公式API文書から統一挙動を断言できないため**環境別の追加検証事項**とする。
- FAT32については上記AttachmentManager CSPが保存不能を明示。exFAT/クラウド同期の個別ケースは「未実機確認」であり、OSやツールの動作を保証しない。
- `HostUrl` にHTTP/HTTPSだけが含まれるという保証はない。ネットワーク/DNSに問い合わせず、URLパーサや外部評判APIに送らない。

## API選択・代替案と不採用理由

1. **採用**: 単一の `Zone.Identifier` をオープンし、最大65536バイト読み取り、utf8・BOM付きutf16を有限個の行として解釈。ADS/ファイルのID照合を行い、ACL拒否とストリーム欠落を別状態にする。
2. **見送り**: `GetFileInformationByHandleEx(FileStreamInfo)` / `FILE_STREAM_INFORMATION`。ハンドルベース列挙ができる一方、可変長バッファ、再試行サイズ、複数エントリの境界・整列検証が必要。単一名を読むMVPではバッファオーバーラン攻撃面の追加に見合わない。
3. **見送り**: `FindFirstStreamW` 列挙。動作としては可能だが、全streamの名前と件数が不要で、ADS以外のメタデータ露出を増やす。まず既知stream名の存在だけを検査。
4. **見送り**: PowerShell `Get-Item -Stream`/COM Attachment Services。外部プロセスやスクリプトを起動する必要があり、権限・出力安定性・実行副作用の懸念。CLIはRustで完結させる。
5. **見送り**: URLをURLクレートで解析しホストを出す方式。任意URLのプライバシー漏出を完全には避けられず、出所の真正性も改善しない。外部crateをゼロにする。
6. **見送り**: Win32下位の`NtCreateFile`相対ハンドル起点の原子的ストリームオープン。将来の厳格なTOCTOU保護候補だが、未文書化部分や追加の動作検証なしで導入しない。

## AegisGuard本体の関連ソースコード確認（読み取りのみ）

- [`src/fsafe.rs`](https://github.com/choko510/AegisGuard/blob/main/src/fsafe.rs): 本体はWindowsの `GetFileInformationByHandle` で64-bit `HandleId` を取得し、`GetFinalPathNameByHandleW` で最終パスを検査する。新モジュールはReFSを考慮して `GetFileInformationByHandleEx(FileIdInfo)` の128-bit IDを使い、リンク/祖先の事前・事後拒否と再オープンを実施。2026-11-05の追補で開いたハンドルの最終パスを `GetFinalPathNameByHandleW` により直接照合する処理を追加（比較不能・不一致なら失敗側に倒す）。ただし親ディレクトリのハンドル固定/相対オープンではないため完全な競合対策ではない。
- [`src/scan.rs`](https://github.com/choko510/AegisGuard/blob/main/src/scan.rs): 既存スキャナーは `FileIdentity`、`path_identity_mismatch`、スキャン中の変更を別状態として扱う。独立CLIの `file_changed_during_read` は統合アダプターで既存の「診断不能」と同義になるよう対応付ける。
- [`src/api.rs`](https://github.com/choko510/AegisGuard/blob/main/src/api.rs) / [`src/model.rs`](https://github.com/choko510/AegisGuard/blob/main/src/model.rs): `ScanReportV2` の `schema_version` は数値 `2`、`Assessment` と `SignalLevel` は独立した評価軸。本CLIは独立した文字列 `"1.0.0"` を使うため、**ScanReportV2として直接デシリアライズしない**。将来のP5アダプターで専用の `FileOriginEvidenceV1` を復号し、観測範囲と疑わしさを分離する。
- これら本体のソースは**参照のみ**で、インポート・依存・改変はしていない。

## PR #44 レビュー後の追加防御と実機検証手順（2026-11-05）

- 開いたファイルの真の解決パスが指定されたパスから逸脱していないか、`GetFinalPathNameByHandleW` (normalized DOS) で初回と事後の別ハンドルに対して検証する。ディレクトリが既にjunctionで迂回している場合に `path_identity_mismatch` を返せる。しかし検査中の再解析ポイントの瞬間的な差替えに対する原子的保証はなく、完全なTOCTOU耐性とは呼べない。
- `tests/windows_integration.rs` で WindowsローカルNTFSの安全な新規ファイルに対し、ADS不在→存在・ZoneId読取りとファイル/親ディレクトリsymlink拒否を実機検証可能にした。symlink作成権限が無いとスキップするため必須検証時は `FILE_ORIGIN_AUDIT_REQUIRE_REPARSE=1` を指定する。
- `tests/run-windows-ntfs.ps1` はオプトインで一時ファイルへの `Zone.Identifier` 作成と `icacls` による一時的な読み取り拒否の検証を実施する。PowerShell [Set-Content -Stream](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-content) と [icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls) が一次情報。ACL変更はスクリプトの一時ファイルに限り、`finally` で復旧を試みる。監査CLI本体は従来どおり読み取りのみ。
- **この環境にはRust/CargoとWindows実機がなく、新しいWindows統合テスト・バイナリの実行成功は未確認。** 本体のGitHub Actions成功は独立crateをビルドした結果ではない。検証ログとテスト実行実績が揃うまでPRはDraft維持。

## 設計上の限界・未検証

- 実行・ネットワーク・Windows設定操作なし。入力1件、パス2048文字、ADS 64KiB、1024行、行8192文字、最大64KiB+1の読み取り、同期I/Oのハードタイムアウトなし。3秒の事後判定はハングしたストレージ呼び出しを中断しない。
- ローカルドライブでもディレクトリの競合的な再解析ポイント挿入があり得る。ベース/ADS ID一致、読み取り後の再オープン、サイズ・時刻の照合は完全な原子性を保証しない。MOTW自体はいつでも上書き・削除・偽造され得る。
- 従来のWindows AVによるMOTWの解釈差、リンク/クラウドプレースホルダー/ACL/DACLとEFS、コピー・ZIP伝播、FAT/exFAT/ReFS/NTFS、Windows 11 x64/x86、Windows Defenderが稼働する端末での動作、負荷・誤検知は**未実機検証**。
- 検査は read-only だがOSの最終アクセス時刻・監査ログ更新など**OSによる付随的な変更**を完全に抑止するものではない。権限不足、非対応、エラー、MOTW不在を「信頼済み」へ昇格しない。
- 現リポジトリはルートREADMEでライセンス未設定と記載。新規コードに第三者のGPL/AGPL等を取り込まず、Rust標準ライブラリ（Rust Project License: [MIT / Apache-2.0](https://github.com/rust-lang/rust/blob/master/COPYRIGHT)）のみ利用。**本モジュールの再配布ライセンスもリポジトリ所有者の決定待ち**。Microsoft API仕様の引用・参照は一次文書のURLで提示し、Microsoftコードはコピーしていない。
