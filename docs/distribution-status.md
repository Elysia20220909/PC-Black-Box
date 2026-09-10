# Usage and distribution status / 利用・配布条件の確認状況

[日本語README](../README.md) / [English README](../README.en.md)

確認日: 2026-09-10。これは確認状況の整理であり、ライセンス契約、法的助言、一般配布の適法性を保証する文書ではありません。所有者が選択した本体の条件を記録し、第三者がそれぞれのライセンスから得る権利を制限しません。

Checked on 2026-09-10. This is a status record, not a license agreement, legal advice, or a blanket redistribution clearance. It records the owner's selected application terms without restricting rights granted under third-party licenses.

## 公開状態と名称 / Visibility and naming

| 項目 / Item | 確認した状態 / Verified status |
|---|---|
| Repository | `Elysia20220909/PC-Black-Box` is public |
| Published release | `v0.13.0-preview.1` is a published prerelease, not a Draft |
| Release source | `831eb7fba4e2c7eb0a434d5e3a2240a0ee3a0c97` from PR #19; not merged into main |
| Documentation base | main 0.12.0, `2278b0feeed7aad47a80624b9f7813c4a61c439f` |
| Planned name | StillLens; the repository URL, EXE/DLL names, and settings location are unchanged |
| Application license | Custom noncommercial personal-use / no-redistribution terms in this local revision; not yet published to GitHub or applied to the existing ZIP |
| Reporting channels | Issues, Discussions, and GitHub private vulnerability reporting are disabled; an owner-provided general contact is recorded below, with delivery unverified |

公開済みZIPはPC Black Box名義の所有者確認用プレビューとして梱包されたものです。その後リポジトリがPublicになりましたが、ZIP内の説明や利用条件を更新したわけではありません。ダウンロード可能という事実と、一般配布の条件が確定したかどうかは区別します。

The published ZIP was packaged as a PC Black Box owner-review preview before the repository became public. Making the repository public did not update its bundled text or settle its distribution terms. The existing ZIP has not been renamed, rebuilt, or repackaged for StillLens.

このローカル文書作業では、公開済みリリース本文やZIPを変更していません。GitHub上の旧案内を修正するには、別途承認された公開操作が必要です。

This local documentation pass does not change the live release notes or ZIP. Correcting the old GitHub text requires a separately approved publication step.

## 本体の条件 / Application terms

本体の条件は[LICENSE](../LICENSE)にまとめています。非商用の個人利用・試用と手元での改変を許可し、業務を含む商用利用、有償・無償の再配布を禁止します。対象は、この条件を添付した改訂の本体ソース、バイナリ、関連文書です。MITやオープンソースライセンスではありません。

The [LICENSE](../LICENSE) permits noncommercial personal use, evaluation, and private modification of the application revision accompanied by those terms. Commercial use, including business use, and paid or free redistribution of application source, binaries, documentation, or modified versions are prohibited. This is a custom license, not MIT or an open-source license.

第三者コンポーネントの権利、適用法が制限を認めない権利、GitHub規約が別途認める権利は制限しません。公開リポジトリの閲覧・フォークなど、GitHubサービス内の権利をこの条件で取り消すものではありません。それをサービス外の再配布や商用利用の許可とは扱いません。[GitHub利用規約](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service#5-license-grant-to-other-users)

Third-party rights, rights that applicable law does not allow to be restricted, and rights separately granted under GitHub's terms remain unaffected. Public-repository viewing and forking rights within GitHub are not revoked; they are not a general grant of off-platform redistribution or commercial-use rights.

今回はローカル文書のみの変更です。公開済みのmain、PR、リリース本文、既存ZIPには反映しておらず、過去に別途与えられた権利を遡って取り消すものではありません。既存プレビューへの適用と外部貢献の受け入れ条件は別途確認します。

This is a local documentation change only. It has not been applied to published main, PRs, release notes, or the existing ZIP, and does not retroactively revoke separately granted rights. Application to the existing preview and contribution acceptance terms require separate confirmation.

## 試用・一般の不具合の連絡先 / Trial and general bug contact

[ChloeFlora23047120947120@protonmail.com](mailto:ChloeFlora23047120947120@protonmail.com)

所有者が指定した公開予定の連絡先です。このローカル変更ではGitHubへ掲載していません。初回はアプリとWindowsの版、症状、再現手順だけを送り、実際の調査対象、未編集のレポート、認証情報、個人パスは添付しないでください。脆弱性の可能性がある場合は、[SECURITY.md](../SECURITY.md)に従って詳細を送る前に安全な受け渡し方法を確認してください。到達性は未確認で、返信時期は保証しません。

This owner-provided address is intended for publication but has not been posted to GitHub by this local change. Initially send only application and Windows versions, symptoms, and reproduction steps, without inspected files, raw reports, credentials, or personal paths. For suspected vulnerabilities, follow [SECURITY.md](../SECURITY.md) and confirm a secure transfer method before sending details. Delivery has not been verified, and no response time is guaranteed. Providing a contact address does not establish SDK recipient agreement.

## 同梱コンポーネント / Included components

この表は公開済み0.13.0-preview.1に対応します。mainの依存関係表ではありません。全文はそのZIP内の `licenses/` と `THIRD-PARTY-NOTICES.txt` にあります。

This table describes the published 0.13.0-preview.1, not main's dependency set. Its full texts are in the ZIP's `licenses/` directory and `THIRD-PARTY-NOTICES.txt`.

| Component | 確認した由来・条件 / Verified origin and terms | Evidence |
|---|---|---|
| OpenMcdf.dll | OpenMcdf 3.3.0, MPL-2.0. Unmodified DLL; the notice identifies the corresponding build-commit source | [Exact source and license](https://github.com/openmcdf/openmcdf/tree/11b5d876cdebb472f1845dfa55e9e9b953aed65f) |
| Microsoft.Windows.SDK.NET.dll | Microsoft.Windows.SDK.NET.Ref 10.0.17763.57, DLL version 10.0.17763.55; Windows SDK license, not labeled MIT | [Package metadata](https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.net.ref/10.0.17763.57/microsoft.windows.sdk.net.ref.nuspec), [SDK terms](https://aka.ms/WinSDKLicenseURL), [REDIST list](https://learn.microsoft.com/en-us/legal/windows-sdk/redist#microsoftwindowssdknetref) |
| WinRT.Runtime.dll | DLL version 2.2.0.48161, shipped through the same SDK package. The notice also preserves the corresponding C#/WinRT MIT source license; it does not discard the SDK package's terms | [Exact C#/WinRT license](https://github.com/microsoft/CsWinRT/blob/8649ee3eeb2445ca2a36d80d878ef60b96a6c65d/LICENSE) |
| .NET apphost in PC Black Box.exe | Microsoft.NETCore.App.Host.win-x64 10.0.8 declares MIT. The application-specific apphost is not the entire .NET Desktop Runtime | [Package metadata](https://api.nuget.org/v3-flatcontainer/microsoft.netcore.app.host.win-x64/10.0.8/microsoft.netcore.app.host.win-x64.nuspec), [Exact runtime license](https://github.com/dotnet/dotnet/blob/94ea82652cdd4e0f8046b5bd5becbd11461482ca/src/runtime/LICENSE.TXT) |

OpenMcdfのバイナリ配布では、対応するソースを入手可能にし、その入手方法を受領者へ案内する必要があります。ライセンス全文の同梱だけで、この条件を満たしたとは扱いません。[MPL 2.0 §3.2(a)](https://www.mozilla.org/en-US/MPL/2.0/)

Distribution of the OpenMcdf binary requires making the corresponding source available and informing recipients how to obtain it. Including the license text alone does not establish fulfillment of that requirement.

各ライセンスは各コンポーネントに適用され、本体へ自動的に同じライセンスを割り当てるものではありません。.NETの上流第三者通知も同梱されていますが、列挙された全コンポーネントがapphostに含まれるという意味ではありません。

Each component retains its own terms; these do not automatically license the application. The included upstream .NET third-party notices do not mean every listed component is present in the apphost.

## 未解決の利用・配布条件 / Unresolved usage and distribution conditions

MicrosoftのREDIST一覧は、WinRT APIの呼び出しを可能にするWindowsアプリの一部として、SDK由来の2つのDLLを未改変で配布する対象に挙げています。ただし、一覧掲載だけでSDKライセンスの条件がすべて満たされたとは言えません。配布者・外部エンドユーザーの同意など、適用される条件を実際の配布方法に合わせて確認する必要があります。全文の同梱だけを同意の証拠とはしません。

Microsoft's REDIST list names the two SDK DLLs for unmodified inclusion in a Windows application to enable WinRT API calls. Listing is not proof that every SDK license condition is satisfied. Applicable distributor and external-end-user agreement requirements must be checked against the actual distribution arrangement; including the license text is not evidence of agreement.

- [x] 本体の条件を所有者が選び、ローカル文書へ反映する。 / Owner selects custom application terms, recorded locally.
- [ ] SDKの適用条件と受領者同意の方法を確認する。 / Confirm applicable SDK requirements and the recipient-agreement mechanism.
- [ ] 選択した本体の条件と第三者ライセンスが両立するか確認する。 / Check compatibility with the chosen application terms.
- [ ] 既存プレビューの扱いと、必要な文書・配布手順の更新を所有者が承認する。 / Owner decides how to handle the existing preview and approves any required document or distribution changes.
- [x] 試用・一般の不具合の連絡先をローカル文書へ記載する。 / Record the owner-provided general contact locally.
- [ ] 外部試用の前に、対象版の使用許諾、メールの到達性、安全な報告手順を確認する。 / Confirm version-specific tester permission, contact delivery, and secure reporting before organized external testing.

これらが未確定のまま「誰でも自由に利用・改変・再配布できる」「一般配布の確認はすべて完了した」とは案内しません。既存リリースの非公開化・削除・差し替えも、この文書では実行しません。

Until resolved, do not advertise unrestricted use, modification, or redistribution, or claim complete distribution clearance. This document does not unpublish, delete, or replace the existing release.

## 名称移行と検証の境界 / Rename and verification boundaries

StillLensへの移行は文書上の準備段階です。正式なリポジトリ名、EXE名、署名、設定移行、新しい配布物は別の変更として扱います。名前の簡易検索は、商標やドメインの利用可能性を保証しません。

The StillLens transition is documentation preparation only. Repository and executable renaming, signing, settings migration, and new release artifacts are separate changes. A preliminary name search is not trademark or domain clearance.

自己署名の信頼、SmartScreen、別PCやGUIでの動作は、ライセンスとは別の検証事項です。過去のCLIテスト合格を、その代わりにはしません。

Certificate trust, SmartScreen, other-PC behavior, and GUI operation are separate verification questions. Earlier CLI test results do not answer them.
