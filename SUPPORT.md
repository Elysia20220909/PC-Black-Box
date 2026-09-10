# Support / 相談と報告

StillLens / PC Black Boxについての連絡先と、送信前に確認してほしいことをまとめています。個人開発のため、返信・解決・対応期限は保証しません。

This guide explains how to contact the StillLens / PC Black Box project and what to check before sharing information. This is a personally maintained project; replies, fixes, and response deadlines are not guaranteed.

## 連絡先 / Contact

[ChloeFlora23047120947120@protonmail.com](mailto:ChloeFlora23047120947120@protonmail.com)

2026-09-10の確認時点では、Issues、Discussions、GitHubの非公開脆弱性報告機能は無効です。メールの到達性も未確認です。返信がない場合に、機密情報を公開PRや別の公開場所へ投稿しないでください。

As checked on 2026-09-10, Issues, Discussions, and GitHub private vulnerability reporting are disabled. Mailbox delivery has not been verified. A lack of response is not a reason to publish sensitive information in a pull request or another public channel.

## 相談の種類 / Where to start

| 用途 / Purpose | 案内 / Guidance |
|---|---|
| 使い方、試用、一般の不具合、改善案 / Usage, trials, general bugs, ideas | 上記メールへ、まず概要だけを送ります。 / Email a brief description first. |
| 脆弱性の可能性 / Suspected vulnerability | [SECURITY.md](SECURITY.md)に従い、詳細を送る前に安全な方法を確認します。 / Follow the security policy and confirm a secure method before sharing details. |
| 嫌がらせ等の行動規範違反 / Conduct concern | [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)の相談方法を使います。 / Follow the code of conduct reporting process. |
| コード・文書の変更 / Code or documentation contribution | [CONTRIBUTING.md](CONTRIBUTING.md)で提出範囲、権利、方法を先に確認します。 / Confirm submission scope, rights, and method first. |

## 初回に伝えること / What to include initially

- アプリのバージョンと入手したリリース、またはソースコミット。 / Application version and release, or source commit.
- Windowsの版、使用している.NET Desktop Runtimeの版。端末名やユーザー名は不要です。 / Windows and .NET Desktop Runtime versions; omit device and user names.
- 起きたこと、期待したこと、再現手順。個人情報を含まない文章で説明します。 / Observed behavior, expected behavior, and reproduction steps without personal data.
- 未実行・未確認の項目は、そのまま記載します。 / Identify checks not performed or outcomes not confirmed.

実際の調査対象、疑わしい実行ファイル、未編集レポート、ログ、認証情報、非公開URL、個人パス、キャプチャを初回に添付しないでください。追加資料が必要なら、最小限の合成例や編集済みの資料を、安全な受け渡し方法を確認してから共有します。

Do not initially attach inspected files, suspicious executables, raw reports, logs, credentials, private URLs, personal paths, or captures. If more evidence is needed, agree on a secure method and use a minimal synthetic example or carefully redacted material.

## 利用と受付の境界 / Usage and intake boundaries

本体は非商用の個人利用・手元での改変に限定した[独自利用条件](LICENSE)で、商用利用と再配布は禁止します。第三者のライセンスは別扱いです。[配布条件の確認状況](docs/distribution-status.md)にある既存プレビュー・SDKの未解決事項も残っています。相談やフォームへの記入だけで、対象版の利用許諾やコード提出の許可が成立するものではありません。

The [custom application terms](LICENSE) allow noncommercial personal use and private modification, not commercial use or redistribution. Third-party licenses remain separate, and the existing-preview and SDK questions in the [distribution status](docs/distribution-status.md) remain unresolved. Contacting the project or filling in a template does not establish version-specific usage or code-submission permission.

Issueテンプレートは将来の受付に備えたものです。ファイルを追加しただけではIssuesを有効にせず、mainへの反映と機能の有効化が済むまでは受付フォームとして利用できません。フォームを使える場合も、脆弱性や機密情報は公開しないでください。

Issue templates are prepared for future use. Adding files does not enable Issues; the templates are not an active intake form until they are merged into main and Issues is enabled. Even when available, do not use public forms for vulnerabilities or sensitive information.
