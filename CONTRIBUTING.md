# Contributing / 変更提案

StillLens is the planned new name for PC Black Box. The current executable, project file, settings location, and repository URL still use their existing names. Do not rename them as part of an unrelated contribution.

The repository is public and a PC Black Box preview is available through GitHub Releases. The source tree excludes release artifacts. The application in this revision is governed by [custom terms](LICENSE): noncommercial personal use and private modification are permitted, while commercial use and redistribution are prohibited. Third-party components retain their own licenses. This guide does not create a contributor license agreement or grant redistribution rights. See [usage and distribution status](docs/distribution-status.md) for the published preview and unresolved SDK requirements.

本体は非商用の個人利用と手元での改変に限って許可し、商用利用と再配布は禁止します。変更やパッチを提出する前に、所有者と提出方法、許可、権利の扱いを確認してください。公開PRによるコードの再公開を、この案内だけで許可するものではありません。第三者ライセンスとGitHub規約が別途認める権利は妨げません。

参加時は[行動規範](CODE_OF_CONDUCT.md)を守り、相談の種類に応じて[SUPPORT.md](SUPPORT.md)の窓口を使ってください。Issueテンプレートは将来の受付に備えたもので、Issuesの有効化やコード提出の許可ではありません。

Follow the [code of conduct](CODE_OF_CONDUCT.md) and use the appropriate contact in [SUPPORT.md](SUPPORT.md). Issue templates are prepared for future intake; they do not enable Issues or grant permission to submit code.

## Before proposing a change / 提案の前に

- Read [README.md](README.md), [README.en.md](README.en.md), [SECURITY.md](SECURITY.md), and [THREAT_MODEL.md](THREAT_MODEL.md). Follow [AGENTS.md](AGENTS.md) for work in this repository.
- Confirm the intended scope with the owner through an available, appropriate channel. Do not assume an intake channel is enabled; check its current status before directing anyone to it.
- Rechecked on 2026-09-10: [Discussions](https://github.com/Elysia20220909/PC-Black-Box/discussions) is enabled for general questions; Issues and GitHub private vulnerability reporting remain disabled. Do not direct testers to an inactive issue form or publish sensitive details in Discussions or other public channels. Use the general contact in [README.md](README.md) to discuss contribution scope without sending code or sensitive attachments first. Confirm permission and an appropriate submission method before sharing changes; private modification permission alone does not authorize patch redistribution.
- Never place vulnerability details in a public issue or pull request. Use the process in [SECURITY.md](SECURITY.md).
- Use a dedicated branch and working directory. Preserve unrelated changes and identify the exact base commit.
- Keep implementation claims tied to that commit. A feature or passing check on another branch is not evidence for the default branch.

変更は目的ごとに小さく分け、対象と検証方法を先に共有してください。公開窓口が利用できない場合に、別の公開場所へ機密情報を投稿しないでください。

## Scope / 対象範囲

Documentation corrections, reproducible test cases, and bounded inspection improvements should preserve read-only inspection, explicit resource limits, and the distinction between risk and completeness.

Changes that execute inspected files, upload them, bypass security controls, inspect game memory, or capture packets are outside the accepted scope. Do not weaken a failing gate simply to make it pass.

実行ファイル、インストーラー、配布アーカイブ、署名鍵、個人設定、キャプチャ、生成レポートは提出しません。検証には合成した最小限の入力を使い、認証情報、個人パス、非公開URL、実際の調査対象を含めないでください。

## Verification / 検証

This guidance is based on main 0.12.0 at `2278b0f`. The 0.13.0-preview.1 artifact was built from PR #19 at `831eb7f`. Use the instructions and expected checks for the commit you actually test; the preview's 111-check result is not a main-branch test result.

After reviewing the source, dependencies, install scripts, hooks, CI, bundled binaries, credential handling, and external communication, run the following in a non-elevated PowerShell session with the .NET 10 SDK:

```powershell
dotnet restore .\Destiny2BlackBox.csproj
dotnet build .\Destiny2BlackBox.csproj -c Release --no-restore
dotnet ".\bin\Release\net10.0-windows10.0.17763.0\PC Black Box.dll" --security-status
dotnet ".\bin\Release\net10.0-windows10.0.17763.0\PC Black Box.dll" --self-test
dotnet format .\Destiny2BlackBox.csproj --verify-no-changes --no-restore
dotnet list .\Destiny2BlackBox.csproj package --vulnerable --include-transitive
git diff --check
```

Record the base commit, SDK/runtime versions, command exit codes, and actual test counts. Required results include zero build warnings/errors, `enforced=true controls=16/16`, and `PC_BLACK_BOX_SELF_TEST passed=true`. Dependency restore and vulnerability checks use the network; do not attach credentials or unsanitized logs.

The full gate list is in [THREAT_MODEL.md](THREAT_MODEL.md). The current `tests/Test-RuntimeBoundaries.ps1` starts the application without command-line arguments. `-WindowStyle Hidden` is not a guarantee of headless operation. Do not run this script when GUI startup is prohibited. Record the boundary gate as not run; a passing self-test does not replace it.

GUI禁止の作業では、境界テストを未実行として記録します。別ブランチのヘッドレス対応や過去の合格結果で、このブランチの未検証を埋めないでください。修正内容、確認できた結果、未確認事項、残るリスクを分けて報告してください。

## Handoff / 引き継ぎ

Include a concise explanation of the change, its exact file scope, verification results, and limitations. Review Japanese and English guidance together. Review the full diff and untracked files before proposing a commit.

For documentation-only edits, verify links, commands, version-specific claims, and preservation of technical limits. If application checks are not rerun, say so explicitly; older passing tests do not become new results. A documentation review does not satisfy all gates required for a code change or commit.

ローカルビルドはその作業フォルダーの `bin/Release/` にあり、配布物ではありません。他の作業フォルダーやインストール済みアプリを置き換えないでください。所有者の承認なしに公開設定、利用許諾、アクセス権を変更せず、配布物も作りません。push、PR作成、mergeはそれぞれ承認された範囲で行い、PRは原則Draftにします。
