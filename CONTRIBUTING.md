# Contributing / 変更提案

StillLens is the planned new name for PC Black Box. The current executable, project file, settings location, and repository URL still use their existing names. Do not rename them as part of an unrelated contribution.

The repository is private and a PC Black Box preview is available to authorized users through GitHub Releases. The source tree excludes release artifacts. The application in this revision is governed by [custom terms](LICENSE): noncommercial personal use and private modification are permitted, while commercial use and redistribution are prohibited. Third-party components retain their own licenses. This guide does not create a contributor license agreement or grant redistribution rights. See [usage and distribution status](docs/distribution-status.md) for the published preview and unresolved SDK requirements.

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

Batch report consumers must accept schema `pc-black-box-batch-report-v2` and stop reading the removed `targets[].path`. Match each `targets` element to input order; display names may repeat and an empty or drive-root name becomes `target`. File paths within a target remain relative. Source filenames, source hosts, hashes, and evidence such as shortcut paths/arguments remain potentially sensitive; the change removes automatically added target paths, not strings inside evidence. JSON privacy tests must inspect decoded string values, including failure results, rather than searching escaped JSON text. Keep batch output outside every original input target. The writer requires the complete input path list and rejects the same path or any descendant, including failed/unknown targets, before creating output or temporary files. Unverifiable boundaries fail closed; missing targets are allowed when their existing ancestor can be verified and output is outside the reserved path.

バッチJSONはv2へ変更し、`targets[].path` を削除しています。入力との対応は配列順で確認してください。表示名の重複は許され、空の名前とドライブルートは `target` になります。対象内の相対パスや証拠文字列は保持します。絶対パス漏れの回帰テストはJSONを解析して文字列値を確認し、失敗対象も含めます。バッチ保存APIには元の全入力パスを渡します。検査に失敗した対象や種類不明の対象も含め、対象と同一または配下への保存を、出力・一時ファイルの作成前に拒否します。存在しない対象は既存の親から検証し、境界を検証できなければ保存全体を停止します。バッチの出力先を全対象の外に置いてください。

The application now restores OpenMcdf 3.4.0 through the repository `NuGet.Config` and checked-in `packages.lock.json`. The one-command runner also records and compares all DLLs directly in the product output directory and the product's `deps.json` / `runtimeconfig.json` after each stage. This detects changed dependencies or execution settings as well as a changed main DLL; it does not measure loaded memory, shared runtime/OS binaries, or atomically prevent concurrent replacement.

本体のOpenMcdf 3.4.0はリポジトリのNuGet設定とlock fileで固定します。一括検証は製品出力直下のDLL一覧と実行設定JSONも各工程後に照合・記録します。共有ランタイム・OSバイナリや実行時メモリは照合対象外で、確認の間の差し替えを原子的に防ぐ保証ではありません。

The 0.12.0 reference documentation describes commit `2278b0f`; the 0.13.0-preview.1 artifact was built from PR #19 at `831eb7f`. Use the source and instructions for the revision you actually test; the preview's 111-check result is not a main-branch test result.

After reviewing the source, dependencies, install scripts, hooks, CI, bundled binaries, credential handling, and external communication, run the following in a non-elevated PowerShell session with the .NET 10 SDK:

The four headless checks can be run together:

```powershell
pwsh -NoProfile -NonInteractive -File .\tests\Invoke-Verification.ps1
```

If `dotnet` is not on PATH, the script also checks the current user's `.dotnet\dotnet.exe`; an explicit `-DotNetPath` can select a different existing SDK. It records the base commit, dirty state, source snapshot, DLL SHA-256, stage exit codes and pass/fail/not-run status in `bin/validation/runs/<run-id>/summary.json`. The boundary test rebuilds and checks that its DLL matches the earlier build. Raw command output is not saved by the wrapper. The four checks do not replace the other verification gates below.

The snapshot covers repository files, including ignored files, except Git metadata and the two projects' known `bin`/`obj` outputs; it also hashes common ancestor build settings. It does not track arbitrary external imports or prevent changes that are reverted between checks. The wrapper does not record the actual runtime version; record it separately when required. Do not run another build or edit the same worktree concurrently.

ビルド・セキュリティ状態・自己テスト・境界テストは上のコマンドで一括実行できます。結果は作業ツリーの `bin/validation/runs/` に保存します。途中で失敗した場合は後続を未実行として記録し、残りの検証ゲートは別途確認します。

照合対象はGit管理外のファイルも含む作業ツリー内のファイル（Git管理情報と両プロジェクトの既知の `bin` / `obj` を除く）と、親階層の主なビルド設定です。任意の外部インポートや、確認の間に変更して戻した内容までは検出できません。実際に使ったランタイムの版は自動記録しないため、必要に応じて別に記録します。同じ作業ツリーで別のビルドや編集を並行しないでください。

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

The full gate list is in [THREAT_MODEL.md](THREAT_MODEL.md). `tests/Test-RuntimeBoundaries.ps1` launches the product DLL through a bounded, headless test-host argument after the same elevation and required-posture checks. It checks the running process from outside and runs the network-guard probe separately. This does not verify the normal GUI path or EXE/apphost-specific startup behavior. A passing self-test does not replace the boundary gate.

境界テストはGUIを作らず実行します。通常のGUI起動とEXE固有の起動経路は別の未検証事項です。別ブランチや過去の合格結果で、このブランチの未検証を埋めないでください。修正内容、確認できた結果、未確認事項、残るリスクを分けて報告してください。

## Handoff / 引き継ぎ

Include a concise explanation of the change, its exact file scope, verification results, and limitations. Review Japanese and English guidance together. Review the full diff and untracked files before proposing a commit.

For documentation-only edits, verify links, commands, version-specific claims, and preservation of technical limits. If application checks are not rerun, say so explicitly; older passing tests do not become new results. A documentation review does not satisfy all gates required for a code change or commit.

ローカルビルドはその作業フォルダーの `bin/Release/` にあり、配布物ではありません。他の作業フォルダーやインストール済みアプリを置き換えないでください。所有者の承認なしに公開設定、利用許諾、アクセス権を変更せず、配布物も作りません。push、PR作成、mergeはそれぞれ承認された範囲で行い、PRは原則Draftにします。
