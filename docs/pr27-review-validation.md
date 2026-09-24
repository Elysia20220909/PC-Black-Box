# PR #27 local review fixes and verification

Date: 2026-09-24. This is a local, source-only verification record, not a hosted CI result or distribution approval.

## Source and build identity

- Worktree: `Destiny2BlackBox-die-integration`, branch `agent/die-integration`.
- HEAD: `51a9ceb2f5165518dfb22b0e252a0e78edd3cefc`.
- PR base: `350ece0a2709973a006eb84ac2c919a4e868807d`.
- Tested state: **dirty**, containing the uncommitted review fixes. The unchanged HEAD alone does not contain these fixes.
- Non-documentation source/configuration fingerprint, including untracked source inputs: `8B088FF7C79B419F7CA16C77B8CAD386FC062B80F578A17B598261F843B42E70`. The integration script verified the fingerprint was unchanged across its execution; an independent read-only reviewer recomputed the same value.

Identifiers of the development binaries used by the successful integration gate, rebuilt locally before execution:

| Input | SHA-256 |
| --- | --- |
| PC Black Box.dll | `52F3488105DC21EA6CE7C9BF7D72B88D8C3541474DE872DB774C256469FB7A6A` |
| DieBridge.dll | `D67C5345E297D3987D46448CDB075892ACC99BBFC860B6D069CEA59AEC80E3FB` |
| DieSandboxProbe.dll | `F18CFE0641A9A9A035FA590F442D84450CBC985DC9ECDDD7A80040F1D4FC57F0` |
| probe.exe | `6C51D251C0073448762120561B3CCB1CFFD41BE4C2C58BAB7D7B355054FA261B` |

These identify local test inputs, not signed or published release artifacts. The official DiE archive was read from the existing installation and matched the pinned hash documented in [die-integration.md](die-integration.md). That installation was not overwritten.

## Changes

- Session responses separate analysis from temporary-data removal, AppContainer-profile removal, and directory-permission restoration. Serialization happens after the cleanup attempts. A valid cleanup acknowledgement survives rejection of malformed/mismatched parser evidence.
- GUI display data and Markdown/JSON include cleanup warnings. Lost acknowledgements and legacy imports report unknown cleanup instead of assuming success. Parser output remains supplementary and cannot reduce the risk score.
- Obfuscation preparation includes the integrated sources, excludes the reviewed `tools/` and `tests/` trees consistently with the application project, and rejects changed compile-exclusion rules. Tests cover excluded nested files, unexpected source files, configuration changes, and transformed-source builds.
- CI now builds/formats the bridge and probes, builds the native probe using discovered MSVC tools, tests obfuscation preparation and the transformed source, and runs DiE integration under the existing disposable standard-user mechanism. The official test archive is hash-pinned; no artifact upload is configured.
- Real session tests disconnect before a request and after parser startup, cancel after startup, and then reconnect twice. A test-only bridge audit checks cleanup on all four started requests, including requests that can no longer receive responses. Git ownership exceptions are scoped to each test command and the exact checkout; no persistent or wildcard trust setting is written.

## Executed locally

| Gate | Result |
| --- | --- |
| Main, DieBridge, RuntimeBoundaryProbe, DieSandboxProbe Release builds | Passed, zero compiler warnings/errors |
| Native probe build | Passed with MSVC `/W4 /WX /MT` |
| Main locked restore with configured advisory policy | Passed; no dependency or lockfile changes |
| Required security controls | `enforced=true controls=16/16` |
| Platform reinforcements | 3/4; user-shadow-stack unavailable on this environment |
| Product self-tests | `passed=true checks=355` |
| Headless runtime boundary tests | `passed=true checks=9` |
| Cleanup failure regression | Real locked-file deletion failure; simulated profile deletion failure; successful retry after releasing the file lock |
| Native isolation probe | Network positive control, sandbox denial/no listener acceptance, write denial, output limit, 30-second timeout, directory seal, running-child cancellation passed |
| Real DiE session | Disconnect before request, disconnect after startup, cancellation after startup, two successful subsequent requests passed |
| Bridge cleanup audit | `requests=4 attention=0` |
| Integration fixture removal | `PCBB_DIE_INTEGRATION passed=true fixtureRemoved=true` |
| Obfuscation preparation and transformed-source build | `Passed=True Checks=155 TransformedCopyBuilt=True`; zero build warnings/errors |
| Formatting | `dotnet format --verify-no-changes --no-restore` passed for all four projects |
| Changed PowerShell scripts | Parser syntax checks passed for all five scripts |
| Patch whitespace | `git diff --check` passed |
| Secret scan | Gitleaks reported no findings in its scanned scope; files over 2 MiB, including SDK binaries, were skipped |
| Independent review | Two P2 findings were fixed; bounded re-review found no additional P1/P2 in the reviewed changes |

The current runtime boundary script was inspected before execution: it uses the console probe's `--hold` and `--network-transport` modes, not the WPF GUI. No GUI was opened or operated.

Final session markers:

```text
PCBB_DIE_SESSION passed=true disconnectBeforeRequest=true disconnectAfterStart=true cancellationAfterStart=true repeatedRequests=2 cleanup=true controls=16/16
PCBB_DIE_SESSION_CLEANUP requests=4 attention=0
PCBB_DIE_INTEGRATION passed=true fixtureRemoved=true
```

## Failures and corrections during this run

- The first full integration gate failed because it could not capture the protected child application's success marker, even though the bridge returned exit code zero. That attempt was not counted as a pass. Test-mode stdout/stderr are now redirected, drained asynchronously and forwarded; the subsequent complete gate passed.
- Independent review found that rejecting parser evidence also discarded valid cleanup detail, and that a temporary CI user needed an exact-checkout Git ownership exception. Both were fixed. The final self-test count includes the additional rejected-evidence/cleanup regression cases.

## Remaining gates and non-actions

- The modified GitHub workflow has **not** run on a hosted runner. Local success does not validate temporary-account creation, hosted permissions, hosted archive download, or the complete hosted job.
- GUI layout/interaction, another-PC behavior, full network tracing, parser fuzzing and an adversarial sandbox-escape audit remain unverified. Isolation-test success is not a guarantee of complete safety.
- Actual binary obfuscation was not run; the tested scope is preparation and the build of the source-path-transformed copy.
- Abrupt termination/OS crash can still leave temporary data. A disconnected GUI can only report cleanup as unknown; the headless test audit does not create a durable production cleanup journal.
- Legacy imports have no post-cleanup acknowledgement and explicitly report unknown cleanup. The live legacy GUI path was not exercised.
- Distribution permission, Microsoft SDK recipient consent, Qt/native redistribution obligations, and cross-PC trust of a self-signed certificate remain separate unresolved gates.
- No commit, push, PR-body/comment update, Draft removal, merge, publication, release package, signing, existing-installation overwrite, or AI work was performed. PR #27 remained open and Draft at the verified head/base. PR #19 and #26 were not modified.
- Test-only integration fixtures were removed. Ignored development outputs and obfuscation preparation evidence remain under `bin/` and `obj/` for inspection; no generated binaries or private name maps were staged.
