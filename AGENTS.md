# AGENTS.md — PC Black Box 共同開発の約束

このファイルが、このリポジトリで作業するすべてのエージェント（Codex / Claude Code）と人間にとっての
**唯一の正典**です。`CLAUDE.md` はこのファイルを指すだけのポインタなので、方針を変えるときは
**ここだけ**を編集してください。二重管理をやめることが、このファイルの存在理由です。

## 1. 基本方針

- 依頼する側 / 作業する側と分かれず、共同開発者として同じ目的へ向かって一緒に考える。
- まず背景と目的を受け止め、対象を理解してから着手する。
- 既存のコード、設計、設定、これまでの判断を尊重し、関係のない変更を混ぜない。必要最小限に保つ。
- 明確な開発依頼は調査だけで終わらせず、実装 / テスト / ビルド / 差分確認まで進める。
- 確認できた事実、推測、未確認事項、残るリスクを分けて報告する。失敗や未検証を成功と呼ばない。
- 秘密情報、個人情報、認証情報を守り、安全性とプライバシーを利便性より優先する。
- 削除、公開、送信、購入、デプロイ、push、merge など外部へ影響する操作は、対象を確認してから行う。
- 大きな作業は小さな段階に分け、進捗 / 検証結果 / 残る課題を簡潔に共有する。

## 2. このリポジトリ固有の禁止事項

- **配布物を作らない。** 配布用 EXE、インストーラー、ZIP、リリースフォルダー、配布用チェックサムなどは、
  明示的な許可がない限り作成しない。**ローカルでのビルドとテストは可能**（`bin/` は `.gitignore` 済み）。
- **非公開 / source-only。** 必要なソースだけを明示的に扱い、生成物や配布物をコミットに混ぜない。
- **GitHub は原則 Draft PR まで。** 許可なく merge しない。

## 3. コミット前の検証

完全な一覧は [THREAT_MODEL.md](THREAT_MODEL.md) の「Verification gates」（17項目）にあります。ここでは重複させず、
入口となるコマンドだけを示します。**どのエージェントが書いた変更でも、通すゲートは同一**です。

```
dotnet build Destiny2BlackBox.csproj -c Release      # 警告ゼロが必須（TreatWarningsAsErrors）
dotnet "bin/Release/net10.0-windows10.0.17763.0/PC Black Box.dll" --security-status
dotnet "bin/Release/net10.0-windows10.0.17763.0/PC Black Box.dll" --self-test
pwsh tests/Test-RuntimeBoundaries.ps1
```

期待する結果:

- `--security-status` → `enforced=true controls=16/16`（`state=not-enforced` の行が1つでもあれば不合格）
- `--self-test` → `PC_BLACK_BOX_SELF_TEST passed=true`
- `Test-RuntimeBoundaries.ps1` → `PC_BLACK_BOX_RUNTIME_BOUNDARY_TEST passed=true`

### 起動方法の落とし穴

環境によって挙動が変わります。**起動に失敗しても、製品の不具合と決めつけないでください。**

- exe を **CreateProcess で直接**起動すると、環境によっては拒否される。実測例:
  bash の `./PC Black Box.exe` → `Permission denied`、PowerShell の
  `Start-Process -NoNewWindow -RedirectStandardOutput` → `ERROR_ELEVATION_REQUIRED`。
  一方、**リダイレクトなしの `Start-Process`（ShellExecute 経由）なら起動できる**。
  `Test-RuntimeBoundaries.ps1` が通るのはこのため。
- したがって `--security-status` と `--self-test` は、上記のとおり **`dotnet` に dll を渡す**のが確実。
- GUI サブシステムなので `& '.\PC Black Box.exe'` では**出力を取り逃し、`$LASTEXITCODE` も設定されない**。
  出力が必要なら `Start-Process -NoNewWindow -Wait -RedirectStandardOutput` を使う
  （ただし上の制約と両立しない環境がある）。

## 4. 分担と衝突回避

- **同じ作業ツリーを同時に触らない。** ブランチは `agent/<topic>`。必要なら `git worktree` で物理的に分ける。
- **実装したエージェント以外がレビューする。** 第三者の目で検証する側に回ることを、遠慮しない。
- **引き継ぎは口頭でなくファイルで。** 「どのビルドが正で、どれが捨てて良い成果物か」を必ず書き残す。

## 5. PR 運用の落とし穴

- **スタック PR は `gh pr merge` が通らない。** `gh api -X PUT repos/OWNER/REPO/pulls/N/merge-async -f merge_method=squash`
  を使い、結果は `gh api .../merge-async/{uuid}` で確認する（`gh pr view` は OPEN のまま返るので失敗に気付きにくい）。
  ブランチ保護の回避にあたるため、**実行前に必ず本人の確認を取る**。
- **親 PR のマージ後、GitHub の自動リベースで GPG 署名が落ちる。** `main` は署名必須なので
  `Commits must have verified signatures.` で失敗する。直し方:
  `git fetch` → `git reset --hard origin/<branch>` → `git rebase --force-rebase --gpg-sign origin/main` → force-push。
  自動リベース後にローカルで `main` を merge すると無用なコンフリクトになるので、**先に reset する**。
- `commit.gpgsign = true` を維持する。

## 6. 既知の未修正の問題

- **「管理者として実行」すると起動できない。** 昇格トークンの Owner が `S-1-5-32-544`（BUILTIN\Administrators）
  になるため、`ProcessObjectLockdown` の読み戻し（`descriptor.Owner != user`）が不一致となり
  `process-object-lockdown` だけが not-enforced になる。必須16項目が揃わず、フェイルクローズドで終了する。
  通常権限なら 16/16 で通る。回避策は昇格せずに起動すること（マニフェストは `asInvoker` で昇格は不要）。
- **ビルド成果物の取り違えに注意。** 外部ツールのスキャン成果物（`.codex/.../artifacts/` 配下など）に
  古いビルドが残ることがある。**正は `bin/Release/`**。動作確認の前に、必ずビルド日時と
  `--self-test` の検査項目数を確認する。
