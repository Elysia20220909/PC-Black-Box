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
- **source-only。** 公開範囲にかかわらず、必要なソースだけを明示的に扱い、生成物や配布物をコミットに混ぜない。
- **公開範囲と利用許諾を分ける。** 公開設定、アクセス権、ライセンスの追加・変更は所有者の明示承認を得る。閲覧できることを改変・再配布の許諾と見なさない。
- **GitHub は原則 Draft PR まで。** 許可なく merge しない。

## 3. コミット前の検証

完全な一覧は [THREAT_MODEL.md](THREAT_MODEL.md) の「Verification gates」（17項目）にあります。ここでは重複させず、
入口となるコマンドだけを示します。**どのエージェントが書いた変更でも、通すゲートは同一**です。実行環境で回せないゲートは、合格ではなく未実行として記録します。

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

この境界テストは、引数なしでアプリを起動します（`tests/Test-RuntimeBoundaries.ps1`）。`-WindowStyle Hidden` はヘッドレス実行の保証ではありません。GUI禁止の作業では実行せず、未検証として残してください。テストを省略した状態を全ゲート合格と報告しないこと。変更提案と検証記録の扱いは [CONTRIBUTING.md](CONTRIBUTING.md) にまとめています。

### 起動方法の落とし穴

環境によって挙動が変わります。**起動に失敗しても、製品の不具合と決めつけないでください。**

- **昇格して起動しない。** 0.7.2 以降、管理者権限での起動は専用メッセージで拒否される
  （コマンドラインでは `PC_BLACK_BOX_ELEVATION elevated=true refusing=true`、終了コード 1）。
  ゲートを回すときに管理者ターミナルを使わないこと。
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

## 5. PR 運用と現在の設定の確認

- 過去の運用メモには、マージや署名の問題に関する未確認の説明が含まれる。記載されていることと、事実として確認できたことを分け、現在の操作手順の根拠にしない。
- マージ前に、対象 PR の base/head、チェック結果、署名状態、現在のブランチ保護・ruleset を読み取りで確認する。API が 403 や 404 を返した場合は、保護なしとも検証済みとも扱わない。
- `Commits must have verified signatures.` などの拒否が出たら、現在のコミットと拒否理由を確認し、修正の対象と副作用を示して承認を得る。保護の回避、`reset --hard`、履歴の書き換え、force-push を定型処理として実行しない。
- `commit.gpgsign = true` を維持する。公開範囲の変更と、push・merge の承認は別。

### 過去の運用メモと未確認事項

[PR #23 の確認記録](https://github.com/Elysia20220909/PC-Black-Box/pull/23)では、
旧メモにある `merge-async` の使用と、自動リベースが署名の問題を起こしたという因果関係は、
裏付けが取れていないと報告されている。ここでは、実行済みの手段や確定した原因として扱わない。

旧メモの具体的なコマンド列は Git 履歴に残るが、現在の手順としては掲載しない。
調査を再開する場合は、当時の操作ログ、対象コミット、署名状態、保護設定を照合し、
確認できた事実と不明な点を記録する。未確認のメモを根拠に保護回避や履歴の書き換えを行わず、
変更が必要なら対象と副作用を示して改めて承認を得る。

## 6. 既知の未修正の問題

- **昇格起動の不具合は解決済み**（#9、0.7.2）。昇格トークンの Owner が `S-1-5-32-544` になるため
  `process-object-lockdown` が誤って not-enforced になっていた問題は、所有者比較を正して解消した。
  あわせて昇格起動そのものを拒否するようにしたので、**現在の期待動作は「拒否」**（§3 参照）。
  昔のビルドで「基準を確認できません」と出た場合は、この件を疑う。
- **ビルド成果物の取り違えに注意。** 外部ツールのスキャン成果物（`.codex/.../artifacts/` 配下など）に
  古いビルドが残ることがある。**正は `bin/Release/`**。動作確認の前に、必ずビルド日時と
  `--self-test` の検査項目数を確認する。
