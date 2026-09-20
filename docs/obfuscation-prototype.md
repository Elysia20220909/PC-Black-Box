# 0.13.0の構造難読化試作 / Structural-obfuscation prototype for 0.13.0

追記: `agent/defender-readonly` ではDefender連携と外部ツール登録確認用のC#ファイル5個を対象一覧へ追加し、
ランダム化するC#は22個、必須入力は32個です。以下の17個・27入力と検証結果は
`adff137` 時点の記録です。[今回の変更と検証](defender-readonly.md)を参照してください。

この作業は、指定された既存EXEに対応するソース `831eb7fba4e2c7eb0a434d5e3a2240a0ee3a0c97` を基準とします。0.12.0用の試作 `8dc4dad` を、別ブランチ `agent/obfuscation-013` へ移植しました。既存の署名済みEXE、ZIP、インストール先、GitHubは変更しません。fetchも行っていません。

This local prototype targets the 0.13.0 source revision matching the specified EXE's version metadata. It does not overwrite, re-sign, or claim byte-for-byte reproduction of that existing signed application.

## 変えるものと残すもの / Scope

- 保守用のC#・XAML・本体プロジェクトは変更しません。コピー内で17個のC#ファイルをランダムなディレクトリ名・ファイル名へ移し、プロジェクト名を `Application.csproj` にします。内容・型名・コメントは変えません。
- `ProductSelfTest.Ole.cs` を追加し、`global.json`、`NuGet.Config`、`packages.lock.json` を無変更で引き継ぎます。SDK 10.0.300を基準に同じfeature band内の最新パッチを許可する `latestPatch` 設定と、OpenMcdf 3.3.0の厳密な固定を維持します。
- このソース版には本体の `LICENSE` がありません。mainに後から追加された利用条件は移植しません。`source-layout.json` に列挙したライセンス・通知ファイルが入力側に存在する場合は、その内容を保持します。不存在は公開や再配布の許可を意味しません。
- 0.12.0など別版のソースを拒否します。候補XMLの生成でもDLLのファイルバージョンが `0.13.0.0` であることを確認します。ただし版のメタデータだけで由来や安全性を証明するものではありません。

The copy has 27 required inputs, plus any listed notices already present in the source. Source text, public history, and copies held by others remain readable. Path renaming is not encryption or a confidentiality boundary.

## ローカル出力と復元 / Local output and rollback

出力は `obj/structure-obfuscation/<RunId>/` 内です。`source/` は変換したソースコピー、隣の `private/` は名前の対応表や絶対パスを含む非公開情報です。親ディレクトリごと公開しないでください。コピー内でビルドした `bin/`・`obj/` も公開対象ではありません。

GitとSDKの通常の列挙から生成物を除外します。固定ローカルドライブだけを許可し、パス逸脱・reparse point・既存RunIdへの上書きを拒否します。Git ignoreは読み取り防止ではなく、検査とアクセスの間の差し替え競合も防ぎません。信頼できる作業場所でのみ使用します。

The private map's `complete: true` means copying completed, not that a release was approved. Failed runs are not automatically removed. Continue building the maintained project to stop using this prototype; no application-source rollback is needed.

## コマンド / Commands

PowerShell 7を使用します。以下はローカル検証であり、配布物を作るコマンドではありません。

```powershell
$copy = ./tools/New-ObfuscatedSource.ps1
Push-Location $copy.SourceDirectory
try {
    dotnet restore Application.csproj --locked-mode --configfile NuGet.Config --source "$env:USERPROFILE/.nuget/packages"
    if ($LASTEXITCODE -ne 0) { throw 'Restore failed.' }
    dotnet build Application.csproj -c Release --no-restore -p:UseAppHost=false
    if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
}
finally { Pop-Location }

./tests/Test-ObfuscationPreparation.ps1 -AssemblyPath '<absolute path to locally built 0.13.0 PC Black Box.dll>'
./tools/New-ObfuscationConfig.ps1 -AssemblyPath '<same DLL>' -ResolutionDirectory '<absolute .NET directory>', '<absolute WPF directory>'
```

既存キャッシュを使用し、未知のパッケージやツールを無断で追加しません。NuGetの監査元は既存設定を維持します。`UseAppHost=false` は検証用EXEランチャーを作らない指定で、ネイティブ化や難読化ではありません。

## バイナリ向け候補設定 / Candidate binary configuration

`New-ObfuscationConfig.ps1` は[Obfuscarの公式設定説明](https://docs.lextudio.com/obfuscar/getting-started/configuration)に基づくXMLを作成するだけです。エンジンをインストール・実行しません。将来の採用前にバージョン固定、依存・ソース・インストール処理・hooks・CI・同梱バイナリ・認証・通信を確認する必要があります。

対象モジュールは自作の `PC Black Box.dll` だけで、OpenMcdfやMicrosoftのDLLは対象に含めません。`FileInspector` と `ShortcutInspector` の内部メンバーだけを候補とし、公開API、プロパティ、イベント、生成コード、全入れ子型、その他の型を除外します。OLEの資源上限管理、WPF、JSON、P/Invoke、起動時の保護処理は保持する設定です。文字列隠蔽と追加のメソッド最適化も無効です。

Configuration tests check XML and selection patterns, not the engine's behavior. DLL filenames, third-party contents, dependency metadata, and assembly identity are unchanged. This is not packing or single-file deployment.

実適用時には、変換後の名前・除外範囲、JSONと画面参照、保護機構、実行性能、対応表・PDB・原本の混入を検証します。難読化は署名前に行い、最終成果物を改めて検証します。GUI禁止の環境では画面操作やGUIを起動する境界テストを実行しません。

## 今回の検証 / Verification for this migration

確認日: 2026-09-17。以下は0.13.0で実行した結果であり、0.12.0版の結果は流用していません。

- 原本0.13.0のロック付き復元とReleaseビルド: 警告0、エラー0。SDK、NuGet設定、ロックファイルは変更なし。
- 準備テスト: 最終版で121項目を通過。27入力の内容、17ソースのパス変換、OLE自己テストとビルド設定の保持、既存通知の保持、別版ソース・DLLの拒否を含む。DLLの負例は既存依存DLLのコピーを入力データとして使い、ロード・実行しない。
- OpenMcdf: キャッシュのメタデータはロックファイルと一致。使用するnet10.0 DLLは既存署名済みビルド内の同DLLとSHA-256が一致。パッケージに導入時の実行スクリプトやMSBuild targetsは含まれていない。これは完全な脆弱性監査やソース再現ビルドの証明ではない。
- 変換コピーもロック付き復元とRelease再ビルドに成功し、警告0、エラー0。SDK・NuGet設定・ロックファイルは復元後も原本と同じ。通常ビルドのC#入力は19件で、生成コピーの混入は0件。
- 原本と変換コピーの両方で `--security-status` は終了コード0、`enforced=true controls=16/16`。追加保護は3/4で、`user-shadow-stack` は `unavailable`。
- 原本と変換コピーの両方で `--self-test` は終了コード0、`passed=true checks=111`。OLE固有の自己テストを含む。
- 依存DLL3個、`PC Black Box.deps.json`、`PC Black Box.runtimeconfig.json` は両ビルドで一致。
- 0.12.0のDLLを候補設定生成に渡す追加の負例を実行し、作成開始前に拒否。準備テスト内の別版ソース拒否と合わせ、取り違えを検出することを確認。
- PowerShell構文、差分の空白、Gitleaksを検査。PSScriptAnalyzerは実行していない。
- 指定の `signed-build-831eb7f` 内の8ファイルは作業前後で全ハッシュが一致。元の作業ツリーも未変更。
- 0.12.0用試作との差分を別担当が静的レビューし、SDKの説明と版違いDLLの回帰テストを修正。再確認で追加指摘なし。レビュー担当はビルド・テストを独立再実行していない。

検証用の変換コピーは `obj/structure-obfuscation/test-683ed32032ae4053bdf3e1d06e524a30/source/`、.NET/WPF 10.0.8の参照先を設定した候補XMLは `obj/structure-obfuscation/final-013-config/private/obfuscar.xml` です。これらと対応表はローカル専用で、コミット対象ではありません。

GUI、別PC、難読化エンジンの実行と変換後バイナリ、配布署名・梱包・公開は未実施です。GUIを起動する境界テストとホスト上にアカウントを作るCI専用テストも実行していません。全ゲート合格や一般配布可能とは報告しません。

No binary obfuscation or new distribution package is claimed. The existing signed-build directory remains a separate artifact, not an output of this prototype.
