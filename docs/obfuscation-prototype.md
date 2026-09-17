# 構造難読化のローカル試作 / Local structural-obfuscation prototype

この試作は保守用ソースを変更せず、外向けコピーのファイル構造を変えます。ソースの内容、型名、コメントは変えません。公開済みのGit履歴や他者のコピーは消えず、機密保持や解析不能を保証する機能ではありません。

This prototype changes paths in a separate source copy, not the maintained source, type names, or comments. It does not erase published history or existing copies and is not a confidentiality boundary.

## 対象と出力 / Scope and output

- `tools/New-ObfuscatedSource.ps1`: 許可リストの16個のC#ファイルをランダムなディレクトリ名・ファイル名へコピーします。アプリのプロジェクト名はコピー内だけ `Application.csproj` にします。XAMLとコードビハインド、アイコン参照、マニフェスト、LICENSEを保持します。
- `tools/New-ObfuscationConfig.ps1`: 将来のObfuscar評価用XMLだけを作ります。実行、ダウンロード、インストール、署名、梱包は行いません。候補エンジンのバージョン固定・安全確認と実機互換性試験は別工程です。
- `tests/Test-ObfuscationPreparation.ps1`: 内容保持、名前の変換、対応表の分離、上書き拒否、パス境界、除外設定を検査します。

The source copy contains only 24 reviewed inputs. The configuration generator does not run an obfuscation engine. Its XML is a candidate, not a verified binary-protection pipeline.

生成先は `obj/structure-obfuscation/<RunId>/` に限定します。`source/` はソースコピー、隣の `private/` は名前の対応表や絶対パスを含む非公開情報です。対応表の `complete: true` はコピー完了を示すだけで、製品テストや公開の承認ではありません。失敗したrunを自動削除・上書きせず、別のRunIdでやり直します。

Only `source/` is a source-copy candidate. Never publish its parent directory: sibling `private/` contains name maps and local absolute paths. Git ignore rules prevent accidental staging, not unauthorized reading. Keep both inside a trusted local workspace; path checks are not a sandbox against concurrent filesystem tampering.

`obj/` はGitと通常のSDKソース列挙から除外されます。通常ビルドを変更せず、変換を使わなければ元の構成のままです。変換後に `source/` 内でビルドした場合、その `bin/`・`obj/` も公開対象ではありません。

## ローカルでの利用 / Local use

PowerShell 7で実行します。生成物を既存ZIPやインストール先へコピーしないでください。

```powershell
$copy = ./tools/New-ObfuscatedSource.ps1
dotnet build (Join-Path $copy.SourceDirectory 'Application.csproj') -c Release -p:UseAppHost=false

# Supply existing local reference/runtime directories matching the application's .NET and WPF version.
./tools/New-ObfuscationConfig.ps1 -AssemblyPath '<absolute path to locally built PC Black Box.dll>' -ResolutionDirectory '<absolute .NET directory>', '<absolute WPF directory>'
./tests/Test-ObfuscationPreparation.ps1 -AssemblyPath '<absolute path to locally built PC Black Box.dll>'
```

ローカル検証では既存のSDK・NuGetキャッシュを使用します。キャッシュが不足した場合は無断で導入を広げず、その不足を報告します。`UseAppHost=false` は検証用EXEランチャーを作らないための指定で、ネイティブ化や難読化ではありません。

## バイナリ向け候補設定 / Candidate binary configuration

対象は自作の `PC Black Box.dll` だけです。`FileInspector` と `ShortcutInspector` の内部メンバーを候補とし、公開API、プロパティ、イベント、生成コードを保持します。入れ子型を含むその他の型はメンバーごと除外するため、WPF、JSON、P/Invoke、初期化と保護処理、新しい未審査の型を無断で変換しません。文字列隠蔽と追加のメソッド最適化は無効です。

The conservative allowlist targets the two parsers only. It preserves the public contract, properties/events, compiler-generated code, and all other types. Third-party DLL names and contents, license notices, runtime dependency metadata, and the application assembly name are not changed. This is not packing, assembly merging, or a single-file deployment.

設定は[Obfuscarの公式設定説明](https://docs.lextudio.com/obfuscar/getting-started/configuration)に基づき、絶対パスをXMLエスケープして生成します。XML構造や選択正規表現のテストは、実際のエンジンが同じ範囲を変換する証拠ではありません。エンジン採用時はバージョンを固定し、ソース・依存・インストール処理・hooks・CI・同梱バイナリ・認証・通信を確認してから実行します。

## 採用前の検証 / Gates before adoption

- 原本と構造変換コピーを同じSDKでビルドし、警告とエラーを確認する。
- 両方の `--security-status` と `--self-test` を実行し、終了コードと期待する結果を比較する。JSONと表示名は既存の自己テストに加え、難読化バイナリでも改めて照合する。
- 難読化後のメタデータを確認し、許可した名前は実際に変わり、除外した名前は残ることを検査する。対応表・PDB・原本が外向け成果物へ混入しないことを確認する。
- GUI禁止の環境では画面表示・操作とGUIを起動する境界テストは実行せず、未検証とする。
- 難読化は署名前に行う。既存の署名済みファイルを加工して署名が維持されるとは扱わず、将来の最終成果物は再検証する。

No binary transformation or GUI validation is implied by preparation tests. Local main and the existing preview ZIP come from different source revisions; this prototype must not be applied to that ZIP without a separate review and approval. Neither a new package nor a GitHub publication is part of this work.

## 今回の検証記録 / Verification record

確認日: 2026-09-17。ローカル作業ブランチは `agent/obfuscation-local-prototype`、起点は `6688179` です。GitHub APIで確認したmain `350ece0` と同じツリー `eb7a0bf3dbe0b177242bdea71b94ce19d2a8ea14` だったため、fetchやmainの更新はしていません。他の作業ツリーと未マージPRは変更していません。

- 構造変換と設定のテスト: 102項目を通過。24入力の内容一致、16ソースのパス変更、対応表の分離、再実行時の上書き拒否、ルートとサブフォルダー内の想定外C#ファイル、パス逸脱、代替データストリーム、junctionとUNCの拒否を確認。ドライブ種別の判定でNetwork・Unknown・NoRootDirectoryを拒否することも確認したが、実際のネットワークドライブ割当は行っていない。
- 原本と構造変換コピー: .NET SDK 10.0.300、既存ローカルNuGetキャッシュのみで復元・ビルド。両方とも警告0、エラー0。`UseAppHost=false` によりローカル検証用のマネージDLLを作成し、配布EXEやZIPは作成していない。
- 両方の `--security-status`: 終了コード0、`enforced=true controls=16/16`。追加保護は3/4で、`user-shadow-stack` は `unavailable`。全行が一致。
- 両方の `--self-test`: 終了コード0、`passed=true checks=93`。出力が一致。
- 構造変換コピーを生成した後も、原本の通常ビルドが成功。生成コピーが通常のコンパイル対象へ混入していないことを確認。
- PowerShell構文検査、差分の空白検査、Gitleaks検査を実施。PSScriptAnalyzerは未導入のため実行していない。ローカルキャッシュによる復元は、脆弱性データが最新であることの確認ではない。

テスト作成中に補助関数のスコープ漏れを修正しました。また、CLIから配列を渡す呼び出しで参照ディレクトリがSourceRootへ位置指定される問題を確認し、位置指定を禁止し、SourceRootに本体プロジェクトの存在を要求しました。誤った場所への作成はアクセス拒否され、その場所に `obj/` が存在しないことを確認しています。修正後のテストは上記のとおり通過しました。

独立レビューで、入れ子ファイルの見落とし、未審査の入れ子型への過剰な対象拡大、ネットワーク割当ドライブの検出不足を指摘され、検査と除外設定を修正しました。ドライブ種別はファイルにアクセスする前に調べ、固定ローカルドライブだけを許可します。

再レビューで3件の実装修正を確認した後、ルート直下と入れ子の拒否テストが互いに影響しないよう、別々の入力コピーに分離しました。この修正も独立した静的確認を受け、準備テスト102件を再実行して通過しています。レビュー担当は動作テストを再実行していません。

最終版でローカル検証したソースコピーは `obj/structure-obfuscation/test-bed153282d3648f0ba9913789bdb2529/source/`、.NET/WPF 10.0.8の参照先を指定した候補設定は `obj/structure-obfuscation/final-config-20260917/private/obfuscar.xml` です。それ以前のrunはテスト途中の記録であり、利用対象ではありません。設定やテスト用runを外部へ公開しないでください。

未実施: 難読化エンジンの採用・実行、難読化後バイナリの動作・メタデータ・性能検査、GUI操作、GUIを起動する境界テスト、別PCでの検証、配布署名と梱包、GitHubへの反映。今回の成功はソースの構造変換と設定準備に限ります。

Verified: source-copy and configuration preparation, both local builds, and headless baseline/self-test parity. Not verified: actual engine compatibility, binary obfuscation, GUI behavior, another PC, signing, or distribution. No installed application or existing release was replaced. To stop using the prototype, continue building the maintained project; no rollback of application sources is necessary.
