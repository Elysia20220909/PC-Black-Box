# StillLens

ファイルを動かさず、手掛かりを見る。

Inspect files without running or uploading them.

[English](README.en.md) / [公開済みプレビュー](https://github.com/Elysia20220909/PC-Black-Box/releases/tag/v0.13.0-preview.1) / [利用・配布条件](docs/distribution-status.md) / [セキュリティ方針](SECURITY.md)

StillLensは、PC Black Boxからの名称移行を準備しているWindows向けファイル検査ツールです。ダウンロードしたファイルを実行・アップロードせず、署名、入手元、実際の形式、注意すべき特徴をローカルで整理します。安全を断定するのではなく、判断の根拠と調べ切れなかった範囲を示します。

> 現在公開されているアプリ名はPC Black Boxです。リポジトリURL、EXE名、設定保存先はまだ変更していません。この文書と同じ改訂の本体には[独自の利用条件](LICENSE)を設定しています。非商用の個人利用と手元での改変を許可し、商用利用と有償・無償の再配布は禁止します。第三者コンポーネントは各自の条件に従います。公開済みZIPへの条件の適用とMicrosoft SDKコンポーネントの受領者同意は未解決です。ダウンロードできることを、一般配布の条件が整ったこととは扱いません。[現在の確認状況](docs/distribution-status.md)を先に確認してください。

## こんなときに

- ダウンロードしたファイルの署名と入手元を、開く前に確認したい。
- 拡張子と実際の形式が合っているか、ショートカットがどこを指しているか調べたい。
- ZIPの内容について、確認できた根拠と未調査の範囲を分けて読みたい。

ウイルス対策ソフト、動的サンドボックス、クラウド評価サービスの代替ではありません。`CLEAR`は安全保証ではなく、`COMPLETE`も対象が安全という意味ではありません。対象の実行、削除、隔離、修復は行いません。

## 公開済み版を確認する

[PC Black Box v0.13.0-preview.1](https://github.com/Elysia20220909/PC-Black-Box/releases/tag/v0.13.0-preview.1)に、次のファイルがあります。

- `PC-Black-Box-v0.13.0-preview.1-win-x64.zip`
- `PC-Black-Box-v0.13.0-preview.1-win-x64.zip.sha256`

利用許諾を確認済みの試用者向けの手順です。この説明によって新しい利用許諾を設定するものではありません。

### 必要な環境

- [.NET 10がサポートするWindows](https://learn.microsoft.com/ja-jp/dotnet/core/install/windows#supported-versions)のx64環境。Windows 10は対象のLTSC / Enterprise版に限られます。
- 更新済みの[x64版 .NET 10 Desktop Runtime](https://dotnet.microsoft.com/download/dotnet/10.0)。ZIPにはランタイムを含みません。実行だけならSDKは不要です。
- アプリは通常権限で使用します。管理者としての起動は拒否されます。

### 確認してから起動する

- ZIPとSHA-256ファイルを取得し、ZIPのハッシュを照合します。ファイル名を付け替えていない場合は、保存先で次のコマンドを使えます。

  ~~~powershell
  Get-FileHash -LiteralPath '.\PC-Black-Box-v0.13.0-preview.1-win-x64.zip' -Algorithm SHA256
  Get-Content -LiteralPath '.\PC-Black-Box-v0.13.0-preview.1-win-x64.zip.sha256'
  ~~~

- ZIP全体を展開し、EXEとDLL、説明書、ライセンス文書を一緒に保ちます。EXEだけを取り出さないでください。
- 同梱READMEと第三者ライセンス文書を確認し、`PC Black Box.exe`を通常権限で起動します。

EXEと本体DLLは自己署名の開発者証明書で署名されています。ハッシュ一致は検証対象と同じファイルであることを確認するもので、安全性や発行者の信頼を保証しません。別PCでの信頼やSmartScreen警告の解消も保証しません。警告を消すためだけに証明書を信頼ストアへ登録したり、Windowsの保護機能を無効にしたりしないでください。

## 基本操作

- ファイルまたはフォルダーを選び、`調査開始`を押します。
- `概要`で指摘と完全性を確認し、`ファイル`で根拠を読みます。
- 必要に応じて`レポート`からMarkdown / JSONをローカルへ保存します。停止は`Esc`です。

`JA / EN`で表示言語を切り替えられます。設定保存先は引き続き`%LOCALAPPDATA%\PCBlackBox\settings.json`です。[ショートカットと操作の詳細](docs/reference-main.md#基本操作)も参照してください。

対象やレポートを自動送信しません。ただし、レポートにはファイル名、入手元ホスト、ハッシュ、対象内の文字列が含まれます。共有前に内容を確認してください。照会URLを別途ブラウザーで開けば、ハッシュが外部サービスへ送られます。クリップボード履歴や同期もWindowsの設定に従います。

## ソースとプレビューの違い

2026-09-10に確認した対応です。今後の更新時には、タグとコミットを確認してください。

| 対象 | 基になるコミット | 注意点 |
|---|---|---|
| この文書変更のベースとなるmain 0.12.0 | `2278b0f` | OLE内部のストレージ木は解析しません。[技術リファレンス](docs/reference-main.md)はこの版の説明です |
| PC Black Box 0.13.0-preview.1 | `831eb7f` | PR #19のコミットから作成。mainへは未マージです。[この版のソース](https://github.com/Elysia20220909/PC-Black-Box/tree/831eb7fba4e2c7eb0a434d5e3a2240a0ee3a0c97)を参照してください |

プレビュー作成時には、展開後DLLの自己テスト111件、必須保護16/16、実行時境界9件を確認しました。これは指定したプレビューの当該端末での結果であり、mainや別PCの合格を示すものではありません。GUI操作と別PCでの起動は未確認です。

## 開発する人へ

本体の利用・変更条件を確認したうえで、ソースと依存関係をレビューしてからビルドしてください。必要なのは[Git](https://git-scm.com/downloads)と[.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)です。次はmainを取得する手順で、公開済みプレビューを再現する手順ではありません。

~~~powershell
git clone --branch main https://github.com/Elysia20220909/PC-Black-Box.git
cd PC-Black-Box
dotnet restore .\Destiny2BlackBox.csproj
dotnet build .\Destiny2BlackBox.csproj -c Release --no-restore
~~~

公開リポジトリの取得にGitHubへのログインは不要です。`dotnet restore`は依存関係の取得と脆弱性情報の確認に通信します。アプリによる対象ファイルのアップロードとは別です。

検証、CLIレポート生成、GUI禁止時に実行できないテストは、[変更提案の手順](CONTRIBUTING.md)と[開発・検証リファレンス](docs/reference-main.md#開発と検証)にまとめています。ローカルビルドは配布物やインストール済みアプリを置き換えません。

## フィードバックと資料

試用・一般の不具合の連絡先: [ChloeFlora23047120947120@protonmail.com](mailto:ChloeFlora23047120947120@protonmail.com)。初回はバージョン、Windowsの版、症状と再現手順だけを送り、実際の調査対象、未編集のレポート、認証情報、個人パスは添付しないでください。メールの到達性は未確認で、返信時期は保証しません。

2026-09-10時点ではIssues、Discussions、GitHubの非公開脆弱性報告機能は無効です。脆弱性は公開せず、[SECURITY.md](SECURITY.md)に従い、詳細を送る前に安全な受け渡し方法を確認してください。

- [利用・配布条件の確認状況](docs/distribution-status.md)
- [操作・検査範囲・上限のリファレンス](docs/reference-main.md)
- [変更履歴](CHANGELOG.md) / [脅威モデル](THREAT_MODEL.md)
- [変更提案](CONTRIBUTING.md) / [共同作業ルール](AGENTS.md)

名称移行だけで、既存の検査能力・安全境界・利用許諾は変わりません。ソースのコミットには実行ファイル、配布ZIP、署名鍵、個人設定、生成レポートを含めません。
