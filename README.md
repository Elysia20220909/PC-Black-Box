# PC Black Box

PC Black Boxは、ダウンロードしたファイルやフォルダーをWindows上で調べる静的調査ツールです。

対象を起動せず、SHA-256、電子署名、入手元、実際のファイル形式、スクリプトやZIP内部の注意点を確認します。画面は日本語と英語に対応しています。

## セットアップ

必要なものは次のとおりです。

- Windows 10またはWindows 11
- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)
- この非公開リポジトリへのアクセス権
- GitHub CLI

PowerShellで次のコマンドを実行します。

```powershell
gh auth login
gh repo clone Elysia20220909/PC-Black-Box
cd PC-Black-Box
dotnet restore
dotnet run --project .\Destiny2BlackBox.csproj
```

すでにGitHubへログインしている場合、`gh auth login`は不要です。

## 使い方

- ファイルまたはフォルダーを画面へドロップします。選択ボタンも使えます。
- `調査開始`を押します。
- `概要`で判定、`ファイル`で個別情報、`レポート`で保存用の文章を確認します。
- `JA / EN`で表示言語を切り替えます。

## 判定の見方

`CLEAR / LOW / REVIEW / HIGH`は確認の優先度です。マルウェア判定や安全保証ではありません。

`REVIEW`や`HIGH`が表示された場合は、電子署名、入手元、想定した用途、Windows Defenderの結果も合わせて確認してください。

## 安全とプライバシー

- 対象を起動しません。
- ファイルをアップロードしません。
- 自動通信、メモリ読み取り、パケット取得を行いません。
- ファイルの削除、隔離、修復を行いません。
- レポートには絶対パス、ユーザー名、IPアドレス、Steam ID、認証情報を残しません。

VirusTotalのハッシュ照会を選んだ場合だけ、確認後にブラウザーを開きます。送信されるのはSHA-256を含むURLで、ファイル本体ではありません。

## 開発用コマンド

ビルドのみ行う場合はこちらです。

```powershell
dotnet build .\Destiny2BlackBox.csproj -c Release
```

画面を開かずにMarkdownレポートを作ることもできます。

```powershell
dotnet ".\bin\Release\net10.0-windows10.0.17763.0\PC Black Box.dll" --report "C:\path\to\target" ".\report.md"
```

## リポジトリ方針

このリポジトリは非公開で、ソースコードだけを管理します。EXE、インストーラー、配布ZIP、署名鍵、ローカル設定、パケットキャプチャ、生成レポートは登録または配布しません。
