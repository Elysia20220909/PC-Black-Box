# Microsoft Defenderの読み取り専用連携

この機能は、このPCのMicrosoft Defenderが保持する保護状態と既存の検出・対処履歴を表示します。新しいスキャンや隔離を開始する機能ではありません。R.A.B.I.D.S.など架空の存在を検出するものでもありません。

## 使い方

画面のDEFENDERページで「状態・履歴を取得」を押します。起動時やファイル検査時には自動照会しません。既存のファイル評価・Markdown/JSON検査レポートには結果を混ぜません。

GUIを開かずに確認する場合は、通常権限でローカルビルドを実行します。

```powershell
dotnet 'bin/Release/net10.0-windows10.0.17763.0/PC Black Box.dll' --defender-status
```

標準出力はDefender専用JSON、標準エラーはアプリの保護状態です。終了コード0は両照会の取得完了を示すだけで、安全や感染なしを意味しません。1は取得不完全・利用不可・保護確認の失敗です。追加引数は受け付けません。

## 読み方とプライバシー

- 保護状態ではサービス、ウイルス対策、リアルタイム保護、定義更新時刻を表示します。欠落値は無効と決めつけず不明にします。
- 履歴は脅威ID、検出・状態更新時刻、Defenderの状態コード、対処成功の記録、追加対処フラグだけです。パス、ユーザー名、端末ID、プロセス名、検出ID、自由記述の例外は取得・出力しません。
- `quarantined` はDefenderに残っている記録です。現在も隔離庫に存在することや、PC全体の安全を保証しません。追加対処フラグはWindowsの数値を保持し、未対応の状態コードは `unknown` とします。
- 履歴0件は感染なしの証明ではありません。権限不足、Defenderが利用できない場合、取得失敗、部分取得、時間切れを区別します。
- 最大256件をWindowsの列挙順で取得します。最新256件とは限りません。上限を超えた履歴は一部取得として表示します。取得中の状態変化もあり、原子的なスナップショットではありません。
- この機能はローカル状態の照会だけです。Defender自身のクラウド通信、自動保護、自動送信はWindows側の設定に従い、本機能では変更しません。Defenderを含むPC全体が完全オフラインになるという意味ではありません。

## 実装境界

C#からWindowsのWMI COM APIへ接続し、`ROOT\Microsoft\Windows\Defender` の2クラスだけを固定の `SELECT` で読みます。ホスト、クラス、クエリ、資格情報を利用者が指定する機能はありません。新しいNuGet依存は追加しません。

`MSFT_MpComputerStatus` と `MSFT_MpThreatDetection` の取得以外に、メソッド実行、書き込み、購読、リモート接続、PowerShell・MpCmdRunの起動はありません。管理者起動拒否、子プロセス禁止、ネットワーク制御、プロセスDACLなど既存の必須保護は維持します。

全照会の協調的な予算は8秒、列挙の待機は1回200ミリ秒です。画面とCLIには約10秒で時間切れを返します。開始済みのCOM処理は強制中断しません。接続にはWindowsの最大待機指定を使いますが、OS・プロバイダー内部の停止を本アプリが保証するものではありません。未終了の処理がある間は次の更新を `Busy` とし、バックグラウンド処理を増殖させません。保護制御を緩めるフォールバックや権限昇格はありません。

WindowsのWMIプロバイダーとCOM登録は信頼するOS境界です。管理者やOS自体の侵害に対する保証ではありません。新しいスキャン、削除・隔離・復元、設定変更、自動更新は別途承認が必要で、この段階には含みません。

## 検証と復元

専用ブランチ `agent/defender-readonly` は `adff137` を基点とします。前回の難読化ツリーと既存の署名済みEXEは変更しません。このツリーの `bin/Release` にあるDLLだけが本変更の検証対象です。旧版へ戻るときは前のツリーを利用できます。配布、コミット、push、mergeは今回行いません。

自己テストは合成データで欠落・不正値・上限・失敗・タイムアウト・同時要求・機微情報の非出力を検証します。通常の自己テストではDefenderへ接続せず、ウイルスやEICARも作りません。実接続は `--defender-status` を明示して別に検証します。

GUIの見た目と操作、別PC、無効化されたDefenderや企業管理下での実動作は別の検証です。成功した範囲は以下の検証記録に追記します。

## 公式資料

- [保護状態のクラス](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/defender/msft-mpcomputerstatus)
- [検出・対処履歴のクラス](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/defender/msft-mpthreatdetection)
- [WMIの読み取りクエリ](https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-execquery)
- [列挙の待機と終了条件](https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-ienumwbemclassobject-next)
- [接続の最大待機指定](https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemlocator-connectserver)
