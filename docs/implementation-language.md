# 実装言語の方針 / Implementation language decision

決定日: 2026-09-12。開発ルールは[AGENTS.md](../AGENTS.md)を正典とし、この文書は判断理由と将来の検討条件を記録します。

Decision date: 2026-09-12. [AGENTS.md](../AGENTS.md) is the authoritative working policy; this document records the rationale and criteria for future changes.

## C#で保守を続ける / Keep development in C#

画面、ファイルアクセス、検査の制御、解析、結果モデル、レポートをC# / .NETで保守します。WPFのXAML、既存のWindows API呼び出し、開発・検証用PowerShellは継続します。「C#を継続する」は、それらの削除や書き換えを意味しません。

Maintain the UI, file access, inspection orchestration, parsing, result models, and reporting in C# / .NET. Keep WPF XAML, existing Windows API interop, and development/test PowerShell. This decision does not require replacing those supporting technologies.

言語を追加する前に、C#内で責務を整理し、必要に応じてアルゴリズム、割り当て、読み取り量を改善します。将来のRustを想定するだけの空のインターフェース、プラグイン機構、DLLローダーは追加しません。

Organize responsibilities in C# and improve algorithms, allocations, or read volume where evidence justifies it. Do not add placeholder interfaces, plugin infrastructure, or a DLL loader solely for a possible Rust implementation.

## 現在の責務の入口 / Current responsibility entry points

確認したソースはmainの `adee10d92a481516d271cb06261eec20582aa448` です。以下は既存の入口であり、完全な層分離が実装済みという意味ではありません。

The source inspected was main at `adee10d92a481516d271cb06261eec20582aa448`. These are existing entry points, not a claim that fully separated layers already exist.

| 責務 / Responsibility | 既存の入口 / Existing entry points |
|---|---|
| 画面と操作 / UI and interaction | [MainWindow.xaml.cs](../MainWindow.xaml.cs), [MainWindow.xaml](../MainWindow.xaml) |
| 読み取りと入力制限 / Reading and input constraints | [SecureFileReader.cs](../SecureFileReader.cs), [SecurityPolicy.cs](../SecurityPolicy.cs) |
| 検査の進行と解析 / Orchestration and parsing | [FileInspector.cs](../FileInspector.cs), [ShortcutInspector.cs](../ShortcutInspector.cs) |
| 結果と未検査部分 / Results and incomplete inspection | [Models.cs](../Models.cs) |
| レポートと保存 / Reporting and output | [ReportBuilder.cs](../ReportBuilder.cs), [SafeReportWriter.cs](../SafeReportWriter.cs) |
| Windows側の保護 / Windows protections | [WindowsProcessHardening.cs](../WindowsProcessHardening.cs), [AssemblySecurity.cs](../AssemblySecurity.cs) |

## Rustを検討する条件 / When to consider Rust

性能を理由にする場合は、代表的な合成入力で処理時間・メモリ使用量・読み取り量を計測し、対象解析がボトルネックであることを確認します。複雑な形式の解析を理由にする場合は、必要な仕様・異常入力への対応と、候補実装の具体的な利点を示します。今回は性能計測もRustとの比較も行っていません。

For performance-driven changes, measure elapsed time, memory use, and read volume on representative synthetic inputs and establish that the selected parser is a bottleneck. For complex formats, identify the required behavior, malformed-input handling, and concrete advantages of the candidate implementation. No benchmark or Rust comparison was performed for this decision.

採用提案には、C#を改善した場合との比較、対象の小さな解析範囲、依存関係、ライセンス、ビルド・保守コストを含めます。必要性と利点を確認したうえで実装範囲を決めます。この方針だけでRust導入や配布物の変更を決定しません。

A proposal must compare improving C# with the candidate approach and describe the bounded parser scope, dependencies, licenses, and build/maintenance cost. Agree on implementation scope after establishing the benefit. This decision alone does not approve introducing Rust or changing release artifacts.

## 将来のDLL境界 / Future DLL boundary

Rustを採用する場合も、ファイルアクセスとアプリ全体の制御はC#側に残します。小さなC ABIを通して、C#が検証して読み取ったサイズ制限付きバイト列を渡し、構造化した解析結果を受け取る設計を基本とします。ファイルパスや任意のファイルハンドルを渡す設計にはしません。

Keep file access and application control in C#. Use a small C ABI to pass bounded bytes read through the C# validation path and return structured parsing results, rather than exposing file paths or arbitrary file handles.

入力長、出力容量、メモリ所有権と解放方法、文字コード、整数幅、構造体配置、ABIの版を明示します。呼び出し終了後に入力ポインターを保持しない設計とし、FFI境界での未定義動作を防ぎます。[.NET native interop guidance](https://learn.microsoft.com/en-us/dotnet/standard/native-interop/best-practices)

Specify input lengths, output capacity, allocation ownership and release, encoding, integer widths, structure layout, and ABI version. Do not retain borrowed input pointers after a call returns. Check both sides of the boundary for undefined behavior.

Rustのpanicや例外をFFI境界越しに伝播させず、想定する解析エラーは明示した状態として返します。ただし、panicの捕捉ですべてのクラッシュやメモリ不足を回復できるとは扱いません。[Rust FFI guidance](https://doc.rust-lang.org/nomicon/ffi.html)

Do not allow Rust panics or exceptions to propagate across the FFI boundary. Return expected parse errors as explicit statuses. Catching panics is not a recovery mechanism for every crash or allocation failure.

同一プロセスのDLLはセキュリティ上の隔離ではありません。DLLはプロセスと同じ権限で動作し、障害はアプリ全体に影響し得ます。既存のDLL探索制限やプロセス保護との整合を確認し、任意の場所からのロードを許可しません。

An in-process DLL is not a security isolation boundary. It runs with the process's authority and can affect the whole application. Review compatibility with existing DLL search restrictions and process protections; do not permit loading from arbitrary locations.

入力サイズ、項目数、再帰深度、出力サイズの上限を引き継ぎます。キャンセルと時間制限は解析内部で実装する必要があり、C#側の待機タイムアウトだけで実行中のネイティブ処理が停止したとは扱いません。

Preserve limits on input size, item count, recursion depth, and output size. Cancellation and time budgets need cooperation inside the parser; a timeout while waiting in C# does not establish that a native call has stopped.

## 将来の採用前に確認すること / Evidence before adoption

- 正常・破損・切り詰め・上限超過の合成入力で、結果と未検査部分を確認する。
- C#実装または独立した期待結果と照合し、異常終了を安全判定に変換しない。
- ネイティブ呼び出しやコピーの負担を含めて性能・メモリを比較する。
- ABI不一致、DLL欠落、キャンセル、資源上限、メモリ解放を確認する。
- 新しい依存関係、署名・配布条件、検証手順を確認する。

- Check valid, malformed, truncated, and over-budget synthetic inputs, including incomplete-inspection results.
- Compare against C# or independently established expected results; never convert parser failure into a safe verdict.
- Include interop and copying overhead in performance and memory comparisons.
- Verify ABI mismatch, missing DLLs, cancellation, resource bounds, and allocation cleanup.
- Review new dependencies, signing/distribution conditions, and verification procedures.

本決定は文書上の方針です。アプリの動作・速度・安全性を変更または実測したものではありません。[THREAT_MODEL.md](../THREAT_MODEL.md)に記載された保護と検証の境界を維持します。

This is an implementation policy, not a measured change to application behavior, performance, or security. Preserve the protection and verification boundaries in [THREAT_MODEL.md](../THREAT_MODEL.md).
