using Microsoft.Win32;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace DestinyBlackBox;

public partial class MainWindow : Window
{
    private readonly FileInspector _inspector = new();
    private string? _selectedPath;
    private ScanResult? _result;
    private CancellationTokenSource? _scanCancellation;
    private string _language;

    private bool IsJapanese => _language == "ja";

    public MainWindow()
    {
        InitializeComponent();
        _language = SettingsStore.LoadLanguage();
        ApplyLanguage();
        ShowPage(OverviewPage, OverviewNav);
    }

    private void SelectFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = IsJapanese ? "調査するファイルを選択" : "Select a file to inspect",
            CheckFileExists = true,
            Multiselect = false,
            Filter = "All files (*.*)|*.*"
        };
        if (dialog.ShowDialog(this) == true)
        {
            SelectTarget(dialog.FileName);
        }
    }

    private void SelectFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog
        {
            Title = IsJapanese ? "調査するフォルダーを選択" : "Select a folder to inspect",
            Multiselect = false
        };
        if (dialog.ShowDialog(this) == true)
        {
            SelectTarget(dialog.FolderName);
        }
    }

    private void SelectTarget(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return;
        _selectedPath = Path.GetFullPath(path);
        TargetHeaderText.Text = File.Exists(path)
            ? (IsJapanese ? "ファイルを調査します" : "FILE READY FOR INSPECTION")
            : (IsJapanese ? "フォルダーを調査します" : "FOLDER READY FOR INSPECTION");
        TargetPathText.Text = _selectedPath;
        TargetPathText.ToolTip = _selectedPath;
        InspectButton.IsEnabled = true;
        ProgressText.Text = IsJapanese ? "準備完了 — 対象は実行しません" : "Ready — the target will not be executed";
        AssessmentText.Text = "READY";
        VerdictText.Text = IsJapanese
            ? "静的な兆候を確認します。調査結果は安全性の保証ではなく、確認順序を示すものです。"
            : "Static indicators will be inspected. The result prioritizes review; it does not guarantee safety.";
    }

    private async void Inspect_Click(object sender, RoutedEventArgs e)
    {
        if (_selectedPath is null || (!File.Exists(_selectedPath) && !Directory.Exists(_selectedPath)))
        {
            ProgressText.Text = IsJapanese ? "対象が見つかりません。選び直してください。" : "The target no longer exists. Select it again.";
            return;
        }

        _scanCancellation?.Dispose();
        _scanCancellation = new CancellationTokenSource();
        SetBusy(true);
        ScanProgressBar.Value = 0;
        AssessmentText.Text = "SCANNING";
        VerdictText.Text = IsJapanese ? "実行せずに読み取り調査中です。少しだけお待ちください。" : "Reading the target without executing it. Please wait.";
        FindingsPanel.Children.Clear();

        var progress = new Progress<ScanProgress>(value =>
        {
            double percent = value.Total == 0 ? 0 : value.Completed / (double)value.Total * 100d;
            ScanProgressBar.Value = percent;
            ProgressText.Text = value.Total == 0
                ? (IsJapanese ? "対象を整理しています…" : "Enumerating the target…")
                : $"{value.Completed}/{value.Total}  {value.CurrentFile}";
        });

        try
        {
            _result = await _inspector.ScanAsync(_selectedPath, progress, _scanCancellation.Token);
            ShowResult(_result);
        }
        catch (OperationCanceledException)
        {
            ProgressText.Text = IsJapanese ? "調査を停止しました。変更は行っていません。" : "Inspection cancelled. No changes were made.";
            AssessmentText.Text = "CANCELLED";
            VerdictText.Text = IsJapanese ? "途中結果は保存していません。" : "Partial results were not retained.";
        }
        catch (Exception ex)
        {
            ProgressText.Text = IsJapanese ? "調査を完了できませんでした。" : "Inspection could not be completed.";
            AssessmentText.Text = "ERROR";
            AssessmentText.Foreground = (Brush)FindResource("DangerBrush");
            VerdictText.Text = ex.Message;
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => _scanCancellation?.Cancel();

    private void SetBusy(bool busy)
    {
        InspectButton.IsEnabled = !busy && _selectedPath is not null;
        SelectFileButton.IsEnabled = !busy;
        SelectFolderButton.IsEnabled = !busy;
        CancelButton.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
    }

    private void ShowResult(ScanResult result)
    {
        RiskValue.Text = $"{result.RiskCode} {result.RiskScore}";
        RiskValue.Foreground = RiskBrush(result.RiskScore);
        FilesValue.Text = result.Files.Count.ToString();
        ActiveValue.Text = result.ActiveContentCount.ToString();
        SignedValue.Text = result.SignedCount.ToString();
        TimeValue.Text = $"{result.Duration.TotalSeconds:F1}s";
        ScanProgressBar.Value = 100;
        ProgressText.Text = result.IsPartial
            ? (IsJapanese ? $"部分調査: {result.PartialReason}" : $"Partial inspection: {result.PartialReason}")
            : (IsJapanese ? "調査完了 — ファイルは実行・変更されていません" : "Inspection complete — no file was executed or modified");
        AssessmentText.Text = $"{result.RiskCode} / {result.RiskScore}";
        AssessmentText.Foreground = RiskBrush(result.RiskScore);
        VerdictText.Text = BuildVerdict(result);

        List<(FileAnalysis File, Indicator Indicator)> findings = result.Files
            .SelectMany(file => file.Indicators.Select(indicator => (file, indicator)))
            .OrderByDescending(item => item.indicator.Score)
            .ThenBy(item => item.file.RelativePath, StringComparer.OrdinalIgnoreCase)
            .Take(25)
            .Select(item => (item.file, item.indicator))
            .ToList();
        PopulateFindings(findings);

        FileGrid.ItemsSource = result.Files.OrderByDescending(file => file.RiskScore).ThenBy(file => file.RelativePath, StringComparer.OrdinalIgnoreCase).ToList();
        if (FileGrid.Items.Count > 0) FileGrid.SelectedIndex = 0;

        ReportPreviewText.Text = ReportBuilder.Build(result, _language);
        CopyReportButton.IsEnabled = true;
        SaveMarkdownButton.IsEnabled = true;
        SaveJsonButton.IsEnabled = true;
    }

    private string BuildVerdict(ScanResult result)
    {
        if (result.RiskScore >= 60)
        {
            return IsJapanese
                ? "優先して確認すべき強い指標があります。隔離・削除は自動では行っていません。実行せず、所見を確認してください。"
                : "Strong indicators require priority review. Nothing was quarantined or deleted; keep the target closed and review the evidence.";
        }
        if (result.RiskScore >= 25)
        {
            return IsJapanese
                ? "追加確認が必要な指標があります。署名、入手元、処理能力を確認してから実行を判断してください。"
                : "Some indicators need additional review. Check the signature, source, and capabilities before deciding whether to run it.";
        }
        return IsJapanese
            ? "明白な強い指標は見つかりませんでした。ただし、静的調査だけで安全を保証することはできません。"
            : "No obvious strong indicator was found. Static inspection alone cannot guarantee safety.";
    }

    private void PopulateFindings(List<(FileAnalysis File, Indicator Indicator)> findings)
    {
        FindingsPanel.Children.Clear();
        if (findings.Count == 0)
        {
            FindingsPanel.Children.Add(CreateFindingCard("good", IsJapanese ? "明白な指標なし" : "NO OBVIOUS INDICATOR", IsJapanese ? "静的調査の範囲では、優先警告はありません。" : "No priority warning was found within the static inspection scope."));
            return;
        }

        foreach ((FileAnalysis file, Indicator indicator) in findings)
        {
            string message = IsJapanese ? indicator.Japanese : indicator.English;
            FindingsPanel.Children.Add(CreateFindingCard(indicator.Severity, file.RelativePath, $"{message}  +{indicator.Score}"));
        }
    }

    private UIElement CreateFindingCard(string severity, string title, string detail)
    {
        Brush color = severity switch
        {
            "danger" => (Brush)FindResource("DangerBrush"),
            "watch" => (Brush)FindResource("WarnBrush"),
            "good" => (Brush)FindResource("GoodBrush"),
            _ => (Brush)FindResource("InfoBrush")
        };
        var card = new Border
        {
            Background = new SolidColorBrush(Color.FromArgb(18, 255, 255, 255)),
            BorderBrush = new SolidColorBrush(Color.FromArgb(50, 255, 255, 255)),
            BorderThickness = new Thickness(1),
            Padding = new Thickness(10),
            Margin = new Thickness(0, 0, 0, 8),
            CornerRadius = new CornerRadius(2)
        };
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(4) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.Children.Add(new Border { Background = color, CornerRadius = new CornerRadius(2) });
        var stack = new StackPanel { Margin = new Thickness(10, 0, 0, 0) };
        Grid.SetColumn(stack, 1);
        stack.Children.Add(new TextBlock { Text = title, FontSize = 10.5, FontWeight = FontWeights.SemiBold, TextTrimming = TextTrimming.CharacterEllipsis, ToolTip = title });
        stack.Children.Add(new TextBlock { Text = detail, Foreground = (Brush)FindResource("MutedBrush"), FontSize = 10, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 4, 0, 0) });
        grid.Children.Add(stack);
        card.Child = grid;
        return card;
    }

    private void FileGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (FileGrid.SelectedItem is not FileAnalysis file)
        {
            CopyHashButton.IsEnabled = false;
            HashLookupButton.IsEnabled = false;
            return;
        }

        var details = new StringBuilder();
        details.AppendLine(file.RelativePath);
        details.AppendLine($"TYPE       {file.FileType}  |  {file.Architecture}");
        details.AppendLine($"SIZE       {file.SizeText}");
        details.AppendLine($"SHA-256    {file.Sha256}");
        details.AppendLine($"SIGNATURE  {file.SignatureStatus}");
        if (file.Signer != "—") details.AppendLine($"SIGNER     {file.Signer}");
        details.AppendLine($"ENTROPY    {file.EntropyText}");
        details.AppendLine($"ZONE       {(file.InternetZone?.ToString() ?? "—")}  |  SOURCE {file.SourceHost}");
        if (file.ArchiveEntries > 0) details.AppendLine($"ARCHIVE    {file.ArchiveEntries} entries");
        if (file.Indicators.Count > 0)
        {
            details.AppendLine();
            foreach (Indicator indicator in file.Indicators.OrderByDescending(value => value.Score))
            {
                details.AppendLine($"[{indicator.Severity.ToUpperInvariant()} +{indicator.Score}] {(IsJapanese ? indicator.Japanese : indicator.English)}");
            }
        }
        FileDetailText.Text = details.ToString();
        CopyHashButton.IsEnabled = !String.IsNullOrWhiteSpace(file.Sha256);
        HashLookupButton.IsEnabled = !String.IsNullOrWhiteSpace(file.Sha256);
    }

    private void CopyHash_Click(object sender, RoutedEventArgs e)
    {
        if (FileGrid.SelectedItem is FileAnalysis file && !String.IsNullOrWhiteSpace(file.Sha256))
        {
            Clipboard.SetText(file.Sha256);
            ProgressText.Text = IsJapanese ? "SHA-256をコピーしました" : "SHA-256 copied";
        }
    }

    private void HashLookup_Click(object sender, RoutedEventArgs e)
    {
        if (FileGrid.SelectedItem is not FileAnalysis file || String.IsNullOrWhiteSpace(file.Sha256)) return;
        string prompt = IsJapanese
            ? "VirusTotalをブラウザーで開きます。ファイル本体は送信せず、SHA-256ハッシュだけをURLで照会します。続けますか？"
            : "Open VirusTotal in your browser? The file will not be uploaded; only its SHA-256 hash is included in the URL.";
        if (MessageBox.Show(this, prompt, "PC Black Box", MessageBoxButton.YesNo, MessageBoxImage.Information) != MessageBoxResult.Yes) return;
        Process.Start(new ProcessStartInfo($"https://www.virustotal.com/gui/file/{file.Sha256}") { UseShellExecute = true });
    }

    private void CopyReport_Click(object sender, RoutedEventArgs e)
    {
        if (_result is null) return;
        Clipboard.SetText(ReportBuilder.Build(_result, _language));
        ProgressText.Text = IsJapanese ? "レポートをコピーしました" : "Report copied";
    }

    private void SaveMarkdown_Click(object sender, RoutedEventArgs e)
    {
        if (_result is null) return;
        var dialog = new SaveFileDialog
        {
            Title = IsJapanese ? "Markdownレポートを保存" : "Save Markdown report",
            Filter = "Markdown (*.md)|*.md",
            FileName = $"pc-black-box-{DateTime.Now:yyyyMMdd-HHmmss}.md",
            AddExtension = true
        };
        if (dialog.ShowDialog(this) == true)
        {
            File.WriteAllText(dialog.FileName, ReportBuilder.Build(_result, _language), new UTF8Encoding(false));
            ProgressText.Text = IsJapanese ? "Markdownレポートを保存しました" : "Markdown report saved";
        }
    }

    private void SaveJson_Click(object sender, RoutedEventArgs e)
    {
        if (_result is null) return;
        var dialog = new SaveFileDialog
        {
            Title = IsJapanese ? "JSONレポートを保存" : "Save JSON report",
            Filter = "JSON (*.json)|*.json",
            FileName = $"pc-black-box-{DateTime.Now:yyyyMMdd-HHmmss}.json",
            AddExtension = true
        };
        if (dialog.ShowDialog(this) == true)
        {
            File.WriteAllText(dialog.FileName, ReportBuilder.BuildJson(_result, _language), new UTF8Encoding(false));
            ProgressText.Text = IsJapanese ? "JSONレポートを保存しました" : "JSON report saved";
        }
    }

    private void Window_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private void Window_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is string[] paths && paths.Length > 0)
        {
            SelectTarget(paths[0]);
        }
    }

    private void OverviewNav_Click(object sender, RoutedEventArgs e) => ShowPage(OverviewPage, OverviewNav);
    private void FilesNav_Click(object sender, RoutedEventArgs e) => ShowPage(FilesPage, FilesNav);
    private void ReportNav_Click(object sender, RoutedEventArgs e) => ShowPage(ReportPage, ReportNav);

    private void ShowPage(UIElement page, Button nav)
    {
        OverviewPage.Visibility = Visibility.Collapsed;
        FilesPage.Visibility = Visibility.Collapsed;
        ReportPage.Visibility = Visibility.Collapsed;
        OverviewNav.Tag = null;
        FilesNav.Tag = null;
        ReportNav.Tag = null;
        page.Visibility = Visibility.Visible;
        nav.Tag = "active";
    }

    private void Language_Click(object sender, RoutedEventArgs e)
    {
        _language = IsJapanese ? "en" : "ja";
        SettingsStore.SaveLanguage(_language);
        ApplyLanguage();
        if (_result is not null) ShowResult(_result);
    }

    private void ApplyLanguage()
    {
        bool ja = IsJapanese;
        ReadOnlyBadgeText.Text = ja ? "読み取り専用" : "READ ONLY";
        OverviewNav.Content = ja ? "概要" : "OVERVIEW";
        FilesNav.Content = ja ? "ファイル" : "FILES";
        ReportNav.Content = ja ? "レポート" : "REPORT";
        SelectFileButton.Content = ja ? "ファイルを選ぶ" : "SELECT FILE";
        SelectFolderButton.Content = ja ? "フォルダーを選ぶ" : "SELECT FOLDER";
        InspectButton.Content = ja ? "調査開始" : "INSPECT";
        CancelButton.Content = ja ? "停止" : "CANCEL";
        RiskLabel.Text = ja ? "リスク" : "RISK";
        FilesLabel.Text = ja ? "ファイル" : "FILES";
        ActiveLabel.Text = ja ? "実行要素" : "ACTIVE";
        SignedLabel.Text = ja ? "署名有効" : "SIGNED";
        TimeLabel.Text = ja ? "時間" : "TIME";
        FindingsTitleText.Text = ja ? "主な所見" : "KEY FINDINGS";
        ScopeTitleText.Text = ja ? "調査するもの" : "INSPECTION SCOPE";
        ScopeBodyText.Text = ja
            ? "SHA-256 / Authenticode署名 / Internet Zone / 入手元ホスト / 実ファイル形式 / 拡張子偽装 / エントロピー / スクリプト能力 / ZIP内部構造\n\n実行・アップロード・パケット取得・メモリ読取は行いません。"
            : "SHA-256 / Authenticode / Internet Zone / source host / true file format / extension mismatch / entropy / script capabilities / ZIP structure\n\nNo execution, upload, packet capture, or memory read.";
        CopyHashButton.Content = ja ? "SHA-256をコピー" : "COPY SHA-256";
        HashLookupButton.Content = ja ? "ハッシュ照会を開く" : "OPEN HASH LOOKUP";
        ReportTitleText.Text = ja ? "匿名化された調査レポート" : "SANITIZED INSPECTION REPORT";
        CopyReportButton.Content = ja ? "コピー" : "COPY";
        SaveMarkdownButton.Content = ja ? "Markdown保存" : "SAVE MARKDOWN";
        SaveJsonButton.Content = ja ? "JSON保存" : "SAVE JSON";
        PrivacyFooterText.Text = ja ? "ローカルのみ • 実行なし • アップロードなし" : "LOCAL ONLY • NO EXECUTION • NO UPLOAD";
        VersionText.Text = ja ? "v0.1 • 静的観測" : "v0.1 • STATIC OBSERVATION";

        if (_selectedPath is null)
        {
            TargetHeaderText.Text = ja ? "調査対象をドロップ" : "DROP A TARGET TO INSPECT";
            TargetPathText.Text = ja ? "ファイルまたはフォルダーを選択してください" : "Select a file or folder";
            ProgressText.Text = ja ? "待機中 — 対象は実行しません" : "Idle — the target will not be executed";
            VerdictText.Text = ja ? "対象を選択すると、根拠とともに評価します。" : "Select a target to receive an evidence-based assessment.";
            ReportPreviewText.Text = ja ? "調査完了後にレポートが表示されます。" : "The report will appear after inspection.";
            FileDetailText.Text = ja ? "ファイルを選択すると詳細を表示します。" : "Select a file to view details.";
        }
        else
        {
            SelectTarget(_selectedPath);
        }
    }

    private Brush RiskBrush(int score) => score >= 60 ? (Brush)FindResource("DangerBrush") : score >= 25 ? (Brush)FindResource("WarnBrush") : (Brush)FindResource("GoodBrush");

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.LeftButton == MouseButtonState.Pressed) DragMove();
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
