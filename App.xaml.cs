using System.IO;
using System.Windows;

namespace DestinyBlackBox;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        if (e.Args.Length >= 3 && e.Args[0].Equals("--report", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var inspector = new FileInspector();
                ScanResult result = inspector.ScanAsync(e.Args[1], null, CancellationToken.None).GetAwaiter().GetResult();
                SafeReportWriter.Write(e.Args[2], ReportBuilder.Build(result, "en"), result, ".md", allowOverwrite: false);
                Environment.ExitCode = 0;
            }
            catch
            {
                try { Console.Error.WriteLine("Inspection failed safely. No report was written."); } catch { }
                Environment.ExitCode = 1;
            }

            Shutdown(Environment.ExitCode);
            return;
        }

        new MainWindow().Show();
    }
}
