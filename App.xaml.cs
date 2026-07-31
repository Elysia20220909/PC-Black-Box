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
                string output = Path.GetFullPath(e.Args[2]);
                Directory.CreateDirectory(Path.GetDirectoryName(output)!);
                File.WriteAllText(output, ReportBuilder.Build(result, "en"));
                Environment.ExitCode = 0;
            }
            catch (Exception ex)
            {
                try { Console.Error.WriteLine(ex); } catch { }
                Environment.ExitCode = 1;
            }

            Shutdown(Environment.ExitCode);
            return;
        }

        new MainWindow().Show();
    }
}
