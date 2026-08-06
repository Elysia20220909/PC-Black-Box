namespace DestinyBlackBox;

internal static class FileViewQuery
{
    public static List<FileAnalysis> Apply(IEnumerable<FileAnalysis> files, string riskFilter, string? searchText)
    {
        string search = searchText?.Trim() ?? String.Empty;
        IEnumerable<FileAnalysis> query = files;
        if (!String.IsNullOrWhiteSpace(search))
        {
            query = query.Where(file => MatchesSearch(file, search));
        }

        query = riskFilter switch
        {
            "HIGH" => query.Where(file => file.RiskScore >= 60),
            "REVIEW" => query.Where(file => file.RiskScore is >= 25 and < 60),
            "LOW" => query.Where(file => file.RiskScore is > 0 and < 25),
            "CLEAR" => query.Where(file => file.RiskScore == 0),
            _ => query
        };
        return query.ToList();
    }

    private static bool MatchesSearch(FileAnalysis file, string search)
    {
        static bool Contains(string value, string needle) => value.Contains(needle, StringComparison.OrdinalIgnoreCase);
        return Contains(file.RelativePath, search) ||
               Contains(file.FileType, search) ||
               Contains(file.SignatureStatus, search) ||
               Contains(file.Signer, search) ||
               Contains(file.SourceHost, search) ||
               file.Indicators.Any(indicator =>
                   Contains(indicator.Code, search) || Contains(indicator.Japanese, search) || Contains(indicator.English, search));
    }
}
