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

        // Filter on the code the list displays, so a file shown as LOW can never be found only under CLEAR.
        if (riskFilter is "HIGH" or "REVIEW" or "LOW" or "CLEAR")
        {
            query = query.Where(file => file.RiskCode == riskFilter);
        }
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
