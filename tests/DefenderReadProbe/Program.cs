using DestinyBlackBox;

// Diagnostic control only. No application module initializer; never used as a product fallback.
// Links the exact read-only adapter to distinguish provider/API problems from product boundaries.
DefenderSnapshot result = await DefenderReader.Shared.ReadAsync();
Console.WriteLine(result.ToJson());
return result.RetrievalComplete ? 0 : 1;
