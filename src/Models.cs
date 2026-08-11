namespace Gcexp;

public enum CertificateStatus { Ok, Expiring, Expired, NoExpiry, Unknown, Error }
public sealed record CheckResult(string Type, string Name, string? Id, string? Fingerprint, DateTimeOffset? CreatedUtc, DateTimeOffset? ExpiresUtc, int? DaysRemaining, CertificateStatus Status, string Source, string? Email = null, string? Issuer = null, string? SerialNumber = null, string? GpgHome = null, string? Detail = null);
public sealed record InspectionError(string Source, string Message);
public sealed record ScanSummary(int Total, int Ok, int Expiring, int Expired, int NoExpiry, int Unknown, int Errors);
public sealed record ScanReport(DateTimeOffset GeneratedAtUtc, int WarningThresholdDays, ScanSummary Summary, IReadOnlyList<CheckResult> Certificates, IReadOnlyList<InspectionError> Errors);
public static class ExpiryEvaluator
{
    public static (CertificateStatus Status, int? Days) Evaluate(DateTimeOffset? expiry, DateTimeOffset now, int warnDays)
    {
        if (expiry is null) return (CertificateStatus.NoExpiry, null);
        var end = expiry.Value.ToUniversalTime(); var current = now.ToUniversalTime();
        var days = (end.Date - current.Date).Days;
        if (end < current) return (CertificateStatus.Expired, days);
        return days <= warnDays ? (CertificateStatus.Expiring, days) : (CertificateStatus.Ok, days);
    }
}
