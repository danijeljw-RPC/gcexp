using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Gcexp.Infrastructure;
namespace Gcexp.Checkers.Files;

public static partial class CertificateFileChecker
{
    public static IReadOnlyList<CheckResult> Check(string path, string? password, DateTimeOffset now, int warnDays) => Path.GetExtension(path).ToLowerInvariant() is ".pfx" or ".p12" ? CheckPfx(path, password, now, warnDays) : CheckX509(path, now, warnDays);
    private static IReadOnlyList<CheckResult> CheckX509(string path, DateTimeOffset now, int warn)
    {
        if (Path.GetExtension(path).Equals(".pem", StringComparison.OrdinalIgnoreCase)) { var matches = PemRegex().Matches(File.ReadAllText(path)); if (matches.Count == 0) throw new InvalidDataException("PEM file contains no certificates."); return matches.Select(m => { using var c = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(SpaceRegex().Replace(m.Groups[1].Value, ""))); return Build(c, "X509", path, now, warn); }).ToArray(); }
        using var cert = X509CertificateLoader.LoadCertificateFromFile(path); return [Build(cert, "X509", path, now, warn)];
    }
    private static IReadOnlyList<CheckResult> CheckPfx(string path, string? password, DateTimeOffset now, int warn) { var cs = X509CertificateLoader.LoadPkcs12CollectionFromFile(path, password, X509KeyStorageFlags.EphemeralKeySet); try { return cs.Cast<X509Certificate2>().Select(c => Build(c, "Pkcs12", path, now, warn)).ToArray(); } finally { foreach (var c in cs) c.Dispose(); } }
    private static CheckResult Build(X509Certificate2 c, string type, string path, DateTimeOffset now, int warn) { var start = c.NotBefore.ToUniversalTime(); var end = c.NotAfter.ToUniversalTime(); var e = ExpiryEvaluator.Evaluate(end, now, warn); return new(type, c.Subject, c.SerialNumber, c.Thumbprint, start, end, e.Days, e.Status, path, Issuer: c.Issuer, SerialNumber: c.SerialNumber); }
    [GeneratedRegex("-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", RegexOptions.Singleline)] private static partial Regex PemRegex();
    [GeneratedRegex("\\s+")] private static partial Regex SpaceRegex();
}
public sealed partial class SshChecker(IProcessRunner runner)
{
    public async Task<CheckResult> CheckAsync(string path, DateTimeOffset now, int warn, CancellationToken token)
    {
        var content = (await File.ReadAllTextAsync(path, token)).TrimStart(); if (!content.StartsWith("ssh-", StringComparison.Ordinal) || !content.Contains("-cert-v01@openssh.com", StringComparison.Ordinal)) return new("SshKey", Path.GetFileName(path), null, null, null, null, null, CertificateStatus.NoExpiry, path, Detail: "No embedded expiry");
        var r = await runner.RunAsync("ssh-keygen", ["-L", "-f", path], TimeSpan.FromSeconds(15), token); if (r.ExitCode != 0) throw new InvalidOperationException(r.StandardError.Trim()); var m = ValidityRegex().Match(r.StandardOutput); if (!m.Success) return new("SshCertificate", Path.GetFileName(path), null, null, null, null, null, CertificateStatus.Unknown, path); if (m.Groups[2].Value == "forever") return new("SshCertificate", Path.GetFileName(path), null, null, null, null, null, CertificateStatus.NoExpiry, path);
        var start = DateTimeOffset.ParseExact(m.Groups[1].Value, "yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal).ToUniversalTime(); var end = DateTimeOffset.ParseExact(m.Groups[2].Value, "yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal).ToUniversalTime(); var e = ExpiryEvaluator.Evaluate(end, now, warn); return new("SshCertificate", Path.GetFileName(path), null, null, start, end, e.Days, e.Status, path);
    }
    [GeneratedRegex(@"Valid:\s+from\s+(\S+)\s+to\s+(\S+)", RegexOptions.IgnoreCase)] private static partial Regex ValidityRegex();
}
