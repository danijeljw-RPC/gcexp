using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Gcexp;
using Gcexp.Checkers.Files;
using Gcexp.Checkers.Gpg;
using Gcexp.Cli;
namespace gcexp.Tests;

public sealed class CoreTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 11, 12, 0, 0, TimeSpan.Zero);
    [Theory]
    [InlineData(31, CertificateStatus.Ok)]
    [InlineData(30, CertificateStatus.Expiring)]
    [InlineData(1, CertificateStatus.Expiring)]
    [InlineData(0, CertificateStatus.Expiring)]
    [InlineData(-1, CertificateStatus.Expired)]
    public void EvaluatesCalendarDays(int days, CertificateStatus expected) { var result = ExpiryEvaluator.Evaluate(Now.AddDays(days), Now, 30); Assert.Equal(expected, result.Status); Assert.Equal(days, result.Days); }
    [Fact] public void NullExpiryIsDistinct() { var result = ExpiryEvaluator.Evaluate(null, Now, 30); Assert.Equal(CertificateStatus.NoExpiry, result.Status); Assert.Null(result.Days); }
    [Fact] public void PastInstantTodayIsExpiredWithZeroDays() { var result = ExpiryEvaluator.Evaluate(Now.AddHours(-1), Now, 30); Assert.Equal(CertificateStatus.Expired, result.Status); Assert.Equal(0, result.Days); }
    [Fact] public void ExitCodePrecedenceIsStable() { var report = new ScanReport(Now, 30, new(2, 0, 1, 1, 0, 0, 1), [], [new("x", "bad")]); Assert.Equal(3, Application.SelectExitCode(report)); }
}
public sealed class GpgParserTests
{
    [Fact]
    public void ParsesPrimarySubkeyFingerprintUidEscapesAndNoExpiry()
    {
        const string data = "pub:u:2048:1:ABC:1700000000:1800000000::::::\nfpr:::::::::PRIMARYFPR:\nuid:u::::1700000000::hash::Jos\\xC3\\xA9 Example <jose@example.com>::::::::::0:\nsub:u:2048:1:DEF:1700000000:::::::::\nfpr:::::::::SUBFPR:\n";
        var results = GpgColonParser.Parse(data, DateTimeOffset.FromUnixTimeSeconds(1750000000), 30, "gpg", "/keys");
        Assert.Equal(2, results.Count); Assert.Equal("José Example", results[0].Name); Assert.Equal("jose@example.com", results[0].Email); Assert.Equal("PRIMARYFPR", results[0].Fingerprint); Assert.Equal(CertificateStatus.NoExpiry, results[1].Status); Assert.Equal("SUBFPR", results[1].Fingerprint);
    }
    [Fact] public void ToleratesMalformedRecordsAndArbitraryUid() { var r = GpgColonParser.Parse("nonsense\npub:u:::ID:bad::::\nuid:::::::::server key:\n", DateTimeOffset.UtcNow, 30, "gpg", null); Assert.Single(r); Assert.Equal("server key", r[0].Name); }
}
public sealed class CertificateTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), $"gcexp-{Guid.NewGuid():N}");
    public CertificateTests() => Directory.CreateDirectory(directory);
    [Fact]
    public void ReadsDerAndPem()
    {
        using var cert = Create("CN=example", DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(60)); var der = Path.Combine(directory, "a.der"); var pem = Path.Combine(directory, "a.pem"); File.WriteAllBytes(der, cert.Export(X509ContentType.Cert)); File.WriteAllText(pem, cert.ExportCertificatePem());
        Assert.Equal(CertificateStatus.Ok, CertificateFileChecker.Check(der, null, DateTimeOffset.UtcNow, 30).Single().Status); Assert.Single(CertificateFileChecker.Check(pem, null, DateTimeOffset.UtcNow, 30));
    }
    [Fact]
    public void ReadsProtectedPfxAndRejectsWrongPassword()
    {
        using var cert = Create("CN=pfx", DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(2)); var path = Path.Combine(directory, "a.pfx"); File.WriteAllBytes(path, cert.Export(X509ContentType.Pfx, "secret")); Assert.Single(CertificateFileChecker.Check(path, "secret", DateTimeOffset.UtcNow, 30)); Assert.Throws<CryptographicException>(() => CertificateFileChecker.Check(path, "wrong", DateTimeOffset.UtcNow, 30));
    }
    [Theory]
    [InlineData(-2, CertificateStatus.Expired)]
    [InlineData(2, CertificateStatus.Expiring)]
    [InlineData(60, CertificateStatus.Ok)]
    public void X509StatusUsesCertificateExpiry(int endDays, CertificateStatus expected)
    {
        using var cert = Create("CN=status", DateTimeOffset.UtcNow.AddDays(-10), DateTimeOffset.UtcNow.AddDays(endDays)); var path = Path.Combine(directory, $"{endDays}.cer"); File.WriteAllBytes(path, cert.Export(X509ContentType.Cert));
        Assert.Equal(expected, CertificateFileChecker.Check(path, null, DateTimeOffset.UtcNow, 30).Single().Status);
    }
    [Fact]
    public void ReadsEveryCertificateInPfxCollection()
    {
        using var first = Create("CN=one", DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(60)); using var second = Create("CN=two", DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(60)); var collection = new X509Certificate2Collection(); collection.Add(first); collection.Add(second); var path = Path.Combine(directory, "many.p12"); File.WriteAllBytes(path, collection.Export(X509ContentType.Pfx, "many")!);
        Assert.Equal(2, CertificateFileChecker.Check(path, "many", DateTimeOffset.UtcNow, 30).Count);
    }
    private static X509Certificate2 Create(string subject, DateTimeOffset start, DateTimeOffset end) { using var rsa = RSA.Create(2048); return new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(start, end); }
    public void Dispose() => Directory.Delete(directory, true);
}
