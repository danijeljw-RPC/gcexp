using System.Globalization;
using System.Text;
using Gcexp.Infrastructure;
namespace Gcexp.Checkers.Gpg;

public static class GpgColonParser
{
    public static IReadOnlyList<CheckResult> Parse(string text, DateTimeOffset now, int warnDays, string source, string? home)
    {
        var results = new List<CheckResult>(); KeyBuilder? current = null; bool wantsFingerprint = false;
        foreach (var line in text.Split('\n'))
        {
            var f = line.TrimEnd('\r').Split(':'); if (f.Length == 0) continue;
            if (f[0] is "pub" or "sub") { if (current is not null) results.Add(current.Build(now, warnDays, source, home)); current = new(f[0] == "pub" ? "Gpg" : "GpgSubkey", Get(f, 4), Epoch(Get(f, 5)), Epoch(Get(f, 6)), Get(f, 1)); wantsFingerprint = true; }
            else if (f[0] == "fpr" && current is not null && wantsFingerprint) { current.Fingerprint = Get(f, 9); wantsFingerprint = false; }
            else if (f[0] == "uid" && current is not null && current.Type == "Gpg" && current.Uid is null) current.Uid = Decode(Get(f, 9));
        }
        if (current is not null) results.Add(current.Build(now, warnDays, source, home)); return results;
    }
    private static string Get(string[] f, int i) => i < f.Length ? f[i] : "";
    private static DateTimeOffset? Epoch(string value) => long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var n) && n > 0 ? DateTimeOffset.FromUnixTimeSeconds(n) : null;
    public static string Decode(string value)
    {
        var bytes = new List<byte>();
        for (var i = 0; i < value.Length; i++) { if (value[i] == '\\' && i + 3 < value.Length && value[i + 1] == 'x' && byte.TryParse(value.AsSpan(i + 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var b)) { bytes.Add(b); i += 3; } else bytes.AddRange(Encoding.UTF8.GetBytes(value[i].ToString())); }
        return Encoding.UTF8.GetString(bytes.ToArray());
    }
    private sealed class KeyBuilder(string type, string id, DateTimeOffset? created, DateTimeOffset? expires, string validity)
    {
        public string Type { get; } = type; public string? Fingerprint { get; set; }
        public string? Uid { get; set; }
        public CheckResult Build(DateTimeOffset now, int warn, string source, string? home)
        {
            var (name, email) = ParseUid(Uid); var e = ExpiryEvaluator.Evaluate(expires, now, warn); var bad = validity is "r" or "d" or "i";
            return new(Type, name ?? id, id, Fingerprint, created, expires, e.Days, bad ? CertificateStatus.Error : e.Status, source, email, GpgHome: home, Detail: bad ? validity switch { "r" => "Revoked", "d" => "Disabled", _ => "Invalid" } : null);
        }
        private static (string? Name, string? Email) ParseUid(string? uid) { if (string.IsNullOrWhiteSpace(uid)) return (null, null); var end = uid.LastIndexOf('>'); var start = end > 0 ? uid.LastIndexOf('<', end) : -1; return start >= 0 && end > start ? (uid[..start].Trim().Trim('"'), uid[(start + 1)..end].Trim()) : (uid, null); }
    }
}
public sealed class GpgChecker(IProcessRunner runner)
{
    public async Task<IReadOnlyList<CheckResult>> CheckAsync(string? home, DateTimeOffset now, int warnDays, CancellationToken token)
    {
        Exception? last = null;
        foreach (var exe in new[] { "gpg", "gpg2" }) try { var args = new List<string>(); if (home is not null) { args.Add("--homedir"); args.Add(home); } args.AddRange(["--batch", "--with-colons", "--fixed-list-mode", "--fingerprint", "--fingerprint", "--list-keys"]); var r = await runner.RunAsync(exe, args, TimeSpan.FromSeconds(30), token); if (r.ExitCode != 0) throw new InvalidOperationException(string.IsNullOrWhiteSpace(r.StandardError) ? $"{exe} exited with code {r.ExitCode}." : r.StandardError.Trim()); return GpgColonParser.Parse(r.StandardOutput, now, warnDays, exe, home); } catch (InvalidOperationException ex) { last = ex; }
        throw last ?? new InvalidOperationException("GnuPG is unavailable.");
    }
}
