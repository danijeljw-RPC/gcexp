using System.Reflection;
using System.Text.Json;
using Gcexp.Checkers.Files;
using Gcexp.Checkers.Gpg;
using Gcexp.Infrastructure;
using Gcexp.Serialization;
namespace Gcexp.Cli;

public static class Application
{
    private static readonly HashSet<string> Extensions = new(StringComparer.OrdinalIgnoreCase) { ".cer", ".crt", ".der", ".pem", ".pfx", ".p12", ".pub" };
    public static async Task<int> RunAsync(string[] args, TextWriter output, TextWriter error, CancellationToken token)
    {
        if (args.Length == 0 || args[0] is "--help" or "-h") { await output.WriteLineAsync(Help); return 0; }
        if (args[0] is "--version" or "-V") { await output.WriteLineAsync(Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "1.0.0"); return 0; }
        if (args[0] is not ("scan" or "check")) { await error.WriteLineAsync("Unknown command. Use 'gcexp --help'."); return 64; }
        if (!TryParse(args, out var options, out var parseError)) { await error.WriteLineAsync(parseError); return 64; }
        var now = DateTimeOffset.UtcNow; var results = new List<CheckResult>(); var errors = new List<InspectionError>(); var runner = new ProcessRunner();
        var files = Discover(options!, errors);
        foreach (var file in files)
        {
            try { if (Path.GetExtension(file).Equals(".pub", StringComparison.OrdinalIgnoreCase)) results.Add(await new SshChecker(runner).CheckAsync(file, now, options.WarnDays, token)); else results.AddRange(CertificateFileChecker.Check(file, GetPfxPassword(options), now, options.WarnDays)); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException or InvalidDataException or InvalidOperationException or FormatException) { errors.Add(new(file, options.Verbose ? ex.ToString() : ex.Message)); }
        }
        if (options.Gpg) try { results.AddRange(await new GpgChecker(runner).CheckAsync(options.GpgHome, now, options.WarnDays, token)); } catch (Exception ex) when (ex is InvalidOperationException or TimeoutException) { errors.Add(new("GPG", options.Verbose ? ex.ToString() : ex.Message)); }
        var summary = new ScanSummary(results.Count, Count(CertificateStatus.Ok), Count(CertificateStatus.Expiring), Count(CertificateStatus.Expired), Count(CertificateStatus.NoExpiry), Count(CertificateStatus.Unknown), errors.Count + Count(CertificateStatus.Error));
        var report = new ScanReport(now, options.WarnDays, summary, results, errors);
        if (options.Json) await output.WriteLineAsync(JsonSerializer.Serialize(report, GcexpJsonContext.Default.ScanReport)); else Render(report, output);
        return SelectExitCode(report);
        int Count(CertificateStatus s) => results.Count(r => r.Status == s);
    }
    public static int SelectExitCode(ScanReport report) => report.Summary.Errors > 0 ? 3 : report.Summary.Expired > 0 ? 2 : report.Summary.Expiring > 0 ? 1 : 0;
    private static string? GetPfxPassword(Options o) { if (!string.IsNullOrEmpty(o.PfxPasswordEnvironment)) return Environment.GetEnvironmentVariable(o.PfxPasswordEnvironment); return null; }
    private static IEnumerable<string> Discover(Options o, List<InspectionError> errors)
    {
        var found = new HashSet<string>(StringComparer.OrdinalIgnoreCase); foreach (var f in o.Files) { try { found.Add(Path.GetFullPath(f)); } catch (Exception ex) { errors.Add(new(f, ex.Message)); } }
        foreach (var path in o.Paths) try { foreach (var f in Directory.EnumerateFiles(path, "*", o.Recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly)) if (Extensions.Contains(Path.GetExtension(f))) found.Add(Path.GetFullPath(f)); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DirectoryNotFoundException) { errors.Add(new(path, ex.Message)); }
        return found;
    }
    private static bool TryParse(string[] args, out Options o, out string? error)
    {
        o = new(); error = null; if (args[0] == "check") { if (args.Length != 2) { error = "Usage: gcexp check <file>"; return false; } o.Files.Add(args[1]); return true; }
        for (var i = 1; i < args.Length; i++) switch (args[i])
            {
                case "--json": o.Json = true; break;
                case "--recursive": o.Recursive = true; break;
                case "--gpg": o.Gpg = true; break;
                case "--all": o.Gpg = true; o.Paths.Add(Directory.GetCurrentDirectory()); break;
                case "--verbose": o.Verbose = true; break;
                case "--warn-days": if (++i >= args.Length || !int.TryParse(args[i], out var n) || n < 0) { error = "--warn-days requires a non-negative integer."; return false; } o.WarnDays = n; break;
                case "--file": if (++i >= args.Length) { error = "--file requires a path."; return false; } o.Files.Add(args[i]); break;
                case "--path": if (++i >= args.Length) { error = "--path requires a directory."; return false; } o.Paths.Add(args[i]); break;
                case "--gpg-home": if (++i >= args.Length) { error = "--gpg-home requires a path."; return false; } o.GpgHome = args[i]; o.Gpg = true; break;
                case "--pfx-password-env": if (++i >= args.Length) { error = "--pfx-password-env requires an environment variable name."; return false; } o.PfxPasswordEnvironment = args[i]; break;
                default: error = $"Unknown option '{args[i]}'."; return false;
            }
        return true;
    }
    private static void Render(ScanReport r, TextWriter w)
    {
        w.WriteLine("TYPE        NAME/SUBJECT                           EXPIRES     DAYS  STATUS");
        foreach (var x in r.Certificates) w.WriteLine($"{Clip(x.Type, 11),-11} {Clip(x.Name, 38),-38} {(x.ExpiresUtc?.ToString("yyyy-MM-dd") ?? "-"),-11} {(x.DaysRemaining?.ToString() ?? "-"),5}  {x.Status.ToString().ToUpperInvariant()}");
        foreach (var e in r.Errors) w.WriteLine($"ERROR: {e.Source}: {e.Message}");
        w.WriteLine($"Total {r.Summary.Total}; OK {r.Summary.Ok}; expiring {r.Summary.Expiring}; expired {r.Summary.Expired}; no expiry {r.Summary.NoExpiry}; errors {r.Summary.Errors}");
    }
    private static string Clip(string s, int n) => s.Length <= n ? s : s[..(n - 1)] + "…";
    private sealed class Options { public int WarnDays { get; set; } = 30; public bool Json { get; set; } public bool Recursive { get; set; } public bool Gpg { get; set; } public bool Verbose { get; set; } public string? GpgHome { get; set; } public string? PfxPasswordEnvironment { get; set; } public List<string> Files { get; } = []; public List<string> Paths { get; } = []; }
    private const string Help = """
gcexp — GNU Certificate Expiry Checker

Usage:
  gcexp --help | --version
  gcexp scan [--file <file>]... [--path <dir>] [--recursive] [--gpg] [--gpg-home <dir>]
             [--warn-days <days>] [--json] [--pfx-password-env <name>] [--verbose] [--all]
  gcexp check <file>

No locations are scanned by default. --all scans the current directory (non-recursively) and GPG.
PFX passwords are read only from the environment variable named by --pfx-password-env.
""";
}
