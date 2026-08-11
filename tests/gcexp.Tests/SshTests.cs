using Gcexp;
using Gcexp.Checkers.Files;
using Gcexp.Infrastructure;
namespace gcexp.Tests;

public sealed class SshTests : IDisposable
{
    private readonly string path = Path.Combine(Path.GetTempPath(), $"gcexp-{Guid.NewGuid():N}.pub");
    [Fact]
    public async Task OrdinaryPublicKeyHasNoEmbeddedExpiry()
    {
        await File.WriteAllTextAsync(path, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest user@example"); var result = await new SshChecker(new NeverRunner()).CheckAsync(path, DateTimeOffset.UtcNow, 30, CancellationToken.None);
        Assert.Equal(CertificateStatus.NoExpiry, result.Status); Assert.Equal("No embedded expiry", result.Detail);
    }
    public void Dispose() { if (File.Exists(path)) File.Delete(path); }
    private sealed class NeverRunner : IProcessRunner { public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken) => throw new InvalidOperationException("Must not invoke ssh-keygen for ordinary keys."); }
}
