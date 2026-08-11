using System.Diagnostics;
namespace Gcexp.Infrastructure;

public sealed record ProcessResult(int ExitCode, string StandardOutput, string StandardError);
public interface IProcessRunner { Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken); }
public sealed class ProcessRunner : IProcessRunner
{
    public async Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var process = new Process { StartInfo = new ProcessStartInfo(fileName) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true } };
        foreach (var argument in arguments) process.StartInfo.ArgumentList.Add(argument);
        try { process.Start(); } catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException) { throw new InvalidOperationException($"Unable to start '{fileName}'. Is it installed and on PATH?", ex); }
        var stdout = process.StandardOutput.ReadToEndAsync(cancellationToken); var stderr = process.StandardError.ReadToEndAsync(cancellationToken);
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); timeoutCts.CancelAfter(timeout);
        try { await process.WaitForExitAsync(timeoutCts.Token); } catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { try { process.Kill(true); } catch (InvalidOperationException) { } throw new TimeoutException($"'{fileName}' timed out."); }
        return new(process.ExitCode, await stdout, await stderr);
    }
}
