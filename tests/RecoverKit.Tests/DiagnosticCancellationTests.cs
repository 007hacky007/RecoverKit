using RecoverKit.Core.Hashcat;
using Xunit;

namespace RecoverKit.Tests;

public sealed class DiagnosticCancellationTests
{
    [Fact]
    public async Task ToolCancellationStopsTheChildBeforeReturning()
    {
        string executable = OperatingSystem.IsWindows() ? Path.Combine(Environment.SystemDirectory, "cmd.exe") : "/bin/sh";
        string[] args = OperatingSystem.IsWindows() ? ["/c", "ping -n 6 127.0.0.1 > nul"] : ["-c", "sleep 10"];
        var tool = HashcatTool.Locate(executable)!;
        using var stop = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => tool.RunAsync(args, TimeSpan.FromSeconds(30), ct: stop.Token));
    }
}
