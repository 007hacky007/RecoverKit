using RecoverKit.Core.Hashcat;

namespace RecoverKit.Core.Diagnostics;

/// <summary>Limit the launch-size search in the isolated engine; module loop limits and self-tests still apply.</summary>
internal static class DiagnosticGpuTuning
{
    public static IDisposable Apply(HashcatTool tool, IEnumerable<BackendDevice> devices)
    {
        string directory = Path.Combine(tool.Directory, "tunings");
        Directory.CreateDirectory(directory);
        string file = Path.Combine(directory, "RecoverKit-diagnostics.hctune");
        byte[]? saved = File.Exists(file) ? File.ReadAllBytes(file) : null;
        var lines = devices.GroupBy(d => d.Name).Select(g =>
        {
            var d = g.First();
            int accel = Math.Clamp(1024 / Math.Max(1, d.Processors), 1, 1024);
            return $"{d.Name.Replace(' ', '_')} 3 * N {accel} 1000";
        });
        File.WriteAllLines(file, lines);
        return new Restore(file, saved);
    }

    private sealed class Restore(string file, byte[]? saved) : IDisposable
    {
        public void Dispose()
        {
            if (saved is null) File.Delete(file); else File.WriteAllBytes(file, saved);
        }
    }
}
