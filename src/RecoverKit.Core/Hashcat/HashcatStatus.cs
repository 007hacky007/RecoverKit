using System.Text.Json;

namespace RecoverKit.Core.Hashcat;

public sealed class DeviceSpeed
{
    public int Id { get; init; }
    public string Name { get; init; } = "";
    public string Type { get; init; } = "";
    public double Speed { get; init; }
    public int Temperature { get; init; } = -1;
    public int Utilization { get; init; } = -1;
}

/// <summary>One line of hashcat --status-json output.</summary>
public sealed class HashcatStatus
{
    public int Status { get; init; }
    public string GuessBase { get; init; } = "";
    public string? GuessMod { get; init; }
    public double GuessBasePercent { get; init; }
    public int? MaskLength { get; init; }
    public long ProgressDone { get; init; }
    public long ProgressTotal { get; init; }
    public long RestorePoint { get; init; }
    /// <summary>Candidates already done before this run started (resumed attacks), excluded from the average speed.</summary>
    public long ResumedFrom { get; init; }
    public long Rejected { get; init; }
    public int RecoveredHashes { get; init; }
    public int TotalHashes { get; init; }
    public long TimeStart { get; init; }
    public long EstimatedStop { get; init; }
    public List<DeviceSpeed> Devices { get; init; } = new();

    public double TotalSpeed => Devices.Sum(d => d.Speed);
    public double Fraction => ProgressTotal > 0 ? (double)ProgressDone / ProgressTotal : 0;

    public string StatusText => Status switch
    {
        0 => "Initializing",
        1 => "Autotuning",
        2 => "Self-testing",
        3 => "Running",
        4 => "Paused",
        5 => "Exhausted",
        6 => "Cracked",
        7 => "Aborted",
        8 => "Quit",
        9 => "Bypass",
        10 => "Aborted (checkpoint)",
        11 => "Aborted (runtime)",
        12 => "Running (stop at checkpoint)",
        13 => "Error",
        14 => "Aborted (finish)",
        15 => "Autodetect",
        _ => $"Status {Status}",
    };

    public static HashcatStatus? TryParse(string line)
    {
        if (!line.StartsWith('{')) return null;
        try
        {
            using var doc = JsonDocument.Parse(line);
            var r = doc.RootElement;
            var guess = r.TryGetProperty("guess", out var g) ? g : default;
            long[] Pair(string name) => r.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.Array
                ? p.EnumerateArray().Select(x => x.GetInt64()).ToArray() : [0, 0];
            var progress = Pair("progress");
            var rec = Pair("recovered_hashes");
            var devs = new List<DeviceSpeed>();
            if (r.TryGetProperty("devices", out var da))
                foreach (var d in da.EnumerateArray())
                    devs.Add(new DeviceSpeed
                    {
                        Id = d.TryGetProperty("device_id", out var id) ? id.GetInt32() : 0,
                        Name = d.TryGetProperty("device_name", out var n) ? n.GetString() ?? "" : "",
                        Type = d.TryGetProperty("device_type", out var t) ? t.GetString() ?? "" : "",
                        Speed = d.TryGetProperty("speed", out var s) ? s.GetDouble() : 0,
                        Temperature = d.TryGetProperty("temp", out var te) ? te.GetInt32() : -1,
                        Utilization = d.TryGetProperty("util", out var u) ? u.GetInt32() : -1,
                    });
            string? Str(JsonElement e, string name) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
            return new HashcatStatus
            {
                Status = r.TryGetProperty("status", out var st) ? st.GetInt32() : 0,
                GuessBase = Str(guess, "guess_base") ?? "",
                GuessMod = Str(guess, "guess_mod"),
                GuessBasePercent = guess.ValueKind == JsonValueKind.Object && guess.TryGetProperty("guess_base_percent", out var gp) ? gp.GetDouble() : 0,
                // Dictionary attacks report 4294967295 (unsigned -1): no mask length.
                MaskLength = guess.ValueKind == JsonValueKind.Object && guess.TryGetProperty("guess_mask_length", out var ml) && ml.ValueKind == JsonValueKind.Number
                             && ml.TryGetInt32(out var mlv) ? mlv : null,
                ProgressDone = progress.ElementAtOrDefault(0),
                ProgressTotal = progress.ElementAtOrDefault(1),
                RestorePoint = r.TryGetProperty("restore_point", out var rp) ? rp.GetInt64() : 0,
                Rejected = r.TryGetProperty("rejected", out var rj) ? rj.GetInt64() : 0,
                RecoveredHashes = (int)rec.ElementAtOrDefault(0),
                TotalHashes = (int)rec.ElementAtOrDefault(1),
                TimeStart = r.TryGetProperty("time_start", out var ts) ? ts.GetInt64() : 0,
                EstimatedStop = r.TryGetProperty("estimated_stop", out var es) ? es.GetInt64() : 0,
                Devices = devs,
            };
        }
        catch (JsonException) { return null; }
        catch (InvalidOperationException) { return null; }
        catch (FormatException) { return null; }
    }
}
