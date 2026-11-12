namespace RecoverKit.Core.Formats;

/// <summary>
/// A weak protection that detection can undo on the spot, without an attack: a password that is
/// stored in a recoverable form, a built-in default password, or a restriction (editing, sheet or
/// permissions password) that can simply be removed. Extractors add these to
/// <see cref="Detection.Unlocks"/>; the GUI shows each one with its password and a save button, and
/// <c>recoverkit-cli unlock</c> applies it.
/// </summary>
public sealed class InstantUnlock
{
    /// <summary>Short headline, e.g. "Sheet protection can be removed".</summary>
    public required string Title { get; init; }

    /// <summary>One or two plain sentences on what was found and what saving does.</summary>
    public required string Description { get; init; }

    /// <summary>A password recovered instantly (may be the empty string), or null when there is none to show.</summary>
    public string? Password { get; init; }

    /// <summary>Label of the save action, e.g. "Save unprotected copy...", or null when nothing can be saved.</summary>
    public string? SaveLabel { get; init; }

    /// <summary>Suffix added to the file name for the suggested output name.</summary>
    public string SuggestedSuffix { get; init; } = "_unlocked";

    /// <summary>Writes the unprotected copy of <c>source</c> to <c>output</c> (never overwrites the source).</summary>
    public Func<string, string, CancellationToken, Task>? SaveCopyAsync { get; init; }

    /// <summary>The suggested output path next to the source file.</summary>
    public string SuggestedPath(string source) =>
        Path.Combine(Path.GetDirectoryName(Path.GetFullPath(source)) ?? ".",
            Path.GetFileNameWithoutExtension(source) + SuggestedSuffix + Path.GetExtension(source));

    /// <summary>
    /// When a file has several restrictions that can each be saved away, one extra unlock that
    /// removes all of them into a single copy (each step works on the previous step's output).
    /// </summary>
    public static InstantUnlock? All(IReadOnlyList<InstantUnlock> unlocks)
    {
        var steps = unlocks.Where(u => u.SaveCopyAsync is not null).ToList();
        if (steps.Count < 2) return null;
        return new InstantUnlock
        {
            Title = "All restrictions can be removed at once",
            Description = $"Saves one copy without any of the {steps.Count} restrictions listed below.",
            SaveLabel = "Save copy without all restrictions...",
            SuggestedSuffix = steps[0].SuggestedSuffix,
            SaveCopyAsync = async (source, output, ct) =>
            {
                string dir = Path.GetDirectoryName(Path.GetFullPath(output)) ?? ".";
                string ext = Path.GetExtension(output);
                string current = source;
                var temps = new List<string>();
                try
                {
                    for (int i = 0; i < steps.Count; i++)
                    {
                        string next = i == steps.Count - 1 ? output : Path.Combine(dir, $".rk-unlock-{Guid.NewGuid():N}{ext}");
                        if (next != output) temps.Add(next);
                        await steps[i].SaveCopyAsync!(current, next, ct);
                        current = next;
                    }
                }
                finally
                {
                    foreach (var t in temps)
                        try { File.Delete(t); } catch (IOException) { } catch (UnauthorizedAccessException) { }
                }
            },
        };
    }

    /// <summary>Runs the save action after checking the output does not replace the source.</summary>
    public async Task SaveAsync(string source, string output, CancellationToken ct = default)
    {
        if (SaveCopyAsync is null) throw new InvalidOperationException("This unlock has no save action.");
        var comparison = OperatingSystem.IsWindows() || OperatingSystem.IsMacOS() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (string.Equals(Path.GetFullPath(source), Path.GetFullPath(output), comparison))
            throw new IOException("Choose a different file name: the original file is never overwritten.");
        await SaveCopyAsync(source, output, ct);
    }
}
