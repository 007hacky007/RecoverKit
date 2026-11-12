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
