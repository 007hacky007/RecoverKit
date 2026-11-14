using RecoverKit.Core.Hashcat;

namespace RecoverKit.Core.Dependencies;

public enum Light { Green, Yellow, Red }

/// <summary>The external components, in install order.</summary>
public enum DependencyId { Hashcat, Nvrtc, CpuRuntime }

public enum DependencyAction { None, CopyBundledHashcat, UseBundledHashcat, DownloadNvrtc, DownloadCpuRuntime, RepairHashcat }

public sealed record DependencyItem(
    DependencyId Id,
    string Name,
    Light Light,
    string Reason,
    DependencyAction Action,
    long DownloadBytes = 0,
    string? LicenseName = null,
    string? LicenseUrl = null,
    string? SkipKey = null,
    bool Pending = false,
    NvrtcRuntime.Package? NvrtcPackage = null)
{
    public bool Installable => Action != DependencyAction.None;
}
