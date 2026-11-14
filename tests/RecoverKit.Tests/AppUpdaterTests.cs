using System.Runtime.InteropServices;
using RecoverKit.Core;
using Xunit;

namespace RecoverKit.Tests;

public class AppUpdaterTests
{
    private const string Json = """
        {
          "tag_name": "v1.5.0",
          "html_url": "https://github.com/007hacky007/RecoverKit/releases/tag/v1.5.0",
          "assets": [
            {"name": "RecoverKit-1.5.0-x64.msi", "browser_download_url": "https://github.com/007hacky007/RecoverKit/releases/download/v1.5.0/RecoverKit-1.5.0-x64.msi", "size": 41000000,
             "digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
            {"name": "RecoverKit-1.5.0-x64-portable.zip", "browser_download_url": "https://github.com/007hacky007/RecoverKit/releases/download/v1.5.0/RecoverKit-1.5.0-x64-portable.zip", "size": 40000000, "digest": null},
            {"name": "RecoverKit-1.5.0-macos-arm64.dmg", "browser_download_url": "https://github.com/007hacky007/RecoverKit/releases/download/v1.5.0/RecoverKit-1.5.0-macos-arm64.dmg", "size": 90000000},
            {"name": "RecoverKit-1.5.0-macos-arm64.dmg.sha256", "browser_download_url": "https://github.com/007hacky007/RecoverKit/releases/download/v1.5.0/RecoverKit-1.5.0-macos-arm64.dmg.sha256", "size": 100},
            {"name": "evil.msi", "browser_download_url": "http://example.com/evil.msi", "size": 1}
          ]
        }
        """;

    [Fact]
    public void ParsesTheReleaseAndItsDigests()
    {
        var r = Assert.IsType<ReleaseInfo>(AppUpdater.ParseRelease(Json));
        Assert.Equal(new Version(1, 5, 0), r.Version);
        Assert.Equal("v1.5.0", r.Tag);
        Assert.Equal(4, r.Assets.Count);   // the http:// one is dropped
        Assert.Equal("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", r.Assets[0].Sha256);
        Assert.Null(r.Assets[1].Sha256);
        Assert.Null(r.Assets[2].Sha256);
        Assert.True(AppUpdater.IsNewer(r, "1.4.1"));
        Assert.False(AppUpdater.IsNewer(r, "1.5.0"));
        Assert.False(AppUpdater.IsNewer(r, "1.6"));
        Assert.Null(AppUpdater.ParseRelease("""{"tag_name": "nightly"}"""));
    }

    [Fact]
    public void ChoosesTheFileForTheInstallation()
    {
        var r = AppUpdater.ParseRelease(Json)!;
        Assert.Equal("RecoverKit-1.5.0-x64.msi", AppUpdater.ChooseAsset(r, InstallKind.WindowsMsi, Architecture.X64)!.Name);
        Assert.Equal("RecoverKit-1.5.0-x64-portable.zip", AppUpdater.ChooseAsset(r, InstallKind.WindowsPortable, Architecture.X64)!.Name);
        Assert.Equal("RecoverKit-1.5.0-macos-arm64.dmg", AppUpdater.ChooseAsset(r, InstallKind.MacBundle, Architecture.Arm64)!.Name);
        Assert.Null(AppUpdater.ChooseAsset(r, InstallKind.MacBundle, Architecture.X64));
        Assert.Null(AppUpdater.ChooseAsset(r, InstallKind.WindowsMsi, Architecture.Arm64));
        Assert.Null(AppUpdater.ChooseAsset(r, InstallKind.Unknown, Architecture.X64));
    }

    [Fact]
    public void ReadsAChecksumListing()
    {
        string listing = "9fa86e1bfd5dd898d3c83aa38a67b08db1ba5d2f5252dffa2af44a8c62585f49  RecoverKit-1.5.0-macos-arm64.dmg\n";
        Assert.Equal("9fa86e1bfd5dd898d3c83aa38a67b08db1ba5d2f5252dffa2af44a8c62585f49", AppUpdater.ChecksumFromListing(listing, "RecoverKit-1.5.0-macos-arm64.dmg"));
        Assert.Null(AppUpdater.ChecksumFromListing(listing, "other.dmg"));
        Assert.Null(AppUpdater.ChecksumFromListing("not a listing", "RecoverKit-1.5.0-macos-arm64.dmg"));
    }

    [Fact]
    public void FindsTheAppBundleOfTheRunningFolder()
    {
        Assert.Equal("/Applications/RecoverKit.app", AppUpdater.BundleOf("/Applications/RecoverKit.app/Contents/MacOS/"));
        Assert.Null(AppUpdater.BundleOf("/Users/me/RecoverKit/bin/Release/net10.0/"));
    }

    [Fact]
    public void ScriptsWaitForTheProcessThenInstallAndRestart()
    {
        string msi = AppUpdater.ApplyScript(new PreparedUpdate(InstallKind.WindowsMsi, "v1.5.0", @"C:\u\RecoverKit-1.5.0-x64.msi", null), 4242,
            @"C:\Program Files\RecoverKit\", @"C:\Program Files\RecoverKit\RecoverKit.exe");
        Assert.Contains("PID eq 4242", msi);
        Assert.Contains("ping -n 2 127.0.0.1 >nul & goto wait", msi);
        Assert.Contains(@"msiexec /i ""C:\u\RecoverKit-1.5.0-x64.msi"" /passive /norestart", msi);
        Assert.Contains(@"start """" ""C:\Program Files\RecoverKit\RecoverKit.exe""", msi);
        Assert.True(msi.IndexOf("msiexec", StringComparison.Ordinal) < msi.IndexOf("start \"\"", StringComparison.Ordinal));

        string portable = AppUpdater.ApplyScript(new PreparedUpdate(InstallKind.WindowsPortable, "v1.5.0", @"C:\u\p.zip", @"C:\u\portable\"), 1,
            @"D:\Tools\RecoverKit\", @"D:\Tools\RecoverKit\RecoverKit.exe");
        Assert.Contains(@"robocopy ""C:\u\portable"" ""D:\Tools\RecoverKit"" /E /IS /IT", portable);   // no trailing backslash before a quote

        string mac = AppUpdater.ApplyScript(new PreparedUpdate(InstallKind.MacBundle, "v1.5.0", "/u/x.dmg", "/u/RecoverKit.app"), 7,
            "/Applications/RecoverKit.app/Contents/MacOS/", "/Applications/RecoverKit.app/Contents/MacOS/RecoverKit");
        Assert.StartsWith("#!/bin/sh\n", mac);
        Assert.Contains("while kill -0 7 2>/dev/null; do sleep 1; done", mac);
        Assert.Contains("mv '/Applications/RecoverKit.app' '/Applications/RecoverKit.app.old' && mv '/u/RecoverKit.app' '/Applications/RecoverKit.app'", mac);
        Assert.Contains("open '/Applications/RecoverKit.app'", mac);

        Assert.Throws<InvalidOperationException>(() => AppUpdater.ApplyScript(new PreparedUpdate(InstallKind.Unknown, "v1", "f", null), 1, "/a", "/a/b"));
    }
}
