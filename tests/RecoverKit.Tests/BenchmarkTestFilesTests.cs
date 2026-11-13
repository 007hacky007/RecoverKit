using System.Text;
using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Native;
using Xunit;

namespace RecoverKit.Tests;

public class BenchmarkTestFilesTests
{
    [Fact]
    public void GeneratedFilesExtractToTheirMeasuredTargetsAndVerify()
    {
        var files = BenchmarkTestFiles.Create();
        Assert.Equal(15, files.Count);
        Assert.Equal(BenchmarkTestFiles.PublicFileNames.Order(), files.Select(f => f.FileName).Order());
        Assert.All(files.Where(f => f.FileName.Contains("check2")), f => Assert.Equal("2", f.Hash.Split('*')[1]));
        foreach (var file in files)
        {
            Assert.InRange(file.Content.Length, 100, 100_000);
            Assert.Equal(file.Hash, BenchmarkTestFiles.Extract(file.FileName, file.Content).HashLines);
            var kernel = NativeKernels.TryCreate(file.Mode, file.Hash);
            if (kernel is not null)
            {
                Assert.True(kernel.Verify(Encoding.ASCII.GetBytes(BenchmarkTestFiles.Password)), file.FileName);
                Assert.False(kernel.Verify("wrong"u8), file.FileName);
            }
        }
        Assert.Contains(files, f => f.Mode == 9400);
        Assert.Contains(files, f => f.Mode == 9600);
        Assert.Contains(files, f => f.Mode == 10700);
    }

    [Fact]
    public void ExportMatchesBytesAndDoesNotInventOrLeakRates()
    {
        string directory = Directory.CreateTempSubdirectory("rk-export-test-").FullName;
        try
        {
            var file = BenchmarkTestFiles.Create()[0];
            var report = new DiagnosticReport();
            report.Measurements.Add(new() { Section = "gpu", Mode = file.Mode, Correct = true, Speed = 12345, Length = 7,
                Target = file.FileName, Details = new() { ["Test file"] = file.FileName, ["Attack"] = BenchmarkTestFiles.Attack } });
            BenchmarkTestFiles.Export(directory, report);
            Assert.Equal(file.Content, File.ReadAllBytes(Path.Combine(directory, file.FileName)));
            string readme = File.ReadAllText(Path.Combine(directory, "readme.txt"));
            Assert.Contains(BenchmarkTestFiles.Password, readme);
            Assert.Contains("12345", readme);
            Assert.Contains("not measured", readme);
            Assert.Contains("RAR 3", readme);
            Assert.Contains("Other program candidates/s", File.ReadAllText(Path.Combine(directory, "results.csv")));
            string html = DiagnosticHtml.Render(report);
            Assert.DoesNotContain(BenchmarkTestFiles.Password, html);
            Assert.DoesNotContain(file.Hash, html);
            Assert.Contains("Compare with another program", html);
            Assert.Contains(file.FileName, html);
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public void DifferentAttackAndInvalidRowsCannotSupplyAComparisonRate()
    {
        var file = BenchmarkTestFiles.Create()[0];
        var report = new DiagnosticReport();
        report.Measurements.Add(new() { Mode = file.Mode, Correct = true, Speed = 999, Length = 8,
            Details = new() { ["Test file"] = file.FileName, ["Attack"] = "another mask" } });
        Assert.Null(BenchmarkTestFiles.Comparisons(report).First().Rate);
    }
    [Theory]
    [InlineData("client-secret-rk-pdf-r3.pdf")]
    [InlineData("rk-pdf-r3.pdf.backup")]
    [InlineData("/private/client/rk-pdf-r3.pdf")]
    public void CatalogNamesInsidePrivateNamesRemainPrivate(string value)
    {
        Assert.DoesNotContain("rk-pdf-r3.pdf", DiagnosticHtml.Scrub(value));
        Assert.Equal("rk-pdf-r3.pdf", DiagnosticHtml.Scrub("rk-pdf-r3.pdf"));
    }

    [Fact]
    public void ZipKernelProfileDoesNotApplyATwoByteChoiceToAOneByteFile()
    {
        var file = BenchmarkTestFiles.Create().First(f => f.FileName == "rk-zip-stored-small-check1.zip");
        var device = new RecoverKit.Core.Hashcat.BackendDevice { Id = 1, Type = "GPU", Key = "OpenCL|Synthetic GPU|0" };
        var profile = new PerformanceProfile { Decisions = [new() { Domain = "zip", Mode = 17210, Length = 7,
            Target = "synthetic ZIP stored, 17 bytes, check2", Engine = "gpu", Variant = "hashcat", DeviceKeys = [device.Key] }] };
        var settings = ProfileSettings.ForAttack(new RecoverKit.Core.Settings(), profile, [device], 17210, 7, file.Hash);
        Assert.Null(settings.ZipGpuPerformanceChoice);
    }

}
