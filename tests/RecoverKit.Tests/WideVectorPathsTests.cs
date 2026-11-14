using System.Text.Json;
using RecoverKit.Core.Diagnostics;
using Xunit;

namespace RecoverKit.Tests;

public sealed class WideVectorPathsTests
{
    [Fact]
    public void MatchingSamplesUseMedianAndSeparateSingleAndAllThreadRatios()
    {
        var report = Report();
        report.Measurements = [Row("avx2", 1, 100), Row("avx2", 1, 120), Row("avx2", 1, 110),
            Row("avx512", 1, 220), Row("avx2", 8, 600), Row("avx512", 8, 900)];
        var row = report.WideVectorPaths.Rows.Single(r => r.Mode == 12500);
        Assert.Equal(110d, row.SingleThread.Avx2.Median);
        Assert.Equal(100d, row.SingleThread.Avx2.Minimum);
        Assert.Equal(120d, row.SingleThread.Avx2.Maximum);
        Assert.Equal(3, row.SingleThread.Avx2.SampleCount);
        Assert.Equal(2d, row.SingleThread.Ratio);
        Assert.Equal(1.5d, row.AllThreads.Ratio);
        Assert.Equal("PASS", row.Correctness);
        Assert.Equal("passed", row.SelfTestState);
    }

    [Fact]
    public void RequestedAvx512FallbackFailsEvenWhenAnotherSamplePassed()
    {
        var report = Report();
        var fallback = Row("avx512", 1, 500);
        fallback.Details["actual path"] = "AVX2";
        report.Measurements = [Row("avx2", 1, 100), Row("avx512", 1, 200), fallback];
        var row = report.WideVectorPaths.Rows.Single(r => r.Mode == 12500);
        Assert.Equal("FAIL", row.SingleThread.Avx512.Status);
        Assert.Contains("AVX2", row.SingleThread.Avx512.Reason);
        Assert.Null(row.SingleThread.Avx512.Median);
        Assert.Null(row.SingleThread.Ratio);
        Assert.Equal("FAIL", row.Correctness);
        Assert.Contains("FAIL", WideSection(DiagnosticHtml.Render(report)));
    }

    [Theory]
    [InlineData("native AVX-512", "PASS")]
    [InlineData("native AVX2", "FAIL")]
    [InlineData("native AVX-512 / native AVX2", "FAIL")]
    [InlineData("", "FAIL")]
    public void ActualPathMustIdentifyOnlyTheRequestedPath(string actualPath, string expected)
    {
        var report = Report();
        var sample = Row("avx512", 1, 200);
        sample.Details["actual path"] = actualPath;
        report.Measurements = [sample];
        Assert.Equal(expected, report.WideVectorPaths.Rows[0].SingleThread.Avx512.Status);
    }

    [Theory]
    [InlineData("failed")]
    [InlineData("switched off")]
    public void FailedNativeGuardCannotBePresentedAsAValidatedRate(string state)
    {
        var report = Report();
        var sample = Row("avx512", 1, 200);
        sample.Details["self-test state"] = state;
        report.Measurements = [sample];
        var path = report.WideVectorPaths.Rows[0].SingleThread.Avx512;
        Assert.Equal("FAIL", path.Status);
        Assert.Contains(state, path.Reason);
        Assert.Null(path.Median);
    }

    [Theory]
    [InlineData("failed")]
    [InlineData("switched off")]
    public void WideGuardFailureDoesNotInvalidateAvx2Baseline(string state)
    {
        var report = Report();
        var baseline = Row("avx2", 1, 100);
        baseline.Details["self-test state"] = state;
        report.Measurements = [baseline, Row("avx512", 1, 200)];
        var row = report.WideVectorPaths.Rows[0];
        Assert.Equal("PASS", row.SingleThread.Avx2.Status);
        Assert.Equal(100d, row.SingleThread.Avx2.Median);
        Assert.Equal(2d, row.SingleThread.Ratio);
        Assert.Equal("passed", row.SelfTestState);
    }

    [Fact]
    public void CorrectnessOnlyRowsDoNotSupplyTimingWorkloadOrObscureWideWorkerState()
    {
        var report = Report();
        var check = Row("avx2", 0, 0);
        check.Target = "correctness only";
        check.Details["self-test state"] = "not run";
        var baseline = Row("avx2", 1, 100);
        baseline.Details["self-test state"] = "not run";
        report.Measurements = [check, baseline, Row("avx512", 1, 200)];
        var row = report.WideVectorPaths.Rows[0];
        Assert.Equal(2d, row.SingleThread.Ratio);
        Assert.Equal("synthetic", row.Target);
        Assert.Equal("passed", row.SelfTestState);
        Assert.NotEqual("FAIL", row.Correctness);
    }

    [Fact]
    public void IntermediateThreadFallbackKeepsKernelFailedDespiteValidEndpointRates()
    {
        var report = Report();
        report.System["Logical threads"] = "16";
        var fallback = Row("avx512", 8, 500);
        fallback.Details["actual path"] = "native AVX2";
        report.Measurements = [Row("avx2", 1, 100), Row("avx512", 1, 200),
            Row("avx2", 16, 1000), Row("avx512", 16, 2000), fallback];
        var row = report.WideVectorPaths.Rows[0];
        Assert.Equal("FAIL", row.Correctness);
        Assert.Equal(2d, row.SingleThread.Ratio);
        Assert.Equal(2d, row.AllThreads.Ratio);
    }

    [Theory]
    [InlineData(false, "passed")]
    [InlineData(true, "failed")]
    public void FailedCorrectnessOnlyRequestKeepsKernelFailed(bool correct, string state)
    {
        var report = Report();
        var check = Row("avx512", 0, 0);
        check.Correct = correct;
        check.Details["self-test state"] = state;
        report.Measurements = [check, Row("avx2", 1, 100), Row("avx512", 1, 200)];
        var row = report.WideVectorPaths.Rows[0];
        Assert.Equal("FAIL", row.Correctness);
        Assert.Equal(2d, row.SingleThread.Ratio);
    }

    [Fact]
    public void PassingCorrectnessOnlyRequestIsNotATimingFailure()
    {
        var report = Report();
        report.Measurements = [Row("avx512", 0, 0)];
        var row = report.WideVectorPaths.Rows[0];
        Assert.Equal("not measured", row.Correctness);
        Assert.Null(row.SingleThread.Avx512.Median);
        Assert.Null(row.AllThreads.Avx512.Median);
    }

    [Theory]
    [InlineData(false, null, 100d)]
    [InlineData(true, "worker failed", 100d)]
    [InlineData(true, null, 0d)]
    [InlineData(true, null, double.NaN)]
    public void FailedOrInvalidSamplesCannotBeRescuedByPassingRepeats(bool correct, string? error, double speed)
    {
        var report = Report();
        var bad = Row("avx512", 1, speed);
        bad.Correct = correct;
        bad.Error = error;
        report.Measurements = [Row("avx512", 1, 200), bad];
        var path = report.WideVectorPaths.Rows.Single(r => r.Mode == 12500).SingleThread.Avx512;
        Assert.Equal("FAIL", path.Status);
        Assert.False(string.IsNullOrWhiteSpace(path.Reason));
        Assert.Null(path.Median);
    }

    [Theory]
    [InlineData("other target", 7)]
    [InlineData("synthetic", 8)]
    public void DifferentTargetsOrLengthsAreNotCompared(string target, int length)
    {
        var report = Report();
        var other = Row("avx512", 1, 200);
        other.Target = target;
        other.Length = length;
        report.Measurements = [Row("avx2", 1, 100), other];
        var comparison = report.WideVectorPaths.Rows.Single(r => r.Mode == 12500).SingleThread;
        Assert.Null(comparison.Ratio);
        Assert.Null(comparison.Avx512.Median);
        Assert.Equal("not measured", comparison.Avx512.Status);
        Assert.Contains("matching target and length", comparison.Avx512.Reason);
    }

    [Fact]
    public void UnsupportedAvx512HasOneNoteAndNoEmptyKernelRowsInHtmlOrJson()
    {
        var report = Report();
        report.System["AVX-512 available"] = "False";
        var summary = report.WideVectorPaths;
        Assert.False(summary.Avx512Available);
        Assert.Empty(summary.Rows);
        Assert.NotNull(summary.Note);
        string html = DiagnosticHtml.Render(report);
        Assert.Equal("<h2>Wide vector paths</h2><p>" + summary.Note + "</p>", WideSection(html));
        using var json = EmbeddedJson(html);
        Assert.Empty(json.RootElement.GetProperty("WideVectorPaths").GetProperty("Rows").EnumerateArray());
        Assert.Equal(summary.Note, json.RootElement.GetProperty("WideVectorPaths").GetProperty("Note").GetString());
    }

    [Fact]
    public void PhysicalCoreSamplesDoNotPretendToBeAllLogicalThreads()
    {
        var report = Report();
        report.Measurements = [Row("avx2", 4, 400), Row("avx512", 4, 800)];
        var row = report.WideVectorPaths.Rows.Single(r => r.Mode == 12500);
        Assert.Equal(8, row.AllThreads.Threads);
        Assert.Equal("not measured", row.AllThreads.Avx2.Status);
        Assert.Null(row.AllThreads.Ratio);
        Assert.All(report.WideVectorPaths.Rows, r => Assert.Equal("not measured", r.Correctness));
    }

    [Fact]
    public void NumericThreadBudgetUsesItsActualCountAndExplicitLabel()
    {
        var report = Report();
        report.System["CPU thread budget"] = "4";
        report.Measurements = [Row("avx2", 4, 400), Row("avx512", 4, 600)];
        var row = report.WideVectorPaths.Rows.Single(r => r.Mode == 12500);
        Assert.Equal(4, row.AllThreads.Threads);
        Assert.Equal(1.5d, row.AllThreads.Ratio);
        Assert.Contains("4 threads (budget cap)", WideSection(DiagnosticHtml.Render(report)));
    }

    [Fact]
    public void MissingLogicalCountDoesNotGuessFromAvailableSamples()
    {
        var report = Report();
        report.System.Remove("Logical threads");
        report.Measurements = [Row("avx2", 4, 400), Row("avx512", 4, 800)];
        Assert.Null(report.WideVectorPaths.Rows[0].AllThreads.Threads);
        Assert.Null(report.WideVectorPaths.Rows[0].AllThreads.Ratio);
    }

    [Fact]
    public void OneLogicalThreadCanUseTheSameSamplesInBothColumns()
    {
        var report = Report();
        report.System["Logical threads"] = "1";
        report.Measurements = [Row("avx2", 1, 100), Row("avx512", 1, 200)];
        var row = report.WideVectorPaths.Rows[0];
        Assert.Equal(2d, row.SingleThread.Ratio);
        Assert.Equal(row.SingleThread, row.AllThreads);
    }

    [Fact]
    public void WorkerSelfTestStateOverridesParentStateAndZipHasNoNativeGuard()
    {
        var report = Report();
        report.System["RAR3 self-test state"] = "not run";
        report.Measurements = [Row("avx2", 1, 100), Row("avx512", 1, 200)];
        Assert.Equal("passed", report.WideVectorPaths.Rows[0].SelfTestState);
        Assert.All(report.WideVectorPaths.Rows.Where(r => r.Mode is 17200 or 17210),
            r => Assert.Equal("no native guard; diagnostic check only", r.SelfTestState));
    }

    [Fact]
    public void AlternateStoredFixtureIsExcluded()
    {
        var report = Report();
        var alternate = Row("avx512", 1, 1000, 17210);
        alternate.Target = "published ZIP stored 453-byte fixture";
        alternate.Correct = false;
        report.Measurements = [Row("avx2", 1, 100, 17210), Row("avx512", 1, 200, 17210), alternate];
        var comparison = report.WideVectorPaths.Rows.Single(r => r.Mode == 17210).SingleThread;
        Assert.Equal("PASS", comparison.Avx512.Status);
        Assert.Equal(2d, comparison.Ratio);
    }

    [Fact]
    public void HtmlAndMachineJsonShareRatesRatiosAndUnmeasuredState()
    {
        var report = Report();
        report.Measurements = [Row("avx2", 1, 100), Row("avx512", 1, 250)];
        string html = DiagnosticHtml.Render(report);
        using var json = EmbeddedJson(html);
        var row = json.RootElement.GetProperty("WideVectorPaths").GetProperty("Rows")[0];
        Assert.Equal(250d, row.GetProperty("SingleThread").GetProperty("Avx512").GetProperty("Median").GetDouble());
        Assert.Equal(2.5d, row.GetProperty("SingleThread").GetProperty("Ratio").GetDouble());
        Assert.Equal(JsonValueKind.Null, row.GetProperty("AllThreads").GetProperty("Avx512").GetProperty("Median").ValueKind);
        string section = WideSection(html);
        Assert.Contains("250.0", section);
        Assert.Contains("2.50x", section);
        Assert.Contains("not measured", section);
    }

    private static DiagnosticReport Report() => new()
    {
        System = new() { ["Logical threads"] = "8", ["AVX-512 available"] = "True" },
    };

    private static DiagnosticMeasurement Row(string variant, int threads, double speed, int mode = 12500) => new()
    {
        Section = "cpu", Mode = mode, Variant = variant, Threads = threads, Correct = true, Speed = speed,
        Target = "synthetic", Length = 7, Repeat = 1,
        Details = new() { ["actual path"] = variant.ToUpperInvariant(), ["self-test state"] = "passed" },
    };

    private static string WideSection(string html)
    {
        int start = html.IndexOf("<h2>Wide vector paths</h2>", StringComparison.Ordinal);
        int end = html.IndexOf("<h2>", start + 1, StringComparison.Ordinal);
        return html[start..end];
    }

    private static JsonDocument EmbeddedJson(string html)
    {
        const string opening = "<script id=\"recoverkit-results\" type=\"application/json\">";
        int start = html.IndexOf(opening, StringComparison.Ordinal) + opening.Length;
        return JsonDocument.Parse(html[start..html.IndexOf("</script>", start, StringComparison.Ordinal)]);
    }
}
