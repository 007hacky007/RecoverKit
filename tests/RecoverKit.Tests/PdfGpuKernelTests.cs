using RecoverKit.Core.Hashcat;
using Xunit;

namespace RecoverKit.Tests;

public class PdfGpuKernelTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void OnlyKnownOriginalsAreReplacedAndRestored(bool crlf)
    {
        string dir = Directory.CreateTempSubdirectory("rk-pdf-install-").FullName;
        try
        {
            var ocl = Directory.CreateDirectory(Path.Combine(dir, "OpenCL")).FullName;
            var originals = new Dictionary<string, string>();
            foreach (string name in new[] { "m10500-pure.cl", "m10510-pure.cl" })
            {
                string source = "// original " + name + "\n";
                originals[name] = HashcatKernels.Hash(source);
                File.WriteAllText(Path.Combine(ocl, name), crlf ? source.Replace("\n", "\r\n") : source);
            }
            var before = originals.Keys.ToDictionary(n => n, n => File.ReadAllBytes(Path.Combine(ocl, n)));
            Assert.True(PdfHashcatKernels.Install(dir, originals));
            foreach (var (name, source) in PdfHashcatKernels.Sources)
            {
                Assert.Equal(source, File.ReadAllText(Path.Combine(ocl, name)));
                Assert.Equal(before[name], File.ReadAllBytes(Path.Combine(ocl, name + ".hashcat")));
            }
            Assert.True(PdfHashcatKernels.Restore(dir, originals));
            foreach (var (name, bytes) in before) Assert.Equal(bytes, File.ReadAllBytes(Path.Combine(ocl, name)));

            File.WriteAllText(Path.Combine(ocl, "m10500-pure.cl"), "// " + HashcatKernels.Marker + " - older version\n");
            Assert.True(PdfHashcatKernels.Install(dir, originals));
            Assert.Equal(PdfHashcatKernels.Sources["m10500-pure.cl"], File.ReadAllText(Path.Combine(ocl, "m10500-pure.cl")));
            Assert.True(PdfHashcatKernels.Restore(dir, originals));

            // Unknown source bytes are never overwritten.
            File.WriteAllText(Path.Combine(ocl, "m10500-pure.cl"), "// another version");
            Assert.False(PdfHashcatKernels.Install(dir, originals));
            Assert.Equal("// another version", File.ReadAllText(Path.Combine(ocl, "m10500-pure.cl")));
            File.WriteAllBytes(Path.Combine(ocl, "m10500-pure.cl"), before["m10500-pure.cl"]);

            // A bad file in another mode cannot strand this verified replacement on opt-out.
            File.WriteAllText(Path.Combine(ocl, "m10510-pure.cl"), "// another version");
            Assert.True(PdfHashcatKernels.Install(dir, originals));
            Assert.True(PdfHashcatKernels.Restore(dir, originals));
            Assert.Equal(before["m10500-pure.cl"], File.ReadAllBytes(Path.Combine(ocl, "m10500-pure.cl")));
            Assert.False(PdfHashcatKernels.Restore(dir, originals));
            Assert.Equal("// another version", File.ReadAllText(Path.Combine(ocl, "m10510-pure.cl")));

            File.WriteAllBytes(Path.Combine(ocl, "m10510-pure.cl"), before["m10510-pure.cl"]);
            File.WriteAllText(Path.Combine(ocl, "m10500-pure.cl.hashcat"), "// corrupt backup");
            Assert.False(PdfHashcatKernels.Install(dir, originals));
            Assert.Equal(before["m10500-pure.cl"], File.ReadAllBytes(Path.Combine(ocl, "m10500-pure.cl")));

            File.WriteAllText(Path.Combine(ocl, "m10500-pure.cl"), PdfHashcatKernels.Sources["m10500-pure.cl"]);
            Assert.False(PdfHashcatKernels.Restore(dir, originals));
            Assert.Equal(PdfHashcatKernels.Sources["m10500-pure.cl"], File.ReadAllText(Path.Combine(ocl, "m10500-pure.cl")));
        }
        finally { Directory.Delete(dir, true); }
    }
}
