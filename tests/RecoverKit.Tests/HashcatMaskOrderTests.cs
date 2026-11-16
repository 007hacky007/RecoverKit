using System.Text;
using RecoverKit.Core.Attacks;
using Xunit;

namespace RecoverKit.Tests;

public sealed class HashcatMaskOrderTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("rk-crt").FullName;

    [Theory]
    [InlineData("api-ms-win-crt-utility-l1-1-0.dll", "ucrtbase.dll")]
    [InlineData("api-ms-win-crt-stdlib-l1-1-0.dll", "ucrtbase.dll")]
    [InlineData("API-MS-WIN-CRT-UTILITY-L1-1-0.DLL", "ucrtbase.dll")]
    [InlineData("ucrtbase.dll", "ucrtbase.dll")]
    [InlineData("msvcrt.dll", "msvcrt.dll")]
    [InlineData("other-crt.dll", null)]
    public void FollowsImportedSiblingToQsortProvider(string provider, string? expected)
    {
        string exe = WritePe("hashcat.exe", true, false, ("engine.dll", "hashcat_init"), ("ucrtbase.dll", "malloc"));
        WritePe("engine.dll", true, false, (provider, "qsort_s"), (provider, "qsort"));
        Assert.Equal(expected, HashcatMaskOrder.ImportedCrt(exe));
    }

    [Theory]
    [InlineData("msvcrt.dll", false, false, "msvcrt.dll")]
    [InlineData("MSVCRT.DLL", true, true, "msvcrt.dll")]
    [InlineData("ucrtbase.dll", true, false, "ucrtbase.dll")]
    [InlineData("api-ms-win-crt-utility-l1-1-0.dll", false, true, "ucrtbase.dll")]
    [InlineData("other-crt.dll", true, false, null)]
    public void DirectImportsSelectTheQsortRuntime(string provider, bool wide, bool addressOnly, string? expected)
    {
        string exe = WritePe("hashcat.exe", wide, addressOnly, ("ucrtbase.dll", "malloc"), (provider, "qsort"));
        Assert.Equal(expected, HashcatMaskOrder.ImportedCrt(exe));
    }

    [Fact]
    public void DoesNotGuessFromUnimportedDllOrOtherCrtFunctions()
    {
        string exe = WritePe("hashcat.exe", true, false, ("ucrtbase.dll", "qsort_s"));
        WritePe("hashcat.dll", true, false, ("msvcrt.dll", "qsort"));
        Assert.Null(HashcatMaskOrder.ImportedCrt(exe));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void UnreadableFileKeepsFallback(bool sibling)
    {
        string path = Path.Combine(_directory, "broken.dll");
        string exe = sibling ? WritePe("hashcat.exe", true, false, ("broken.dll", "hashcat_init")) : path;
        Assert.Null(HashcatMaskOrder.ImportedCrt(exe));
        File.WriteAllText(path, "not a PE file");
        Assert.Null(HashcatMaskOrder.ImportedCrt(exe));
    }

    // A single .idata section with named imports; no executable code or external fixtures needed.
    private string WritePe(string name, bool wide, bool addressOnly, params (string Library, string Function)[] imports)
    {
        var bytes = new byte[4096];
        using var stream = new MemoryStream(bytes);
        using var writer = new BinaryWriter(stream, Encoding.ASCII, leaveOpen: true);
        writer.Write((ushort)0x5a4d); // MZ
        stream.Position = 0x3c;
        writer.Write(0x80);
        stream.Position = 0x80;
        writer.Write(0x00004550); // PE
        writer.Write((ushort)(wide ? 0x8664 : 0x14c));
        writer.Write((ushort)1); // section count
        stream.Position = 0x94;
        int optionalSize = wide ? 240 : 224;
        writer.Write((ushort)optionalSize);
        writer.Write((ushort)2);
        writer.Write((ushort)(wide ? 0x20b : 0x10b));
        stream.Position = 0x98 + 32;
        writer.Write(0x1000); // section alignment
        writer.Write(0x200); // file alignment
        stream.Position = 0x98 + 56;
        writer.Write(0x2000); // image size
        writer.Write(0x200); // header size
        stream.Position = 0x98 + (wide ? 108 : 92);
        writer.Write(16); // data directory count
        stream.Position += 8; // export directory
        writer.Write(0x1000); // import directory RVA
        writer.Write((imports.Length + 1) * 20);
        stream.Position = 0x98 + optionalSize;
        writer.Write(Encoding.ASCII.GetBytes(".idata\0\0"));
        writer.Write(0x1000); // virtual size
        writer.Write(0x1000); // virtual address
        writer.Write(bytes.Length - 0x200); // raw size
        writer.Write(0x200); // raw offset
        for (int i = 0; i < imports.Length; i++)
        {
            int data = 0x400 + i * 256;
            int thunk = data - 0x200 + 0x1000;
            stream.Position = 0x200 + i * 20;
            writer.Write(addressOnly ? 0 : thunk);
            writer.Write(0L);
            writer.Write(thunk + 32);
            writer.Write(thunk);
            stream.Position = data;
            if (wide) writer.Write((ulong)(thunk + 128));
            else writer.Write(thunk + 128);
            stream.Position = data + 32;
            writer.Write(Encoding.ASCII.GetBytes(imports[i].Library + "\0"));
            stream.Position = data + 128;
            writer.Write((ushort)0); // hint
            writer.Write(Encoding.ASCII.GetBytes(imports[i].Function + "\0"));
        }
        string path = Path.Combine(_directory, name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    public void Dispose() => Directory.Delete(_directory, true);
}
