using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace RecoverKit.Core.Attacks;

internal static class HashcatMaskOrder
{
    private static readonly Lazy<int[]> UnixOrder = new(() => Sort(OperatingSystem.IsMacOS() ? "/usr/lib/libSystem.B.dylib" : "libc.so.6"));

    public static int[]? TryGet(string? executable)
    {
        if (!OperatingSystem.IsWindows())
        {
            if (!OperatingSystem.IsMacOS() && executable is not null && !UsesSystemGlibc(executable)) return null;
            try { return UnixOrder.Value; }
            catch (DllNotFoundException) { return null; }
        }
        // Official builds put qsort in a sibling DLL; MinGW builds can import it directly.
        string? crt = executable is null ? "ucrtbase.dll" : ImportedCrt(executable);
        try { return crt is null ? null : Sort(crt); }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException) { return null; }
    }

    private static unsafe int[] Sort(string library)
    {
        nint handle = NativeLibrary.Load(library, Assembly.GetExecutingAssembly(), DllImportSearchPath.System32);
        try
        {
            var sort = (delegate* unmanaged[Cdecl]<void*, nuint, nuint, delegate* unmanaged[Cdecl]<void*, void*, int>, void>)NativeLibrary.GetExport(handle, "qsort");
            // mpsp.c sorts all 256 {u32 key, u64 value} records before filtering the charset.
            // --markov-disable zeros every value. Equal-key order comes from the linked CRT's qsort.
            var records = stackalloc ulong[512];
            for (int i = 0; i < 256; i++) { records[2 * i] = (uint)i; records[2 * i + 1] = 0; }
            sort(records, 256, 16, &Compare);
            var ranks = new int[256];
            for (int i = 0; i < 256; i++) ranks[(uint)records[2 * i]] = i;
            return ranks;
        }
        finally { NativeLibrary.Free(handle); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe int Compare(void* left, void* right) => 0;

    internal static string? ImportedCrt(string executable)
    {
        try
        {
            var imports = ReadImports(executable);
            if (imports.FirstOrDefault(i => i.Qsort) is { Qsort: true } direct) return Runtime(direct.Library);
            string directory = Path.GetDirectoryName(Path.GetFullPath(executable))!;
            foreach (var import in imports)
            {
                // Inspect only imported libraries beside the exe, never load them into this process.
                if (!import.Library.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || import.Library.IndexOfAny(['/', '\\', ':']) >= 0) continue;
                string sibling = Path.Combine(directory, import.Library);
                if (File.Exists(sibling) && ReadImports(sibling).FirstOrDefault(i => i.Qsort) is { Qsort: true } provider)
                    return Runtime(provider.Library);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or BadImageFormatException or ArgumentOutOfRangeException or OverflowException) { }
        return null;

        static string? Runtime(string library) => library.Equals("msvcrt.dll", StringComparison.OrdinalIgnoreCase) ? "msvcrt.dll"
            : library.Equals("ucrtbase.dll", StringComparison.OrdinalIgnoreCase)
                || library.StartsWith("api-ms-win-crt-", StringComparison.OrdinalIgnoreCase) && library.EndsWith("-l1-1-0.dll", StringComparison.OrdinalIgnoreCase)
                ? "ucrtbase.dll" : null;
    }

    private static List<(string Library, bool Qsort)> ReadImports(string path)
    {
        using var file = File.OpenRead(path);
        using var pe = new PEReader(file);
        var header = pe.PEHeaders.PEHeader;
        if (header is null || header.ImportTableDirectory.Size == 0) return [];
        var imports = pe.GetSectionData(header.ImportTableDirectory.RelativeVirtualAddress).GetReader(0, header.ImportTableDirectory.Size);
        var result = new List<(string Library, bool Qsort)>();
        while (imports.RemainingBytes >= 20)
        {
            uint thunk = imports.ReadUInt32();
            imports.ReadUInt64(); // timestamp and forwarder chain
            int name = imports.ReadInt32();
            uint address = imports.ReadUInt32();
            if (name == 0) return result;
            string dll = ReadName(pe, name);
            var functions = pe.GetSectionData(checked((int)(thunk == 0 ? address : thunk))).GetReader();
            bool wide = header.Magic == PEMagic.PE32Plus;
            bool qsort = false, terminated = false;
            while (functions.RemainingBytes >= (wide ? 8 : 4))
            {
                ulong function = wide ? functions.ReadUInt64() : functions.ReadUInt32();
                if (function == 0) { terminated = true; break; }
                if ((function & (wide ? 1UL << 63 : 1UL << 31)) != 0) continue;
                if (ReadName(pe, checked((int)function + 2)) == "qsort") qsort = true;
            }
            if (!terminated) throw new BadImageFormatException("Unterminated import lookup table.");
            result.Add((dll, qsort));
        }
        throw new BadImageFormatException("Unterminated import directory.");
    }

    private static string ReadName(PEReader pe, int rva)
    {
        var bytes = pe.GetSectionData(rva).GetContent().AsSpan();
        int end = bytes.IndexOf((byte)0);
        if (end < 0) throw new BadImageFormatException("Unterminated import name.");
        return Encoding.ASCII.GetString(bytes[..end]);
    }

    internal static bool UsesSystemGlibc(string executable)
    {
        // A static or musl hashcat can have a different qsort; leave its masks to hashcat.
        try
        {
            using var file = File.OpenRead(executable);
            var header = new byte[64];
            file.ReadExactly(header);
            if (!header.AsSpan(0, 6).SequenceEqual(new byte[] { 0x7f, (byte)'E', (byte)'L', (byte)'F', 2, 1 })) return false;
            long offset = checked((long)BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(32)));
            int size = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(54));
            int count = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(56));
            if (size < 56 || size > 4096 || count > 4096) return false;
            var entry = new byte[56];
            for (int i = 0; i < count; i++)
            {
                file.Position = checked(offset + (long)i * size);
                file.ReadExactly(entry);
                if (BinaryPrimitives.ReadUInt32LittleEndian(entry) != 3) continue; // PT_INTERP
                long start = checked((long)BinaryPrimitives.ReadUInt64LittleEndian(entry.AsSpan(8)));
                int length = checked((int)BinaryPrimitives.ReadUInt64LittleEndian(entry.AsSpan(32)));
                if (length is < 1 or > 4096) return false;
                file.Position = start;
                var path = new byte[length];
                file.ReadExactly(path);
                return Encoding.ASCII.GetString(path).TrimEnd('\0').Split('/').Last().StartsWith("ld-linux-", StringComparison.Ordinal);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or OverflowException or ArgumentOutOfRangeException) { }
        return false;
    }
}
