using System.Buffers.Binary;
using System.Security.Cryptography;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;

namespace RecoverKit.Core.Diagnostics;

/// <summary>Independent digest checks for every real lane, including a partial second batch.</summary>
internal static unsafe class WideCpuChecks
{
    internal static CpuDiagnostics.CorrectnessResult Check(int mode)
    {
        if (mode is 9400 or 9500 or 9600) return CheckOffice(mode);
        if (mode is 13600 or 22000) return CheckPbkdf2Sha1();
        if (TrueCryptSha512Kernel.SupportsMode(mode)) return CheckPbkdf2Sha512();
        if (mode == 29331) return CheckWhirlpool();
        int cases = 0;
        int width = mode == 12500 ? RkNative.Rar3Lanes() : RkNative.Pbkdf2Sha256Lanes();
        int n = width + 3;
        byte[] salt = Convert.FromHexString(mode == 12500 ? "45109af8ab5f297a" : "38466361001011015181344360681307");
        foreach (int length in mode == 12500 ? new[] { 1, 7, 26 } : new[] { 1, 7, 65 })
        {
            var passwords = new byte[n * length];
            for (int i = 0; i < n; i++)
                for (int q = 0; q < length; q++) passwords[i * length + q] = (byte)(33 + i * 17 + q * 7);
            int stride = mode == 12500 ? 36 : 32;
            var actual = new byte[n * stride];
            fixed (byte* p = passwords, s = salt, o = actual)
            {
                int code = mode == 12500 ? RkNative.Rar3Hash(s, p, length, n, o)
                    : RkNative.Pbkdf2Sha256(p, length, null, n, s, salt.Length, 32768 + 32, o, 32);
                if (code != 0) return new(false, cases, "Native lane check rejected the request.");
            }
            for (int i = 0; i < n; i++)
            {
                byte[] expected = mode == 12500 ? Rar3Reference(passwords.AsSpan(i * length, length), salt)
                    : Rfc2898DeriveBytes.Pbkdf2(passwords.AsSpan(i * length, length), salt, 32768 + 32, HashAlgorithmName.SHA256, 32);
                cases++;
                if (!expected.AsSpan().SequenceEqual(actual.AsSpan(i * stride, stride)))
                    return new(false, cases, $"Native digest/IV differs from the reference at length {length}, batch position {i}.");
            }
        }
        if (mode == 13000)
        {
            // All positions are real matches; a filter that loses a lane cannot hide behind confirmation.
            byte[] pws = Enumerable.Range(0, n).SelectMany(_ => "hashcat"u8.ToArray()).ToArray();
            byte[] check = Convert.FromHexString("cc7a30583e62676a");
            int[] hits = new int[n];
            fixed (byte* p = pws, s = salt, c = check)
            fixed (int* h = hits)
                if (RkNative.Rar5Search(s, 15, c, p, 7, n, h, n) != n || !hits.SequenceEqual(Enumerable.Range(0, n)))
                    return new(false, cases, "RAR 5 filter lost or reordered matching batch positions.");
            cases += n;
        }
        return new(true, cases);
    }

    private static CpuDiagnostics.CorrectnessResult CheckOffice(int mode)
    {
        const int stride = 512;
        int n = Math.Max(9, (mode == 9400 ? RkNative.Office2007Lanes() : RkNative.OfficeAgileLanes(mode)) + 3), cases = 0;
        int hashBytes = mode == 9600 ? 64 : 20;
        uint spins = mode == 9400 ? 50000u : 100000u;
        int[] sizes = [0, 2, 14, 54, 56, 110, 128, 256, 512];
        int[] lengths = Enumerable.Range(0, n).Select(i => sizes[i % sizes.Length]).ToArray();
        byte[] passwords = new byte[n * stride];
        for (int i = 0; i < passwords.Length; i += 2)
        {
            passwords[i] = (byte)(33 + i * 17);
            passwords[i + 1] = (byte)(i % 7);
        }
        byte[] salt = Convert.FromHexString("e6773b8ca35c5e57d61e2d3a4d634566");
        byte[] actual = new byte[n * hashBytes];
        fixed (byte* p = passwords, s = salt, o = actual)
        fixed (int* lens = lengths)
            if ((mode == 9400 ? RkNative.Office2007Spin(p, stride, lens, n, s, o)
                : RkNative.OfficeAgileSpin(mode, p, stride, lens, n, s, spins, o)) != 0)
                return new(false, cases, $"Native Office mode {mode} rejected the lane check.");
        Span<byte> digest = stackalloc byte[hashBytes];
        Span<byte> round = stackalloc byte[4 + hashBytes];
        for (int i = 0; i < n; i++)
        {
            byte[] input = [.. salt, .. passwords.AsSpan(i * stride, lengths[i])];
            if (mode == 9600) SHA512.HashData(input, digest);
            else SHA1.HashData(input, digest);
            for (int counter = 0; counter < spins; counter++)
            {
                BinaryPrimitives.WriteInt32LittleEndian(round, counter);
                digest.CopyTo(round[4..]);
                if (mode == 9600) SHA512.HashData(round, digest);
                else SHA1.HashData(round, digest);
            }
            cases++;
            if (!digest.SequenceEqual(actual.AsSpan(i * hashBytes, hashBytes)))
                return new(false, cases, $"Office mode {mode} spin hash differs from the reference at batch position {i}, UTF-16LE length {lengths[i]}.");
        }
        return new(true, cases);
    }

    private static CpuDiagnostics.CorrectnessResult CheckPbkdf2Sha1()
    {
        const int stride = 80, iterations = 17;
        int n = Math.Max(9, RkNative.Pbkdf2Sha1Lanes() + 3), cases = 0;
        int[] sizes = [0, 1, 7, 8, 55, 63, 64, 65, 80];
        int[] lengths = Enumerable.Range(0, n).Select(i => sizes[i % sizes.Length]).ToArray();
        byte[] passwords = new byte[n * stride];
        for (int i = 0; i < passwords.Length; i++) passwords[i] = (byte)(33 + i * 17);
        foreach (int saltLength in new[] { 0, 16, 32, 60 })
        {
            byte[] salt = Enumerable.Range(0, saltLength).Select(i => (byte)(i * 7)).ToArray();
            foreach (int dkLength in new[] { 32, 66 })
            {
                byte[] actual = new byte[n * dkLength];
                fixed (byte* p = passwords, s = salt, o = actual)
                fixed (int* lens = lengths)
                    if (RkNative.Pbkdf2Sha1(p, stride, lens, n, s, salt.Length, iterations, o, dkLength) != 0)
                        return new(false, cases, "Native PBKDF2 SHA-1 rejected the lane check.");
                for (int i = 0; i < n; i++)
                {
                    var expected = Rfc2898DeriveBytes.Pbkdf2(passwords.AsSpan(i * stride, lengths[i]), salt, iterations, HashAlgorithmName.SHA1, dkLength);
                    cases++;
                    if (!expected.AsSpan().SequenceEqual(actual.AsSpan(i * dkLength, dkLength)))
                        return new(false, cases, $"PBKDF2 SHA-1 differs from the reference at batch position {i}, password length {lengths[i]}, output length {dkLength}.");
                }
            }
            foreach (uint block in new uint[] { 1, 2, 4 })
            {
                byte[] actual = new byte[n * 20];
                fixed (byte* p = passwords, s = salt, o = actual)
                fixed (int* lens = lengths)
                    if (RkNative.Pbkdf2Sha1Block(p, stride, lens, n, s, salt.Length, iterations, block, o) != 0)
                        return new(false, cases, "Native PBKDF2 SHA-1 rejected the selected-block check.");
                for (int i = 0; i < n; i++)
                {
                    var expected = Rfc2898DeriveBytes.Pbkdf2(passwords.AsSpan(i * stride, lengths[i]), salt, iterations, HashAlgorithmName.SHA1, (int)block * 20);
                    cases++;
                    if (!expected.AsSpan(expected.Length - 20).SequenceEqual(actual.AsSpan(i * 20, 20)))
                        return new(false, cases, $"PBKDF2 SHA-1 block {block} differs from the reference at batch position {i}.");
                }
            }
        }
        return new(true, cases);
    }

    private static CpuDiagnostics.CorrectnessResult CheckPbkdf2Sha512()
    {
        const int stride = 129;
        int n = Math.Max(9, RkNative.Pbkdf2Sha512Lanes() + 3), cases = 0;
        int[] sizes = [0, 1, 7, 63, 64, 111, 127, 128, 129];
        int[] lengths = Enumerable.Range(0, n).Select(i => sizes[i % sizes.Length]).ToArray();
        byte[] passwords = new byte[n * stride];
        new Random(29321).NextBytes(passwords);
        foreach (int saltLength in new[] { 0, 64, 108, 112, 128 })
        foreach (int dkLength in new[] { 64, 128, 192 })
        {
            byte[] salt = Enumerable.Range(0, saltLength).Select(i => (byte)(i * 7)).ToArray();
            byte[] actual = new byte[n * dkLength];
            fixed (byte* p = passwords, s = salt, o = actual)
            fixed (int* lens = lengths)
                if (RkNative.Pbkdf2Sha512(p, stride, lens, n, s, salt.Length, 17, o, dkLength) != n)
                    return new(false, cases, "Native PBKDF2 SHA-512 rejected the lane check.");
            for (int i = 0; i < n; i++)
            {
                var expected = Rfc2898DeriveBytes.Pbkdf2(passwords.AsSpan(i * stride, lengths[i]), salt, 17, HashAlgorithmName.SHA512, dkLength);
                cases++;
                if (!expected.AsSpan().SequenceEqual(actual.AsSpan(i * dkLength, dkLength)))
                    return new(false, cases, $"PBKDF2 SHA-512 differs at batch position {i}, password length {lengths[i]}, salt length {saltLength}, output length {dkLength}.");
            }
        }
        return new(true, cases);
    }

    private static CpuDiagnostics.CorrectnessResult CheckWhirlpool()
    {
        const int n = 11; // One complete AVX-512 group and a partial second group.
        int cases = 0;
        byte[] salt = Enumerable.Range(0, 64).Select(q => (byte)q).ToArray();
        foreach (int length in new[] { 0, 1, 7, 64 })
        {
            var passwords = new byte[n * length];
            for (int i = 0; i < n; i++)
                for (int q = 0; q < length; q++) passwords[i * length + q] = (byte)(33 + i * 17 + q * 7);
            var actual = new byte[n * 64];
            fixed (byte* p = passwords, s = salt, o = actual)
                if (RkNative.WhirlpoolPbkdf2(s, p, length, n, o) != n)
                    return new(false, cases, "Native Whirlpool rejected the request.");
            for (int i = 0; i < n; i++)
            {
                cases++;
                if (!TrueCryptWhirlpoolKernel.Derive(passwords.AsSpan(i * length, length), salt).AsSpan().SequenceEqual(actual.AsSpan(i * 64, 64)))
                    return new(false, cases, $"Whirlpool key differs from the reference at length {length}, batch position {i}.");
            }
        }
        return new(true, cases);
    }

    // Append whole 16,384-round chunks to SHA-1, independent of the native schedule and layout.
    internal static byte[] Rar3Reference(ReadOnlySpan<byte> password, byte[] salt)
    {
        int size = password.Length * 2 + 11;
        var template = new byte[size];
        for (int q = 0; q < password.Length; q++) template[2 * q] = password[q];
        salt.CopyTo(template, password.Length * 2);
        var chunk = new byte[size * 16384];
        var iv = new byte[16];
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        Span<byte> snapshot = stackalloc byte[20];
        for (int block = 0; block < 16; block++)
        {
            for (int r = 0; r < 16384; r++)
            {
                var record = chunk.AsSpan(r * size, size);
                template.CopyTo(record);
                int counter = block * 16384 + r;
                record[^3] = (byte)counter; record[^2] = (byte)(counter >> 8); record[^1] = (byte)(counter >> 16);
            }
            hash.AppendData(chunk.AsSpan(0, size));
            hash.GetCurrentHash(snapshot);
            iv[block] = snapshot[19];
            hash.AppendData(chunk.AsSpan(size));
        }
        return [.. hash.GetHashAndReset(), .. iv];
    }
}
