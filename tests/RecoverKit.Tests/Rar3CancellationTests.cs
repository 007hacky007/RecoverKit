using System.Security.Cryptography;
using System.Text;
using RecoverKit.Core;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

public sealed class Rar3CancellationTests
{
    [Fact]
    public void CancellationInsideRar3BatchReplaysUntestedCandidateOnResume()
    {
        string directory = Path.Combine(Settings.AppDataDir, "rar3-cancellation", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8];
            byte[] content = "RAR cancellation"u8.ToArray();
            var (digest, iv) = Rar3Kernel.DeriveUtf16(Encoding.Unicode.GetBytes("a"), salt);
            var key = new byte[16];
            for (int i = 0; i < key.Length; i++) key[i] = digest[(i & ~3) + 3 - (i & 3)];
            using var aes = Aes.Create();
            aes.Key = key;
            string path = Path.Combine(directory, "entry.bin");
            File.WriteAllBytes(path, aes.EncryptCbc(content, iv, PaddingMode.None));
            var target = new Rar3FileTarget(path, 0, content.Length, content.Length, 0x30, 65536,
                salt, ZipCryptoSample.Crc32(content));
            var space = new MaskSpace { Positions = [[(byte)'a']], MinLength = 1, MaxLength = 1 };
            using var stop = new CancellationTokenSource();
            var interruptedKernel = new CancelOnSearch(new Rar3FileKernel(target, stop.Token), stop);
            var interrupted = new NativeEngine(interruptedKernel, space) { Threads = 1 }.Run(null, stop.Token);

            Assert.Equal(NativeOutcome.Stopped, interrupted.Outcome);
            Assert.NotNull(interrupted.ResumeAt);
            Assert.Equal(0, interrupted.ResumeAt.PrefixIndex);
            var resumed = new NativeEngine(new Rar3FileKernel(target), space) { Threads = 1 }
                .Run(interrupted.ResumeAt, CancellationToken.None);
            Assert.Equal(NativeOutcome.Found, resumed.Outcome);
            Assert.Equal("a"u8.ToArray(), resumed.Password);
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    // Cancel after the engine has entered its batch, as a user stopping during KDF/decode would.
    private sealed class CancelOnSearch(NativeKernel kernel, CancellationTokenSource stop) : NativeKernel
    {
        public override string Name => kernel.Name;
        public override double SpeedHint => kernel.SpeedHint;
        public override bool Verify(ReadOnlySpan<byte> password) => kernel.Verify(password);
        public override KernelWorker CreateWorker() => new Worker(kernel.CreateWorker(), stop);

        private sealed class Worker(KernelWorker inner, CancellationTokenSource stop) : KernelWorker
        {
            public override int Search(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last)
            {
                stop.Cancel();
                return inner.Search(prefix, last);
            }
        }
    }
}
