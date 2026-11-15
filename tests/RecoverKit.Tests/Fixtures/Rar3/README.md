# RAR 3 decoder fixtures

The original small-* and large-* files are decrypted entry streams from synthetic RAR 4 archives created with
WinRAR 6.24 x64. The original archives passed `rar t`. The original five 8 KiB small
streams also produced the source file's CRC with hashcat 8.0.0's unmodified RAR 3 decoder.
The added PPM protocol cases expose limitations in that decoder and were verified with `rar t`.

Gzip only reduces fixture storage; the tests remove it before calling the RAR decoder.
No complete uncompressed file is stored. Small entries unpack to 8,192 bytes, except
`small-ppm-allbytes`, which holds the byte values 0 to 255 repeated 512 times and unpacks
to 131,072 bytes. This entry exercises PPM's escaped literal command. Large entries
unpack to 5,242,917 bytes with a 4 MiB dictionary, crossing its wrap boundary.
`small-ppm-defaultesc` holds byte 2 and 32 unique ASCII bytes. A synthetic stream containing
bytes 2, 1 and those ASCII bytes was changed to omit the explicit escape character,
using the format's default value of 2. The archive's output length and CRC were adjusted
to account for the escaped literal, then it was re-encrypted. WinRAR's `rar t` accepted
the resulting archive, independently confirming both default escape 2 and literal command 1.

Creation used `rar a -cfg- -ma4 -m5 -md4096k -s- -ep1 -idq -pkit3 -y -mc-`.
The variants add `-mc6:4t+` (PPMd), `-mc1d+` (delta), `-mc1a+` (audio), `-mce+`
(x86), or `-mcc+` (RGB). The filenames describe the requested compression path.
The decoder tests record each source file's exact length and CRC32 independently of the
compressed stream.

The compressed data contains synthetic text, byte ramps, sample values, instruction-like
bytes and pixel values. It contains no third-party documents or personal information.

The review regressions add four small synthetic PPM streams. Their range-coded symbols use
an encoder derived from the public domain PPMd decoder/model already in this repository:

- `ppm-lz-transition`: 40 copies of `first block\n`, escape command 0, then an LZ
  block containing 30 copies of `next block\n` (810 bytes, CRC32 34fc0041).
- `ppm-model-transition`: the same plaintext, with a second PPM header that reuses
  the first block's model and default escape character (810 bytes, CRC32 34fc0041).
- `ppm-vm-record`: escape command 3, an extended-length standard x86 VM record,
  then 256 bytes. The bytes are 0x42 except E8 45 23 01 00 at offset 16; the
  filter changes the address to 0x12334 (256 bytes, CRC32 f57459d7).
- `ppm-escape-commands`: escape command 1 and commands 6 through 255, then ASCII
  END. Each escape produces byte 2 (254 bytes, CRC32 d31abadc).

The first, second and fourth streams were wrapped in RAR 3 headers and independently
extracted by macOS bsdtar with the stated lengths and CRCs. That reader does not support
PPM VM records. The VM case has the same standard program and independently computed x86
output as the LZ filter tests. The installed 7-Zip builds refuse RAR decoding, and the
installed macOS RAR is version 7.23, which cannot create RAR 3 files. No new Windows VM
archive creation was used for this review fix.

Tests also construct 1 MiB streams of zeros and a repeated byte, incomplete Huffman tables
for all 256 literal values, 16-byte-stride data over 16 LZ blocks, low-distance repeats
across table changes, chained filters at EOF, VM resets and an x86 block after 32 MiB of output.
These inputs are generated in memory; they are not large repository fixtures. Native
filter regressions cover E8/E8E9 positions above 2 GiB, Itanium's trailing bundle and an
audio predictor coefficient boundary against independent expected results.

Additional real-encoder interoperability coverage can be generated with WinRAR 6.x
`-ma4 -pkit3`: 1 MiB of zeros, 1 MiB of one repeated byte, 16-byte-stride data across
several blocks, and an x86 executable larger than 16 MiB. The previous 144 real archives
and the generated stream checks remain separate tests.
