#!/usr/bin/env python3
"""Writes ordered.hcstat2, the Markov statistics file RecoverKit passes to hashcat in hybrid attacks.

hashcat sorts the characters of every mask position by its Markov statistics before enumerating a
mask. With this file every character's count is 256 minus its byte value, at every position and
after every previous character, so all counts differ and hashcat enumerates each position in plain
ascending byte order. That makes hashcat's --skip/--limit word numbers predictable, which the
built-in CPU engine needs to take the other part of the keyspace.

Format (hashcat src/mpsp.c, sp_setup_tbl): raw LZMA2 stream (properties byte 0x1c) of
version (u64 BE), zero (u64), 256*256 root counts, 256*256*256 Markov counts (u64 BE each).
Usage: python3 make-ordered-hcstat2.py ordered.hcstat2
"""
import lzma
import struct
import sys

row = b"".join(struct.pack(">Q", 256 - k) for k in range(256))
data = struct.pack(">Q", 0x6863737461740002) + struct.pack(">Q", 0) + row * 256 + row * (256 * 256)
out = lzma.compress(data, format=lzma.FORMAT_RAW,
                    filters=[{"id": lzma.FILTER_LZMA2, "dict_size": 1 << 20, "preset": 9}])
with open(sys.argv[1], "wb") as f:
    f.write(out)
