"""Regenerate independent Office 2007 KATs with Python hashlib and cryptography.

Run with Python 3 and cryptography installed. No RecoverKit code is used.
"""
import hashlib
import json
from pathlib import Path
from struct import pack

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def spin(password, salt):
    h = hashlib.sha1(salt + password.encode("utf-16le")).digest()
    for i in range(50000):
        h = hashlib.sha1(pack("<I", i) + h).digest()
    return h


def key_from_spin(h, bits):
    h = hashlib.sha1(h + pack("<I", 0)).digest()
    return b"".join(hashlib.sha1(bytes(x ^ pad for x in h) + bytes([pad]) * 44).digest()
                    for pad in (0x36, 0x5c))[:bits // 8]


assert key_from_spin(spin("Password1234_", bytes.fromhex("e88266490c5bd1eebd2b4394e3f830ef")), 128).hex() == "40b13a71f90b966e375408f2d181a1aa"
rows = []
for bits in (128, 256):
    for name, password in [("empty", ""), ("ascii", "office-test"),
                           ("unicode", "p\u0159\u00edli\u0161-\U0001f510"),
                           ("supplementary", "\U0001f510" * 64),
                           ("utf8-256", "\u00e9" * 128),
                           ("utf16-127", "a" * 127), ("utf16-128", "a" * 128),
                           ("utf16-129", "a" * 129), ("ascii-256", "a" * 256)]:
        salt = bytes(range(16))
        h = spin(password, salt)
        cipher = Cipher(algorithms.AES(key_from_spin(h, bits)), modes.ECB())
        verifier = bytes(range(16, 32))
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(verifier + hashlib.sha1(verifier).digest() + bytes(12)) + encryptor.finalize()
        # Hashcat serializes only 20 encrypted verifier-hash bytes.
        line = f"$office$*2007*20*{bits}*16*{salt.hex()}*{encrypted[:16].hex()}*{encrypted[16:36].hex()}"
        rows.append(dict(name=f"{bits}-{name}", password=password, hash=line, spin=h.hex()))
Path(__file__).with_name("standard-vectors.json").write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
