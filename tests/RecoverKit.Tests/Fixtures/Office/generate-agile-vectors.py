"""Independent Office Agile vectors. Requires Python 3 and cryptography.

Optional --msoffcrypto writes a complete independently encrypted OLE fixture using
msoffcrypto-tool 6.1.0. No RecoverKit code or .NET cryptography is used.
"""
import argparse
import hashlib
import io
import json
import zipfile
from pathlib import Path
from struct import pack

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

INPUT_KEY = bytes.fromhex("fea7d2763b4b9e79")
VALUE_KEY = bytes.fromhex("d7aa0f6d3061344e")
ROOT = Path(__file__).parent


def spin(utf16, salt, mode, count):
    digest = hashlib.sha1 if mode == 9500 else hashlib.sha512
    state = digest(salt + utf16).digest()
    for i in range(count):
        state = digest(pack("<I", i) + state).digest()
    return state


def aes_key(state, block, mode, bits):
    digest = hashlib.sha1 if mode == 9500 else hashlib.sha512
    return (digest(state + block).digest() + b"\x36" * 32)[:bits // 8]


def crypt(data, key, salt, decrypt=False):
    cipher = Cipher(algorithms.AES(key), modes.CBC(salt))
    transform = cipher.decryptor() if decrypt else cipher.encryptor()
    return transform.update(data) + transform.finalize()


def vector(name, mode, bits, count, password=None, raw=None, utf16=None):
    if raw is None:
        raw = password.encode("utf-8")
        utf16 = password.encode("utf-16le")
    salt = bytes(range(16))
    verifier = bytes(range(16, 32))
    digest = hashlib.sha1 if mode == 9500 else hashlib.sha512
    state = spin(utf16, salt, mode, count)
    encrypted = crypt(verifier, aes_key(state, INPUT_KEY, mode, bits), salt)
    checksum = digest(verifier).digest()
    checksum += bytes((-len(checksum)) % 16)
    encrypted_hash = crypt(checksum, aes_key(state, VALUE_KEY, mode, bits), salt)[:32]
    year = 2010 if mode == 9500 else 2013
    line = f"$office$*{year}*{count}*{bits}*16*{salt.hex()}*{encrypted.hex()}*{encrypted_hash.hex()}"
    return dict(name=f"{mode}-{name}", mode=mode, password=password, raw=raw.hex(),
                utf16=utf16.hex(), hash=line, spin=state.hex(), spins=count,
                supported=count == 100000 and bits == (128 if mode == 9500 else 256))


def check_hashcat_examples():
    examples = [
        "$office$*2010*100000*128*16*34170046140146368675746031258762*de5bc114991bb3a5679a6e24320bdb09*1b72a4ddffba3dcd5395f6a5ff75b126cb832b733c298e86162028ca47a235a9",
        "$office$*2013*100000*256*16*67805436882475302087847656644837*0c392d3b9ca889656d1e615c54f9f3c9*612b79e33b96322c3253fc8a0f314463cd76bc4efe1352f7efffca0f374f7e4b",
    ]
    for mode, line in zip((9500, 9600), examples):
        _, _, count, bits, _, salt, encrypted, encrypted_hash = line.split("*")
        salt = bytes.fromhex(salt)
        state = spin("hashcat".encode("utf-16le"), salt, mode, int(count))
        verifier = crypt(bytes.fromhex(encrypted), aes_key(state, INPUT_KEY, mode, int(bits)), salt, True)
        digest = hashlib.sha1 if mode == 9500 else hashlib.sha512
        expected = crypt(digest(verifier).digest()[:16], aes_key(state, VALUE_KEY, mode, int(bits)), salt)
        assert expected == bytes.fromhex(encrypted_hash)[:16]


def generate():
    check_hashcat_examples()
    rows = []
    cases = [("empty", ""), ("ascii", "office-test"),
             ("unicode", "p\u0159\u00edli\u0161-\U0001f510"),
             ("supplementary", "\U0001f510" * 64), ("utf8-256", "\u00e9" * 128),
             ("utf16-19", "a" * 19), ("utf16-20", "a" * 20),
             ("utf16-27", "a" * 27), ("utf16-28", "a" * 28),
             ("utf16-127", "a" * 127), ("utf16-128", "a" * 128),
             ("utf16-129", "a" * 129), ("ascii-256", "a" * 256)]
    for mode, bits in ((9500, 128), (9600, 256)):
        for name, password in cases:
            rows.append(vector(name, mode, bits, 100000, password))
        for raw, utf16 in (("f4908080", "00dc00dc"), ("f4bfbfbf", "bfdcffdf")):
            rows.append(vector("raw-" + raw, mode, bits, 100000,
                               raw=bytes.fromhex(raw), utf16=bytes.fromhex(utf16)))
        for count in (0, 1, 7, 255, 256, 50000, 100001):
            rows.append(vector("spins-" + str(count), mode, bits, count, "spin-test"))
        for other_bits in (128, 192, 256):
            if bits != other_bits:
                rows.append(vector("unsupported-aes-" + str(other_bits), mode, other_bits, 100000, "office-test"))
    ROOT.joinpath("agile-vectors.json").write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")


def independent_document():
    import msoffcrypto
    import msoffcrypto.method.ecma376_agile as agile
    import msoffcrypto.method.container.ecma376_encrypted as ole
    ole.datetime2filetime = lambda _: 0  # Stable OLE directory timestamps.
    # Reproducible test randomness, never production encryption.
    counter = 0
    def random_buffer(size):
        nonlocal counter
        counter += 1
        return hashlib.shake_256(b"RecoverKit Agile fixture" + pack("<I", counter)).digest(size)
    agile._random_buffer = random_buffer
    package = io.BytesIO()
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr(zipfile.ZipInfo("[Content_Types].xml"), b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        archive.writestr(zipfile.ZipInfo("fixture.txt"), b"Independent Office Agile fixture.\n" * 256)
    plaintext = package.getvalue()
    original_init = agile.ECMA376AgileEncryptionInfo.__init__
    for bits in (256, 128):
        def configure(info):
            original_init(info)
            info.keyData.keyBits = bits
            info.encryptedKey.keyBits = bits
            if bits == 128:
                info.encryptedKey.hashName = "SHA1"
                info.encryptedKey.hashSize = 20
        agile.ECMA376AgileEncryptionInfo.__init__ = configure
        try:
            info, secret_key = agile.ECMA376Agile.generate_encryption_parameters(
                "independent-\u00e9-\U0001f510", bytes(range(16)))
            # encrypt() assumes package and password hash algorithms are equal.
            # Use its public steps so payload hashing follows keyData's SHA512.
            payload = agile.ECMA376Agile.encrypt_payload(
                io.BytesIO(plaintext), info.keyData, secret_key, info.keyData.saltValue)
            encryption_info = agile.ECMA376Agile.get_encryption_information(info, payload, secret_key)
            container = io.BytesIO()
            agile.ECMA376Encrypted(payload, encryption_info).write_to(container)
            encrypted = container.getvalue()
            office = msoffcrypto.OfficeFile(io.BytesIO(encrypted))
            # 6.1.0 compares SHA1's padded verifier hash without truncation. Its
            # password-derived payload key and HMAC still independently verify it.
            office.load_key(password="independent-\u00e9-\U0001f510", verify_password=bits == 256)
            decrypted = io.BytesIO()
            office.decrypt(decrypted, verify_integrity=True)
            assert decrypted.getvalue() == plaintext
            name = "sha1" if bits == 128 else "sha512"
            ROOT.joinpath(f"agile-msoffcrypto-{name}.bin").write_bytes(encrypted)
        finally:
            agile.ECMA376AgileEncryptionInfo.__init__ = original_init



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--msoffcrypto", action="store_true")
    args = parser.parse_args()
    generate()
    if args.msoffcrypto:
        independent_document()
