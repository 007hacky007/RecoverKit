"""Independent hashlib checks. Pass a native library, or --generate-kat to refresh the header."""
import ctypes as c
import functools
import hashlib
import os
from pathlib import Path
import struct
import sys


LENGTHS = (0, 2, 8, 38, 40, 48, 54, 56, 94, 96, 110, 112, 126, 128, 240, 512)
SALT = bytes(range(16))


def password(lane, length):
    return bytes((1 + (lane * 17 + q * 7) % 255) if q % 2 == 0
                 else (lane * 29 + q * 11) % 256 for q in range(length))


@functools.lru_cache(None)
def reference(mode, pw, spins):
    digest = hashlib.sha1 if mode in (9400, 9500) else hashlib.sha512
    h = digest(SALT + pw).digest()
    for i in range(spins):
        h = digest(struct.pack('<I', i) + h).digest()
    return h


def generate_kat():
    lines = ['/* Independent Python hashlib full 100000-spin answers; regenerate with',
             ' * python3 native/tests/office_agile_test.py --generate-kat. */',
             'static const int AGILE_TEST_LENGTHS[16] = {' + ', '.join(map(str, LENGTHS)) + '};']
    for mode, width, words in ((9500, 4, 5), (9600, 8, 8)):
        lines.append(f'static const uint{width * 8}_t AGILE_{mode}_ANSWERS[16][{words}] = {{')
        for lane, length in enumerate(LENGTHS):
            h = reference(mode, password(lane, length), 100000)
            values = [f'0x{int.from_bytes(h[q:q+width], "big"):0{2*width}x}' for q in range(0, len(h), width)]
            values = [v + 'u' if width == 4 else 'UINT64_C(' + v + ')' for v in values]
            lines.append('    { ' + ', '.join(values) + ' },')
        lines.append('};')
    Path(__file__).resolve().parents[1].joinpath('office_agile_kat.h').write_text('\n'.join(lines) + '\n')


def check_library(path):
    lib = c.CDLL(path)
    # Absence is the intended pre-implementation failure.
    assert hasattr(lib, 'rk_office_agile_spin'), 'native Agile spin export is missing'
    spin = lib.rk_office_agile_spin
    spin.argtypes = [c.c_int, c.c_void_p, c.c_int, c.c_void_p, c.c_int,
                     c.c_void_p, c.c_uint32, c.c_void_p]
    spin.restype = c.c_int
    for name in ('selected_path', 'lanes', 'selftest_state', 'executed_paths'):
        getattr(lib, 'rk_office_agile_' + name).argtypes = [c.c_int]
    features = lib.rk_features()
    paths = [('scalar', 1)]
    for name, bit, feature in (('avx2', 2, 1), ('avx512', 4, 512), ('neon', 8, 8),
                               ('arm-sha1', 32, 32), ('sha-ni', 64, 2), ('arm-sha512', 128, 128)):
        if features & feature:
            paths.append((name, bit))
    packed = b''.join(password(lane, length).ljust(512, b'\0') for lane, length in enumerate(LENGTHS))
    lengths = (c.c_int * 16)(*LENGTHS)
    for mode in (9500, 9600):
        key = f'RECOVERKIT_OFFICE{2010 if mode == 9500 else 2013}_PATH'
        size = 20 if mode == 9500 else 64
        assert lib.rk_office_agile_executed_paths(mode) == 0
        for path_name, bit in paths:
            if mode == 9500 and path_name == 'arm-sha512':
                continue
            if mode == 9600 and path_name in ('arm-sha1', 'sha-ni'):
                continue
            os.environ[key] = path_name
            assert lib.rk_office_agile_selected_path(mode) == bit, (mode, path_name)
            assert lib.rk_office_agile_selftest_state(mode) == (0 if bit == 1 else 1)
            assert lib.rk_office_agile_executed_paths(mode) == 0
            for spins in (0, 1, 2, 255, 256, 65536, 100000):
                # A final partial batch must not lose or mix candidates.
                for count in (1, 15, 16):
                    output = c.create_string_buffer(count * size)
                    assert spin(mode, packed, 512, lengths, count, SALT, spins, output) == 0
                    want = b''.join(reference(mode, password(q, LENGTHS[q]), spins) for q in range(count))
                    assert output.raw == want, (mode, path_name, spins, count)
            assert lib.rk_office_agile_executed_paths(mode) & bit
            lib.rk_reset_executed_paths(mode)
            assert lib.rk_office_agile_executed_paths(mode) == 0
            print(f'{mode} {path_name}: full-spin, variable-spin, boundaries and partial batches passed')
        # Validation is atomic: an invalid final length cannot modify an earlier output.
        output = c.create_string_buffer(b'!' * (16 * size), 16 * size)
        invalid = (c.c_int * 16)(*LENGTHS)
        invalid[15] = 514
        assert spin(mode, packed, 512, invalid, 16, SALT, 1, output) == -1
        assert output.raw == b'!' * (16 * size)
        for args in ((mode, packed, -1, None, 1, SALT, 1, output),
                     (mode, packed, 513, None, 1, SALT, 1, output),
                     (mode, packed, 514, None, 1, SALT, 1, output),
                     (mode, packed, 512, None, -1, SALT, 1, output),
                     (mode, packed, 512, None, 1, None, 1, output),
                     (mode, None, 512, None, 1, SALT, 1, output),
                     (mode, packed, 512, None, 1, SALT, 1, None)):
            assert spin(*args) == -1
        for length in (-2, 1, 513):
            invalid[15] = length
            assert spin(mode, packed, 512, invalid, 16, SALT, 1, output) == -1
        assert spin(mode, None, 0, None, 1, SALT, 0, output) == 0
        assert output.raw[:size] == reference(mode, b'', 0)
        assert spin(mode, None, 0, None, 0, SALT, 0, None) == 0
        os.environ.pop(key)
    assert spin(9400, None, 0, None, 0, SALT, 0, None) == -1
    for name in ('selected_path', 'lanes', 'selftest_state', 'executed_paths'):
        assert getattr(lib, 'rk_office_agile_' + name)(9400) == -1
    # Sharing the iterator cannot change Office 2007's fixed 50000-spin digest.
    lib.rk_office2007_spin.argtypes = [c.c_void_p, c.c_int, c.c_void_p, c.c_int, c.c_void_p, c.c_void_p]
    for path_name, _ in paths:
        if path_name == 'arm-sha512':
            continue
        os.environ['RECOVERKIT_OFFICE2007_PATH'] = path_name
        output = c.create_string_buffer(16 * 20)
        assert lib.rk_office2007_spin(packed, 512, lengths, 16, SALT, output) == 0
        assert output.raw == b''.join(reference(9400, password(q, LENGTHS[q]), 50000) for q in range(16))
    os.environ.pop('RECOVERKIT_OFFICE2007_PATH')
    print('Office 2007 regression and Agile validation passed')


if __name__ == '__main__':
    if sys.argv[1:] == ['--generate-kat']:
        generate_kat()
    else:
        check_library(sys.argv[1])
