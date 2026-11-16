Small encrypted archives, password `7`, created with Info-ZIP 3.0 and 7-Zip 26.03 on macOS.
All archive bytes together occupy less than 140 KB. No large source files are required.

- `infozip.z01` + `infozip.zip`: `zip -X -P 7 -s 64k -0`, ZipCrypto, stored data crossing disks.
- `infozip64.z01` + `infozip64.zip`: the same with `-fz`, forcing ZIP64 records and local sizes.
- `7zip-crypto.zip.001` through `.003`: `7zz -tzip -p7 -mem=ZipCrypto -v100b`, Deflate.
- `7zip-aes.zip.001` through `.003`: `7zz -tzip -p7 -mem=AES256 -v100b`, AE-2, Deflate.
- `7zip-aes-store.zip.001` through `.014`: the same with `-mx=0`, Store. The EOCD crosses parts.

The `.hash` files are references extracted from independent Info-ZIP `zip -s 0 --out` copies.
Tests compare these with hashes read directly from both parts. Byte-split hashes are compared
with an in-memory concatenation of the small fixture. Programmatic tests add PKZIP AES AE-1/AE-2,
central directories crossing disks, ZIP64 disk/offset extras, corruption and sparse offsets
above 4 GiB. No joined reference archive is kept in the repository.

To regenerate, build the Release CLI, then run `python3 tests/fixtures/zip-split/generate.py`.
The script requires `zip`, `7zz` and `dotnet` on PATH. Encryption headers/salts are random,
so it also regenerates the joined-reference hashes. Source files have fixed timestamps and
Info-ZIP uses `-X` to omit platform-specific extra fields.
