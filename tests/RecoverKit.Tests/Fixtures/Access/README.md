# Access header fixtures

These are first-page excerpts only, not complete databases. The only modification is truncation
to 2048 bytes (Jet 3) or 4096 bytes (Jet 4 / ACE). Full files are used for manual CLI verification
outside the repository. The upstream projects distribute these files under Apache License 2.0.

| Fixture | Upstream source | Expected database password |
|---|---|---|
| jet3-plain.bin | Jackcess src/test/data/V1997/testV1997.mdb | None |
| jet4-protected.bin | Jackcess Encrypt src/test/data/pwd-set.mdb | testpassword |
| jet4-plain.bin | Jackcess Encrypt src/test/data/pwd-none.mdb | None |
| ace-encrypted.bin | Jackcess Encrypt src/test/data/db2007-enc.accdb | Unsupported encryption |
| ace-plain.bin | Jackcess src/test/data/V2007/testV2007.accdb | None |

Jackcess source revision: be0a2139b087a227d14cafd4ea231306a5a3a862
(https://github.com/jahlborn/jackcess).
Jackcess Encrypt source revision: 77a1d54db8fc71606f391d94adacae7e34b108ca
(https://github.com/jahlborn/jackcessencrypt).

LICENSE.txt is the upstream Apache license. NOTICE.txt is the upstream Jackcess notice.
