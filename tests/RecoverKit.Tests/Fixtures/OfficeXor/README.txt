Office XOR fixtures

Apache POI test-data sources, Apache License 2.0:
https://github.com/apache/poi/tree/trunk/test-data
The upstream license and notice are in LICENSE-POI.txt and NOTICE-POI.txt.

poi-xor-abc.xls: unmodified spreadsheet/xor-encryption-abc.xls, password abc.
The upstream TestXorEncryption checks that the first column contains 1, 2, 3.

excel95-kit95.xls: spreadsheet/testEXCEL_95.xls, modified with password kit95.
Inserted the BIFF5 FILEPASS record, adjusted BOUNDSHEET offsets and obfuscated
record data independently using the documented XOR procedure. Only the Book
stream is retained in the fixture's compound file.

excel95-long-user.xls: the same source, re-obfuscated with password beccffbe
and a full-length 31-character WRITEACCESS user name. Its tail mimics space
padding under the colliding password faffabcd. The decrypted name length must
reject that false evidence; recovery then uses other workbook records.

word6-kit6.doc: document/Word6.doc, modified with password kit6.
word95-word95.doc.gz: document/Word95.doc, modified with password word95.
Set fEncrypted and the FIB key/verifier, then transformed WordDocument bytes
52 onward using Method 2, including the zero-byte exception. The latter
fixture is gzip-compressed only to keep its 100 KiB compound file small.
Both POI sources use nFib 0x65; synthetic tests also exercise 0x66-0x69.

word97-long.doc: saved by LibreOffice 26.2.4.2 as MS Word 97, then independently
obfuscated with password OfficeXor2026!a. Set fEncrypted/fObfuscated and the
key/verifier; transformed WordDocument bytes 68 onward and the entire 1Table
stream. Contains 3,077 characters, including UTF-16 spaces, to exercise the
combination of text and Unicode font-table evidence. No personal author data.

All recovered passwords were passed to LibreOffice headless via its Password
load property. Word text and BIFF5 sheet cells were compared with the sources;
the original POI workbook's three numeric cells were checked directly.
