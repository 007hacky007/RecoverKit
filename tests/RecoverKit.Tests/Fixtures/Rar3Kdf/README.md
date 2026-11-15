# RAR 3 KDF fixtures

These 22 tiny archives contain synthetic stored data, created and checked with RAR 6.24 x64
using `rar a -cfg- -ma4 -m0 -s- -ep1 -idq -pPASSWORD -y` and `rar t`.

The tests define each password and independent SHA-1 digest/IV answer. Two salts at each
ASCII length 26, 27, 28, 29, 32, 64, 95, 127 and 128 cover the legacy SHA-1 input-buffer
mutation boundary. Four Unicode inputs cover the same boundary in UTF-16 bytes.
RAR 6.24 truncates a 128-character command-line input to 127 characters; the test records
that effective password separately. A generated true 128-character-key test ensures the
verifier tries the full key before the command-line creator's truncated form.

A separate scalar C oracle derived the recorded answers using SHA-1 input mutation, and
its decrypted data matched the archive CRC. No creator or oracle implementation is bundled
in these fixtures. The files contain no third-party documents or personal information.
