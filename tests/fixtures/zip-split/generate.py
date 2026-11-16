"""Regenerate small real-tool split ZIPs (password: 7). Requires Info-ZIP and 7zz."""
from pathlib import Path
import os
import random
import subprocess
import tempfile

output = Path(__file__).resolve().parent
with tempfile.TemporaryDirectory(prefix="rk-zip-fixtures-") as temporary:
    source = Path(temporary)
    (source / "data.bin").write_bytes(random.Random(42).randbytes(66000))
    (source / "small.txt").write_bytes(b"Split ZIP password recovery fixture.\n" * 30)
    for file in source.iterdir():
        os.utime(file, (1577836800, 1577836800))
    for name, force in [("infozip", []), ("infozip64", ["-fz"])]:
        for file in output.glob(name + ".*"):
            if file.suffix != ".hash":
                file.unlink()
        subprocess.run(["zip", "-q", "-X", "-P", "7", "-s", "64k", "-0", *force,
                        str(output / (name + ".zip")), "data.bin", "small.txt"], cwd=source, check=True)
    for name, encryption, compression in [("7zip-crypto", "ZipCrypto", "5"),
                                            ("7zip-aes", "AES256", "5"),
                                            ("7zip-aes-store", "AES256", "0")]:
        for file in output.glob(name + ".zip.*"):
            file.unlink()
        subprocess.run(["7zz", "a", "-tzip", "-p7", "-mem=" + encryption, "-mx=" + compression,
                        "-v100b", str(output / (name + ".zip")), "small.txt"], cwd=source, check=True)

    cli = output.parents[2] / "src/RecoverKit.Cli/bin/Release/net10.0/recoverkit-cli.dll"
    for name in ["infozip", "infozip64"]:
        joined = source / (name + "-joined.zip")
        subprocess.run(["zip", "-q", "-s", "0", str(output / (name + ".zip")), "--out", str(joined)], check=True)
        line = subprocess.run(["dotnet", str(cli), "extract", str(joined), "--full"], capture_output=True, check=True).stdout
        (output / (name + ".hash")).write_bytes(line)
