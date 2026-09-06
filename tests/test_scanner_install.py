"""Check scanner checksum enforcement and safe extraction without network access."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("installer", Path(__file__).resolve().parents[1] / "scripts/install_gitleaks.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


def main():
    for kind in ("regular", "corrupt", "symlink"):
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode="w:gz") as archive:
            member = tarfile.TarInfo("gitleaks")
            if kind == "symlink":
                member.type = tarfile.SYMTYPE
                member.linkname = "../outside"
                archive.addfile(member)
            else:
                member.size = 4
                archive.addfile(member, io.BytesIO(b"test"))
        encoded = payload.getvalue()
        expected = hashlib.sha256(encoded if kind != "corrupt" else b"different").hexdigest()
        with tempfile.TemporaryDirectory(prefix="latch-scanner-test-") as directory:
            with patch.object(installer, "SHA256", expected), patch.object(installer.sys, "argv", ["installer", directory]), patch.object(installer.urllib.request, "urlopen", return_value=io.BytesIO(encoded)):
                rejected = False
                try:
                    installer.main()
                except SystemExit:
                    rejected = True
            binary = Path(directory) / "gitleaks"
            if kind == "regular":
                assert not rejected and binary.read_bytes() == b"test"
                assert binary.stat().st_mode & 0o777 == 0o700
            else:
                assert rejected and not binary.exists(), "Unverified or linked scanner was installed"
    print("Passed: verified extraction, checksum rejection, symlink rejection.")


if __name__ == "__main__":
    main()
