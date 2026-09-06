"""Install the pinned Linux scanner after verifying its pinned checksum."""

import hashlib
import io
from pathlib import Path
import sys
import tarfile
import urllib.request

VERSION = "8.30.1"
ASSET = f"gitleaks_{VERSION}_linux_x64.tar.gz"
BASE = f"https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/"
SHA256 = "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"


def main():
    """Extract only the verified scanner executable into the supplied directory."""
    destination = Path(sys.argv[1])
    payload = urllib.request.urlopen(BASE + ASSET, timeout=30).read()
    if hashlib.sha256(payload).hexdigest() != SHA256:
        raise SystemExit("Scanner checksum mismatch")
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        member = archive.getmember("gitleaks")
        if not member.isfile() or member.size > 100 * 1024 * 1024:
            raise SystemExit("Unexpected scanner archive")
        source = archive.extractfile(member)
        if source is None:
            raise SystemExit("Scanner executable missing")
        destination.mkdir(parents=True, exist_ok=True)
        binary = destination / "gitleaks"
        binary.write_bytes(source.read())
        binary.chmod(0o700)


if __name__ == "__main__":
    main()
