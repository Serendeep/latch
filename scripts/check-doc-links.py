"""Check local links and assets in the exported documentation site."""
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit

root = Path(__file__).resolve().parents[1] / "site" / "out"
failures = []


class Links(HTMLParser):
    def __init__(self, current):
        super().__init__()
        self.current = current

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if name not in ("href", "src") or not value:
                continue
            url = urlsplit(urljoin(self.current, value))
            if url.scheme or url.netloc or not url.path:
                continue
            path = root / unquote(url.path).lstrip("/")
            if not any(p.is_file() for p in (path, Path(str(path) + ".html"), path / "index.html")):
                failures.append(f"{self.current}: {value}")


pages = list(root.rglob("*.html"))
if not pages:
    raise SystemExit("Build the documentation before checking links.")
for page in pages:
    current = "/" + str(page.relative_to(root))
    Links(current).feed(page.read_text())
if failures:
    raise SystemExit("Broken documentation links:\n" + "\n".join(sorted(set(failures))))
print(f"Checked local links and assets in {len(pages)} exported pages.")
