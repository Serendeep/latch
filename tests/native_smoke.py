"""Exercise the actual Linux webview bridge and deny an ungranted window command."""

import json
from pathlib import Path
import shutil
import subprocess
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:4444"


def request(method, path, body=None):
    """Send a WebDriver message; test payloads contain no credentials."""
    data = None if body is None else json.dumps(body).encode()
    message = urllib.request.Request(BASE + path, data=data, method=method, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(message, timeout=30) as response:
        return json.load(response)


def main():
    """Start only this test's driver/app, verify the boundary, and close them."""
    app = Path(__file__).resolve().parents[1] / "target/debug/latch-desktop"
    for binary in ("tauri-driver", "WebKitWebDriver"):
        if shutil.which(binary) is None:
            raise SystemExit(f"Native smoke test requires {binary} on PATH")
    session = None
    with subprocess.Popen(["tauri-driver", "--port", "4444"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as driver:
        try:
            for _ in range(100):
                try:
                    request("GET", "/status")
                    break
                except (urllib.error.URLError, ConnectionError):
                    if driver.poll() is not None:
                        raise AssertionError("Native driver exited before readiness") from None
                    time.sleep(0.1)
            else:
                raise AssertionError("Native driver did not start")
            result = request("POST", "/session", {"capabilities": {"alwaysMatch": {"tauri:options": {"application": str(app)}}}})
            session = result["value"]["sessionId"]
            prefix = f"/session/{session}"
            result = request("POST", prefix + "/execute/async", {"script": "const done = arguments[arguments.length - 1]; window.__TAURI_INTERNALS__.invoke('app_status').then(done, () => done({error: true}));", "args": []})
            assert result["value"] == {"protocol_version": 1, "vault": "unavailable"}, "Native metadata bridge failed"
            result = request("POST", prefix + "/execute/async", {"script": "const done = arguments[arguments.length - 1]; window.__TAURI_INTERNALS__.invoke('plugin:window|set_title', {label: 'main', title: 'unexpected'}).then(() => done('allowed'), () => done('denied'));", "args": []})
            assert result["value"] == "denied", "Ungranted native command succeeded"
            result = request("POST", prefix + "/execute/sync", {"script": "return document.querySelector('output.status').textContent;", "args": []})
            assert result["value"] == "Vault setup is not available in this build.", "Native UI did not render the actual state"
            print("Passed: native status IPC, ungranted command denied, actual UI availability.")
        finally:
            if session:
                try:
                    request("DELETE", f"/session/{session}")
                except (urllib.error.URLError, ConnectionError):
                    pass
            driver.terminate()
            try:
                driver.wait(timeout=10)
            except subprocess.TimeoutExpired:
                driver.kill()


if __name__ == "__main__":
    main()
