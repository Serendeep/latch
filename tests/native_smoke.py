"""Exercise the actual Linux webview bridge and deny an ungranted window command."""

import json
import os
import tempfile
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


VAULT_FLOW = r"""
const done = arguments[arguments.length - 1];
(async () => {
  const wait = async (test) => {
    const deadline = Date.now() + 15000;
    while (!test()) { if (Date.now() > deadline) throw new Error('test timeout'); await new Promise(r => setTimeout(r, 50)); }
  };
  const status = () => document.querySelector('output.status')?.textContent;
  const fill = (value) => { document.querySelectorAll('input').forEach(input => { input.value = value; }); };
  const submit = () => document.querySelector('form').requestSubmit();
  let passphrase = crypto.randomUUID() + crypto.randomUUID();
  fill(passphrase); submit();
  await wait(() => status() === 'Your vault is locked.');
  await wait(() => document.querySelector('input'));
  if (document.querySelector('input').value !== '') throw new Error('input not cleared');
  fill(crypto.randomUUID()); submit();
  await wait(() => document.querySelector('[role=alert]'));
  await wait(() => document.querySelector('input'));
  fill(passphrase); submit();
  await wait(() => status() === 'Your vault is unlocked.');
  [...document.querySelectorAll('button')].find(b => b.textContent === 'Lock vault').click();
  await wait(() => status() === 'Your vault is locked.' && document.querySelector('input'));
  fill(passphrase); submit();
  await wait(() => [...document.querySelectorAll('button')].some(b => b.textContent === 'Cancel and lock'));
  [...document.querySelectorAll('button')].find(b => b.textContent === 'Cancel and lock').click();
  await wait(() => status() === 'Your vault is locked.');
  passphrase = '';
  done(true);
})().catch(() => done(false));
"""


def main():
    """Start only this test's driver/app, verify the boundary, and close them."""
    app = Path(__file__).resolve().parents[1] / "target/debug/latch-desktop"
    for binary in ("tauri-driver", "WebKitWebDriver"):
        if shutil.which(binary) is None:
            raise SystemExit(f"Native smoke test requires {binary} on PATH")
    session = None
    if os.environ.get("LATCH_RUN_NATIVE_VAULT") == "1" and (
        os.environ.get("LATCH_ISOLATED_KEYRING_TEST") != "1"
        or not (Path(os.environ.get("XDG_DATA_HOME", "/")) / "latch-test-isolated").is_file()
    ):
        raise SystemExit("Native vault input requires the isolated keyring runner")
    isolated_data = tempfile.TemporaryDirectory(prefix="latch-native-data-")
    env = os.environ.copy()
    if env.get("LATCH_RUN_NATIVE_VAULT") != "1":
        env["XDG_DATA_HOME"] = isolated_data.name
    # Do not retain native logs or WebDriver payload artifacts around passphrase input.
    with subprocess.Popen(["tauri-driver", "--port", "4444"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as driver:
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
            result = request("POST", prefix + "/execute/async", {"script": "const done = arguments[arguments.length - 1]; window.__TAURI_INTERNALS__.invoke('app_status').then(done, e => done({error: ['storage_unavailable','already_running','recovery_required'].includes(e) ? e : 'unexpected'}));", "args": []})
            for _ in range(50):
                if result["value"] == {"protocol_version": 1, "lock_epoch": "0", "vault": "absent"}:
                    break
                time.sleep(0.1)
                result = request("POST", prefix + "/execute/async", {"script": "const done = arguments[arguments.length - 1]; window.__TAURI_INTERNALS__.invoke('app_status').then(done, e => done({error: ['storage_unavailable','already_running','recovery_required'].includes(e) ? e : 'unexpected'}));", "args": []})
            else:
                raise AssertionError("Native metadata bridge failed: " + str(result["value"].get("error", "unexpected state")))
            result = request("POST", prefix + "/execute/async", {"script": "const done = arguments[arguments.length - 1]; window.__TAURI_INTERNALS__.invoke('plugin:window|set_title', {label: 'main', title: 'unexpected'}).then(() => done('allowed'), () => done('denied'));", "args": []})
            assert result["value"] == "denied", "Ungranted native command succeeded"
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                result = request("POST", prefix + "/execute/sync", {"script": "return document.querySelector('output.status')?.textContent === 'Create your local vault.';", "args": []})
                if result["value"] is True:
                    break
                time.sleep(0.1)
            else:
                raise AssertionError("Native UI did not render the actual state")
            if env.get("LATCH_RUN_NATIVE_VAULT") == "1":
                request("POST", prefix + "/timeouts", {"script": 90000})
                result = request("POST", prefix + "/execute/async", {"script": VAULT_FLOW, "args": []})
                assert result["value"] is True, "Native vault flow failed"
                print("Passed: native create, wrong passphrase, unlock, lock, and cancellation.")
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
                driver.wait()
            isolated_data.cleanup()


if __name__ == "__main__":
    main()
