"""Run the real Linux vault test against a disposable GNOME Keyring and D-Bus."""
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time


def main():
    if len(sys.argv) == 1 or sys.argv[1] in ("--native", "--blank"):
        native = "--native" in sys.argv
        blank = "--blank" in sys.argv
        with tempfile.TemporaryDirectory(prefix="latch-keyring-test-") as directory:
            root = Path(directory)
            env = os.environ.copy()
            env.pop("LATCH_RUN_NATIVE_VAULT", None)
            env.pop("LATCH_TEST_BLANK_KEYRING", None)
            env["MISE_DATA_DIR"] = os.environ.get("MISE_DATA_DIR", str(Path(os.environ.get("XDG_DATA_HOME", str(Path.home()/".local/share")))/"mise"))
            for name in ("DISPLAY", "WAYLAND_DISPLAY", "GNOME_KEYRING_CONTROL", "GNOME_KEYRING_PID"):
                if not native or name not in ("DISPLAY", "WAYLAND_DISPLAY"):
                    env.pop(name, None)
            for name in ("XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR"):
                path = root / name.lower()
                path.mkdir(mode=0o700)
                env[name] = str(path)
            (Path(env["XDG_DATA_HOME"]) / "latch-test-isolated").touch()
            env["LATCH_ISOLATED_KEYRING_TEST"] = "1"
            if native:
                env["LATCH_RUN_NATIVE_VAULT"] = "1"
            if blank:
                env["LATCH_TEST_BLANK_KEYRING"] = "1"
            command = ["dbus-run-session", "--", sys.executable, __file__, str(root)]
            try:
                result = subprocess.run(command, env=env).returncode
            finally:
                # Only unmount this run's private document portal, never the user session's.
                mount = Path(env["XDG_RUNTIME_DIR"]) / "doc"
                if os.path.ismount(mount):
                    subprocess.run(["fusermount3", "-u", "-z", str(mount)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    if os.path.ismount(mount):
                        raise SystemExit("Could not unmount the isolated test portal")
            raise SystemExit(result)
    root = Path(sys.argv[1])
    if (os.environ.get("LATCH_ISOLATED_KEYRING_TEST") != "1"
            or not root.is_absolute()
            or not root.name.startswith("latch-keyring-test-")
            or any(not Path(os.environ.get(name, "/")).is_relative_to(root) for name in ("XDG_DATA_HOME", "XDG_RUNTIME_DIR"))
            or not (Path(os.environ["XDG_DATA_HOME"]) / "latch-test-isolated").is_file()):
        raise SystemExit("Isolated runner context required")
    control = Path(os.environ["XDG_RUNTIME_DIR"]) / "keyring"
    control.mkdir(mode=0o700)
    daemon = subprocess.Popen(
        ["gnome-keyring-daemon", "--foreground", "--components=secrets", "--control-directory", str(control), "--unlock"],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        daemon.stdin.write(secrets.token_hex(32).encode())
        daemon.stdin.close()
        for _ in range(100):
            owner = subprocess.run(["busctl", "--user", "call", "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "NameHasOwner", "s", "org.freedesktop.secrets"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=2)
            if b"true" not in owner.stdout:
                if daemon.poll() is not None:
                    raise SystemExit("Isolated keyring exited before acquiring its bus name")
                time.sleep(0.1)
                continue
            probe = subprocess.run(["busctl", "--user", "call", "org.freedesktop.secrets", "/org/freedesktop/secrets", "org.freedesktop.Secret.Service", "ReadAlias", "s", "login"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=2)
            if probe.returncode == 0 and b"/collection/login" in probe.stdout:
                break
            time.sleep(0.1)
        else:
            raise SystemExit("Isolated keyring did not start")
        if os.environ.get("LATCH_TEST_BLANK_KEYRING") == "1":
            # Simulate an unprotected on-disk collection in this disposable store.
            (Path(os.environ["XDG_DATA_HOME"]) / "keyrings/login.keyring").write_bytes(b"[keyring]\ndisplay-name=Login\n")
        command = ([sys.executable, "tests/native_smoke.py"] if os.environ.get("LATCH_RUN_NATIVE_VAULT") == "1" else ["mise", "exec", "--", "cargo", "test", "-p", "latch-core", "--locked", "isolated_linux_vault_lifecycle", "--", "--ignored", "--test-threads=1"])
        result = subprocess.run(command, timeout=180)
        raise SystemExit(result.returncode)
    finally:
        daemon.terminate()
        try:
            daemon.wait(timeout=5)
        except subprocess.TimeoutExpired:
            daemon.kill()
            daemon.wait()


if __name__ == "__main__":
    main()
