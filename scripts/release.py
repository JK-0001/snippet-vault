#!/usr/bin/env python3
"""Build, sign and publish a Snippet Vault release.

Usage:
    python scripts/release.py 0.4.0 notes.md
    python scripts/release.py 0.4.0 "- one line of notes"

What it does:
  1. writes the version into tauri.conf.json, package.json, Cargo.toml
  2. runs `pnpm tauri build` with the update-signing key from ~/.tauri
  3. copies the NSIS installer (+ .sig) and the MSI to names without spaces
  4. writes latest.json, which installed copies poll for updates
  5. creates the GitHub release vX.Y.Z with all four files attached

Commit and push the version bump yourself (the script only touches files).
"""
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = "JK-0001/snippet-vault"
ROOT = Path(__file__).resolve().parent.parent
KEY = Path.home() / ".tauri" / "snippet-vault.key"


def run(cmd, **kw):
    print("+", " ".join(cmd) if isinstance(cmd, list) else cmd)
    subprocess.run(cmd, check=True, cwd=ROOT, **kw)


def set_version(v):
    for f, pat, rep in [
        ("src-tauri/tauri.conf.json", r'"version": "[^"]+"', f'"version": "{v}"'),
        ("package.json", r'"version": "[^"]+"', f'"version": "{v}"'),
        ("src-tauri/Cargo.toml", r'^version = "[^"]+"', f'version = "{v}"'),
    ]:
        p = ROOT / f
        s = p.read_text(encoding="utf-8")
        s2 = re.sub(pat, rep, s, count=1, flags=re.M)
        p.write_text(s2, encoding="utf-8")


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(2)
    version = sys.argv[1].lstrip("v")
    notes_arg = sys.argv[2]
    notes = Path(notes_arg).read_text(encoding="utf-8") if Path(notes_arg).is_file() else notes_arg
    if not KEY.is_file():
        sys.exit(f"signing key not found at {KEY}")

    set_version(version)

    env = dict(os.environ)
    env["TAURI_SIGNING_PRIVATE_KEY"] = KEY.read_text(encoding="utf-8").strip()
    env.setdefault("TAURI_SIGNING_PRIVATE_KEY_PASSWORD", "")
    run(["pnpm", "tauri", "build"], env=env, shell=(os.name == "nt"))

    bundle = ROOT / "src-tauri" / "target" / "release" / "bundle"
    nsis = bundle / "nsis" / f"Snippet Vault_{version}_x64-setup.exe"
    sig = nsis.with_name(nsis.name + ".sig")
    msi = bundle / "msi" / f"Snippet Vault_{version}_x64_en-US.msi"
    for f in (nsis, sig, msi):
        if not f.is_file():
            sys.exit(f"missing build output: {f}")

    out_exe = bundle / f"SnippetVault_{version}_x64-setup.exe"
    out_sig = bundle / f"SnippetVault_{version}_x64-setup.exe.sig"
    out_msi = bundle / f"SnippetVault_{version}_x64.msi"
    out_exe.write_bytes(nsis.read_bytes())
    out_sig.write_bytes(sig.read_bytes())
    out_msi.write_bytes(msi.read_bytes())

    latest = {
        "version": version,
        "notes": notes.strip(),
        "pub_date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "platforms": {
            "windows-x86_64": {
                "signature": sig.read_text(encoding="utf-8").strip(),
                "url": f"https://github.com/{REPO}/releases/download/v{version}/{out_exe.name}",
            }
        },
    }
    latest_path = bundle / "latest.json"
    latest_path.write_text(json.dumps(latest, indent=2), encoding="utf-8")

    run([
        "gh", "release", "create", f"v{version}",
        str(out_exe), str(out_sig), str(out_msi), str(latest_path),
        "--repo", REPO,
        "--title", f"Snippet Vault {version}",
        "--notes", notes,
    ], shell=(os.name == "nt"))
    print(f"released v{version}")


if __name__ == "__main__":
    main()
