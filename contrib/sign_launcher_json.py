#!/usr/bin/env python3
"""Sign a release's launcher.json with minisign and check the result before it is attached."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

SHA256 = re.compile(r"^[0-9a-f]{64}$")


def check_config(path):
    config = json.loads(path.read_text(encoding="utf-8"))
    if config.get("schema") != 1:
        raise ValueError("launcher.json must have \"schema\": 1")
    depot = config.get("depot_downloader") or {}
    for key in ("sha256", "exe_sha256"):
        if not SHA256.match(str(depot.get(key, ""))):
            raise ValueError(f"depot_downloader.{key} must be 64 lowercase hex digits")
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path, help="the launcher.json to attach to the release")
    parser.add_argument("--secret-key", type=Path, required=True, help="the release key's minisign .key file")
    parser.add_argument("--public-key", required=True,
                        help="the public key built into the release (DINGOSDK_RELEASE_PUBLIC_KEY, RW...)")
    parser.add_argument("--minisign", default="minisign", help="the minisign program")
    args = parser.parse_args()

    minisign = shutil.which(args.minisign)
    if not minisign:
        sys.exit(f"{args.minisign} was not found; install minisign 0.11 or newer")
    config = check_config(args.config)
    signature = args.config.with_name(args.config.name + ".minisig")
    version = (config.get("launcher") or {}).get("version", "")
    comment = f"ReSkate launcher.json {version}".strip()
    # minisign asks for the key's password itself.
    subprocess.run([minisign, "-S", "-s", str(args.secret_key), "-m", str(args.config),
                    "-x", str(signature), "-t", comment], check=True)
    # A signature the release's own key cannot check would only make the launchers refuse it.
    if subprocess.run([minisign, "-V", "-P", args.public_key, "-m", str(args.config), "-x", str(signature)]).returncode:
        signature.unlink()
        sys.exit("The signature does not verify with --public-key; it was removed. Is that the right key pair?")
    print(f"Attach {args.config.name} and {signature.name} to the release, unchanged.")


if __name__ == "__main__":
    main()
