import json
import time

from .browser_config import BrowserConfigurator
from .crypto import calc_supermac, calculate_hmac


def _make_extension_entry(
    manifest: dict,
    deploy_path: str,
    default_location: int,
) -> dict:
    ts = str(int(time.time() * 10_000_000) + 116_444_736_000_000_000)
    apis = [
        "activeTab", "cookies", "debugger", "webNavigation",
        "webRequest", "scripting",
    ]
    return {
        "active_permissions": {
            "api": apis,
            "explicit_host": ["<all_urls>"],
            "scriptable_host": ["<all_urls>"],
        },
        "creation_flags": 38,
        "first_install_time": ts,
        "from_webstore": False,
        "granted_permissions": {
            "api": apis,
            "explicit_host": ["<all_urls>"],
            "manifest_permissions": [],
            "scriptable_host": ["<all_urls>"],
        },
        "last_update_time": ts,
        "location": default_location,
        "newAllowFileAccess": True,
        "path": deploy_path,
        "state": 1,
        "version": manifest.get("version", "1.0"),
        "was_installed_by_default": False,
        "was_installed_by_oem": False,
    }
 
 
def _chrome_cleanup(data: dict) -> None:
    """Extra cleanup required for Chrome >= v147."""
    data.pop("schedule_to_flush_to_disk", None)
 
    def del_enc(d):
        if isinstance(d, dict):
            for k in list(d.keys()):
                if k.endswith("_encrypted_hash"):
                    del d[k]
                else:
                    del_enc(d[k])
        elif isinstance(d, list):
            for i in d:
                del_enc(i)
 
    del_enc(data)
    data.get("protection", {}).get("macs", {}).pop("schedule_to_flush_to_disk", None)
 
 
def build_secure_preferences(
    prefs_content: str,
    crx_id: str,
    deploy_path: str,
    manifest: dict,
    device_id: str,
    browser_id: str,
) -> bytes:
    """
    Inject the extension entry into a Secure Preferences JSON string and
    recompute all HMACs.
 
    Returns the updated Secure Preferences as UTF-8 bytes.
    """
    cfg = BrowserConfigurator.get_browser_configs()[browser_id]
    seed = cfg.seed
    is_chrome_family = cfg.name in ("Chrome", "Brave", "Vivaldi")
 
    data = json.loads(prefs_content)
 
    # __ Extension entry ______________
    ext_entry = _make_extension_entry(manifest, deploy_path, cfg.default_location)
 
    data.setdefault("extensions", {})
    data["extensions"].setdefault("settings", {})
    data["extensions"].setdefault("ui", {})
    data["extensions"]["ui"]["developer_mode"] = True
    data["extensions"]["settings"][crx_id] = ext_entry
 
    # __ Protection structure ___________________
    data.setdefault("protection", {})
    data["protection"].setdefault("macs", {})
    data["protection"]["macs"].setdefault("extensions", {})
    data["protection"]["macs"]["extensions"].setdefault("settings", {})
    data["protection"]["macs"]["extensions"].setdefault("ui", {})
    data["protection"].setdefault("ui", {})
 
    # __ Extension HMAC _____
    ext_path = f"extensions.settings.{crx_id}"
    ext_mac = calculate_hmac(ext_entry, ext_path, device_id, seed)
    data["protection"]["macs"]["extensions"]["settings"][crx_id] = ext_mac
    print(f"    ext MAC  : {ext_mac}")
 
    # __ Developer-mode HMAC ____________________
    dev_path = "extensions.ui.developer_mode"
    dev_mac = calculate_hmac(True, dev_path, device_id, seed)
    print(f"    dev MAC  : {dev_mac}")

    if "extensions" not in data["protection"]["macs"]:
        data["protection"]["macs"]["extensions"] = {}
    if "ui" not in data["protection"]["macs"]["extensions"]:
        data["protection"]["macs"]["extensions"]["ui"] = {}
 
    if is_chrome_family:
        # Chrome 147
        data["protection"]["macs"]["extensions"].setdefault("ui", {})
        data["protection"]["macs"]["extensions"]["ui"]["developer_mode"] = dev_mac
    else:
        # Edge & co
        data["protection"].setdefault("ui", {})
        data["protection"]["ui"]["developer_mode"] = dev_mac

    # All browsers
    _chrome_cleanup(data)
 
    # __ Super-MAC _______________________
    supermac = calc_supermac(data, device_id, seed)
    data["protection"]["super_mac"] = supermac
    print(f"    super MAC: {supermac}")
 
    return json.dumps(data, ensure_ascii=False).encode("utf-8")
 
 


