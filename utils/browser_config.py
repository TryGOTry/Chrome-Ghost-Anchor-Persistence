"""
browser_config.py - Browser configuration (seeds, paths, location codes)
"""

from dataclasses import dataclass
from typing import Dict


@dataclass
class BrowserConfig:
    name: str
    seed: bytes
    default_location: int
    preferences_path: str
    secure_preferences_path: str
    proc_name: str
    profile_path: str


class BrowserConfigurator:
    # Seeds
    CHROME_SEED = (
        b"\xe7H\xf36\xd8^\xa5\xf9\xdc\xdf%\xd8\xf3G\xa6[L\xdffv\x00\xf0-"
        b"\xf6rJ*\xf1\x8a!-&\xb7\x88\xa2P\x86\x91\x0c\xf3\xa9\x03\x13ihq"
        b"\xf3\xdc\x05\x8270\xc9\x1d\xf8\xba\\O\xd9\xc8\x84\xb5\x05\xa8"
    )
    EDGE_SEED: bytes = b""
    BRAVE_SEED: bytes = b""
    VIVALDI_SEED: bytes = b""

    # ------------------------------------------------------------------
    # Platform-specific browser paths
    # ------------------------------------------------------------------
    _PATHS = {
        "chrome": {
            "windows": {
                "preferences_path":        r"AppData\Local\Google\Chrome\User Data\Default\Preferences",
                "secure_preferences_path": r"AppData\Local\Google\Chrome\User Data\Default\Secure Preferences",
                "proc_name":               "chrome.exe",
                "profile_path":            r"Google\Chrome\User Data\Default",
            },
            "darwin": {
                "preferences_path":        "Library/Application Support/Google/Chrome/Default/Preferences",
                "secure_preferences_path": "Library/Application Support/Google/Chrome/Default/Secure Preferences",
                "proc_name":               "Google Chrome",
                "profile_path":            "Google/Chrome/Default",
            },
            "linux": {
                "preferences_path":        ".config/google-chrome/Default/Preferences",
                "secure_preferences_path": ".config/google-chrome/Default/Secure Preferences",
                "proc_name":               "google-chrome",
                "profile_path":            "google-chrome/Default",
            },
        },
        "edge": {
            "windows": {
                "preferences_path":        r"AppData\Local\Microsoft\Edge\User Data\Default\Preferences",
                "secure_preferences_path": r"AppData\Local\Microsoft\Edge\User Data\Default\Secure Preferences",
                "proc_name":               "msedge.exe",
                "profile_path":            r"Microsoft\Edge\User Data\Default",
            },
            "darwin": {
                "preferences_path":        "Library/Application Support/Microsoft Edge/Default/Preferences",
                "secure_preferences_path": "Library/Application Support/Microsoft Edge/Default/Secure Preferences",
                "proc_name":               "Microsoft Edge",
                "profile_path":            "Microsoft Edge/Default",
            },
            "linux": {
                "preferences_path":        ".config/microsoft-edge/Default/Preferences",
                "secure_preferences_path": ".config/microsoft-edge/Default/Secure Preferences",
                "proc_name":               "microsoft-edge",
                "profile_path":            "microsoft-edge/Default",
            },
        },
        "brave": {
            "windows": {
                "preferences_path":        r"AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Preferences",
                "secure_preferences_path": r"AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Secure Preferences",
                "proc_name":               "brave.exe",
                "profile_path":            r"BraveSoftware\Brave-Browser\User Data\Default",
            },
            "darwin": {
                "preferences_path":        "Library/Application Support/BraveSoftware/Brave-Browser/Default/Preferences",
                "secure_preferences_path": "Library/Application Support/BraveSoftware/Brave-Browser/Default/Secure Preferences",
                "proc_name":               "Brave Browser",
                "profile_path":            "BraveSoftware/Brave-Browser/Default",
            },
            "linux": {
                "preferences_path":        ".config/BraveSoftware/Brave-Browser/Default/Preferences",
                "secure_preferences_path": ".config/BraveSoftware/Brave-Browser/Default/Secure Preferences",
                "proc_name":               "brave-browser",
                "profile_path":            "BraveSoftware/Brave-Browser/Default",
            },
        },
        "vivaldi": {
            "windows": {
                "preferences_path":        r"AppData\Local\Vivaldi\User Data\Default\Preferences",
                "secure_preferences_path": r"AppData\Local\Vivaldi\User Data\Default\Secure Preferences",
                "proc_name":               "vivaldi.exe",
                "profile_path":            r"Vivaldi\User Data\Default",
            },
            "darwin": {
                "preferences_path":        "Library/Application Support/Vivaldi/Default/Preferences",
                "secure_preferences_path": "Library/Application Support/Vivaldi/Default/Secure Preferences",
                "proc_name":               "Vivaldi",
                "profile_path":            "Vivaldi/Default",
            },
            "linux": {
                "preferences_path":        ".config/vivaldi/Default/Preferences",
                "secure_preferences_path": ".config/vivaldi/Default/Secure Preferences",
                "proc_name":               "vivaldi",
                "profile_path":            "vivaldi/Default",
            },
        },
    }

    # ------------------------------------------------------------------
    @staticmethod
    def get_browser_configs(platform: str = "windows") -> Dict[str, BrowserConfig]:
        """
        Return browser configs with paths appropriate for the target *platform*.

        platform: "windows" | "linux" | "darwin"
        """
        p = platform

        def _cfg(key: str, name: str, seed: bytes, default_location: int) -> BrowserConfig:
            paths = BrowserConfigurator._PATHS[key][p]
            return BrowserConfig(
                name=name,
                seed=seed,
                default_location=default_location,
                preferences_path=paths["preferences_path"],
                secure_preferences_path=paths["secure_preferences_path"],
                proc_name=paths["proc_name"],
                profile_path=paths["profile_path"],
            )

        return {
            "chrome":  _cfg("chrome",  "Chrome",         BrowserConfigurator.CHROME_SEED,  4),
            "edge":    _cfg("edge",    "Microsoft Edge",  BrowserConfigurator.EDGE_SEED,    4),
            "brave":   _cfg("brave",   "Brave",           BrowserConfigurator.BRAVE_SEED,   4),
            "vivaldi": _cfg("vivaldi", "Vivaldi",         BrowserConfigurator.VIVALDI_SEED, 4),
        }
