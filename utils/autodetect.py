"""autodetect.py - 在目标机上自动探测 GAP 需要的三个运行时参数。

配合 auto_gap.py 使用：当 --prefs-file / --device-id / --target-dir 未提供时，
本模块会在“本机”(目标机)上自动找出对应的值。
"""

import glob
import os
import platform
import re
import subprocess

from .browser_config import BrowserConfigurator

# Windows 平台字符串 -> 浏览器程序名（用于判断哪些浏览器已安装）
BROWSER_EXES = {
    "edge":    "msedge.exe",
    "chrome":  "chrome.exe",
    "brave":   "brave.exe",
    "vivaldi": "vivaldi.exe",
}


def _run(cmd, shell=True) -> str:
    """跑一条命令并返回字符串输出；失败返回空串。"""
    try:
        r = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=15)
        return (r.stdout or "") + (r.stderr or "")
    except Exception:
        return ""


def detect_platform_name() -> str:
    """返回 browser_config 所用的平台名: windows | linux | darwin。"""
    s = platform.system().lower()
    if s.startswith("win"):
        return "windows"
    if s == "darwin":
        return "darwin"
    return "linux"


def detect_device_id(platform_name: str) -> str | None:
    """探测目标机机器标识：Windows SID / macOS HW UUID / Linux Machine ID。"""
    if platform_name == "windows":
        out = _run("whoami /user")
        m = re.search(r"S-1-(?:\d+-)+\d+", out)
        return m.group(0) if m else None
    if platform_name == "darwin":
        out = _run("ioreg -rd1 -c IOPlatformExpertDevice")
        m = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', out)
        return m.group(1) if m else None
    # linux
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(p) as f:
                v = f.read().strip()
                if v:
                    return v
        except Exception:
            continue
    return None


def detect_target_dir(platform_name: str) -> str | None:
    """探测部署根目录：Windows 用 %LOCALAPPDATA%，macOS/Linux 用用户配置目录。"""
    if platform_name == "windows":
        return os.environ.get("LOCALAPPDATA")
    if platform_name == "darwin":
        return os.path.expanduser("~/Library/Application Support")
    return os.path.expanduser("~/.config")


def _base_dir(platform_name: str) -> str | None:
    return detect_target_dir(platform_name)


def find_installed_browsers(platform_name: str) -> list[str]:
    """返回本机已安装的浏览器 (edge/chrome/brave/vivaldi)，按顺序。"""
    order = ["edge", "chrome", "brave", "vivaldi"]
    installed: list[str] = []
    for b in order:
        # 1) 能找到浏览器可执行文件
        if platform_name == "windows":
            found = False
            for root in (os.environ.get("PROGRAMFILES", r"C:\Program Files"),
                         os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
                         os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Edge", "Application")):
                if root and os.path.exists(os.path.join(root, BROWSER_EXES[b])):
                    found = True
                    break
            if found:
                installed.append(b)
                continue
        # 2) 或本机存在该浏览器的 User Data 目录（有 profile 就算安装）
        if _profile_search(platform_name, b):
            installed.append(b)
    return installed


def _browser_userdata_roots(platform_name: str) -> dict:
    """每个浏览器在本机的 User Data 根目录位置。"""
    cfg_map = BrowserConfigurator.get_browser_configs(platform_name)
    roots = {}
    base = _base_dir(platform_name)
    if not base:
        return roots
    for bid, cfg in cfg_map.items():
        # profile_path 形如 "Microsoft\Edge\User Data\Default"
        parts = cfg.profile_path.replace("\\", "/").split("/")
        # User Data 目录 = profile_path 去掉最后的 profile 名
        if len(parts) >= 2:
            userdata = os.path.join(base, *parts[:-1])
        else:
            userdata = os.path.join(base, *parts)
        roots[bid] = userdata
    return roots


def _profile_search(platform_name: str, browser: str) -> str | None:
    """在当前浏览器 User Data 下找最新改动的 Secure Preferences 所在 profile 目录。"""
    roots = _browser_userdata_roots(platform_name)
    ud = roots.get(browser)
    if not ud or not os.path.isdir(ud):
        return None
    candidates = glob.glob(os.path.join(ud, "*", "Secure Preferences"))
    if not candidates:
        return None
    # 取最近修改的那个（通常就是当前正在用的 profile）
    cand = max(candidates, key=lambda p: os.path.getmtime(p))
    return os.path.dirname(cand)


def detect_prefs_file(platform_name: str, browser: str) -> tuple[str | None, str | None]:
    """返回 (secure preferences 文件路径, 其所在 profile 目录)；失败为 (None, None)。"""
    prof = _profile_search(platform_name, browser)
    if not prof:
        return None, None
    prefs = os.path.join(prof, "Secure Preferences")
    return prefs, prof


def auto_browser(platform_name: str) -> str | None:
    """选择一个已安装且能找到 User Data 的浏览器；找不到返回 None。"""
    for b in find_installed_browsers(platform_name):
        if _profile_search(platform_name, b):
            return b
    return None

