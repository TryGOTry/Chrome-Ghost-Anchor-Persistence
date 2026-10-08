"""verify.py - 在 apply 之后自动核对 GAP 是否真正生效。

思路：从 A 的 background.js 里取一个特征字符串，然后去该 profile 的
Service Worker\\ScriptCache (*_0 编译缓存) 里找。找到了 => A 的代码确已被
缓存并由 service worker 执行 => GAP 成功；否则给出可能原因。
"""
import glob
import os
import re


def profile_user_data_dir(prefs_file: str) -> str | None:
    """由 Secure Preferences 路径推出其 User Data 目录。"""
    d = os.path.dirname(prefs_file)          # ...\User Data\<Profile>
    return os.path.dirname(d)                 # ...\User Data


def extract_marker(background_js: str) -> str | None:
    """从背景脚本里取一个足够独特的特征串用于在缓存里检索。"""
    try:
        txt = open(background_js, encoding="utf-8", errors="ignore").read()
    except OSError:
        return None
    # 优先挑一条“无空格、长度>=8”的完整行
    for line in txt.splitlines():
        s = line.strip()
        if len(s) >= 8 and " " not in s and ";" not in s and "//" not in s:
            return s
    # 退而求其次：任取一个长度>=12 的标识符
    m = re.search(r"[\w$@]{12,}", txt)
    return m.group(0) if m else None


def scriptcache_has_marker(user_data: str, marker: str) -> list:
    hits = []
    if not marker:
        return hits
    cache_dir = os.path.join(user_data, "Service Worker", "ScriptCache")
    if not os.path.isdir(cache_dir):
        return hits
    b = marker.encode("utf-8")
    for f in glob.glob(os.path.join(cache_dir, "*_0")):
        try:
            data = open(f, "rb").read()
        except OSError:
            continue
        if b in data:
            hits.append(f)
    return hits


def verify(prefs_file: str, background_js: str) -> bool:
    marker = extract_marker(background_js)
    ud = profile_user_data_dir(prefs_file)
    print("\n" + "=" * 62)
    print("  GAP 生效性自动校验")
    print("=" * 62)
    print(f"[*] 特征串: {marker!r}")
    print(f"[*] User Data: {ud}")

    if not marker:
        print("[?] A 的 background.js 里没有足够长的可辨识字符串，无法校验。")
        print("    请先在 A 的 background.js 里写真实的恶意逻辑（现在可能就是个空壳）。")
        return False

    hits = scriptcache_has_marker(ud, marker)
    if hits:
        print(f"[+] 校验通过：ScriptCache 已缓存到恶意代码，共 {len(hits)} 处命中。")
        print("[+] GAP 已生效 —— 关闭并重新打开浏览器即可看到 worker 从缓存运行恶意代码。")
        return True

    print("[-] 校验失败：ScriptCache 中没有你的特征串。可能原因：")
    print("    1) “开一次浏览器缓存 worker”那步时间太短 / 被强杀，A 没来得及写入 ScriptCache；")
    print("       请重跑并加大等待时间，或改用本工具的--apply加强版。")
    print("    2) 你的扩展不是 MV3，或 manifest 里没有 background.service_worker；")
    print("    3) A 的 background.js 本身是空的（没有真实逻辑）。")
    return False
