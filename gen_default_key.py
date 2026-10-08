#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_default_key.py - 把 SecurityShield.pem 的公钥写死进代码，之后不再需要私钥。

用法（只需在有你私钥的那台机器上跑一次）：
    python gen_default_key.py                      # 默认读脚本目录下的 SecurityShield.pem
    python gen_default_key.py --pem C:\\keys\\SecurityShield.pem

作用：
    1. 从私钥推导出对应的公钥（写进 manifest 的 key 字段就靠它）；
    2. 把公钥写入 utils/crypto.py 的 DEFAULT_PUBLIC_KEY 常量；
    3. 之后运行 auto_gap.py 时自动使用这个公钥 —— 得到固定、稳定的扩展 ID，
       且运行时只需要公钥，私钥永远不用再出现在任何地方。

私钥只在这里被读取一次，用于推导公钥；本脚本和代码里**都只存公钥，不存私钥**。
"""
import argparse, json, os, sys, io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
base = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, base)

from utils.crypto import resolve_fixed_key

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pem", default=os.path.join(base, "SecurityShield.pem"),
                    help="私钥 PEM 文件路径（默认：脚本目录 SecurityShield.pem）")
    args = ap.parse_args()

    if not os.path.exists(args.pem):
        print("[-] 找不到私钥文件:", args.pem)
        print("   请在脚本目录放一个 SecurityShield.pem，或用 --pem 指定路径。")
        sys.exit(1)

    pub_key, cid = resolve_fixed_key(args.pem)
    print(f"[+] 已从 {args.pem} 推导出公钥 (base64) 和扩展 ID:")
    print(f"    ID    : {cid}")
    print(f"    公钥  : {pub_key[:40]}...")

    crypto_py = os.path.join(base, "utils", "crypto.py")
    src = open(crypto_py, encoding="utf-8").read()
    import re
    new_src = re.sub(
        r'DEFAULT_PUBLIC_KEY = ""',
        f'DEFAULT_PUBLIC_KEY = {json.dumps(pub_key)}',
        src, count=1,
    )
    if new_src == src:
        print("[-] 未能在 utils/crypto.py 中找到 DEFAULT_PUBLIC_KEY 常量，未改动。")
        sys.exit(1)
    open(crypto_py, "w", encoding="utf-8", newline="\n").write(new_src)
    print("[+] 已把公钥写死到 utils/crypto.py 的 DEFAULT_PUBLIC_KEY。")
    print("[+] 之后运行 auto_gap.py 将自动使用该公钥得到稳定 ID；私钥可以删掉。")

if __name__ == "__main__":
    main()
