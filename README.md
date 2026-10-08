# auto_gap.py — GAP（Ghost Anchor Persistence）一键工具

基于 Fir3n0x 的 **GAP**（无文件扩展持久化）研究封装的自动化工具。核心思路：
把恶意代码藏进浏览器的 **Service Worker ScriptCache（编译缓存）**，磁盘上只留一个
**空壳扩展**。于是浏览器每次启动都会从缓存执行恶意代码，而磁盘上没有恶意源文件。

# 原项目地址:https://github.com/Fir3n0x/GAP

## 一条命令（本机直跑，参数自动探测）

只需给出你的恶意扩展文件夹 `A`（必须含 `manifest.json`，且为 MV3、带
`background.service_worker`）：

```bash
python auto_gap.py --malicious C:\path\to\your_extension
```

程序会自动：
- 从 A **自动生成**良性孪生扩展 B（同名空脚本、共享同一扩展 ID）；
- **自动探测**目标参数：
  - `--device-id` ← 本机 `whoami /user` 的 SID
  - `--prefs-file` ← 浏览器 `User Data\*\Secure Preferences`（优先 Edge，其次
    Chrome/Brave/Vivaldi）
  - `--target-dir` ← `%LOCALAPPDATA%`（win）/ `~/Library/Application Support`
    （mac）/ `~/.config`（linux）
- 自动重算全部 HMAC，生成部署包。

### 常用选项

| 选项 | 说明 |
|------|------|
| `--malicious` | 必填，你的恶意扩展文件夹 |
| `--spoof <ID>` | 伪装成白名单扩展，**名字/描述/图标/ID 整套套用**（用于 GPO 环境，需能连商店） |
| `--apply` | 打包后**直接在本机执行完整注入链**，并自动校验恶意代码有没有写进 ScriptCache |
| `--proxy <URL>` | `--spoof` 时用于访问浏览器商店的代理 |
| `--benign <目录>` | 可选，已有良性 B 就给它，否则自动生成 |
| `--prefs-file` / `--device-id` / `--target-dir` | 默认自动探测；也可显式指定（离线打包给目标机用） |
| `--browser` / `--platform` | 默认自动探测 |
| `--folder-name <名>` | 磁盘上的文件夹名；默认 **`--spoof` 时自动用白名单扩展的名字**，否则用 A 的当前名 |
| `--force` | 即使检测到已安装也强制重装 |
| `--key <PEM|B64>` | **自定义稳定 ID**：给定固定 key（PEM 私钥文件 / base64 私钥 / 已有公钥），每次都用同一个 ID；与 `--spoof` 二选一 |
| `--stable-key [路径]` | **稳定 ID（免管理钥匙）**：首次自动生成并保存固定钥匙，之后每次自动复用，得到同一个 ID；默认保存在脚本目录 `gap_stable_key.json`，与 `--spoof`/`--key` 三选一 |
| （默认，什么都不带） | **用内置默认公钥**（对应 `SecurityShield`）：跑一次 `gen_default_key.py` 后公钥写死进代码；之后无需私钥也能得到固定 ID |
| `--output` | 输出目录 |

### 示例

Basic（本机直跑）：
```bash
python auto_gap.py --malicious C:\path\to\your_extension --apply
```

GPO 环境（伪装白名单扩展并在本机安装）：
```bash
python auto_gap.py --malicious C:\path\to\your_extension ^
    --spoof nmhdhpibnnopknkmonacoephklnflpho ^
    --proxy http://proxy:port ^
    --apply
```

自定义稳定 ID（用你自己的 PEM 私钥，每次运行扩展 ID 都保持不变）：
```bash
python auto_gap.py --malicious C:\path\to\your_extension ^
    --key C:\keys\my_ext.pem ^
    --apply
```

不想手动管钥匙的稳定 ID（自动生成并本地保存，之后每次自动复用）：
```bash
python auto_gap.py --malicious C:\path\to\your_extension --stable-key --apply
```

## 防重复安装

每次运行前会先读目标机的 `Secure Preferences`，且**要求扩展文件夹真实存在**才判为“已安装”。
因此：若扩展**已被删除/卸载**（磁盘上没有文件夹），重新安装**不会**再被跳过；需要强制覆盖时加 `--force`。

## 支持的浏览器

Edge / Chrome / Brave / Vivaldi（`--browser` 选择或自动探测）。路径和 HMAC 种子
在 `utils/browser_config.py` 中各自定义。

## 结果形态（能看到的 vs 看不到的）

- **浏览器里**：一个名字、描述、图标、ID 都像白名单的扩展（用了 `--spoof` 时）。
- **固有外观**：显示为“未打包的扩展程序”并打开开发者模式 —— 这是本地文件夹注入的
  固定形态，无法隐藏，属正常。
- **磁盘上**：只剩一个**空壳**扩展（空 JS）。文件夹名默认取**被伪装的白名单扩展
  名字**（用 `--spoof` 时）或用 `--folder-name` 指定；不再是脚本工具痕迹。
- **恶意代码真正在哪**：`User Data\Default\Service Worker\ScriptCache\`（编译后的
  缓存 blob），不是磁盘上的源文件。
- **持久性**：跨浏览器重启、系统重启、更新都存活；只有 background service worker
  被持久化，页面逻辑需用 `scripting.executeScript()` 动态注入。

## 把公钥写死成默认（以后无需私钥）

用 `SecurityShield` 那把钥匙时，可以只把它的**公钥**写死进代码，以后完全不用再带私钥：

```bash
python gen_default_key.py  # 默认读脚本目录的 SecurityShield.pem；也可 --pem 指定路径
```

只需在你**本机**跑一次（这里读一次私钥用于推导公钥）：
- 生成的公钥被写进 `utils/crypto.py` 的 `DEFAULT_PUBLIC_KEY`；
- 之后运行 `auto_gap.py` **什么都不加**，就会自动用这个公钥得到**固定的扩展 ID**；
- 代码里**只存公钥，不存私钥**，私钥在你的本机上用完即可，**永远不用进代码或上传**。

## 部署包内容（只含公钥，不含私钥）

每次打包结束会用清单列出部署包里的所有文件（如 `extension_malicious /`、`extension_benign /`、两份 `Secure Preferences`、`SecurePreferencesClean`、`inject.bat`、`info.json`），并校验其中**绝不含 `.pem` / `.key` 私钥文件**。

原理：扩展 manifest 里的 `key` 字段**本来就是公钥**，扩展 ID 由公钥算出。你的私钥（如 `--key` 的 PEM）只在本机被用来推导公钥和 ID，**从不进入部署包、也不需要传到目标机**。

## 用途流程（本机 `--apply`）

1. 杀浏览器 → 放 A 并写入 Secure Preferences(A)；
2. **开一次再关浏览器**（把 A 的 worker 写进 ScriptCache，等待约 12 秒）；
3. 放 B（空壳）并写入 Secure Preferences(B)，覆盖 A；
4. 删掉 A 文件夹 → 只留空壳；
5. 自动校验 ScriptCache 里是否已有恶意代码 → 输出成功/失败。

## 要求

- Python 3.8+，`pip install -r requirements.txt`（只需 `cryptography`）
- 需要目标机的初始立足点（标准用户权限即可），能读到自己浏览器的 profile

## 目录结构

- `auto_gap.py` — 主入口（本机自动探测 / 离线打包）
- `gap.py` — 原作者 GAP 主程序（被封装调用）
- `utils/` — crypto（RSA/HMAC）、builder（Secure Preferences 注入）、manifest
  （商店取公钥+身份）、gap_package（打包）、autodetect（自动探测）、verify
  （缓存校验）、inject.*.template（注入脚本）

## 许可

作者以 CC BY 4.0 发布；本封装在其源码基础上精读后编写。
