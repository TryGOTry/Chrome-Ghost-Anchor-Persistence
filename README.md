# Chrome-Ghost-Anchor-Persistence
基于 Fir3n0x 的 **GAP**（无文件扩展持久化）研究封装的自动化工具。核心思路： 把恶意代码藏进浏览器的 **Service Worker ScriptCache（编译缓存）**，磁盘上只留一个 **空壳扩展**。于是浏览器每次启动都会从缓存执行恶意代码，而磁盘上没有恶意源文件。
