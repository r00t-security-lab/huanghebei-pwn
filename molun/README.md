# molun

栈溢出 + tape 容量常数与栈帧不一致，PIE-only 打法（不依赖 libc 版本）。

完整分析见 [REPORT.md](REPORT.md)（漏洞 / 通防 / 修法 / 打法）；逐步逆向过程见 [molun.md](molun.md)。

## 文件

| 文件 | 说明 |
| --- | --- |
| `molun.md` | 逆向 / 漏洞分析过程（含截图） |
| `REPORT.md` | 分析报告 |
| `exp.py` | 利用脚本（pwntools） |
| `molun` | 上过通防的版本（`0x1180` 处 20 字节 NOP，去掉构造函数里的 `open("./flag")`） |
| `patch/molun.bak` | 原题未通防版本（构造函数据 `open("./flag")`，fd 3 即 flag） |
| `patch/molun` | 官方 patch 版（= 上面的 `molun`） |
| `molun.fixcap` | 修法 A：改 4 个立即数，把 tape 容量改回与栈帧一致 |
| `*.i64` | IDA 数据库 |
| `libc.so.6` / `ld-2.31.so` | Ubuntu GLIBC 2.31-0ubuntu9.18 |

## REPORT.md 中的路径对照

报告里按原始工作目录书写，本仓库对应关系如下：

| REPORT 中 | 本仓库 |
| --- | --- |
| `attachment/molun` | `molun`（或 `patch/molun`） |
| `attachment/molun.bak` | `patch/molun.bak` |
| `attachment/libc.so.6` | `libc.so.6` |
| `work/ld-2.31.so` | `ld-2.31.so` |

## 复现

```bash
cd molun
python3 exp.py
```
