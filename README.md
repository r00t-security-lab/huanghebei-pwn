# huanghebei-pwn

黄鹤杯等 CTF 题目的题解与复现资料。

## 目录

| 题目 | 类型 | 说明 |
| --- | --- | --- |
| [postbox](postbox/postbox.md) | Pwn / 逆向 | ELF x86-64，glibc 2.31，负数下标越界导致的任意地址读写 |
| [molun](molun/REPORT.md) | Pwn | 栈溢出，tape 容量常数与栈帧不一致 |

### postbox

- 题解：[postbox/postbox.md](postbox/postbox.md)
- Exp：[postbox/exp.py](postbox/exp.py)
- 附件：`postbox/postbox`、`postbox/libc.so.6`、`postbox/ld-2.31.so`
- 修复补丁版本：`postbox/patch/`
- IDA 数据库：`postbox/*.i64`

复现：

```bash
cd postbox
python3 exp.py
```

### molun

- 逆向过程：[molun/molun.md](molun/molun.md)
- 报告：[molun/REPORT.md](molun/REPORT.md)（漏洞 / 通防 / 修法 / 打法）
- Exp：[molun/exp.py](molun/exp.py)
- 原题未通防版本：`molun/patch/molun.bak`；通防版本：`molun/molun`

复现：

```bash
cd molun
python3 exp.py
```

## 声明

仓库内容仅用于 CTF 竞赛学习与安全研究，请勿用于未授权测试。
