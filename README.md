# huanghebei-pwn

黄鹤杯 Pwn 题目题解与复现资料。

## 目录

| 题目 | 类型 | 说明 |
| --- | --- | --- |
| [postbox](postbox/postbox.md) | Pwn / 逆向 | ELF x86-64，glibc 2.31，负数下标越界导致的任意地址读写 |

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

## 声明

仓库内容仅用于 CTF 竞赛学习与安全研究，请勿用于未授权测试。
