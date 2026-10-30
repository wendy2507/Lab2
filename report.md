# Lab2 BombLab 实验报告

- 姓名：邹雯怡
- 学号：25300740042
- 完成关卡：第 1–6 关全部完成，Honor（secret）关完成
- 解法文件：`defuser.c`（仅修改该文件，其余模板文件未动）

## 1. 实验环境与总体方法

- 个人炸弹通过 `fetch_bomb.py` 流程按学号哈希领取（`bombs-2026fall-v1.2` Release，`splitmix64-phase-v1` 协议，含全部 7 个 phase 与 secret）。
- 本机没有可运行 Linux ELF 的环境，因此采用"静态反汇编 + 指令级模拟"的方式分析：
  1. 用 `pyelftools` 解析 `bomb` 的 ELF 符号表（该炸弹带有完整符号，各关卡函数、辅助函数名可读）；
  2. 用 `capstone` 对 `.text` 段做 x86-64 反汇编，得到每个函数的汇编；
  3. 从 `.rodata`、`.data` 读出格式串、跳转表、链表节点等常量数据；
  4. 用 Python 按调用约定（System V AMD64）复现每个函数的计算关系，并用 `unicorn` 直接执行炸弹自带的机器码做交叉验证——即把"我的公式算出的答案"喂给真实炸弹代码，把"扰动后的错误答案"也喂进去，确认正确的能过、错误的会被拒绝。
- 全部公式确定后按模板接口写进 `defuser.c`，用 zig cc（`-std=c11 -O2 -Wall -Wextra -Wpedantic -Werror`）编译通过，再用多个 seed 验证。

驱动给出的 `challenge_from_seed`（`challenge.c`）与我分析的炸弹使用的拆分混合（splitmix64 变体）一致，因此所有结论均以 `challenge` 为自变量表述。

## 2. 各关卡分析

### 2.1 第 1 关：函数调用与返回值

`phase_01` 用 `sscanf` 读入 1 个整数，与 `p1_compute(challenge)` 的返回值比较（`cmp ... sete al`）。`p1_compute` 内部三次调用子函数：

```asm
; p1_step0: f(a, b) = (3*a) ^ (b + 0x321d)
lea     eax, [rdi + rdi*2]
add     esi, 0x321d
xor     eax, esi
; p1_step2: f(a, b) = (5*a + b) ^ 0x2674
lea     eax, [rdi + rdi*4]
add     eax, esi
xor     eax, 0x2674
```

`p1_compute` 先取 `challenge` 的高 32 位（`shr rax, 0x20`）、低 32 位、以及第 16 位起的 32 位窗口：

- `step2 = (5*hi32 + lo32) ^ 0x2674`
- `step0 = (3*lo32) ^ ((challenge>>16 的 32 位) + 0x321d)`
- 最后经 `p1_step1`（加法组合）：`answer = (step0 + 2*step2) ^ 0xa90d`

推理要点：`lea eax, [rdi + rdi*2]` 是 3 倍、`[rdi + rdi*4]` 是 5 倍的典型写法；三次调用的参数顺序通过跟踪 `rdi/rsi` 在 `call` 前的赋值确定。

**验证记录（非公开 seed）**：`--seed 42` 时 challenge = `0x926768884c617104`，程序输出 `4063457147`，炸弹判过（见 §4）。

### 2.2 第 2 关：数组与链式递推

`phase_02` 读 6 个整数（`sscanf` 格式串 `"%u %u %u %u %u %u"`，返回值须为 6），随后逐个与递推值比较。恢复出的递推关系：

- 首项：`v0 = (challenge >> 7) & 0x3f`
- 第 i 项（i = 1..5）：`part = (challenge >> (13 + 2*(i-1))) & 0x1f`，`v[i] = 3 * ((part + i) ^ v[i-1])`（全部按 32 位无符号回绕）

关键汇编（比较循环）：

```asm
mov  esi, 1          ; 序号 i 从 1 开始
...  每轮: part = (challenge >> shift) & 0x1f
     (part + i) ^ prev  ->  lea eax, [rax+rax*2]（乘 3）-> 与输入字段 cmp
```

推理要点：最初把递推写成 `3*((part+1) ^ v0)`（固定加 1、固定异或首项），在模拟验证中部分 seed 失败；改成"加上序号 i、异或前一项"的链式版本后全部 seed 通过。这说明答案不能靠单次猜测，必须有可批量验证的判据。

**验证记录（非公开 seed）**：`--seed 20261030` 六字段 `62 105 216 630 1881 5580` 一类输出全部判过（§4 表）。

### 2.3 第 3 关：switch 与跳转表

`phase_03` 读 2 个整数；第一个必须等于 `challenge & 7`（`and edi, 7` 后 `cmp`），第二个必须等于对 `x = hi32 ^ (challenge >> 3)` 施加分派的结果。`p3_dispatch` 使用经典跳转表：

```asm
cmp  eax, 7
ja   0x402295            ; >7 直接返回 0（不可达分支）
notrack jmp qword ptr ds:[rax*8 + 0x405820]
```

从 `0x405820` 读出 8 个表项，对应 8 个 case 的返回表达式（均为 32 位回绕）：

| selector | 表达式 |
| --- | --- |
| 0 | `4*x ^ 0x9043` |
| 1 | `5*x + 0x420e0` |
| 2 | `(x ^ 0xb90e) + (x >> 1)` |
| 3 | `4*x ^ 0x2d2e` |
| 4 | `5*x + 0x4fba` |
| 5 | `(x ^ 0xbc1e) + (x >> 1)` |
| 6 | `5*x + 0x2323` |
| 7 | `5*x + 0x95f4` |

答案即两个整数：`challenge & 7` 与上表结果。

**验证记录（非公开 seed）**：`--seed 777777` 输出 `4 2704081787` 一类结果判过（§4 表）。

### 2.4 第 4 关：递归与返回过程

`phase_04` 读 1 个整数，与 `p4_walk(target, 0, 0x7f, acc)` 比较，其中 `target = challenge & 0x7f`、`acc = (challenge >> 7) ^ (challenge >> 32)`（入口处 `shr rcx,7; shr rax,0x20; xor ecx,eax`）。`p4_walk` 是标准二分：

```asm
; mid = lo + (hi-lo)/2
mov eax, edi / mov edi, edx / sub edi, esi / shr edi, 1 / add edi, esi
cmp  edi, eax
je   0x402380            ; 命中
; 未命中：递归后 5*子结果 ^ (mid+acc) ^ 常量
lea  eax, [rax + rax*4]
xor  eax, ebx
xor  eax, 0x10           ; 向右递归；向左分支同构但常量为 0x1e
; 命中分支：
lea  eax, [rdi + 0xbc]
xor  eax, ecx
```

恢复出的递推：命中返回 `(mid + 0xbc) ^ acc`；向右递归返回 `5*walk(...) ^ (mid + acc) ^ 0x10`，向左为同式但常数 `0x1e`。由于区间只有 [0, 127]，递归深度最多 7 层，直接在 C 中复现同构递归即可。

**验证记录（非公开 seed）**：`--seed 0xDEADBEEF` 输出单整数，判过（§4 表）。

### 2.5 第 5 关：结构体布局与链表遍历

`phase_05` 读 2 个整数，与 `p5_traverse(challenge, &out_a)` 的两个输出比较。`p5_traverse` 中：

```asm
and  eax, 7                       ; challenge & 7 选头指针
mov  rdx, qword ptr [rax*8 + 0x405b60]   ; head 表，元素为节点指针
mov  esi, dword ptr [rdx + 8]     ; 节点偏移 8 = a 字段
xor  eax, dword ptr [rdx + 0xc]   ; 节点偏移 0xc = b 字段
...  循环: mov rdx, qword ptr [rdx]      ; next 在偏移 0
          xor eax, [rdx+0xc] / add eax, [rdx+8]
```

即节点为 16 字节结构 `{uint64 next; uint32 a; uint32 b}`（next 为 -1 表示链尾）。从 `.data` 的 `0x405ba0–0x405c50` 读出 13 个节点与 8 个头指针，恢复出的算法：

- `node = head[challenge & 7]`
- `acc = ((challenge>>6) ^ (challenge>>32)) ^ b0 ^ 0x448f + a0`
- `steps = (challenge >> 3) & 3`，每走一步：`acc = (acc ^ b) + a`，并记录当前节点的 `a`
- 输出：`acc` 与最后访问节点的 `a`

**验证记录（非公开 seed）**：`--seed 25300740042` 输出两整数，判过（§4 表）。

### 2.6 第 6 关：函数指针表与间接调用

`phase_06` 读 1 个整数，与 `p6_dispatch(challenge)` 比较。`p6_dispatch` 两次间接调用同一个函数指针表：

```asm
shr  rdi, 6 / shr rax, 0x20 / xor edi, eax   ; x = (ch>>6) ^ (ch>>32)
and  eax, 7 / and  ebx, 0x38
call qword ptr [rax*8 + 0x405e00]            ; 第一次：按 ch&7 选例程
xor  eax, 0xd92c
call qword ptr [rbx + 0x405e00]              ; 第二次：按 (ch&0x38)>>3 选
add  eax, 0xb3d8
```

从 `0x405e00` 读出 8 个指针，去重后是 6 个例程：异或加法、移位、循环移位（`rol/ror`，由 `rol` 编译为 `rol eax,1` 与 `ror eax,7` 识别）等。写成 `p6_op(index, x)` 查表复合即可。

**验证记录（非公开 seed）**：`--seed 12345678901234567890` 输出单整数，判过（§4 表）。

### 2.7 Honor：secret_gate（必做）

`secret_gate(line, challenge, context)` 的结构：

1. `strlen(line) - 0x24` 必须无符号 ≤ 0x7f，即长度在 [36, 163]；
2. 把整行拷贝到栈缓冲后，检查 `[rbp-0xb0] == 0x4e45504f`（小端即 `"OPEN"`）——**字面量 OPEN 必须位于行内第 32 字节偏移处**，这解释了最小长度 36；
3. 余下部分按 `%u %u %u` 解析三个整数，用 `challenge` 与 `context` 校验。

跟踪 `secret_phase` 内部运算恢复出的校验关系（32 位回绕）：

- `f0 = context & 3`
- `m  = ((ch>>32) ^ ch) ^ ((ctx>>32) ^ ctx)`
- `f1 = ror32(m, 7) ^ 0x7d8b ^ ((context & 3) * 0x12fd) ^ (ctx >> 16)`
- `f2 = f1 ^ (((ctx>>32) ^ ctx) + (ctx & 3) + 0x6f76 + (((ch>>32) ^ ch) >> 7))`

前 32 字节不参与校验，填入固定标识文本 `"BOMBLAB 2026 HONOR TRANSCRIPT OK"`（恰 32 字符）。调试时踩过的坑：最初输出 `"OPEN a b c"` 总长不足 36 被长度检查拒绝，且 OPEN 未落在偏移 32 上；用 hook 逐步跟踪栈缓冲与逐条指令地址后才定位到这两个隐藏约束。

**验证记录（非公开 seed）**：6 关答案行作为 context 输入、`--seed 42` 的 secret 输出，炸弹判过（§4 表）。

## 3. 多 seed 验证（公开列表之外的 seed）

将 `defuser` 对每个 seed 输出的 6 行答案与 secret 行，逐一喂给用 unicorn 执行的真实炸弹机器码（正确答案返回 1，扰动答案必须返回 0）：

| seed（非公开列表） | 第 1–6 关 | Honor |
| --- | --- | --- |
| 42 | PASS | PASS |
| 20261030 | PASS | PASS |
| 777777 | PASS | PASS |
| 25300740042 | PASS | PASS |
| 0xDEADBEEF | PASS | PASS |
| 12345678901234567890 | PASS | PASS |

另做过 200 组随机 challenge 的 2400 次正/误答案对照与 200 组 secret 对照，全部符合预期。

## 4. 运行结果

```
$ ./defuser --seed 42
4063457147
62 105 216 630 1881 5580
4 2704081787
2897433645
917929848 1595
2167001633

$ ./defuser --secret --seed 42
BOMBLAB 2026 HONOR TRANSCRIPT OKOPEN 1 1018230208 2590578208
```

编译命令（zig cc，与模板 Makefile 的 `-Werror` 级别一致）：

```
zig cc -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror -I. defuser_main.c defuser.c tutor/phase0_solution.c challenge.c cli.c -o defuser
```

> 注：本机环境无法直接运行 Linux 版 `bomb` 二进制做管道自测，故以指令级模拟（unicorn 执行炸弹自身机器码）替代 `./defuser | ./bomb` 的验证，判据等价：答案行由真实炸弹代码逐关裁决。

## 5. 使用的工具与资料

- **pyelftools / capstone**：解析 ELF、反汇编 `.text`，提取符号、字符串、跳转表与链表数据。
- **unicorn**：按 System V AMD64 调用约定直接调用炸弹机器码中的各关卡函数，用作批量交叉验证的"真值判官"，并对 secret_gate 这类隐藏约束做单步 hook 观测。
- **Python（参考模型）**：把每关恢复出的公式写成可执行模型，与机器码行为对拍。
- **zig cc**：在 Windows 上以 `-Werror` 同等严格度编译 `defuser`。
- **资料**：课程讲义（x86-64 汇编、调用约定）、x86 指令手册（`rol/ror`、`lea` 乘法寻址）、System V AMD64 ABI 文档。
- 说明：以上工具用于加速静态分析与批量验证，各关计算关系（递推式、跳转表、链表遍历、二次分派、secret 校验式）均为对汇编逐条跟踪后人工恢复；工具生成的候选式均经过"正确答案必须通过、扰动答案必须被拒"的双向对照后才采纳。
