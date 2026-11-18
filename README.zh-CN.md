# Java4ShellRCE — CVE-2026-114938（"Java4Shell"）实验室 RCE 利用工具

单文件、零依赖的 Java 利用程序，把 Java4Shell 堆溢出升级为**任意命令执行**，
已在真实硬件上端到端验证（AMD Ryzen 7 7840U / Zen 4、Temurin 21.0.13+9、
Windows 11，2026-11-18）。[English README](README.md)。

- **漏洞**：HotSpot AVX-512 VBMI Base64 解码 intrinsic
  （`StubGenerator::generate_base64_decodeBlock` 的 `L_finalBit` 尾部路径）。
  填充尾短于 4 字符的畸形输入使输出长度/掩码算术下溢（CWE-191），一次完整的
  64 字节 `VMOVDQU8` 存储越过目标 `byte[]` 末端最多 **62 字节**（CWE-122）。
- **触发串**：JDK 21/25/27 用 `"A"×64 + "="`（65 字节，`=` 追加在末尾）；
  JDK 17.0.6+ 用 `"A"×128 + "="`（129 字节）。
- **受影响 JDK**：17.0.6–17.0.21、21.0.13.0.3、25.0.5.0.3、27.0.1.0.3（Oracle
  CPU 记法；Temurin/Corretto/Zulu/Liberica/SapMachine/GraalVM 同线路均含）。
  **修复版**：17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1
  （[JDK-8393212](https://github.com/openjdk/jdk/commit/5177a70b385c16f26ede191fdac7aaba0bed0f8b)，
  一个 `length < 4` 守卫）。
- **硬件门槛**：x86-64 且支持 AVX-512 VBMI+BW（Intel Ice Lake+ / AMD Zen 4+）。
  ARM64 与较老的 x86（Zen 3、Coffee Lake 等）不受影响。
- **利用链**：堆上连续布置 `dst|victim|cmd` → 溢出改写邻接数组的 length
  （64 → 1771742825）→ 越界**读**定位命令数组 → 越界**写**注入 payload →
  `Runtime.exec` 执行。

已验证的运行记录（完整日志见
[docs/run_evidence.txt](docs/run_evidence.txt)）：

```
probe[A-input] rejected=true changed=62 first=50 last=111
  store: 9a 69 a6 9a 69 a6 9a 69 a6 ...
  VULNERABLE (62-byte overflow past a 48B destination)
attempt dst=48B ret=47 victim.length=1771742825 (was 64)
  cmd data located at victim[80] via OOB read; injecting payload
  cmd array now: [cmd|/c|whoami > java4shell_pwned.txt 2>&1]
exec rc=0
--- java4shell_pwned.txt ---
gpd\aquaflux
RCE PROVEN: command executed via CVE-2026-114938 heap corruption
```

## 环境要求

| 要求 | 取值 |
|---|---|
| JDK | 受影响版本（见上）。**实测：Temurin 21.0.13+9-LTS** |
| CPU | x86-64 且支持 AVX-512 VBMI+BW（Intel Ice Lake+、AMD Zen 4+） |
| JVM 参数 | 默认即可（`UseAVX≥3`、`UseBASE64Intrinsics=true`），工具自己做预热 |
| 操作系统 | **实测 Windows 11。** 默认 payload 是 Windows `cmd` 命令——其他系统请用 `--exec`（如 `sh|-c|id`）。Linux 预期可用但未实测 |
| 权限 | 只需 `--add-opens java.base/java.util`（jar manifest 已内置） |

## 快速开始

从 [Releases](../../releases) 下载
[`Java4ShellRCE.jar`](../../releases/latest/download/Java4ShellRCE.jar)
（SHA256
`4a83a5cc72a1d296d4e66894b499cf7f8622d1182b2bbd6458554297843e5b56`），
在受影响的 JDK 上运行：

```bash
java -jar Java4ShellRCE.jar
```

- **有漏洞**的 JVM：probe 打印 `VULNERABLE (62-byte overflow ...)`，exploit
  打印 `RCE PROVEN ...`，退出码 `0`。
- **已修复或已缓解**的 JVM（如 `-XX:-UseBASE64Intrinsics`）：干净地打印
  `NOT EXPLOITED`，退出码 `2`，不崩溃（阴性对照记录见
  [docs/run_evidence.txt](docs/run_evidence.txt)）。

从源码构建：

```bash
javac src/Java4ShellRCE.java -d build
java --add-opens java.base/java.util=ALL-UNNAMED -cp build Java4ShellRCE [选项]
```

## 用法

```
java -jar Java4ShellRCE.jar [--exec "cmd|/c|<命令>"] [--probe-only] [--exploit-only]
```

| 选项 | 含义 |
|---|---|
| *（无）* | 完整流程：安全探测 + 利用。默认 payload：`cmd /c whoami > java4shell_pwned.txt 2>&1` |
| `--exec "cmd\|/c\|<命令>"` | 自定义 payload。`\|` 分隔 argv 各项（内部转为 NUL，因此 `>` 等重定向符能完整传给命令） |
| `--probe-only` | 只跑有界探测：通过**公开** `Base64.decode()` 触发，写入 4096 字节金丝雀数组。62 个越界字节全部落在金丝雀内部，不破坏其他对象——可作为生产 JVM 实验副本的漏洞检查 |
| `--exploit-only` | 跳过探测，直接利用 |

退出码：`0` = RCE 已证明 · `2` = 未利用成功（看探测输出）· `3` = 用法错误。

工具以 **JVM 进程用户身份**执行命令——只在对该行为可接受的环境里运行。

## 利用原理

```
WARM      20 万次公开 decode + 20 万次 decodeBlock MethodHandle 直调，
          编译出 intrinsic。预热用合法输入：不触发溢出，
          堆上不存在任何被破坏的杂散对象。
PROBE     65 字节畸形输入经公开 API 解码进 4096 字节金丝雀：
          证明 62 字节溢出并打印写入模式（`9a 69 a6` 循环，
          与 Intel 上已发表的测量一致——原语跨厂商确定）。
GROOM     dst[48] | victim[64] | cmd[] 在同一个 TLAB 里连续分配，
          通过精确签名的 MethodHandle 调用私有 decodeBlock()——
          与 JDK 内部 decode0() 同形，且没有公开 API 的容量检查
          （decodedOutLength=50 会拒绝 48 字节的 dst）。
TRIGGER   一次 65 字节 decodeBlock 调用：64 字节向量存储越过 dst；
          victim.length 64 -> 1771742825（klass 一并被破坏——
          一颗 GC 定时炸弹，见下文的拆除）。
READ      用被破坏的 length 做普通越界读，在 victim[80] 定位 cmd 的
          payload（自校准签名扫描）。解释执行的 baload 不解引用
          klass，普通读可以存活。
WRITE     Unsafe.putByte 把攻击者 payload 注入 cmd 的数据区。
          解释执行的 bastore 会解引用被破坏的 klass（byte[]/boolean[]
          消歧要读 layout helper）——必须用裸内存写。
EXEC      Runtime.exec(new String(cmd))；在 waitFor() 之前就丢弃
          全部引用，被破坏的对象已死，执行期间任何 GC 都会跳过它。
```

破坏发生后的所有数组访问都跑在解释执行（未被编译）的方法里：解释器每次
边界检查都从活动对象头重新读 length，因此被破坏的 length 生效；且 byte[]
读不碰被破坏的 klass 字。

## 开发过程——这个工具是怎么做出来的

目标：公开材料证明了溢出（ikow 的有界触发器）和邻接 length 破坏
（r3dvei1 的 Calif65），Calif 声称产品级 RCE 但没有公开利用链。本仓库补上
缺失的最后一环：破坏 → 受控读 → 受控写 → 执行。

**0. 先找到能跑的硬件。** 这个洞需要 AVX-512 VBMI+BW。快速盘点手头机器：
开发机 Ryzen 5 5600H（Zen 3）✗、i7-9750H（Coffee Lake）✗、Ryzen 7 7840U
（Zen 4）✓。在 Zen 4 机器上安装受影响的 Temurin 21.0.13+9。

**1. v1——只用公开 API。** 把 65 字节触发串经公开
`Base64.Decoder.decode()` 解码进 4096 字节金丝雀，一次就证明了 62 字节
溢出（`changed=62 first=50 last=111`，模式 `9a 69 a6`）。但用紧凑 48 字节
dst 的 exploit 一直看不到 victim 被碰。两个根因：

- *C2 常量折叠*：预热循环写在 `main` 里，OSR 编译把 exploit 一起编译了，
  `victim.length` 被折叠回静态已知的 64。修复：预热循环移进独立方法，
  exploit 路径保持解释执行（解释器每次都从对象头重读 length）。
- *容量检查*：`decode(src, dst)` 预计算
  `decodedOutLength("A"×64+"=") = 50`，在 intrinsic 运行**之前**就用 IAE
  拒绝 `dst.length < 50`。紧凑的 dst 根本到不了公开 API 的 intrinsic——
  这正是确定性配方要直调私有 `decodeBlock` 的原因。

**2. v2——decodeBlock 直调配方。** 采纳 r3dvei1 的 MIT 实验室方案
（Calif65）：精确签名 MethodHandle 直调私有 `decodeBlock(...)`（无容量
检查），加 `dst|victim|cmd` 单 TLAB 邻接。先在 AMD 机器上原样跑他们的
Calif65：4/4 确定成功（length 64 → 1771742825，klass `0x2318` →
`0x9aa6699a`）——破坏原语在 Zen 4 上同样确定，不只限于 r3dvei1 测量的
Intel。

**3. 第一次完整尝试：GC 炸弹。** JVM 在 GC 线程里
EXCEPTION_ACCESS_VIOLATION 崩溃——溢出同样砸坏了 victim 的 klass 字，第
一个访问该对象的 GC 解引用它就死。三个修复：MethodHandle 预热改用**合法**
输入（预热本身不破坏任何东西）；破坏之后绝不 `System.gc()`（唯一允许的
GC 在破坏之前跑，清空 eden 便于 groom）；等待子进程前先丢弃全部引用。

**4. 第二次尝试：bastore 的 klass 解引用。** 破坏、越界读、注入全部
成功——然后在解释帧里崩溃。`hs_err` 的 MachCode 说明了原因：解释执行的
`bastore` 存储前要读数组 klass（byte[]/boolean[] 消歧要读 layout
helper）；`baload` 从不读。klass 被破坏后，普通写会崩，普通读能活。
修复：所有越界写改走 `Unsafe.putByte`。这个不对称性对今后的 Java 堆破坏
利用都有参考价值。

**5. 一个值得记住的静默触发 bug。** 一次重写不小心把填充符写在最后一个
`'A'` **上面**（变成合法的 64 字节 `AAA=` 形尾——不溢出）。填充符必须
**追加**：`"A"×64 + "="` 共 65 字节。写错的症状：`rejected=false,
changed=0`。

**6. 结果。** 源码两次证明 RCE，然后干净重打 jar（单 class、manifest 带
`Add-Opens`）并三重验证——免参数完整流程、缓解 JVM 上的阴性对照（干净
`NOT EXPLOITED`，退出码 2，不崩溃）、自定义 payload。记录：
[docs/run_evidence.txt](docs/run_evidence.txt)。

## 值得保留的技术发现

1. **公开 API 同样可触发。** 只要 `dst.length ≥ 50`，`decode(src, dst)`
   就会触发同样的 62 字节溢出——破坏内存不需要私有调用。直调
   `decodeBlock` 只是*紧凑确定性*原语的需要。
2. **跨厂商确定性。** 被破坏的 length 1771742825、klass `0x9aa6699a`、
   写入模式 `9a 69 a6`——Zen 4（本仓库）与 Intel（r3dvei1 测量）完全
   一致。
3. **`bastore` 解引用 klass，`baload` 不解引用。** 被破坏数组上的越界读
   用普通解释 Java 就能做；越界写必须用裸写（`Unsafe`）——见
   docs/hs_err_pid878384.log。
4. **被破坏的 klass 是 GC 定时炸弹。** 拆除方法 = 合法输入预热 + 破坏后
   不 GC + waitFor 前清引用——见 docs/hs_err_pid878888.log。
5. **内容敏感性（开放观察）。** `"Q"×64+"="` 不触发（changed=0）而
   `"A"×64+"="` 触发——向量尾部路径对内容敏感，不只对形状敏感。
6. **一个便宜的行为指纹。** 同一畸形输入下，带病的 intrinsic 返回
   `ret=47`，标量路径返回 `ret=48`——不比内存也能观察到。

## 限制——依赖本工具前必读

- **这是实验室链，不是通用武器。** 它证明的是：攻击者数据到达被 groom 过的
  堆上的 Base64 解码 ⇒ 该 JVM 内任意命令执行。对具体产品（Keycloak、
  Jira……）的**远程**一键利用仍需按目标做堆布局（TLAB 大小、分配节奏、
  预热）——与 Calif "没有通用利用"的说法一致（CVSS AC:H）。
- 对未做布局的远程服务裸发触发串，现实结果是堆破坏、崩溃或信息泄露——
  不是 shell。
- **只在一个配置上验证过**：Temurin 21.0.13+9-LTS、Windows 11、
  Ryzen 7 7840U（2026-11-18）。JDK 17（129 字节触发、dst=96）代码已写但
  **未**实测；JDK 25/27、Linux/macOS、Intel 硬件本仓库**未**实测。
- 默认 payload 仅适用于 Windows；其他平台用 `--exec`。
- 工具以 JVM 进程用户执行命令，需要
  `--add-opens java.base/java.util`（jar manifest 已内置）——定位是实验
  室验证与内部检测，不是拿去打不属于自己的生产 JVM。

## 防御 / 检测速查

- **打补丁**：17.0.21.1、21.0.13.1、25.0.5.1、27.0.1.1（JDK-8393212）。
  别只看系统 Java——容器镜像和应用自带的 JRE 都要查。
- **缓解**：`-XX:-UseBASE64Intrinsics`（或 `-XX:UseAVX=2`）。两者都可能影响
  Base64 吞吐，先压测。
- **安全验证**：在变更窗口、对 JVM 的实验副本跑
  `java -jar Java4ShellRCE.jar --probe-only`。有漏洞的版本打印
  `VULNERABLE`；已修复/缓解后 `changed=0` 且退出码 2。
- **留意**：JVM 崩溃（`hs_err_pid*.log`，base64/decode stub 里的
  SIGSEGV）；以及 Authorization 头、Cookie、JWT、SAML 等攻击者可控的
  Base64 中出现 `A`×64 + `=` 式的填充尾。

## 致谢

- **Quang Luong（Calif.io）**——原始披露（2026-11-17）、触发形状、受影响
  版本矩阵。
- [ikow/java4shell-poc](https://github.com/ikow/java4shell-poc)（MIT）——
  有界触发器与测量方法。
- [r3dvei1/java4shell](https://github.com/r3dvei1/java4shell)（MIT）——
  根因分析、decodeBlock 直调 MethodHandle 配方与 dst|victim 邻接
  （Calif65）、修正后的利用链状态。
- [OpenJDK](https://github.com/openjdk/jdk/commit/5177a70b385c16f26ede191fdac7aaba0bed0f8b)——修复。
- 升级到命令执行的部分（越界读扫描、Unsafe 注入、GC 炸弹拆除、
  bastore/baload 不对称、公开 API 可达性证明）：**本仓库**。

## 许可证

[MIT](LICENSE)。引用的第三方材料遵循其自身许可证（见链接）。
