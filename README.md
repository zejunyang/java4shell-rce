# Java4ShellRCE — CVE-2026-114938 ("Java4Shell") lab RCE exploit

A single-file, dependency-free Java exploit that escalates the **Java4Shell**
heap overflow to **arbitrary command execution**, verified end-to-end on real
hardware (AMD Ryzen 7 7840U / Zen 4, Temurin 21.0.13+9, Windows 11,
2026-11-18). [中文说明见 README.zh-CN.md](README.zh-CN.md).

- **Vulnerability**: HotSpot AVX-512 VBMI Base64 decode intrinsic
  (`StubGenerator::generate_base64_decodeBlock`, `L_finalBit` tail). A
  malformed input whose padded tail is shorter than 4 chars underflows the
  output-size/mask arithmetic (CWE-191), and one full 64-byte `VMOVDQU8`
  store lands up to **62 bytes past the end** of the destination `byte[]`
  (CWE-122).
- **Trigger**: `"A" × 64 + "="` (65 bytes, appended `=`) on JDK 21/25/27;
  `"A" × 128 + "="` (129 bytes) on JDK 17.0.6+.
- **Affected JDKs**: 17.0.6–17.0.21, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3
  (Oracle CPU notation; same lines in Temurin/Corretto/Zulu/Liberica/
  SapMachine/GraalVM). **Fixed** in 17.0.21.1 / 21.0.13.1 / 25.0.5.1 /
  27.0.1.1 ([JDK-8393212](https://github.com/openjdk/jdk/commit/5177a70b385c16f26ede191fdac7aaba0bed0f8b),
  a `length < 4` guard).
- **Hardware gate**: x86-64 with AVX-512 VBMI+BW (Intel Ice Lake+ / AMD
  Zen 4+). ARM64 and older x86 (Zen 3, Coffee Lake, …) are not affected.
- **Exploit chain**: groomed `dst|victim|cmd` heap adjacency → overflow
  corrupts the adjacent array's length (64 → 1771742825) → out-of-bounds
  **read** locates the command array → out-of-bounds **write** injects the
  payload → `Runtime.exec`.

Proven transcript (full logs in [docs/run_evidence.txt](docs/run_evidence.txt)):

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

## Requirements

| Requirement | Value |
|---|---|
| JDK | An affected build (see above). **Verified on: Temurin 21.0.13+9-LTS** |
| CPU | x86-64 with AVX-512 VBMI+BW (Intel Ice Lake+, AMD Zen 4+) |
| JVM flags | Defaults are fine (`UseAVX≥3`, `UseBASE64Intrinsics=true`); the tool warms the intrinsic itself |
| OS | **Verified on Windows 11.** The default payload is a Windows `cmd` command — on other OSes pass `--exec` (e.g. `sh|-c|id`). Linux is expected to work but was not tested |
| Privileges | None beyond `--add-opens java.base/java.util` (already in the jar manifest) |

## Quick start

Download [`Java4ShellRCE.jar`](../../releases/latest/download/Java4ShellRCE.jar)
from [Releases](../../releases) (SHA256
`4a83a5cc72a1d296d4e66894b499cf7f8622d1182b2bbd6458554297843e5b56`), then on
an affected JDK:

```bash
java -jar Java4ShellRCE.jar
```

- On a **vulnerable** JVM: probe prints `VULNERABLE (62-byte overflow ...)`,
  exploit prints `RCE PROVEN ...`, exit code `0`.
- On a **fixed or mitigated** JVM (e.g. `-XX:-UseBASE64Intrinsics`): clean
  `NOT EXPLOITED`, exit code `2` — no crash (see the negative-control
  transcript in [docs/run_evidence.txt](docs/run_evidence.txt)).

Build from source instead:

```bash
javac src/Java4ShellRCE.java -d build
java --add-opens java.base/java.util=ALL-UNNAMED -cp build Java4ShellRCE [options]
```

## Usage

```
java -jar Java4ShellRCE.jar [--exec "cmd|/c|<command>"] [--probe-only] [--exploit-only]
```

| Option | Meaning |
|---|---|
| *(none)* | Full pipeline: safe probe + exploit. Default payload: `cmd /c whoami > java4shell_pwned.txt 2>&1` |
| `--exec "cmd\|/c\|<command>"` | Custom payload. `\|` separates argv entries (it becomes NUL internally, so shell metacharacters like `>` reach the command intact) |
| `--probe-only` | Bounded detection probe only: fires the trigger through the **public** `Base64.decode()` into a 4096-byte canary. The 62 stray bytes land inside the canary, so nothing else is corrupted — safe to run as a vulnerability check on a lab copy of a production JVM |
| `--exploit-only` | Skip the probe, go straight to the exploit |

Exit codes: `0` = RCE proven · `2` = not exploited (see probe output) ·
`3` = usage error.

The tool executes a command **as the JVM user** — run it only where that is
acceptable.

## How the exploit works

```
WARM      200k public decodes + 200k direct decodeBlock MethodHandle calls
          compile the intrinsic. Warmup uses VALID input: no overflow fires,
          so no stray corrupted objects exist anywhere on the heap.
PROBE     malformed 65-byte decode into a 4096-byte canary through the
          PUBLIC API: proves the 62-byte overflow and dumps the store
          pattern (`9a 69 a6` repeating — identical to published Intel
          measurements, so the primitive is deterministic across vendors).
GROOM     dst[48] | victim[64] | cmd[] allocated back-to-back in one TLAB,
          invoked through an exact-signature MethodHandle into the PRIVATE
          decodeBlock() — same shape as the JDK's internal decode0(), and
          crucially WITHOUT the public API's dst-capacity check
          (decodedOutLength=50 would reject a 48-byte dst).
TRIGGER   one 65-byte decodeBlock call: the 64-byte vector store overflows
          dst; victim.length 64 -> 1771742825 (its klass is corrupted too
          — a GC time bomb, defused below).
READ      plain interpreted byte[] loads through the corrupted length locate
          cmd's payload at victim[80] (self-calibrating signature scan).
          Interpreted baload never dereferences the klass, so plain reads
          survive.
WRITE     Unsafe.putByte injects the attacker payload into cmd's data.
          Interpreted bastore DOES dereference the corrupted klass (byte[]
          vs boolean[] disambiguation via the layout helper) — raw memory
          stores are required.
EXEC      Runtime.exec(new String(cmd)); all references to the groomed
          arrays are dropped BEFORE waitFor(), so the corrupted object is
          already dead and any GC during execution skips it.
```

Everything after the corruption runs in interpreted (never-compiled)
methods: the interpreter re-reads the array length from the live object
header on every bounds check, so the corrupted length is honoured, and
byte[] loads avoid the corrupted klass word.

## Development walkthrough — how this was built

The goal: public material proved the overflow (ikow's bounded trigger) and
the adjacent-length corruption (r3dvei1's Calif65), and Calif claimed
product-level RCE but published no chain. This repo closes the missing
link: corruption → controlled read → controlled write → execution.

**0. Finding hardware that can run it at all.** The bug needs AVX-512
VBMI+BW. A quick census of the machines at hand: dev box Ryzen 5 5600H
(Zen 3) ✗, i7-9750H (Coffee Lake) ✗, Ryzen 7 7840U (Zen 4) ✓. Installed
Temurin 21.0.13+9 (the affected 21-line build) on the Zen 4 box.

**1. v1 — public API only.** A probe decoding the 65-byte trigger through
the public `Base64.Decoder.decode()` into a 4096-byte canary proved the
62-byte overflow on the first try (`changed=62 first=50 last=111`, pattern
`9a 69 a6`). But the exploit — a tight 48-byte dst — saw the victim
untouched. Two root causes:

- *C2 constant folding*: the warmup loop lived in `main`, so OSR
  compilation pulled the exploit in and folded `victim.length` back to the
  statically-known 64. Fix: warmup loops moved into separate methods; the
  exploit path stays interpreted (the interpreter re-reads the length from
  the header).
- *Capacity check*: `decode(src, dst)` precomputes
  `decodedOutLength("A"×64+"=") = 50` and rejects `dst.length < 50` with an
  IAE **before** the intrinsic runs. A tight dst is simply unreachable
  through the public API — which is exactly why the deterministic recipe
  calls the private `decodeBlock` directly.

**2. v2 — the direct-decodeBlock recipe.** Adopted from r3dvei1's MIT lab
(Calif65): an exact-signature MethodHandle into the private
`decodeBlock(...)` (no capacity check), plus `dst|victim|cmd` adjacency in
one TLAB. Their unmodified Calif65 was first re-run on our AMD box: 4/4
deterministic (length 64 → 1771742825, klass `0x2318` → `0x9aa6699a`) —
the corruption primitive is deterministic on Zen 4, not just the Intel
parts r3dvei1 measured.

**3. First full attempt: GC bomb.** The JVM died with
EXCEPTION_ACCESS_VIOLATION in a GC thread — the overflow also smashes the
victim's klass word, and the first GC that visits the object dereferences
it. Three fixes: warm the MethodHandle with a **valid** input (so warmup
itself corrupts nothing), never `System.gc()` after corruption (the single
allowed GC runs before, to empty eden for a clean groom), and drop all
references to the groomed arrays before waiting on the spawned process.

**4. Second attempt: the bastore klass dereference.** Corruption, OOB
read, and injection all worked — then a crash in an interpreter frame. The
`hs_err` MachCode dump explains it: interpreted `bastore` loads the array
klass (byte[]-vs-boolean[] disambiguation via the layout helper) before
storing; `baload` never does. With the klass corrupted, plain writes crash
while plain reads survive. Fix: all OOB writes go through
`Unsafe.putByte`. This asymmetry is a generally useful fact for Java
heap-corruption work.

**5. A silent trigger bug worth remembering.** One rewrite accidentally
wrote the pad char *over* the last `'A'` (a legal 64-byte `AAA=`-shaped
tail — no overflow). The pad must be **appended**:
`"A"×64 + "="` is 65 bytes. Symptom of getting it wrong: `rejected=false,
changed=0`.

**6. Result.** RCE proven twice from source, then the jar rebuilt cleanly
(single class, `Add-Opens` manifest) and verified three ways — full
pipeline with no flags, a negative control on a mitigated JVM (clean
`NOT EXPLOITED`, exit 2, no crash), and a custom payload. Transcripts:
[docs/run_evidence.txt](docs/run_evidence.txt).

## Notable technical findings

1. **The public API is exploitable too.** `decode(src, dst)` fires the
   same 62-byte overflow whenever `dst.length ≥ 50` — the bug needs no
   private calls to corrupt memory. The direct `decodeBlock` call is only
   needed for a *tight, deterministic* primitive.
2. **Deterministic across vendors.** Corrupted length 1771742825, klass
   `0x9aa6699a`, store pattern `9a 69 a6` — identical on Zen 4 (this repo)
   and Intel (r3dvei1's measurements).
3. **`bastore` dereferences the klass, `baload` does not.** OOB reads
   through a corrupted array work in plain interpreted Java; OOB writes must
   use raw stores (`Unsafe`) — see docs/hs_err_pid878384.log.
4. **The corrupted klass is a GC time bomb.** Defusing = valid-input
   warmup, no GC after corruption, drop references before `waitFor()` —
   see docs/hs_err_pid878888.log.
5. **Content sensitivity (open observation).** `"Q"×64+"="` does NOT
   trigger (changed=0) while `"A"×64+"="` does — the vector-tail path is
   content-sensitive, not just shape-sensitive.
6. **A cheap behavioral fingerprint.** For the same malformed input, the
   buggy intrinsic returns `ret=47` where the scalar path returns `ret=48`
   — observable without any memory comparison.

## Limitations — read before you rely on this

- **This is the lab chain, not a universal weapon.** It proves: attacker
  data reaching a Base64 decode in a groomed heap ⇒ arbitrary command
  execution inside that JVM. A **remote** one-shot exploit against a
  specific product (Keycloak, Jira, …) still needs per-target heap
  grooming (TLAB size, allocation pacing, warmup) — consistent with
  Calif's "no universal exploit" statement (CVSS AC:H).
- Firing the raw trigger at an ungroomed service realistically yields heap
  corruption, crashes, or info leak — not a shell.
- **Verified on exactly one configuration**: Temurin 21.0.13+9-LTS,
  Windows 11, Ryzen 7 7840U (2026-11-18). JDK 17 (129-byte trigger, dst=96)
  is coded but **not** tested; JDK 25/27, Linux/macOS, and Intel hardware
  are **not** tested by this repo.
- The default payload is Windows-only; use `--exec` elsewhere.
- The tool runs a command as the JVM user and needs
  `--add-opens java.base/java.util` (in the jar manifest) — it is for lab
  verification and internal detection, not for running against production
  JVMs you don't own.

## Defense / detection quick notes

- **Patch**: 17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1 (JDK-8393212). Check
  bundled JREs in containers and app distributions, not just the system
  Java.
- **Mitigate**: `-XX:-UseBASE64Intrinsics` (or `-XX:UseAVX=2`). Both may
  cost Base64 throughput; benchmark first.
- **Verify safely**: run `java -jar Java4ShellRCE.jar --probe-only` on a
  lab copy of the JVM in a change window. `VULNERABLE` on the vulnerable
  build; `changed=0` + exit 2 once patched or mitigated.
- **Watch for**: JVM crashes (`hs_err_pid*.log`, SIGSEGV in base64/decode
  stubs), and Base64-shaped attacker input — e.g. Authorization headers,
  cookies, JWTs, SAML — containing `A`×64 + `=` style padded tails.

## Credits

- **Quang Luong (Calif.io)** — original disclosure (2026-11-17), trigger
  shapes, affected-version matrix.
- [ikow/java4shell-poc](https://github.com/ikow/java4shell-poc) (MIT) —
  bounded trigger and measurement methodology.
- [r3dvei1/java4shell](https://github.com/r3dvei1/java4shell) (MIT) —
  root-cause analysis, the direct-decodeBlock MethodHandle recipe and
  dst|victim adjacency (Calif65), and the corrected exploit-chain status.
- [OpenJDK](https://github.com/openjdk/jdk/commit/5177a70b385c16f26ede191fdac7aaba0bed0f8b) — the fix.
- The escalation to command execution (OOB read scan, Unsafe injection,
  GC-bomb defusing, bastore/baload asymmetry, public-API reachability
  proof): **this repository**.

## License

[MIT](LICENSE). Third-party material referenced above is under its own
licenses (linked).
