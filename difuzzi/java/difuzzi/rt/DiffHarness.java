package difuzzi.rt;

import java.io.*;
import java.lang.reflect.*;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/**
 * The Java differential fuzzing run (the counterpart of difuzzi/harness.py), executed as a Jazzer target.
 *
 * Steps: load A and B in separate class loaders (they may use the same class names); run the example
 * inputs; phase 1 is Jazzer's coverage-guided fuzzing; phase 2 (top-up) feeds random bytes through the
 * same input generator. Every input is deduplicated, run on A and B, and the outcomes are compared.
 * Jazzer cannot hand control back, so phase 2 and the final result are produced from inside the last
 * fuzzing callback, which then halts the JVM.
 *
 * The job is a properties file given by -Ddifuzzi.job=PATH (written by difuzzi/java_backend.py).
 */
public final class DiffHarness {
    static final int PLATEAU = 200, SATURATION = 500, MAX_COUNTEREXAMPLES = 20;
    static final long CHECKPOINT_MS = 2000;

    static Properties job;
    static String level, mode;
    static long t0, deadline, lastCheckpoint;
    static int maxCases;
    static long callTimeoutMs;
    static boolean topup;

    static Side sideA, sideB;
    static Method fileGenerator;             // file level: DiffGen.generate, loaded once
    static Method fdpFactory;                // FuzzedDataProviderImpl.withJavaData(byte[])

    static String phase = "examples";
    static final Map<String, Integer> distinct = new LinkedHashMap<>(), attempts = new LinkedHashMap<>();
    static final Map<String, Integer> outcomes = new LinkedHashMap<>();
    static final Set<String> seen = new HashSet<>();
    static final List<Map<String, Object>> counterexamples = new ArrayList<>();
    static final List<String> exampleErrors = new ArrayList<>();
    static final List<String> genFailureSamples = new ArrayList<>(), aErrorSamples = new ArrayList<>();  // for the LLM
    static int duplicates, genFailures, streak, sinceNewCov;
    static long probesSeen = -1;
    static String stopReason;

    static final PrintStream REAL_OUT = System.out, REAL_ERR = System.err;
    static final InputStream REAL_IN = System.in;
    static final PrintStream SILENT = new PrintStream(OutputStream.nullOutputStream());

    /** One program (A or B) loaded in its own class loader. */
    static final class Side {
        final String name;
        final ClassLoader loader;
        final Class<?> mainClass;
        final List<Method> entries = new ArrayList<>();   // function level: overloads of the entry point
        Method generator;                                 // function level: DiffGen.generate in this loader
        Class<?> examples;                                // function level: DiffExamples in this loader

        Side(String name, Path dir, Path genDir, String mainClass, String entry) throws Exception {
            this.name = name;
            List<URL> urls = new ArrayList<>(List.of(dir.toUri().toURL()));
            if (genDir != null) urls.add(genDir.toUri().toURL());
            loader = new URLClassLoader(urls.toArray(new URL[0]), DiffHarness.class.getClassLoader());
            this.mainClass = Class.forName(mainClass, false, loader);
            if (level.equals("function")) {
                for (Method m : this.mainClass.getDeclaredMethods())
                    if (m.getName().equals(entry) && !m.isSynthetic()) { m.setAccessible(true); entries.add(m); }
                if (entries.isEmpty()) throw new IllegalStateException(name + ": method " + entry + " not found in " + mainClass);
                generator = findGenerate(Class.forName("DiffGen", true, loader));
                try { examples = Class.forName("DiffExamples", true, loader); } catch (ClassNotFoundException ignored) { }
            } else {
                Method main = this.mainClass.getDeclaredMethod("main", String[].class);
                main.setAccessible(true);
                entries.add(main);
            }
        }
    }

    /** Result of running one program on one input. */
    static final class Outcome {
        final String kind;      // ok | raise | timeout
        final Object value;     // return value (function level) or normalized stdout (file level)
        final String error;

        Outcome(String kind, Object value, String error) { this.kind = kind; this.value = value; this.error = error; }

        boolean ok() { return kind.equals("ok"); }

        String show() { return ok() ? (value instanceof String && level.equals("file") ? quoted((String) value) : Values.repr(value)) : (error != null ? error : kind); }
    }

    // ---- setup ----------------------------------------------------------------------------------------
    public static void fuzzerInitialize() {
        try {
            job = new Properties();
            try (Reader r = Files.newBufferedReader(Paths.get(System.getProperty("difuzzi.job")), StandardCharsets.UTF_8)) {
                job.load(r);
            }
            level = job.getProperty("level");
            mode = job.getProperty("mode");
            maxCases = Integer.parseInt(job.getProperty("max_cases"));
            callTimeoutMs = (long) (Double.parseDouble(job.getProperty("call_timeout")) * 1000);
            topup = Boolean.parseBoolean(job.getProperty("topup"));
            t0 = System.currentTimeMillis();
            deadline = t0 + (long) (Double.parseDouble(job.getProperty("time_budget")) * 1000);
            for (String p : List.of("examples", "phase1", "phase2")) distinct.put(p, 0);
            attempts.put("phase1", 0);
            attempts.put("phase2", 0);
            for (String k : List.of("same_output", "both_error", "different_output", "b_error_only", "a_error_only")) outcomes.put(k, 0);
            fdpFactory = Class.forName("com.code_intelligence.jazzer.driver.FuzzedDataProviderImpl").getMethod("withJavaData", byte[].class);

            Path gen = Paths.get(job.getProperty("gen_dir"));
            boolean fn = level.equals("function");
            try {
                sideA = new Side("A", Paths.get(job.getProperty("a_dir")), fn ? gen : null, job.getProperty("a_main"), job.getProperty("entry_a"));
                sideB = new Side("B", Paths.get(job.getProperty("b_dir")), fn ? gen : null, job.getProperty("b_main"), job.getProperty("entry_b"));
                if (!fn) fileGenerator = findGenerate(Class.forName("DiffGen", true, new URLClassLoader(
                        new URL[]{gen.toUri().toURL()}, DiffHarness.class.getClassLoader())));
            } catch (Throwable e) {
                fail("loading failed: " + describe(e));
            }

            // 1. example inputs
            int n = Integer.parseInt(job.getProperty("n_examples"));
            for (int i = 0; i < n; i++) {
                Object inA, inB;
                try {
                    if (fn) {
                        inA = sideA.examples.getMethod("ex" + i).invoke(null);
                        inB = sideB.examples.getMethod("ex" + i).invoke(null);
                    } else {
                        inA = inB = Files.readString(Paths.get(job.getProperty("examples_dir"), "ex" + i + ".txt"));
                    }
                } catch (Throwable e) {
                    fail("example input " + (i + 1) + " could not be evaluated: " + describe(e));
                    return;
                }
                runInput(inA, inB);
            }
            if (Boolean.parseBoolean(job.getProperty("examples_only", "false"))) {   // evaluation: fixed inputs only
                stopReason = "max_cases";
                finish();
            }
            if (!exampleErrors.isEmpty()) fail("A fails on an example input: " + String.join("; ", exampleErrors));
            stopReason = globalStop();
            if (stopReason != null) finish();
            phase = "phase1";
        } catch (Throwable e) {
            fail("harness setup failed: " + describe(e));
        }
    }

    static Method findGenerate(Class<?> gen) {
        for (Method m : gen.getDeclaredMethods())
            if (m.getName().equals("generate") && m.getParameterCount() == 1) { m.setAccessible(true); return m; }
        throw new IllegalStateException("the input generator does not define generate(FuzzedDataProvider)");
    }

    // ---- one input --------------------------------------------------------------------------------------
    static Object fdp(byte[] data) throws Exception { return fdpFactory.invoke(null, (Object) data); }

    static void close(Object fdp) {
        try { ((AutoCloseable) fdp).close(); } catch (Exception ignored) { }
    }

    /** Fuzzer bytes -> one input for A and one for B (built separately, from the same bytes) -> run. */
    static void tryBytes(byte[] data) {
        attempts.merge(phase, 1, Integer::sum);
        Object inA, inB;
        if (level.equals("function")) {
            Outcome ga = generate(sideA.generator, sideA.loader, data);
            if (!ga.ok() || !(ga.value instanceof Object[])) { genFailures++; streak++; genFailure(ga, "Object[]"); return; }
            Outcome gb = generate(sideB.generator, sideB.loader, data);
            inA = ga.value;
            inB = gb.ok() && gb.value instanceof Object[] ? gb.value : gb;   // B cannot build its own input
        } else {
            Outcome g = generate(fileGenerator, DiffHarness.class.getClassLoader(), data);
            if (!g.ok() || g.value == null) { genFailures++; streak++; genFailure(g, "String"); return; }
            inA = inB = String.valueOf(g.value);
        }
        runInput(inA, inB);
    }

    static void genFailure(Outcome g, String expected) {
        if (genFailureSamples.size() >= 3) return;
        genFailureSamples.add(shorten(g.ok() ? "generate returned " + (g.value == null ? "null" : g.value.getClass().getName())
                + " instead of a " + expected : g.show(), 300));
    }

    static Outcome generate(Method gen, ClassLoader loader, byte[] data) {
        return withTimeout(loader, () -> {
            Object f = fdp(data);
            try { return gen.invoke(null, f); } finally { close(f); }
        }, false);
    }

    static void runInput(Object inA, Object inB) {
        String key = level.equals("function") ? showArgs((Object[]) inA) : (String) inA;
        if (!seen.add(key)) { duplicates++; streak++; return; }
        streak = 0;
        distinct.merge(phase, 1, Integer::sum);

        Outcome a = execute(sideA, inA);
        Outcome b = inB instanceof Outcome ? new Outcome("raise", null, "B could not build the input: " + ((Outcome) inB).error) : execute(sideB, inB);
        long probes = Coverage.count();
        if (probes > probesSeen) { probesSeen = probes; sinceNewCov = 0; } else sinceNewCov++;

        String kind;
        if (a.ok() && b.ok()) kind = same(a.value, b.value) ? "same_output" : "different_output";
        else if (a.ok()) kind = "b_error_only";
        else if (b.ok()) kind = "a_error_only";
        else kind = "both_error";
        outcomes.merge(kind, 1, Integer::sum);
        String shown = level.equals("function") ? showArgs((Object[]) inA) : quoted((String) inA);
        if (phase.equals("examples") && !a.ok()) exampleErrors.add(shorten(shown, 300) + " -> " + a.show());
        else if (!a.ok() && aErrorSamples.size() < 3) aErrorSamples.add(shorten(shown, 500) + " -> " + a.show());
        if ((kind.equals("different_output") || kind.equals("b_error_only")) && counterexamples.size() < MAX_COUNTEREXAMPLES) {
            Map<String, Object> cx = new LinkedHashMap<>();
            cx.put("input", shorten(shown, 2000));
            cx.put("phase", phase);
            cx.put("kind", kind);
            cx.put("at_input", totalDistinct());
            cx.put("a", shorten(a.show(), 2000));
            cx.put("b", shorten(b.show(), 2000));
            counterexamples.add(cx);
        }
    }

    static boolean same(Object a, Object b) {
        if (level.equals("file")) return a.equals(b);   // both already normalized
        return Values.same(a, b);
    }

    static Outcome execute(Side side, Object input) {
        if (level.equals("function")) {
            Object[] args = (Object[]) input;
            Method m = side.entries.stream().filter(x -> x.getParameterCount() == args.length).findFirst().orElse(side.entries.get(0));
            return withTimeout(side.loader, () -> {
                Object target = null;
                if (!Modifier.isStatic(m.getModifiers())) {
                    Constructor<?> c = side.mainClass.getDeclaredConstructor();
                    c.setAccessible(true);
                    target = c.newInstance();
                }
                return m.invoke(target, args);
            }, true);
        }
        // file level: fresh static state, the input as standard input, capture standard output
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setIn(new ByteArrayInputStream(((String) input).getBytes(StandardCharsets.UTF_8)));
        System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8));
        System.setErr(SILENT);
        Outcome o;
        try {
            o = withTimeout(side.loader, () -> {
                Statics.resetAll(side.loader);
                try {
                    side.entries.get(0).invoke(null, (Object) new String[0]);
                } catch (InvocationTargetException e) {
                    Throwable c = unwrap(e);
                    if (!(c instanceof Exit.ExitException) || ((Exit.ExitException) c).status != 0) throw e;
                }
                return null;
            }, false);
        } finally {
            System.out.flush();
            System.setOut(REAL_OUT);
            System.setErr(REAL_ERR);
            System.setIn(REAL_IN);
        }
        return o.ok() ? new Outcome("ok", normalize(out.toString(StandardCharsets.UTF_8)), null) : o;
    }

    /** The threads of one call: the worker and any thread the program under test starts. */
    static final class ProgramGroup extends ThreadGroup {
        volatile Throwable uncaught;
        ProgramGroup() { super("difuzzi-program"); }
        @Override public void uncaughtException(Thread t, Throwable e) { if (uncaught == null) uncaught = e; }
        Thread[] threads() {
            Thread[] ts = new Thread[activeCount() + 16];
            return Arrays.copyOf(ts, enumerate(ts, true));
        }
        Thread otherThan(Thread self) {
            for (Thread x : threads()) if (x != self && x.isAlive()) return x;
            return null;
        }
    }

    /** Run `body` in a worker thread, stopping it after the per-call timeout. A program may hand its work
     *  to threads it starts (e.g. `new Thread(null, r, "", 1 << 26).start()` for a larger stack), so the
     *  call ends only when those threads have ended too; an uncaught exception in one of them is the
     *  program's error (System.exit(0) is a normal end). */
    @SuppressWarnings({"deprecation", "removal"})
    static Outcome withTimeout(ClassLoader loader, java.util.concurrent.Callable<Object> body, boolean silence) {
        Object[] result = new Object[1];
        Throwable[] error = new Throwable[1];
        ProgramGroup group = new ProgramGroup();
        Thread t = new Thread(group, () -> {
            try {
                result[0] = body.call();
                Thread self = Thread.currentThread();
                for (Thread o; (o = group.otherThan(self)) != null; ) o.join();
                Throwable u = group.uncaught;
                if (u != null && !(u instanceof Exit.ExitException && ((Exit.ExitException) u).status == 0)) throw u;
            } catch (Throwable e) { error[0] = e; }
        }, "difuzzi-call");
        t.setDaemon(true);
        t.setContextClassLoader(loader);
        if (silence) { System.setOut(SILENT); System.setErr(SILENT); }
        try {
            t.start();
            t.join(callTimeoutMs);
            if (t.isAlive()) {
                for (Thread x : group.threads()) x.stop();   // the worker and every thread the program started
                t.join(200);
                return new Outcome("timeout", null, "timeout");
            }
        } catch (InterruptedException e) {
            return new Outcome("timeout", null, "timeout");
        } finally {
            if (silence) { System.setOut(REAL_OUT); System.setErr(REAL_ERR); }
        }
        if (error[0] != null) return new Outcome("raise", null, describe(error[0]));
        return new Outcome("ok", result[0], null);
    }

    // ---- fuzzing ----------------------------------------------------------------------------------------
    public static void fuzzerTestOneInput(byte[] data) {
        if (Boolean.parseBoolean(job.getProperty("random_only", "false"))) {   // evaluation baseline:
            phase2();                                                          // random inputs only
            finish();
        }
        tryBytes(data);
        stopReason = globalStop();
        if (stopReason == null && (sinceNewCov >= PLATEAU || streak >= SATURATION)) {
            if (topup) phase2();
            else stopReason = sinceNewCov >= PLATEAU ? "coverage_plateau" : "input_space_exhausted";
        }
        if (stopReason != null) finish();
        checkpoint();
    }

    static void phase2() {
        phase = "phase2";
        streak = 0;
        Random rng = new Random(Long.parseLong(job.getProperty("seed")));
        while (true) {
            byte[] data = new byte[1 + rng.nextInt(512)];
            rng.nextBytes(data);
            tryBytes(data);
            stopReason = globalStop();
            if (stopReason == null && streak >= SATURATION) stopReason = "input_space_exhausted";
            if (stopReason != null) return;
            checkpoint();
        }
    }

    static int totalDistinct() { return distinct.values().stream().mapToInt(Integer::intValue).sum(); }

    static String globalStop() {
        if (mode.equals("equivalence") && !counterexamples.isEmpty()) return "counterexample_found";
        if (totalDistinct() >= maxCases) return "max_cases";
        if (System.currentTimeMillis() >= deadline) return "time_limit";
        return null;
    }

    // ---- results ----------------------------------------------------------------------------------------
    static Map<String, Object> result(boolean done) {
        int scored = outcomes.get("same_output") + outcomes.get("both_error") + outcomes.get("different_output") + outcomes.get("b_error_only");
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("status", done ? "done" : "running");
        r.put("level", level);
        r.put("mode", mode);
        r.put("stop_reason", stopReason);
        r.put("elapsed", Math.round((System.currentTimeMillis() - t0) / 10.0) / 100.0);
        r.put("distinct_inputs", totalDistinct());
        r.put("distinct_by_phase", distinct);
        r.put("attempts_by_phase", attempts);
        r.put("duplicates_skipped", duplicates);
        r.put("generator_failures", genFailures);
        r.put("outcomes", outcomes);
        r.put("scored", scored);
        r.put("agreement", scored == 0 ? null : (outcomes.get("same_output") + outcomes.get("both_error")) / (double) scored);
        r.put("counterexamples", counterexamples);
        r.put("example_errors", exampleErrors);
        r.put("generator_failure_samples", genFailureSamples);
        r.put("a_error_samples", aErrorSamples);
        Map<String, Object> cfg = new LinkedHashMap<>();
        cfg.put("max_cases", maxCases);
        cfg.put("time_budget", Double.parseDouble(job.getProperty("time_budget")));
        cfg.put("call_timeout", Double.parseDouble(job.getProperty("call_timeout")));
        cfg.put("seed", Long.parseLong(job.getProperty("seed")));
        cfg.put("topup", topup);
        r.put("config", cfg);
        if (mode.equals("equivalence")) r.put("verdict", counterexamples.isEmpty() ? "no_counterexample_found" : "not_equivalent");
        return r;
    }

    static void checkpoint() {
        long now = System.currentTimeMillis();
        if (now - lastCheckpoint >= CHECKPOINT_MS) {
            lastCheckpoint = now;
            writeResult(result(false));
        }
    }

    static void finish() {
        try {
            Files.write(Paths.get(job.getProperty("exec_path")), Coverage.dump());
        } catch (Throwable ignored) { }
        writeResult(result(true));
        REAL_OUT.flush();
        REAL_ERR.flush();
        Runtime.getRuntime().halt(0);
    }

    static void fail(String message) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("status", "error");
        r.put("error", message);
        writeResult(r);
        Runtime.getRuntime().halt(0);
    }

    static void writeResult(Map<String, Object> r) {
        try {
            Path target = Paths.get(job.getProperty("result_path")), tmp = Paths.get(target + ".tmp");
            Files.writeString(tmp, Json.write(r));
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            REAL_ERR.println("difuzzi: cannot write result: " + e);
        }
    }

    // ---- helpers ----------------------------------------------------------------------------------------
    static Throwable unwrap(Throwable e) {
        while ((e instanceof InvocationTargetException || e instanceof ExceptionInInitializerError) && e.getCause() != null)
            e = e.getCause();
        return e;
    }

    static String describe(Throwable e) {
        e = unwrap(e);
        if (e instanceof Exit.ExitException) return "SystemExit: exit status " + ((Exit.ExitException) e).status;
        String msg = e.getMessage();
        return e.getClass().getSimpleName() + (msg == null ? "" : ": " + shorten(msg, 200));
    }

    static String showArgs(Object[] args) {
        StringBuilder sb = new StringBuilder("(");
        for (int i = 0; i < args.length; i++) {
            if (i > 0) sb.append(", ");
            sb.append(Values.repr(args[i]));
        }
        return sb.append(")").toString();
    }

    static String quoted(String s) {
        StringBuilder sb = new StringBuilder();
        Values.quote(s, sb);
        return sb.toString();
    }

    static String shorten(String s, int n) { return s.length() <= n ? s : s.substring(0, n) + "..."; }

    /** Program output with trailing whitespace on each line and trailing blank lines ignored. */
    static String normalize(String text) {
        String[] lines = text.replace("\r\n", "\n").split("\n", -1);
        StringBuilder sb = new StringBuilder();
        for (String line : lines) sb.append(line.replaceAll("\\s+$", "")).append('\n');
        return sb.toString().replaceAll("\\s+$", "");
    }
}
