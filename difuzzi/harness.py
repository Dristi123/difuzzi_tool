"""The differential fuzzing run. Executed in its own subprocess:

    python -m difuzzi.harness job.json

Steps
  0. Load A and B with Atheris instrumentation; start line/branch coverage measurement.
  1. Run the example inputs.
  2. Phase 1: coverage-guided fuzzing (libFuzzer). The binding turns fuzzer bytes into an input.
  3. Phase 2 (top-up): random bytes through the same binding, until enough distinct inputs.
Every input is deduplicated, run on A and B, and the outcomes are compared.

The run stops at the first of: max distinct inputs, time limit, input space exhausted,
and (equivalence mode) the first counterexample. libFuzzer cannot return control to Python,
so phase 2 and the final report are run from inside the last fuzzing callback, which then
ends the process with os._exit.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import shutil
import sys
import tempfile
import time

import atheris
import coverage

from . import sandbox
from .compare import values_equal

PLATEAU = 200      # distinct inputs without new coverage before phase 1 hands over to phase 2
SATURATION = 500   # consecutive attempts without a new distinct input: input space exhausted
CHECKPOINT_EVERY = 2.0
SEED_FILES = 64    # random seed inputs for phase 1 (libFuzzer's starting corpus)
SEED_MAX_LEN = 512
MAX_COUNTEREXAMPLES = 20


class Run:
    def __init__(self, job: dict):
        self.job = job
        self.level = job["level"]
        self.mode = job["mode"]
        self.t0 = time.time()
        self.seen = set()
        self.phase = "examples"
        self.distinct = {"examples": 0, "phase1": 0, "phase2": 0}
        self.attempts = {"phase1": 0, "phase2": 0}
        self.duplicates = 0
        self.gen_failures = 0
        self.streak = 0                # attempts in a row without a new distinct input
        self.since_new_cov = 0         # distinct inputs since the last one that reached a new line
        self.new_lines = 0             # lines of A/B executed for the first time (monitor)
        self.outcomes = {"same_output": 0, "both_error": 0, "different_output": 0,
                         "b_error_only": 0, "a_error_only": 0}
        self.counterexamples = []
        self.example_errors = []
        self.gen_failure_samples, self.a_error_samples = [], []   # shown to the LLM when a check fails
        self.stop_reason = None
        self.last_checkpoint = 0.0

    # ---- setup -------------------------------------------------------------------------------
    def setup(self):
        j = self.job
        self.paths = [j["a_path"], j["b_path"]]
        self.cov = coverage.Coverage(branch=True, include=self.paths, data_file=None)
        self.cov.start()
        self._start_monitor()
        if self.level == "function":
            ns_a = sandbox.load_module(j["a_path"], "program_a", instrument=True)
            ns_b = sandbox.load_module(j["b_path"], "program_b", instrument=True)
            for ns, entry, which in ((ns_a, j["entry_a"], "A"), (ns_b, j["entry_b"], "B")):
                if not callable(ns.get(entry)):
                    raise UserError(f"{which}: function {entry!r} not found")
            self.fa, self.fb = ns_a[j["entry_a"]], ns_b[j["entry_b"]]
            self.ns_a = ns_a
            b_ns = dict(ns_a, __name__="binding", __file__=j["binding_path"], atheris=atheris)
        else:
            self.code_a = sandbox.compile_script(j["a_path"], instrument=True)
            self.code_b = sandbox.compile_script(j["b_path"], instrument=True)
            b_ns = sandbox.new_namespace("binding", j["binding_path"])
            b_ns["atheris"] = atheris
        with open(j["binding_path"], encoding="utf-8") as f:
            exec(compile(f.read(), j["binding_path"], "exec"), b_ns)
        if not callable(b_ns.get("generate")):
            raise UserError("the binding does not define generate(fdp)")
        self.generate = b_ns["generate"]

    def _start_monitor(self):
        """Count lines of A and B executed for the first time (cheap: each line reports once)."""
        mon = sys.monitoring
        tool = next(i for i in range(6) if mon.get_tool(i) is None)
        mon.use_tool_id(tool, "difuzzi")
        targets = set(self.paths)

        def on_line(code, line):
            if code.co_filename in targets:
                self.new_lines += 1
            return mon.DISABLE

        mon.register_callback(tool, mon.events.LINE, on_line)
        mon.set_events(tool, mon.events.LINE)

    # ---- one input ---------------------------------------------------------------------------
    def execute(self, which: str, inp):
        if self.level == "function":
            f = self.fa if which == "A" else self.fb
            return sandbox.call(f, inp, self.job["call_timeout"])
        code = self.code_a if which == "A" else self.code_b
        path = self.paths[0] if which == "A" else self.paths[1]
        return sandbox.run_script(code, path, inp, self.job["call_timeout"])

    def same(self, a, b) -> bool:
        if self.level == "file":
            return sandbox.normalize_output(a) == sandbox.normalize_output(b)
        return values_equal(a, b)

    def run_input(self, inp):
        """Deduplicate, run A and B, classify. Returns True if the input was new."""
        try:
            key = hashlib.blake2b(repr(inp).encode("utf-8", "replace"), digest_size=16).digest()
        except Exception:
            key = os.urandom(16)
        if key in self.seen:
            self.duplicates += 1
            self.streak += 1
            return False
        self.seen.add(key)
        self.streak = 0
        self.distinct[self.phase] += 1

        lines_before = self.new_lines
        ka, va = self.execute("A", inp)
        kb, vb = self.execute("B", inp)
        if self.new_lines > lines_before:
            self.since_new_cov = 0
        else:
            self.since_new_cov += 1

        a_ok, b_ok = ka == "ok", kb == "ok"
        if a_ok and b_ok:
            kind = "same_output" if self.same(va, vb) else "different_output"
        elif a_ok:
            kind = "b_error_only"
        elif b_ok:
            kind = "a_error_only"      # A rejects the input: no reference behaviour, not scored
        else:
            kind = "both_error"
        self.outcomes[kind] += 1
        if self.phase == "examples" and not a_ok:
            self.example_errors.append({"input": _short(inp), "a": va if ka == "raise" else ka})
        elif not a_ok and len(self.a_error_samples) < 3:
            self.a_error_samples.append({"input": _short(inp, 500), "a": va if ka == "raise" else ka})
        if kind in ("different_output", "b_error_only") and len(self.counterexamples) < MAX_COUNTEREXAMPLES:
            self.counterexamples.append({
                "input": _short(inp, 2000), "phase": self.phase, "kind": kind,
                "at_input": self.total_distinct(),
                "a": _short(va, 2000) if a_ok else (va or ka),
                "b": _short(vb, 2000) if b_ok else (vb or kb)})
        return True

    def try_bytes(self, data: bytes):
        """Turn fuzzer bytes into an input with the binding and run it."""
        self.attempts[self.phase] += 1
        sandbox.reseed(int.from_bytes(hashlib.blake2b(data, digest_size=4).digest(), "little"))
        try:
            inp = sandbox.run_with_timeout(lambda: self.generate(atheris.FuzzedDataProvider(data)),
                                           self.job["call_timeout"])
        except BaseException as e:
            self.gen_failures += 1
            self.streak += 1
            if len(self.gen_failure_samples) < 3:
                self.gen_failure_samples.append(f"{type(e).__name__}: {e}"[:300])
            return
        if self.level == "function" and not isinstance(inp, tuple):
            inp = (inp,)
        if self.level == "file" and not isinstance(inp, str):
            inp = str(inp)
        self.run_input(inp)

    # ---- stopping ----------------------------------------------------------------------------
    def total_distinct(self) -> int:
        return sum(self.distinct.values())

    def global_stop(self):
        if self.mode == "equivalence" and self.counterexamples:
            return "counterexample_found"
        if self.total_distinct() >= self.job["max_cases"]:
            return "max_cases"
        if time.time() - self.t0 >= self.job["time_budget"]:
            return "time_limit"
        return None

    def phase1_done(self) -> bool:
        return self.since_new_cov >= PLATEAU or self.streak >= SATURATION

    def fuzz_callback(self, data: bytes):
        """libFuzzer's TestOneInput."""
        self.try_bytes(data)
        self.stop_reason = self.global_stop()
        if self.stop_reason is None and self.phase1_done():
            if self.job["topup"]:
                self.phase2()
            else:
                self.stop_reason = "coverage_plateau" if self.since_new_cov >= PLATEAU else "input_space_exhausted"
        if self.stop_reason:
            self.finish()
        self.checkpoint()

    def phase2(self):
        self.phase = "phase2"
        self.streak = 0
        rng = random.Random(self.job["seed"])
        while True:
            self.try_bytes(rng.randbytes(rng.randint(1, 512)))
            self.stop_reason = self.global_stop()
            if self.stop_reason is None and self.streak >= SATURATION:
                self.stop_reason = "input_space_exhausted"
            if self.stop_reason:
                return
            self.checkpoint()

    # ---- results -----------------------------------------------------------------------------
    def result(self, final: bool) -> dict:
        o = self.outcomes
        scored = o["same_output"] + o["both_error"] + o["different_output"] + o["b_error_only"]
        res = {
            "status": "done" if final else "running",
            "level": self.level, "mode": self.mode,
            "stop_reason": self.stop_reason,
            "elapsed": round(time.time() - self.t0, 2),
            "distinct_inputs": self.total_distinct(),
            "distinct_by_phase": self.distinct,
            "attempts_by_phase": self.attempts,
            "duplicates_skipped": self.duplicates,
            "generator_failures": self.gen_failures,
            "outcomes": o,
            "scored": scored,
            "agreement": (o["same_output"] + o["both_error"]) / scored if scored else None,
            "counterexamples": self.counterexamples,
            "example_errors": self.example_errors,
            "generator_failure_samples": self.gen_failure_samples,
            "a_error_samples": self.a_error_samples,
            "config": {k: self.job[k] for k in ("max_cases", "time_budget", "call_timeout", "seed", "topup")},
        }
        if self.mode == "equivalence":
            res["verdict"] = "not_equivalent" if self.counterexamples else "no_counterexample_found"
        return res

    def checkpoint(self, force=False):
        now = time.time()
        if force or now - self.last_checkpoint >= CHECKPOINT_EVERY:
            self.last_checkpoint = now
            _write_json(self.job["result_path"], self.result(final=False))

    def finish(self):
        self.cov.stop()
        res = self.result(final=True)
        res["coverage"] = coverage_report(self.cov, {"A": self.paths[0], "B": self.paths[1]})
        _write_json(self.job["result_path"], res)
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(0)


def write_seed_corpus(job: dict) -> str:
    """Random byte strings as libFuzzer's starting corpus. Without one, libFuzzer starts from tiny inputs
    and grows them slowly, so the generator runs out of bytes and phase 1 only sees minimal inputs.
    Modes (job["seed_corpus"]): "none" (default), "long" (random lengths), "mixed" (half very short)."""
    d = os.path.join(os.path.dirname(job["result_path"]), "corpus")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    rng = random.Random(job["seed"] + 7)
    mixed = job.get("seed_corpus") == "mixed"
    for i in range(SEED_FILES):   # "mixed": half very short (edge values: fdp falls back to range minima)
        n = rng.randint(1, 8) if mixed and i % 2 == 0 else rng.randint(1 if not mixed else 9, SEED_MAX_LEN)
        with open(os.path.join(d, f"seed{i}"), "wb") as f:
            f.write(rng.randbytes(n))
    return d


class UserError(Exception):
    pass


def coverage_report(cov, files: dict) -> dict:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out = f.name
    try:
        cov.json_report(outfile=out, include=list(files.values()), show_contexts=False)
        with open(out) as f:
            data = json.load(f)["files"]
    finally:
        os.unlink(out)
    by_path = {os.path.realpath(p): info for p, info in data.items()}
    rep = {}
    for name, path in files.items():
        info = by_path.get(os.path.realpath(path))
        if info is None:
            rep[name] = {"lines": [0, 0], "branches": [0, 0], "executed_lines": [], "missing_lines": [],
                         "missing_branches": []}
            continue
        s = info["summary"]
        rep[name] = {"lines": [s["covered_lines"], s["num_statements"]],
                     "branches": [s.get("covered_branches", 0), s.get("num_branches", 0)],
                     "executed_lines": info["executed_lines"], "missing_lines": info["missing_lines"],
                     "missing_branches": info.get("missing_branches", [])}
    return rep


def _short(v, n=300) -> str:
    try:
        r = repr(v)
    except Exception as e:
        r = f"<unprintable {type(e).__name__}>"
    return r if len(r) <= n else r[:n] + "..."


def _write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1, default=str)
    os.replace(tmp, path)


def main():
    with open(sys.argv[1]) as f:
        job = json.load(f)
    run = Run(job)
    try:
        run.setup()
    except UserError as e:
        _write_json(job["result_path"], {"status": "error", "error": str(e)})
        os._exit(0)
    except BaseException as e:
        _write_json(job["result_path"], {"status": "error", "error": f"loading failed: {type(e).__name__}: {e}"})
        os._exit(0)

    # 1. example inputs
    for ex in job["examples"]:
        try:
            inp = sandbox.eval_input(ex, run.ns_a) if run.level == "function" else ex
        except BaseException as e:
            _write_json(job["result_path"], {"status": "error",
                                             "error": f"example input {ex!r} could not be evaluated: {e}"})
            os._exit(0)
        run.run_input(inp)
    if run.example_errors:
        _write_json(job["result_path"], {"status": "error", "error": "A fails on an example input: "
                                         + "; ".join(f"{e['input']} -> {e['a']}" for e in run.example_errors)})
        os._exit(0)
    run.stop_reason = run.global_stop()
    if run.stop_reason:
        run.finish()

    if job.get("random_only"):          # evaluation baseline: random differential testing, no guidance
        run.phase2()
        run.finish()

    # 2. phase 1 (and 3. phase 2, started from inside the callback)
    run.phase = "phase1"
    args = [sys.argv[0], f"-seed={job['seed'] + 1}", "-rss_limit_mb=4096",
            f"-artifact_prefix={os.path.dirname(os.path.abspath(job['result_path']))}{os.sep}",
            f"-max_total_time={int(job['time_budget']) + 30}"]
    if job.get("seed_corpus", "none") != "none":
        args += [f"-max_len={SEED_MAX_LEN}", write_seed_corpus(job)]
    atheris.Setup(args, run.fuzz_callback)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
