"""Checks on a binding before fuzzing, and the LLM repair loop.

Blocking checks (a failing binding is sent back to the LLM with the problems):
  G1 static     compiles, defines generate(fdp), reads from fdp, no other randomness source
  G2 robust     generate() succeeds on every one of 100 random byte strings
  G3 valid      A returns normally, or deliberately rejects the input (a `raise`/`assert`
                in A's own code), on every generated input
Feedback (one extra LLM round, kept only if it does not make things worse):
  G4 coverage   lines of A that no generated input executed
Errors in the user's inputs (not retried):
  A cannot be loaded, the entry point is missing, or A raises on an example input.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

from . import binding, llm

MIN_GEN_OK = 1.0    # generate() must succeed on every byte string
MIN_A_OK = 1.0      # A must accept every generated input


class UserInputError(Exception):
    """A, the entry point or the example inputs are wrong; retrying the LLM cannot help."""


class BindingError(Exception):
    """No binding passed the checks within the allowed attempts."""


@dataclass
class Verdict:
    blocking: List[str] = field(default_factory=list)
    uncovered: List[str] = field(default_factory=list)   # "line N: <source>" of A
    stats: dict = field(default_factory=dict)

    @property
    def covered_lines(self) -> int:
        return self.stats.get("lines", [0, 0])[0]


def run_probe(a_path: Path, entry: str, binding_src: str, examples: List[str], *,
              n: int = 100, call_timeout: float = 1.0, budget: float = 10.0) -> dict:
    """Run difuzzi.probe in a subprocess (user code is isolated from the tool)."""
    with tempfile.TemporaryDirectory(prefix="difuzzi_probe_") as tmp:
        tmp = Path(tmp)
        (tmp / "binding.py").write_text(binding_src)
        job = {"a_path": str(Path(a_path).resolve()), "entry": entry,
               "binding_path": str(tmp / "binding.py"), "examples": examples,
               "n": n, "call_timeout": call_timeout, "budget": budget}
        (tmp / "job.json").write_text(json.dumps(job))
        try:
            p = subprocess.run([sys.executable, "-m", "difuzzi.probe", str(tmp / "job.json"),
                                str(tmp / "out.json")], capture_output=True, text=True,
                               timeout=budget + 60, cwd=Path(__file__).resolve().parent.parent)
        except subprocess.TimeoutExpired:
            return {"crash": "binding check did not finish (A or the binding hangs outside the call timeout)"}
        if p.returncode != 0 or not (tmp / "out.json").exists():
            return {"crash": p.stderr.strip().splitlines()[-1] if p.stderr.strip() else f"exit code {p.returncode}"}
        return json.loads((tmp / "out.json").read_text())


def evaluate(res: dict, a_src: str) -> Verdict:
    v = Verdict()
    if "crash" in res:
        v.blocking.append(f"The check process crashed: {res['crash']}")
        return v
    st = res["static"]
    if st["syntax_error"]:
        v.blocking.append(f"Syntax error: {st['syntax_error']}")
        return v
    if not st["defines_generate"]:
        v.blocking.append("The code does not define `generate(fdp)`.")
        return v
    if res["load_error"]:
        if res["load_error"].startswith("A:"):
            raise UserInputError(f"Reference A could not be loaded: {res['load_error'][3:]}")
        v.blocking.append(f"Loading the generator failed: {res['load_error']}")
        return v
    if not st["uses_fdp"]:
        v.blocking.append("`generate` never reads from `fdp`; every value must be derived from it.")
    if st["forbidden"]:
        v.blocking.append(f"`generate` uses {', '.join(st['forbidden'])}; derive all values from `fdp` only.")

    for ex in res["examples"]:
        if "error" in ex:
            raise UserInputError(f"Example input {ex['src']!r} could not be evaluated: {ex['error']}")
        if ex["a"] not in ("ok", "timeout"):
            raise UserInputError(f"A raises on example input {ex['src']!r}: {ex['a']}")

    s = res["summary"]
    n, gen_ok, a_ok = s["n"], s["gen_ok"], s["a_ok"] + s["a_reject"]
    v.stats = {"n": n, "gen_ok": gen_ok, "a_ok": s["a_ok"], "a_reject": s["a_reject"], "distinct": s["distinct"],
               "lines": (res.get("coverage_a") or {}).get("lines", [0, 0]), "seconds": res["elapsed"]}
    if n == 0:
        v.blocking.append("No input could be generated within the time budget.")
        return v
    if gen_ok < MIN_GEN_OK * n:
        errs = "\n".join(f"    {e} ({c}x)" for e, c in s["gen_errors"])
        v.blocking.append(f"`generate` raised on {n - gen_ok} of {n} byte strings. Errors:\n{errs}")
    if gen_ok and a_ok < MIN_A_OK * gen_ok:
        bad = [r for r in res["inputs"] if "gen_error" not in r and r["a"] != "ok"
               and not r.get("deliberate")][:3]
        lines = "\n".join(f"    A{r['args']} -> {r['a']}" for r in bad)
        v.blocking.append(f"The reference function failed with an unexpected error on {gen_ok - a_ok} of "
                          f"{gen_ok} generated inputs, so these inputs are outside its domain (or too "
                          f"large). Examples:\n{lines}")

    src_lines = a_src.splitlines()
    for ln in (res.get("coverage_a") or {}).get("missing_lines", []):
        if 0 < ln <= len(src_lines):
            v.uncovered.append(f"  line {ln}: {src_lines[ln - 1].strip()}")
    return v


def generate_checked(a_path: Path, entry: str, examples: List[str], description: Optional[str] = None,
                     *, initial: Optional[str] = None, max_attempts: int = 3,
                     log: Callable[[str], None] = lambda m: None):
    """Generate a binding with the LLM and check it, repairing it up to `max_attempts` times.
    Returns (binding_src, verdict, history)."""
    a_src = Path(a_path).read_text()
    base = binding.build_prompt(a_src, entry, examples, description)
    src = initial if initial is not None else llm.extract_code(llm.chat(base))
    history = []
    for attempt in range(1, max_attempts + 1):
        v = evaluate(run_probe(a_path, entry, src, examples), a_src)
        history.append({"attempt": attempt, "kind": "check", "binding": src,
                        "blocking": v.blocking, "uncovered": v.uncovered, "stats": v.stats})
        log(f"attempt {attempt}: " + ("ok" if not v.blocking else f"{len(v.blocking)} problem(s)"))
        if not v.blocking:
            break
        if attempt == max_attempts:
            raise BindingError("No binding passed the checks:\n- " + "\n- ".join(v.blocking))
        problems = "\n".join(f"- {p}" for p in v.blocking)
        src = llm.extract_code(llm.chat(base + binding.REPAIR_SUFFIX.format(previous=src.strip(), problems=problems)))

    if v.uncovered:  # G4: one round of coverage feedback; keep the result only if it is no worse
        log(f"{len(v.uncovered)} line(s) of A not reached; asking for a wider generator")
        cand = llm.extract_code(llm.chat(base + binding.COVERAGE_SUFFIX.format(
            previous=src.strip(), lines="\n".join(v.uncovered))))
        cv = evaluate(run_probe(a_path, entry, cand, examples), a_src)
        accepted = not cv.blocking and cv.covered_lines >= v.covered_lines
        history.append({"attempt": len(history) + 1, "kind": "coverage", "binding": cand, "accepted": accepted,
                        "blocking": cv.blocking, "uncovered": cv.uncovered, "stats": cv.stats})
        log("coverage round: " + ("accepted" if accepted else "kept previous binding"))
        if accepted:
            src, v = cand, cv
    return src, v, history


# ---- checks for every language and level, run by the pipeline ------------------------------------
# Python functions use the probe above (it can tell a deliberate `raise` in A from a crash). Java and
# file-level programs are checked by a short run of the fuzzer itself with A against A, random bytes
# only: its counters give G2 (generator failures) and G3 (inputs on which A ends with an error).
JAVA_FORBIDDEN = [(re.compile(r"\bMath\s*\.\s*random\b"), "Math.random"),
                  (re.compile(r"\bThreadLocalRandom\b"), "ThreadLocalRandom"),
                  (re.compile(r"\bSecureRandom\b"), "SecureRandom"),
                  (re.compile(r"\bUUID\s*\.\s*randomUUID\b"), "UUID.randomUUID"),
                  (re.compile(r"\bSystem\s*\.\s*(nanoTime|currentTimeMillis)\b"), "System time"),
                  (re.compile(r"\b(Instant|LocalDateTime|LocalDate|Clock)\s*\.\s*now\b"), "the clock")]
SELF_RUN_CASES, SELF_RUN_SECONDS = 100, 30.0

JAVA_REPAIR_SUFFIX = """
Your previous generator was:

```java
{previous}
```

Running it on random fuzzer bytes showed these problems:
{problems}

Write a corrected DiffGen class that follows all rules above.
"""


def java_static_checks(src: str) -> dict:
    """Same questions as probe.static_checks, for a Java DiffGen class."""
    from .java_backend import _strip_comments
    code = _strip_comments(src)
    m = re.search(r"\bstatic\s+[\w<>\[\], ]+\s+generate\s*\(\s*(?:final\s+)?(?:[\w.]*\.)?FuzzedDataProvider\s+(\w+)\s*\)",
                  code)
    out = {"syntax_error": None, "defines_generate": bool(m), "uses_fdp": False, "forbidden": []}
    if not m:
        return out
    name = m.group(1)
    out["uses_fdp"] = re.search(rf"\b{re.escape(name)}\s*\.\s*(consume|pick|remaining)", code) is not None
    out["forbidden"] = [what for rx, what in JAVA_FORBIDDEN if rx.search(code)]
    for r in re.finditer(r"\bnew\s+(?:java\.util\.)?Random\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)", code):
        if not re.search(rf"\b{re.escape(name)}\s*\.", r.group(1)):   # Random must be seeded from the fuzzer
            out["forbidden"].append("java.util.Random not seeded from the fuzzer")
    out["forbidden"] = sorted(set(out["forbidden"]))
    return out


def self_run(cfg, src: str) -> dict:
    """A short random-bytes run of the fuzzer with A against A, using the binding `src`."""
    from dataclasses import replace
    from . import pipeline
    with tempfile.TemporaryDirectory(prefix="difuzzi_check_") as tmp:
        bp = Path(tmp) / ("binding.java" if cfg.lang == "java" else "binding.py")
        bp.write_text(src)
        c = replace(cfg, b_path=cfg.a_path, entry_b=cfg.entry_a, binding_path=str(bp), random_only=True,
                    max_cases=SELF_RUN_CASES, time_budget=SELF_RUN_SECONDS, examples_only=False, topup=True,
                    mode="similarity", out_dir=str(Path(tmp) / "run"), validate=False)
        try:
            return pipeline.run(c, log=lambda m: None)
        except Exception as e:   # e.g. the binding does not compile
            return {"status": "error", "error": f"{type(e).__name__}: {e}"}


def evaluate_self_run(res: dict, static: dict) -> Verdict:
    v = Verdict()
    if static["syntax_error"]:
        v.blocking.append(f"Syntax error: {static['syntax_error']}")
        return v
    if not static["defines_generate"]:
        v.blocking.append("The code does not define `generate` taking the fuzzer's data provider.")
        return v
    if not static["uses_fdp"]:
        v.blocking.append("`generate` never reads from the data provider; every value must be derived from it.")
    if static["forbidden"]:
        v.blocking.append(f"`generate` uses {', '.join(static['forbidden'])}; derive all values from the fuzzer only.")
    if res.get("status") != "done":
        v.blocking.append(f"Running the generator failed: {str(res.get('error'))[:500]}")
        return v
    attempts = sum((res.get("attempts_by_phase") or {}).values())
    failures = res.get("generator_failures", 0)
    o = res["outcomes"]
    # A is compared with itself: "both_error" is an input on which A ends with an error; any other
    # disagreement means A gives different results on the same input
    runs = sum(o.values())
    a_error = o.get("both_error", 0)
    unstable = o.get("different_output", 0) + o.get("a_error_only", 0) + o.get("b_error_only", 0)
    v.stats = {"n": attempts, "gen_ok": attempts - failures, "a_ok": runs - a_error, "a_error": a_error,
               "distinct": res.get("distinct_inputs"), "seconds": res.get("elapsed")}
    if unstable:
        raise UserInputError(f"The reference program gives different results when run twice on the same input "
                             f"({unstable} of {runs} inputs); it must be deterministic to serve as the reference.")
    if attempts == 0:
        v.blocking.append("No input could be generated within the time budget.")
        return v
    if attempts - failures < MIN_GEN_OK * attempts:
        errs = "\n".join(f"    {e}" for e in res.get("generator_failure_samples") or [])
        v.blocking.append(f"`generate` failed on {failures} of {attempts} random byte strings. Errors:\n{errs}")
    if runs and runs - a_error < MIN_A_OK * runs:
        bad = []
        for x in res.get("a_error_samples") or []:
            bad.append(f"    {x['input']} -> {x['a']}" if isinstance(x, dict) else f"    {x}")
        v.blocking.append(f"The reference program ended with an error on {a_error} of {runs} generated "
                          "inputs, so these inputs are outside its domain (or too large). Examples (input -> "
                          "error of the reference program):\n" + "\n".join(bad))
    return v


def check(cfg, src: str) -> Verdict:
    """G1-G3 for any language and level."""
    from . import probe
    if cfg.lang == "python" and cfg.level == "function":
        return evaluate(run_probe(Path(cfg.a_path), cfg.entry_a, src, cfg.examples,
                                  call_timeout=cfg.call_timeout), Path(cfg.a_path).read_text())
    static = java_static_checks(src) if cfg.lang == "java" else probe.static_checks(src)
    if static["syntax_error"] or not static["defines_generate"]:
        return evaluate_self_run({}, static)
    return evaluate_self_run(self_run(cfg, src), static)


def checked(cfg, src: str, *, repair: bool, max_attempts: int = 3, log: Callable[[str], None] = lambda m: None):
    """Check a binding (G1-G3) and, if `repair`, send the problems back to the LLM up to
    `max_attempts` times. Returns (binding_src, verdict, history); raises BindingError if none passes."""
    history = []
    base = None
    for attempt in range(1, max_attempts + 1):
        v = check(cfg, src)
        history.append({"attempt": attempt, "blocking": v.blocking, "stats": v.stats})
        log(f"input generator check {attempt}: " + ("passed" if not v.blocking else "; ".join(
            p.splitlines()[0] for p in v.blocking)))
        if not v.blocking:
            return src, v, history
        if not repair or attempt == max_attempts:
            break
        if base is None:
            base = binding.build_prompt(Path(cfg.a_path).read_text(), cfg.entry_a, cfg.examples, cfg.description,
                                        cfg.level, cfg.lang)
        suffix = JAVA_REPAIR_SUFFIX if cfg.lang == "java" else binding.REPAIR_SUFFIX
        problems = "\n".join(f"- {p}" for p in v.blocking)
        src = llm.extract_code(llm.chat(base + suffix.format(previous=src.strip(), problems=problems)))
    raise BindingError("The input generator did not pass the checks:\n- " + "\n- ".join(v.blocking))
