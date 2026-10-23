"""Trial run of a binding against the reference A, before fuzzing.

Runs `generate(fdp)` on random byte strings, calls A on each generated input, measures
A's line coverage, and records what happened. This module only measures; the decisions
are made in `guardrails.py`.

Run in a subprocess:  python -m difuzzi.probe job.json result.json
job.json: {"a_path", "entry", "binding_path", "examples": [src, ...],
           "n": 100, "call_timeout": 1.0, "budget": 10.0, "seed": 0}
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import random
import sys
import tempfile
import time
from collections import Counter

import atheris
import coverage

from . import sandbox

# Modules / attributes that make a binding depend on something other than the fuzzer bytes.
FORBIDDEN = {"random", "time", "uuid", "secrets", "urandom"}


def _seeded_rng(tree, attr) -> bool:
    """`attr` (np.random) is used as np.random.default_rng(seed) with a seed read from fdp, as the
    binding prompt allows."""
    for call in ast.walk(tree):
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.value is attr \
                and call.func.attr == "default_rng" and call.args:
            return any(isinstance(n, ast.Name) and n.id == "fdp" for n in ast.walk(call.args[0]))
    return False


def static_checks(src: str) -> dict:
    """What the binding's code uses, without running it."""
    out = {"syntax_error": None, "defines_generate": False, "uses_fdp": False, "forbidden": []}
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        out["syntax_error"] = f"line {e.lineno}: {e.msg}"
        return out
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "generate":
            out["defines_generate"] = True
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "fdp":
            out["uses_fdp"] = True
        if isinstance(node, ast.ImportFrom) and node.module and node.module.split(".")[0] in FORBIDDEN:
            out["forbidden"].append(node.module.split(".")[0])      # from random import randint
        elif isinstance(node, ast.Attribute):
            base = node.value
            if isinstance(base, ast.Name) and base.id in FORBIDDEN:
                out["forbidden"].append(base.id)                     # random.randint(...), time.time()
            elif node.attr == "urandom":
                out["forbidden"].append("urandom")
            elif node.attr == "random" and isinstance(base, ast.Name) and base.id in ("np", "numpy") \
                    and not _seeded_rng(tree, node):
                out["forbidden"].append("numpy.random")   # np.random.default_rng(<from fdp>) is allowed
    out["forbidden"] = sorted(set(out["forbidden"]))
    return out


def _short(v, n=160) -> str:
    try:
        r = repr(v)
    except Exception as e:
        r = f"<unrepr-able {type(e).__name__}>"
    return r if len(r) <= n else r[:n] + "..."


def _coverage_summary(cov, path) -> dict:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out = f.name
    try:
        cov.json_report(outfile=out, include=[path])
        with open(out) as f:
            info = next(iter(json.load(f)["files"].values()))
        s = info["summary"]
        return {"lines": [s["covered_lines"], s["num_statements"]],
                "branches": [s.get("covered_branches", 0), s.get("num_branches", 0)],
                "missing_lines": info["missing_lines"]}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    finally:
        os.unlink(out)


def run(job: dict) -> dict:
    res = {"static": None, "load_error": None, "examples": [], "inputs": [],
           "coverage_a": None, "elapsed": None, "budget_hit": False}
    t0 = time.time()
    src = open(job["binding_path"], encoding="utf-8").read()
    res["static"] = static_checks(src)
    if res["static"]["syntax_error"] or not res["static"]["defines_generate"]:
        return res

    a_path, timeout = job["a_path"], job.get("call_timeout", 1.0)
    cov = coverage.Coverage(branch=True, include=[a_path], data_file=None)
    cov.start()
    try:
        a_ns = sandbox.load_module(a_path, "reference_a")
    except BaseException as e:
        res["load_error"] = f"A: {type(e).__name__}: {e}"
        return res
    finally:
        cov.stop()
    func = a_ns.get(job["entry"])
    if not callable(func):
        res["load_error"] = f"A: entry point {job['entry']!r} not found"
        return res

    # The binding sees A's module-level names (constants, helpers, imports), as in A's source.
    b_ns = dict(a_ns, __name__="binding", __file__=job["binding_path"], atheris=atheris)
    try:
        exec(compile(src, job["binding_path"], "exec"), b_ns)
        generate = b_ns["generate"]
    except BaseException as e:
        res["load_error"] = f"binding: {type(e).__name__}: {e}"
        return res

    # Example inputs: not counted in coverage, which measures what the binding reaches.
    for ex in job["examples"]:
        rec = {"src": ex}
        try:
            args = sandbox.run_with_timeout(lambda: sandbox.eval_input(ex, a_ns), timeout)
            kind, val = sandbox.call(func, args, timeout)
            rec["a"] = "ok" if kind == "ok" else (kind if kind == "timeout" else val)
        except BaseException as e:
            rec["error"] = f"{type(e).__name__}: {e}"
        res["examples"].append(rec)

    rng = random.Random(job.get("seed", 0))
    cov.start()
    for _ in range(job.get("n", 200)):
        if time.time() - t0 > job.get("budget", 10.0):
            res["budget_hit"] = True
            break
        data = rng.randbytes(rng.randint(1, 256))
        rec = {}
        try:
            args = sandbox.run_with_timeout(lambda: generate(atheris.FuzzedDataProvider(data)), timeout)
            if not isinstance(args, tuple):
                args = (args,)
            rec["args"] = _short(args)
            rec["key"] = hashlib.md5(_short(args, 10**6).encode()).hexdigest()[:16]
            kind, val = sandbox.call(func, args, timeout, path=a_path)
            rec["a"] = kind if kind in ("ok", "timeout") else val
            rec["deliberate"] = kind == "reject"
        except sandbox.CallTimeout:
            rec["gen_error"] = "timeout"
        except BaseException as e:
            rec["gen_error"] = f"{type(e).__name__}: {str(e)[:200]}"
        res["inputs"].append(rec)
    cov.stop()
    res["coverage_a"] = _coverage_summary(cov, a_path)
    res["elapsed"] = round(time.time() - t0, 3)
    return res


def summarize(res: dict) -> dict:
    """Aggregate numbers from a probe result."""
    inputs = res["inputs"]
    gen_ok = [r for r in inputs if "gen_error" not in r]
    return {
        "n": len(inputs),
        "gen_ok": len(gen_ok),
        "a_ok": sum(r.get("a") == "ok" for r in gen_ok),
        "a_reject": sum(r.get("deliberate", False) for r in gen_ok),
        "distinct": len({r["key"] for r in gen_ok}),
        "gen_errors": Counter(r["gen_error"] for r in inputs if "gen_error" in r).most_common(3),
        "a_errors": Counter(r["a"] for r in gen_ok
                            if r.get("a") != "ok" and not r.get("deliberate")).most_common(3),
    }


def main():
    job = json.load(open(sys.argv[1]))
    out = run(job)
    out["summary"] = summarize(out)
    with open(sys.argv[2], "w") as f:
        json.dump(out, f, indent=1, default=str)


if __name__ == "__main__":
    main()
