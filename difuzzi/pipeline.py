"""End-to-end pipeline: input binding -> differential fuzzing run -> report."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

from . import binding, java_backend, llm, report

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Config:
    a_path: str
    b_path: str
    examples: List[str]                 # function level: argument-tuple sources; file level: stdin texts
    level: str = "function"             # "function" | "file"
    mode: str = "similarity"            # "similarity" | "equivalence"
    entry_a: Optional[str] = None
    entry_b: Optional[str] = None
    description: Optional[str] = None
    binding_path: Optional[str] = None  # user-written binding; otherwise the LLM writes one
    max_cases: int = 1000
    time_budget: float = 60.0
    call_timeout: float = 1.0
    seed: int = 0
    topup: bool = True
    out_dir: str = "difuzzi-out"
    lang: str = ""                      # "python" | "java"; set from the file extension
    random_only: bool = False           # evaluation baseline: random inputs only, no coverage guidance
    examples_only: bool = False         # evaluation (Java): run A and B on the given inputs only
    seed_corpus: str = "none"           # phase-1 starting corpus: "none" | "long" | "mixed" (under evaluation)
    validate: bool = True               # check the input generator (G1-G3, guardrails.py) before fuzzing
    meta: dict = field(default_factory=dict)


class PipelineError(Exception):
    pass


def _parse(path: str) -> ast.Module:
    try:
        return ast.parse(Path(path).read_text(encoding="utf-8"))
    except SyntaxError as e:
        raise PipelineError(f"{path} is not valid Python (line {e.lineno}: {e.msg})")


def first_function(path: str) -> Optional[str]:
    tree = _parse(path)
    return next((n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))), None)


def defines(path: str, name: str) -> bool:
    tree = _parse(path)
    return any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name for n in tree.body)


def language(path: str) -> str:
    ext = Path(path).suffix.lower()
    if ext == ".py":
        return "python"
    if ext == ".java":
        return "java"
    raise PipelineError(f"unsupported file type {ext!r} ({path}); expected .py or .java")


def resolve_entries(cfg: Config):
    if cfg.lang == "java":
        try:
            java_backend.resolve_entries(cfg)
        except java_backend.JavaError as e:
            raise PipelineError(str(e))
        return
    if cfg.level != "function":
        return
    cfg.entry_a = cfg.entry_a or first_function(cfg.a_path)
    if not cfg.entry_a:
        raise PipelineError(f"no function found in {cfg.a_path}; pass --entry")
    if not cfg.entry_b:
        cfg.entry_b = cfg.entry_a if defines(cfg.b_path, cfg.entry_a) else first_function(cfg.b_path)
    if not cfg.entry_b:
        raise PipelineError(f"no function found in {cfg.b_path}; pass --entry-b")


def cache_dir() -> Path:
    d = Path(os.environ.get("DIFUZZI_CACHE", Path.home() / ".cache" / "difuzzi")) / "bindings"
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_binding(cfg: Config, log: Callable[[str], None]) -> tuple:
    """Source of the binding and a description of where it came from, after the checks of
    guardrails.py (G1-G3). LLM bindings depend only on A, the examples and the description, so they
    are cached, with the result of their check, and reused for every candidate B."""
    if cfg.binding_path:
        src = Path(cfg.binding_path).read_text(encoding="utf-8")
        key = hashlib.sha256(src.encode()).hexdigest()[:24]
        return _validated(cfg, src, key, None, repair=False, log=log), f"user file {cfg.binding_path}"
    a_src = Path(cfg.a_path).read_text(encoding="utf-8")
    prompt = binding.build_prompt(a_src, cfg.entry_a, cfg.examples, cfg.description, cfg.level, cfg.lang)
    _, model, api_key = llm.config(require_key=False)
    key = hashlib.sha256(f"{model}\n{prompt}".encode()).hexdigest()[:24]
    ext = ".java" if cfg.lang == "java" else ".py"
    shipped = Path(__file__).resolve().parent / "generators" / f"{key}{ext}"   # for the bundled examples
    cached = cache_dir() / f"{key}{ext}"
    if shipped.exists():
        log(f"input generator: using shipped pre-generated binding ({shipped.name})")
        src, source, path = shipped.read_text(encoding="utf-8"), f"LLM ({model}), pre-generated", None
    elif cached.exists():
        log(f"input generator: reusing cached LLM binding ({cached.name})")
        src, source, path = cached.read_text(encoding="utf-8"), f"LLM ({model}), cached", cached
    else:
        log(f"input generator: asking {model} to write the binding ...")
        src, source, path = llm.extract_code(llm.chat(prompt)), f"LLM ({model})", cached
        cached.write_text(src, encoding="utf-8")
    return _validated(cfg, src, key, path, repair=bool(api_key), log=log), source


def _validated(cfg: Config, src: str, key: str, path: Optional[Path], *, repair: bool,
               log: Callable[[str], None]) -> str:
    """The binding after the G1-G3 checks (repaired by the LLM if needed and possible). The outcome
    is stored next to the cached binding, so a binding is checked once, not for every B."""
    if not cfg.validate or cfg.examples_only:
        return src
    from . import guardrails
    record = cache_dir() / f"{key}.check.json"
    digest = lambda s: hashlib.sha256(s.encode()).hexdigest()
    if record.exists():
        rec = json.loads(record.read_text())
        # the binding as checked (rec["sha256"]) or the one it was repaired from (rec["original_sha256"])
        if rec.get("passed") and digest(src) in (rec.get("sha256"), rec.get("original_sha256")):
            final = rec["binding"]
            cfg.meta["binding_check"] = rec
            log("input generator: passed the checks before (" + ("repaired, " if rec.get("repaired") else "")
                + "cached result)")
            return final
    try:
        final, verdict, history = guardrails.checked(cfg, src, repair=repair, log=log)
    except guardrails.BindingError as e:
        record.write_text(json.dumps({"passed": False, "sha256": digest(src), "error": str(e)}, indent=1))
        raise PipelineError(str(e))
    except guardrails.UserInputError as e:
        raise PipelineError(str(e))
    rec = {"passed": True, "sha256": digest(final), "original_sha256": digest(src), "repaired": final != src,
           "attempts": len(history), "history": history, "binding": final}
    if final != src and path is not None:   # keep the generator the LLM wrote first, use the repaired one
        path.with_name(path.stem + ".orig" + path.suffix).write_text(src, encoding="utf-8")
        path.write_text(final, encoding="utf-8")
    record.write_text(json.dumps(rec, indent=1))
    cfg.meta["binding_check"] = rec
    return final


def run(cfg: Config, log: Callable[[str], None] = print) -> dict:
    for p in (cfg.a_path, cfg.b_path):
        if not Path(p).is_file():
            raise PipelineError(f"file not found: {p}")
    if not cfg.examples:
        raise PipelineError("at least one example input is required")
    cfg.a_path, cfg.b_path = str(Path(cfg.a_path).resolve()), str(Path(cfg.b_path).resolve())
    cfg.lang = language(cfg.a_path)
    if language(cfg.b_path) != cfg.lang:
        raise PipelineError("A and B must be written in the same language")
    resolve_entries(cfg)
    out = Path(cfg.out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)

    # 1. input binding
    src, source = get_binding(cfg, log)
    (out / ("binding.java" if cfg.lang == "java" else "binding.py")).write_text(src, encoding="utf-8")

    # 2. fuzzing run (isolated subprocess)
    if cfg.lang == "java":
        try:
            res = java_backend.run(cfg, src, out, log)
        except java_backend.JavaError as e:
            res = {"status": "error", "error": str(e)}
        return _finish(cfg, out, res, source)
    job = {"level": cfg.level, "mode": cfg.mode, "a_path": cfg.a_path, "b_path": cfg.b_path,
           "entry_a": cfg.entry_a, "entry_b": cfg.entry_b, "binding_path": str((out / "binding.py").resolve()),
           "examples": cfg.examples, "max_cases": cfg.max_cases, "time_budget": cfg.time_budget,
           "call_timeout": cfg.call_timeout, "seed": cfg.seed, "topup": cfg.topup,
           "random_only": cfg.random_only, "seed_corpus": cfg.seed_corpus,
           "result_path": str((out / "result.json").resolve())}
    (out / "job.json").write_text(json.dumps(job, indent=1))
    (out / "result.json").unlink(missing_ok=True)
    log(f"fuzzing: {cfg.mode} mode, up to {cfg.max_cases} distinct inputs or {cfg.time_budget:g} s ...")
    env = dict(os.environ, PYTHONPATH=str(ROOT) + os.pathsep + os.environ.get("PYTHONPATH", ""))
    with open(out / "fuzzer.log", "w") as logf:
        try:
            subprocess.run([sys.executable, "-m", "difuzzi.harness", str(out / "job.json")], cwd=out,
                           stdout=logf, stderr=subprocess.STDOUT, env=env,
                           timeout=cfg.time_budget + cfg.call_timeout * 4 + 60)
            killed = False
        except subprocess.TimeoutExpired:
            killed = True
    try:
        res = json.loads((out / "result.json").read_text())
    except (OSError, ValueError):
        res = {"status": "error", "error": "the fuzzing process ended without a result; see fuzzer.log"}
    if res.get("status") == "running":   # last checkpoint of a run that did not finish cleanly
        res.update(status="error", error="the fuzzing process was " + ("killed after exceeding the time limit"
                   if killed else "terminated unexpectedly") + "; partial counts are in result.json")

    return _finish(cfg, out, res, source)


def _finish(cfg: Config, out: Path, res: dict, source: str) -> dict:
    """3. report"""
    meta = {"a_path": cfg.a_path, "b_path": cfg.b_path, "entry_a": cfg.entry_a, "entry_b": cfg.entry_b,
            "examples": cfg.examples, "binding_source": source}
    check = cfg.meta.get("binding_check")
    if check:
        meta["binding_check"] = {k: check.get(k) for k in ("passed", "repaired", "attempts")}
    res["meta"] = meta
    (out / "result.json").write_text(json.dumps(res, indent=1, default=str))
    (out / "report.html").write_text(report.render_html(res, meta), encoding="utf-8")
    return res
