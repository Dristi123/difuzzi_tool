"""Java backend: compile A, B, the input generator and the examples, rewrite the bytecode,
run the Jazzer harness (difuzzi/java/difuzzi/rt/DiffHarness.java), and turn JaCoCo's
coverage into the same result format as the Python backend."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Callable, List, Optional

ROOT = Path(__file__).resolve().parent.parent
RT_SRC = Path(__file__).resolve().parent / "java" / "difuzzi" / "rt"
_DEPS = None   # folder with Jazzer, JaCoCo and ASM (java_deps.py), resolved on first use
JAVA_KEYWORDS = {"if", "for", "while", "switch", "catch", "synchronized", "return", "new", "else", "do", "try"}


class JavaError(Exception):
    pass


def _dep(name: str) -> Path:
    global _DEPS
    if _DEPS is None:
        from . import java_deps
        try:
            _DEPS = java_deps.ensure()
        except Exception as e:
            raise JavaError(f"the Java dependencies could not be set up ({e}); run difuzzi-setup, or set "
                            "DIFUZZI_JAVA_DEPS to a folder that has them")
    p = _DEPS / name
    if not p.exists():
        raise JavaError(f"missing {p}; run difuzzi-setup")
    return p


def _run(cmd: List[str], what: str, env=None, cwd=None) -> str:
    p = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=cwd)
    if p.returncode != 0:
        msg = (p.stderr or p.stdout).strip()
        raise JavaError(f"{what} failed:\n{msg[-3000:]}")
    return p.stdout


def _strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group(0)), src, flags=re.S)
    src = re.sub(r"//[^\n]*", "", src)
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', src)


def package_of(src: str) -> str:
    m = re.search(r"^\s*package\s+([\w.]+)\s*;", _strip_comments(src), re.M)
    return m.group(1) + "." if m else ""


def public_class(src: str) -> Optional[str]:
    m = re.search(r"\bpublic\s+(?:final\s+|abstract\s+)*(?:class|record|interface|enum)\s+(\w+)", _strip_comments(src))
    return m.group(1) if m else None


# A method declaration: a name, a parameter list without nested parentheses, optional throws, then a body.
# Linear-time (no nested repetition); callers filter out calls, constructors and keywords.
METHOD_RE = re.compile(r"(?<![\w.$])(\w+)\s*\(([^()]*)\)\s*(?:throws\s+[\w.,\s]*)?\{")


def _is_declaration(code: str, start: int) -> bool:
    """The text before a candidate name must end with a type (e.g. `int`, `List<Integer>`, `int[]`),
    not with an operator, `new`, `return` or `.` (which would make it a call or an expression)."""
    before = code[max(0, start - 200):start].rstrip()
    if not before or before[-1] not in ">]" and not (before[-1].isalnum() or before[-1] in "_$"):
        return False
    prev = re.search(r"(\w+)\s*$", before)
    return not (prev and prev.group(1) in ("new", "return", "else", "throw", "case", "yield"))


def classes_and_methods(src: str) -> List[tuple]:
    """[(binary class name, [method names in order]), ...] for the top-level and nested classes in the
    source (a nested class is named Outer$Inner).
    A rough parse: comments and strings are blanked, class bodies are found by brace matching, and each
    method is attributed to the innermost class around it. Constructors are excluded."""
    code = _strip_comments(src)
    spans = []
    for m in re.finditer(r"\b(?:class|record|enum|interface)\s+(\w+)[^{;]*\{", code):
        depth, i = 1, m.end()
        while i < len(code) and depth:
            depth += {"{": 1, "}": -1}.get(code[i], 0)
            i += 1
        spans.append((m.start(), i, m.group(1)))
    def binary(span):
        outer = sorted((s for s in spans if s[0] < span[0] and span[1] <= s[1]), key=lambda s: s[0])
        return "$".join([s[2] for s in outer] + [span[2]])

    methods = {span: [] for span in spans}
    for m in METHOD_RE.finditer(code):
        name = m.group(1)
        if name in JAVA_KEYWORDS or not _is_declaration(code, m.start(1)):
            continue
        inner = [s for s in spans if s[0] < m.start(1) < s[1]]
        if inner:
            owner = max(inner, key=lambda s: s[0])
            if name != owner[2]:
                methods[owner].append(name)
    return [(binary(span), methods[span]) for span in spans]


def main_class(src: str, level: str, entry: Optional[str] = None) -> str:
    """File level: the class declaring main(). Function level: the class declaring the entry method
    (or, without one, the public class if it declares methods, else the first class that does)."""
    found = classes_and_methods(src)
    if not found:
        raise JavaError("no class found")
    if level == "file":
        owners = [c for c, ms in found if "main" in ms]
        if not owners:
            raise JavaError("no main method found (file level needs public static void main)")
        return owners[0]
    if entry:
        owners = [c for c, ms in found if entry in ms]
        if not owners:
            raise JavaError(f"method {entry!r} not found")
        return owners[0]
    pub = public_class(src)
    candidates = [c for c, ms in found if [m for m in ms if m != "main"]]
    if pub in candidates:
        return pub
    if not candidates:
        raise JavaError("no method found; pass --entry")
    return candidates[0]


def resolve_entries(cfg):
    a_src, b_src = Path(cfg.a_path).read_text(), Path(cfg.b_path).read_text()
    if cfg.level == "function":
        if not cfg.entry_a:
            cls = main_class(a_src, "function")
            cfg.entry_a = [m for c, ms in classes_and_methods(a_src) if c == cls for m in ms if m != "main"][0]
        if not cfg.entry_b:
            b_methods = {m for _, ms in classes_and_methods(b_src) for m in ms}
            cfg.entry_b = cfg.entry_a if cfg.entry_a in b_methods else None
            if cfg.entry_b is None:
                cls = main_class(b_src, "function")
                cfg.entry_b = [m for c, ms in classes_and_methods(b_src) if c == cls for m in ms if m != "main"][0]
    cfg.meta["a_main"] = package_of(a_src) + main_class(a_src, cfg.level, cfg.entry_a)
    cfg.meta["b_main"] = package_of(b_src) + main_class(b_src, cfg.level, cfg.entry_b)


def runtime_classes() -> Path:
    """Compile the harness runtime once per version of its sources (cached)."""
    sources = sorted(RT_SRC.glob("*.java"))
    key = hashlib.sha256(b"".join(p.read_bytes() for p in sources)).hexdigest()[:16]
    out = Path(os.environ.get("DIFUZZI_CACHE", Path.home() / ".cache" / "difuzzi")) / "java-rt" / key
    if not (out / "difuzzi" / "rt" / "DiffHarness.class").exists():
        tmp = out.with_suffix(".tmp")
        shutil.rmtree(tmp, ignore_errors=True)
        tmp.mkdir(parents=True)
        cp = os.pathsep.join(map(str, [_dep("asm.jar"), _dep("jazzer-api.jar")]))
        _run(["javac", "-nowarn", "-Xlint:none", "-encoding", "UTF-8", "-cp", cp, "-d", str(tmp)] + list(map(str, sources)),
             "compiling the difuzzi Java runtime")
        shutil.rmtree(out, ignore_errors=True)
        tmp.rename(out)
    return out


def compile_program(src_path: str, work: Path, name: str, reset: bool, rt: Path) -> dict:
    """Copy the source to <PublicClass>.java (javac requires it), compile with debug info, rewrite."""
    src = Path(src_path).read_text(encoding="utf-8")
    cls = public_class(src) or classes_and_methods(src)[0][0].split("$")[0]
    src_dir, raw, out = work / f"src_{name}", work / f"raw_{name}", work / f"cls_{name}"
    for d in (src_dir, raw, out):
        shutil.rmtree(d, ignore_errors=True)
        d.mkdir(parents=True)
    pkg = package_of(src)
    target_dir = src_dir / pkg.rstrip(".").replace(".", "/") if pkg else src_dir
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / f"{cls}.java").write_text(src, encoding="utf-8")
    try:
        _run(["javac", "-g", "-nowarn", "-encoding", "UTF-8", "-d", str(raw), str(target_dir / f"{cls}.java")],
             f"compiling {name.upper()} ({src_path})")
    except JavaError as e:
        raise JavaError(str(e).replace(str(target_dir / f"{cls}.java"), src_path))
    _run(["java", "-cp", os.pathsep.join([str(rt), str(_dep("asm.jar"))]), "difuzzi.rt.Rewriter",
          str(raw), str(out), "true" if reset else "false"], f"rewriting {name.upper()}")
    classes = sorted(str(p.relative_to(out))[:-6].replace("/", ".") for p in out.rglob("*.class"))
    return {"src_dir": src_dir, "cls_dir": out, "classes": classes}


def compile_generator(binding_src: str, examples: List[str], level: str, a_cls: Path, work: Path,
                      program_classes: List[str] = (), drop_bad_examples: bool = False):
    """Compile the input generator and (function level) the example inputs into gen/.
    With drop_bad_examples (evaluation only), examples that do not compile are left out;
    returns (gen dir, kept examples)."""
    gen = work / "gen"
    shutil.rmtree(gen, ignore_errors=True)
    gen.mkdir(parents=True)
    src = re.sub(r"\bpublic\s+class\s+\w+", "public class DiffGen", binding_src, count=1)
    (gen / "DiffGen.java").write_text(src, encoding="utf-8")
    cp = os.pathsep.join(map(str, [a_cls, _dep("jazzer-api.jar")]))
    _run(["javac", "-nowarn", "-encoding", "UTF-8", "-cp", cp, "-d", str(gen), str(gen / "DiffGen.java")],
         "compiling the input generator")
    kept = list(examples)
    if level == "function":
        imports = "\n".join(sorted(set(re.findall(r"^\s*import\s+[\w.*]+\s*;", binding_src, re.M)) | {"import java.util.*;"}))
        header = f"{imports}\n\npublic class DiffExamples {{\n"
        for _ in range(3):
            body = "\n".join(f"    public static Object[] ex{i}() {{ return new Object[]{{ {e} }}; }}"
                             for i, e in enumerate(kept))
            (gen / "DiffExamples.java").write_text(header + body + "\n}\n", encoding="utf-8")
            p = subprocess.run(["javac", "-nowarn", "-encoding", "UTF-8", "-cp", f"{cp}{os.pathsep}{gen}", "-d", str(gen),
                                str(gen / "DiffExamples.java")], capture_output=True, text=True)
            if p.returncode == 0:
                break
            if not drop_bad_examples:
                raise JavaError("the example inputs are not valid Java argument lists:\n" + (p.stderr or p.stdout)[-3000:])
            first = header.count("\n")
            bad = {int(m) - first - 1 for m in re.findall(r"DiffExamples\.java:(\d+): error", p.stderr)}
            if not bad:
                raise JavaError("the example inputs could not be compiled:\n" + p.stderr[-3000:])
            kept = [e for i, e in enumerate(kept) if i not in bad]
        else:
            raise JavaError("the example inputs could not be compiled")
    for name in program_classes:   # a generator that re-declares the program's classes must use A's/B's own
        (gen / (name.replace(".", "/") + ".class")).unlink(missing_ok=True)
    return gen, kept


def coverage_from_jacoco(exec_path: Path, prog: dict, work: Path, name: str) -> dict:
    empty = {"lines": [0, 0], "branches": [0, 0], "executed_lines": [], "missing_lines": [], "missing_branches": []}
    if not exec_path.exists():
        return empty
    xml = work / f"jacoco_{name}.xml"
    try:
        _run(["java", "-jar", str(_dep("jacococli.jar")), "report", str(exec_path), "--classfiles", str(prog["cls_dir"]),
              "--sourcefiles", str(prog["src_dir"]), "--xml", str(xml), "--quiet"], "coverage report")
    except JavaError:
        return empty
    root = ET.parse(xml).getroot()
    src_lines = next(prog["src_dir"].rglob("*.java")).read_text(encoding="utf-8").splitlines()
    # The compiler's implicit default constructor sits on the class declaration line; it is not code the
    # user wrote, so an unused one should not count as a missed line.
    implicit = {int(m.get("line")) for m in root.iter("method")
                if m.get("name") == "<init>" and m.get("desc") == "()V" and m.get("line")
                and 0 < int(m.get("line")) <= len(src_lines)
                and re.search(r"\b(class|record|enum)\s+\w+", src_lines[int(m.get("line")) - 1])}
    executed, missing, partial = set(), set(), set()
    lines_total = lines_cov = br_total = br_cov = 0
    for sf in root.iter("sourcefile"):
        for ln in sf.iter("line"):
            nr, mi, ci, mb, cb = (int(ln.get(k)) for k in ("nr", "mi", "ci", "mb", "cb"))
            if mi + ci == 0 or (nr in implicit and ci == 0):
                continue
            lines_total += 1
            br_total += mb + cb
            br_cov += cb
            if ci > 0:
                executed.add(nr)
                lines_cov += 1
                if mb > 0:
                    partial.add(nr)
            else:
                missing.add(nr)
    return {"lines": [lines_cov, lines_total], "branches": [br_cov, br_total], "executed_lines": sorted(executed),
            "missing_lines": sorted(missing), "missing_branches": [[n, -1] for n in sorted(partial)]}


def run(cfg, binding_src: str, out: Path, log: Callable[[str], None]) -> dict:
    """Compile, fuzz with Jazzer and collect coverage. Returns the result dict (same schema as Python)."""
    for tool in ("java", "javac"):
        if not shutil.which(tool):
            raise JavaError(f"`{tool}` not found; the Java backend needs a JDK 17")
    work = out / "java"
    work.mkdir(parents=True, exist_ok=True)
    rt = runtime_classes()
    reset = cfg.level == "file"
    a = compile_program(cfg.a_path, work, "a", reset, rt)
    b = compile_program(cfg.b_path, work, "b", reset, rt)
    gen, examples = compile_generator(binding_src, cfg.examples, cfg.level, a["cls_dir"], work,
                                      sorted(set(a["classes"]) | set(b["classes"])), cfg.examples_only)

    examples_dir = work / "examples"
    shutil.rmtree(examples_dir, ignore_errors=True)
    examples_dir.mkdir()
    if cfg.level == "file":
        for i, e in enumerate(examples):
            (examples_dir / f"ex{i}.txt").write_text(e, encoding="utf-8")

    exec_path, result_path = work / "jacoco.exec", out / "result.json"
    for p in (exec_path, result_path):
        p.unlink(missing_ok=True)
    props = {"level": cfg.level, "mode": cfg.mode, "max_cases": cfg.max_cases, "time_budget": cfg.time_budget,
             "call_timeout": cfg.call_timeout, "seed": cfg.seed, "topup": str(cfg.topup).lower(),
             "result_path": result_path, "exec_path": exec_path, "a_dir": a["cls_dir"], "b_dir": b["cls_dir"],
             "gen_dir": gen, "a_main": cfg.meta["a_main"], "b_main": cfg.meta["b_main"],
             "entry_a": cfg.entry_a or "", "entry_b": cfg.entry_b or "", "n_examples": len(examples),
             "examples_dir": examples_dir, "random_only": str(cfg.random_only).lower(),
             "examples_only": str(cfg.examples_only).lower()}
    job = work / "job.properties"
    job.write_text("".join(f"{k}={_prop(v)}\n" for k, v in props.items()), encoding="utf-8")

    classes = sorted(set(a["classes"]) | set(b["classes"]))
    includes = ":".join(classes)
    env = dict(os.environ, JAVA_TOOL_OPTIONS=f"-javaagent:{_dep('jacocoagent.jar')}=output=none,includes={includes}")
    cmd = [str(_dep("jazzer/jazzer")), f"--cp={rt}", "--target_class=difuzzi.rt.DiffHarness",
           f"--instrumentation_includes={includes}", "--hooks=false",
           f"--jvm_args=-Ddifuzzi.job={job}:-Xss16m:-XX:-OmitStackTraceInFastThrow",
           f"-seed={cfg.seed + 1}", "-rss_limit_mb=8192", f"-max_total_time={int(cfg.time_budget) + 60}",
           "-timeout=3600"]
    if cfg.seed_corpus != "none":
        cmd += ["-max_len=512", str(_seed_corpus(work, cfg.seed, mixed=cfg.seed_corpus == "mixed"))]
    log(f"fuzzing (Java, Jazzer): {cfg.mode} mode, up to {cfg.max_cases} distinct inputs or {cfg.time_budget:g} s ...")
    with open(out / "fuzzer.log", "w") as logf:
        try:
            subprocess.run(cmd, stdout=logf, stderr=subprocess.STDOUT, env=env, cwd=work,
                           timeout=cfg.time_budget + cfg.call_timeout * 4 + 120)
            killed = False
        except subprocess.TimeoutExpired:
            killed = True
    try:
        res = json.loads(result_path.read_text())
    except (OSError, ValueError):
        res = {"status": "error", "error": "the fuzzing process ended without a result; see fuzzer.log"}
    if res.get("status") == "running":
        res.update(status="error", error="the fuzzing process was " + ("killed after exceeding the time limit"
                   if killed else "terminated unexpectedly") + "; partial counts are in result.json")
    if cfg.examples_only:
        res["inputs_dropped"] = len(cfg.examples) - len(examples)
    if res.get("status") == "done":
        res["coverage"] = {"A": coverage_from_jacoco(exec_path, a, work, "a"),
                           "B": coverage_from_jacoco(exec_path, b, work, "b")}
    return res


def _seed_corpus(work: Path, seed: int, files: int = 64, max_len: int = 512, mixed: bool = False) -> Path:
    """Random byte strings as Jazzer's starting corpus (see harness.write_seed_corpus)."""
    import random
    d = work / "corpus"
    shutil.rmtree(d, ignore_errors=True)
    d.mkdir(parents=True)
    rng = random.Random(seed + 7)
    for i in range(files):
        n = rng.randint(1, 8) if mixed and i % 2 == 0 else rng.randint(9 if mixed else 1, max_len)
        (d / f"seed{i}").write_bytes(rng.randbytes(n))
    return d


def _prop(v) -> str:
    """Escape a value for a Java .properties file."""
    s = str(v)
    return s.replace("\\", "\\\\").replace("\n", "\\n").replace(":", "\\:").replace("=", "\\=")
