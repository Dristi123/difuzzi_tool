"""Loading user code and calling it safely. Used inside the worker subprocess only."""

from __future__ import annotations

import ast
import builtins
import contextlib
import copy
import io
import os
import random
import signal
import sys
import tempfile
import types

# Names commonly assumed by benchmark snippets without importing them.
PREAMBLE = """\
from typing import List, Tuple, Dict, Optional, Any, Set
from collections import defaultdict, Counter, OrderedDict, deque
from itertools import combinations, permutations, product
from functools import reduce
import math, re, hashlib, copy, string, heapq, bisect
"""


class CallTimeout(BaseException):
    """Raised by the alarm handler; a BaseException so user code cannot swallow it."""


def _on_alarm(signum, frame):
    raise CallTimeout()


signal.signal(signal.SIGALRM, _on_alarm)


def new_namespace(name: str, path: str) -> dict:
    g = {"__name__": name, "__file__": path, "__builtins__": builtins}
    exec(compile(PREAMBLE, "<preamble>", "exec"), g)
    return g


def load_module(path: str, name: str, instrument: bool = False) -> dict:
    """Execute the file at `path` in a fresh namespace and return the namespace.

    With `instrument`, the module code is run as an Atheris-instrumented function,
    so every function it defines carries coverage instrumentation."""
    g = new_namespace(name, path)
    with open(path, encoding="utf-8") as f:
        code = compile(f.read(), path, "exec")
    if instrument:
        import atheris
        atheris.instrument_func(types.FunctionType(code, g))()
    else:
        exec(code, g)
    return g


def eval_input(src: str, namespace: dict) -> tuple:
    """Evaluate an example input: Python source whose last statement is an expression
    giving the tuple of positional arguments. Earlier statements may set things up."""
    tree = ast.parse(src.strip())
    if not tree.body or not isinstance(tree.body[-1], ast.Expr):
        raise ValueError("example input must end with an expression (the argument tuple)")
    g = dict(namespace)
    setup = ast.Module(body=tree.body[:-1], type_ignores=[])
    exec(compile(setup, "<example>", "exec"), g)
    value = eval(compile(ast.Expression(tree.body[-1].value), "<example>", "eval"), g)
    return value if isinstance(value, tuple) else (value,)


def reseed(seed: int = 0):
    random.seed(seed)
    np = sys.modules.get("numpy")
    if np is not None:
        np.random.seed(seed % 2**32)


def compile_script(path: str, instrument: bool = False):
    """Code object of a whole program (file level), optionally Atheris-instrumented."""
    with open(path, encoding="utf-8") as f:
        code = compile(f.read(), path, "exec")
    if instrument:
        import atheris
        code = atheris.instrument_func(types.FunctionType(code, {})).__code__
    return code


_FILES = {}   # fd -> temporary file standing in for the program's standard input / output


def _redirect_fd(fd: int, data: bytes = b""):
    """Point file descriptor `fd` at a temporary file holding `data`, as a real stdin/stdout would
    be: programs that use os.read(0, ...), os.fstat(0), os.write(1, ...) or .fileno() (fast I/O in
    competitive programming) then read the input and write the output. Returns the saved descriptor."""
    f = _FILES.get(fd)
    if f is None:
        f = _FILES[fd] = tempfile.TemporaryFile(dir="/dev/shm" if os.path.isdir("/dev/shm") else None)
    f.seek(0)
    f.truncate()
    f.write(data)
    f.flush()
    try:
        saved = os.dup(fd)
    except OSError:
        saved = None
    os.dup2(f.fileno(), fd)
    os.lseek(fd, 0, os.SEEK_SET)
    return saved


def _restore_fd(fd: int, saved):
    if saved is None:
        os.close(fd)
    else:
        os.dup2(saved, fd)
        os.close(saved)


def run_script(code, path: str, stdin_text: str, timeout: float):
    """Run a program in-process with `stdin_text` as standard input. Standard input and output are
    real file descriptors 0 and 1 for the duration of the run (restored afterwards).
    Returns ("ok", stdout), ("raise", "Type: message") or ("timeout", None).
    A non-zero exit status counts as "raise"."""
    g = {"__name__": "__main__", "__file__": path, "__builtins__": builtins}
    old = sys.stdin, sys.stdout, sys.stderr
    sys.__stdout__.flush() if sys.__stdout__ else None
    saved_in = _redirect_fd(0, stdin_text.encode("utf-8"))
    saved_out = _redirect_fd(1)
    sys.stdin = open(0, "r", encoding="utf-8", closefd=False)
    sys.stdout = open(1, "w", encoding="utf-8", closefd=False)
    sys.stderr = io.StringIO()
    reseed()
    result = None
    try:
        try:
            run_with_timeout(types.FunctionType(code, g), timeout)
        except SystemExit as e:
            if e.code not in (None, 0):
                result = ("raise", f"SystemExit: exit status {e.code}")
        if result is None:
            result = ("ok", None)
    except CallTimeout:
        result = ("timeout", None)
    except BaseException as e:
        result = ("raise", f"{type(e).__name__}: {str(e)[:200]}")
    finally:
        try:
            sys.stdout.flush()
        except Exception:
            pass
        sys.stdin, sys.stdout, sys.stderr = old
        _restore_fd(0, saved_in)
        _restore_fd(1, saved_out)
    if result[0] == "ok":
        f = _FILES[1]
        f.seek(0)
        return "ok", f.read().decode("utf-8", "replace")
    return result


def normalize_output(text: str) -> str:
    """Program output with trailing whitespace on each line and trailing blank lines ignored."""
    return "\n".join(line.rstrip() for line in text.rstrip().splitlines())


def run_with_timeout(fn, timeout: float):
    signal.setitimer(signal.ITIMER_REAL, timeout)
    try:
        return fn()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def deliberate_raise(exc: BaseException, path: str) -> bool:
    """Was `exc` raised by a `raise` or `assert` statement in the file at `path`
    (an intentional rejection by the code itself, not an incidental error)?"""
    tb = exc.__traceback__
    while tb is not None and tb.tb_next is not None:
        tb = tb.tb_next
    if tb is None or tb.tb_frame.f_code.co_filename != path:
        return False
    import linecache
    line = linecache.getline(path, tb.tb_lineno).strip()
    return line.startswith(("raise", "assert"))


def call(func, args: tuple, timeout: float, path: str = None):
    """Call `func(*args)` on a deep copy of the arguments with the RNGs reseeded and
    output silenced. Returns ("ok", value), ("raise", "Type: message") or ("timeout", None);
    with `path`, a deliberate raise from that file is reported as ("reject", "Type: message")."""
    try:
        args = copy.deepcopy(args)
    except Exception:
        pass
    reseed()
    sink = io.StringIO()
    try:
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            value = run_with_timeout(lambda: func(*args), timeout)
        return "ok", value
    except CallTimeout:
        return "timeout", None
    except BaseException as e:  # includes SystemExit raised by user code
        kind = "reject" if path and deliberate_raise(e, path) else "raise"
        return kind, f"{type(e).__name__}: {str(e)[:200]}"
