"""Equality of program outputs: float tolerance, NaN-aware, numpy/pandas aware."""

from __future__ import annotations

import math


def values_equal(a, b, rel_tol: float = 1e-9) -> bool:
    try:
        return _eq(a, b, rel_tol)
    except Exception:
        return repr(a) == repr(b)


def _eq(a, b, tol) -> bool:
    if isinstance(a, float) or isinstance(b, float):
        if isinstance(a, (int, float)) and isinstance(b, (int, float)) \
                and not isinstance(a, bool) and not isinstance(b, bool):
            a, b = float(a), float(b)
            if math.isnan(a) or math.isnan(b):
                return math.isnan(a) and math.isnan(b)
            if math.isinf(a) or math.isinf(b):
                return a == b
            return abs(a - b) <= tol * max(abs(a), abs(b), 1.0)
    if type(a) is not type(b) and not (isinstance(a, (list, tuple)) and isinstance(b, (list, tuple))
                                       and type(a) is type(b)):
        return _foreign(a, b, tol)
    if isinstance(a, (list, tuple)):
        return len(a) == len(b) and all(_eq(x, y, tol) for x, y in zip(a, b))
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(_eq(a[k], b[k], tol) for k in a)
    return _foreign(a, b, tol)


def _foreign(a, b, tol) -> bool:
    mod = type(a).__module__.split(".")[0]
    if mod == "numpy":
        import numpy as np
        if isinstance(a, np.ndarray) and isinstance(b, np.ndarray):
            if a.shape != b.shape:
                return False
            if a.dtype.kind in "fc" or b.dtype.kind in "fc":
                return bool(np.allclose(a, b, rtol=tol, atol=0, equal_nan=True))
            return bool(np.array_equal(a, b))
    if mod == "pandas" and hasattr(a, "equals"):
        return bool(a.equals(b))
    if mod == "numpy" or type(b).__module__.split(".")[0] == "numpy":
        a, b = getattr(a, "item", lambda: a)(), getattr(b, "item", lambda: b)()   # numpy scalar -> Python
        if type(a) is not type(b) and isinstance(a, (int, float)) and isinstance(b, (int, float)):
            return _eq(float(a), float(b), tol)
    r = a == b
    return bool(r) if isinstance(r, bool) else repr(a) == repr(b)
