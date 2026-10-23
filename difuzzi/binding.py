"""LLM generation of the input binding: a function `generate(fdp)` that turns
fuzzer bytes (via atheris.FuzzedDataProvider) into arguments for the reference A."""

from __future__ import annotations

from typing import List, Optional

from . import llm

FUNCTION_PROMPT = """\
You are writing the input generator for a differential fuzzer (Python, Atheris).
The fuzzer calls a reference function and a candidate function on the same inputs and
compares their outputs. Your generator decides which inputs are tested.

You will write ONE Python function:

    def generate(fdp):
        ...
        return (arg1, arg2, ...)

It receives an `atheris.FuzzedDataProvider` and returns the tuple of positional arguments
for the reference function (a 1-tuple `(x,)` for a single argument).

Valid domain:
- Generate only inputs that the function is meant to accept, as stated by the description and
  implied by the code and the example inputs. Respect every stated constraint (e.g. "positive",
  "sorted", "string of digits", "non-empty"). Match the types and structure of the example inputs.
- If one argument is the length of another (e.g. `n` for `arr`), derive it with `len(...)`.

Variety (inside the valid domain):
- Vary sizes from the smallest allowed (empty or a single element) up to the maximum size.
- Vary values: small and large, repeated and distinct, and every alternative form an argument
  may take (e.g. both `None` and a list, if both are valid).

Ranges:
- The example inputs show the types and structure of valid inputs, not the range of values;
  do not limit values to what the examples happen to contain.
- If the description or the code states limits for a value, use exactly those limits.
- Otherwise choose the ranges yourself. Make them wide enough to exercise the function's
  behaviour (a good default for numbers is -1000..1000, or 0..1000 if negatives are not valid),
  but small enough that every call finishes quickly: judge from the code how its running time
  grows with each argument, and keep arguments small where it grows fast (exponential
  recursion, nested loops, building large structures).
- Include the edges of the domain: 0, 1, -1 where valid, empty and single-element collections,
  the smallest and largest allowed values.
- Keep collections and strings to about 20 elements so each call stays fast.

Fuzzer API:
- Derive every value from `fdp`, so the fuzzer controls it. Do not use `random`, `time`, `uuid`
  or `os.urandom`. If you need a random generator (e.g. for a large array), seed it from `fdp`:
  `np.random.default_rng(fdp.ConsumeIntInRange(0, 2**32 - 1))`.
- Integers: `fdp.ConsumeIntInRange(lo, hi)`. Floats: `fdp.ConsumeFloatInRange(lo, hi)`.
  Booleans: `fdp.ConsumeBool()`. Choice from a fixed set: `fdp.PickValueInList([...])`.
- `PickValueInList` only accepts a Python list, never a string: write
  `fdp.PickValueInList(list('abc'))`, not `fdp.PickValueInList('abc')` (that raises TypeError).
- Strings: `fdp.ConsumeUnicodeNoSurrogates(n)`; if only certain characters are allowed, build the
  string from them: `''.join(fdp.PickValueInList(list('()')) for _ in range(n))`.
- Lists: draw a length with `ConsumeIntInRange`, then generate each element.
- Do not use `while` loops; only `for _ in range(n)`. (A `while` loop waiting for new values can
  run forever, because `fdp` returns the same value again and again once its input is used up.)
  If values must be distinct or sorted, draw n values and then use `set(...)` / `sorted(...)`.
- You may import standard-library or third-party modules inside `generate` if needed
  (e.g. to build a pandas DataFrame).

{few_shot}
Now the task.

Reference function (entry point: `{entry}`):

```python
{code}
```
{description_section}
Example inputs. Each line is the tuple of positional arguments of one valid call:
{examples}

Output only the code of `generate` in one ```python block.
"""

FEW_SHOT = """\
Worked examples (for other functions):

Example 1. A constraint from the description ("sorted"), and inputs where the target is
present and absent.

```python
def binary_search(arr, target):
    lo, hi = 0, len(arr) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        if arr[mid] == target:
            return mid
        if arr[mid] < target:
            lo = mid + 1
        else:
            hi = mid - 1
    return -1
```
Description: Return the index of target in the sorted list arr, or -1 if it is absent.
Example inputs: ([1, 3, 5, 7], 5)

```python
def generate(fdp):
    n = fdp.ConsumeIntInRange(0, 20)
    arr = sorted(fdp.ConsumeIntInRange(-1000, 1000) for _ in range(n))
    if arr and fdp.ConsumeBool():
        target = fdp.PickValueInList(arr)            # present
    else:
        target = fdp.ConsumeIntInRange(-1000, 1000)  # usually absent
    return (arr, target)
```

Example 2. A string restricted to the characters the description allows.

```python
def is_balanced(s):
    depth = 0
    for c in s:
        depth += 1 if c == '(' else -1
        if depth < 0:
            return False
    return depth == 0
```
Description: Given a string of '(' and ')', return whether it is balanced.
Example inputs: ("(())",)

```python
def generate(fdp):
    n = fdp.ConsumeIntInRange(0, 20)
    s = ''.join(fdp.PickValueInList(['(', ')']) for _ in range(n))
    return (s,)
```

Example 3. An optional field: produce inputs with and without it.

```python
def get_city(record):
    if 'address' not in record:
        return None
    return record['address']['city']
```
Description: Return the city of a customer record, or None if the record has no address.
Example inputs: ({'name': 'Ann', 'address': {'city': 'Oslo'}},)

```python
def generate(fdp):
    record = {'name': fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 10))}
    if fdp.ConsumeBool():
        record['address'] = {'city': fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 15))}
    return (record,)
```

Example 4. Running time grows exponentially with n, so the range is kept small.

```python
def fib(n):
    return n if n < 2 else fib(n - 1) + fib(n - 2)
```
Description: Return the n-th Fibonacci number (n >= 0).
Example inputs: (10,)

```python
def generate(fdp):
    return (fdp.ConsumeIntInRange(0, 25),)
```
"""


REPAIR_SUFFIX = """
Your previous generator was:

```python
{previous}
```

Running it on random fuzzer bytes showed these problems:
{problems}

Write a corrected `generate(fdp)` that follows all rules above.
"""

COVERAGE_SUFFIX = """
Your previous generator was:

```python
{previous}
```

It works, but none of the inputs it produced executed these lines of the reference function:
{lines}

If inputs that the function is meant to accept (per the description and the code) can reach
these lines, extend `generate` so that some inputs do. Do not generate inputs the function is
not meant to accept just to reach them. If no such input reaches them, return the generator
unchanged.
"""


FILE_PROMPT = """\
You are writing the input generator for a differential fuzzer (Python, Atheris).
The fuzzer runs a reference program and a candidate program on the same standard input and
compares what they print. Your generator decides which inputs are tested.

You will write ONE Python function:

    def generate(fdp):
        ...
        return stdin_text

It receives an `atheris.FuzzedDataProvider` and returns the complete standard input for the
program, as a string (lines separated by "\\n", ending with "\\n").

Valid domain:
- Generate only inputs in the format the program reads and within the constraints it expects,
  as stated by the description and implied by the code and the example inputs. Respect every
  stated constraint (e.g. "1 <= n <= 100", "distinct", "sorted").
- Counts in the input must match the data that follows (e.g. a first line `n` followed by
  exactly n numbers).

Variety (inside the valid domain):
- Vary sizes from the smallest allowed up to the maximum size, and vary values: small and large,
  repeated and distinct.

Ranges:
- The example inputs show the format of valid inputs, not the range of values; do not limit
  values to what the examples happen to contain.
- If the description or the code states limits for a value, use exactly those limits.
- Otherwise choose the ranges yourself. Make them wide enough to exercise the program's
  behaviour (a good default for numbers is -1000..1000, or 0..1000 if negatives are not valid),
  but small enough that every run finishes quickly: judge from the code how its running time
  grows with the input, and keep the input small where it grows fast.
- Include the edges: the smallest and largest allowed sizes and values.
- Keep inputs to about 20 items so each run stays fast.

Fuzzer API:
- Derive every value from `fdp`, so the fuzzer controls it. Do not use `random`, `time`, `uuid`
  or `os.urandom`.
- Integers: `fdp.ConsumeIntInRange(lo, hi)`. Floats: `fdp.ConsumeFloatInRange(lo, hi)`.
  Booleans: `fdp.ConsumeBool()`. Choice from a fixed set: `fdp.PickValueInList([...])`.
- `PickValueInList` only accepts a Python list, never a string: write
  `fdp.PickValueInList(list('abc'))`, not `fdp.PickValueInList('abc')` (that raises TypeError).
- Do not use `while` loops; only `for _ in range(n)`. (A `while` loop waiting for new values can
  run forever, because `fdp` returns the same value again and again once its input is used up.)
  If values must be distinct or sorted, draw n values and then use `set(...)` / `sorted(...)`.

{few_shot}
Now the task.

Reference program:

```python
{code}
```
{description_section}
Example inputs (standard input of valid runs):
{examples}

Output only the code of `generate` in one ```python block.
"""

FILE_FEW_SHOT = """\
Worked examples (for other programs):

Example 1. A count followed by that many numbers.

```python
n = int(input())
a = list(map(int, input().split()))
print(max(a) - min(a))
```
Description: Given n (1 <= n <= 100) and n integers, print the difference between the largest
and the smallest.
Example inputs:
  "3\\n4 9 1\\n"

```python
def generate(fdp):
    n = fdp.ConsumeIntInRange(1, 20)
    a = [fdp.ConsumeIntInRange(-1000, 1000) for _ in range(n)]
    return f"{n}\\n{' '.join(map(str, a))}\\n"
```

Example 2. Several test cases, each a word of lowercase letters.

```python
t = int(input())
for _ in range(t):
    s = input().strip()
    print("YES" if s == s[::-1] else "NO")
```
Description: For each of t test cases, print YES if the word is a palindrome.
Example inputs:
  "2\\nabba\\nabc\\n"

```python
def generate(fdp):
    t = fdp.ConsumeIntInRange(1, 10)
    words = []
    for _ in range(t):
        k = fdp.ConsumeIntInRange(1, 10)
        words.append(''.join(fdp.PickValueInList(list('ab')) for _ in range(k)))
    return f"{t}\\n" + "".join(w + "\\n" for w in words)
```
"""


def _format_examples(examples: List[str]) -> str:
    return "\n".join(f"  {e}" for e in examples)


def build_prompt(code: str, entry: Optional[str], examples: List[str], description: Optional[str] = None,
                 level: str = "function", lang: str = "python") -> str:
    """The binding prompt. Function level: `examples` are argument-tuple sources (Python) or argument
    lists (Java). File level: `examples` are standard-input texts."""
    if lang == "java":
        from . import binding_java
        return binding_java.build_prompt(code, entry, examples, description, level)
    desc = f"\nDescription:\n{description.strip()}\n" if description and description.strip() else ""
    if level == "file":
        return FILE_PROMPT.format(code=code.strip(), description_section=desc,
                                  examples=_format_examples([repr(e) for e in examples]),
                                  few_shot=FILE_FEW_SHOT)
    return FUNCTION_PROMPT.format(entry=entry, code=code.strip(), description_section=desc,
                                  examples=_format_examples(examples), few_shot=FEW_SHOT)


def generate_binding(code: str, entry: Optional[str], examples: List[str],
                     description: Optional[str] = None, level: str = "function") -> str:
    """Ask the LLM for a binding; returns the source code of `generate(fdp)`."""
    return llm.extract_code(llm.chat(build_prompt(code, entry, examples, description, level)))
