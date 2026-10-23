"""Interactive tour of the bundled examples: pick one from a menu, see the exact difuzzi command, watch it run,
and open its HTML report. The examples ship with their input generators, so no LLM key is needed.

    difuzzi-demo              menu
    difuzzi-demo --list       list the examples
    difuzzi-demo 2            run example 2 (no menu)
    difuzzi-demo --all        run every example (e.g. to check an installation)
"""

from __future__ import annotations

import argparse
import os
import shlex
import shutil
import subprocess
import sys
import webbrowser
from pathlib import Path

# (title, what it shows, language, arguments relative to the examples folder)
EXAMPLES = [
    ("Binary search, off-by-one bug (Python)",
     "the paper's running example: `while lo < hi` misses the last element; similarity score and counterexamples",
     "python", ["python/binary_search/a.py", "python/binary_search/b_buggy.py",
                "--examples", "python/binary_search/examples.txt",
                "--description", "python/binary_search/description.txt"]),
    ("Rank a folder of candidates (Python)",
     "four binary-search implementations fuzzed with one input generator and ranked by similarity",
     "python", ["python/binary_search/a.py", "python/binary_search/candidates",
                "--examples", "python/binary_search/examples.txt",
                "--description", "python/binary_search/description.txt"]),
    ("Median, buggy candidate (Python)",
     "a candidate that is wrong only for lists of even length",
     "python", ["python/median/a.py", "python/median/b_buggy.py", "--examples", "python/median/examples.txt"]),
    ("Whole program on standard input, early stop (Python)",
     "file level: an age check where the candidate treats 18 as a minor; stops at the first counterexample",
     "python", ["python/adult_check/a.py", "python/adult_check/b_buggy.py", "--level", "file",
                "--examples", "python/adult_check/in1.txt", "--early-stop"]),
    ("Binary search, off-by-one bug (Java)",
     "the running example in Java, fuzzed with Jazzer",
     "java", ["java/binary_search/A.java", "java/binary_search/B_buggy.java",
              "--examples", "java/binary_search/examples.txt",
              "--description", "java/binary_search/description.txt"]),
    ("Median, buggy and correct candidates (Java)",
     "a buggy candidate; try java/median/B_correct.java for an equivalent one",
     "java", ["java/median/A.java", "java/median/B_buggy.java", "--examples", "java/median/examples.txt"]),
    ("List sum (Java)",
     "a linked-list sum whose candidate skips the last node; the input generator builds linked lists",
     "java", ["java/list_sum/A.java", "java/list_sum/B_buggy.java", "--examples", "java/list_sum/examples.txt"]),
    ("Whole program on standard input (Java)",
     "file level in Java: an equivalent candidate (similarity 1)",
     "java", ["java/stdin_sum/A.java", "java/stdin_sum/B_correct.java", "--level", "file",
              "--examples", "java/stdin_sum/in1.txt"]),
]


def examples_dir(given: str | None) -> Path:
    """The examples folder: --examples-dir, ./examples, the source checkout, or the Docker image."""
    here = Path(__file__).resolve().parent
    for d in ([Path(given)] if given else []) + [Path("examples"), here.parent / "examples",
                                                  Path("/opt/difuzzi/examples")]:
        if (d / "python").is_dir():
            return d.resolve()
    sys.exit("difuzzi-demo: examples folder not found; run it from a clone of the repository or pass --examples-dir")


def run(i: int, root: Path, out_root: Path, ask_open: bool) -> int:
    title, what, lang, args = EXAMPLES[i]
    if lang == "java" and not (shutil.which("java") and shutil.which("javac")):
        print(f"\n[{i + 1}] {title}: skipped, it needs a JDK 17 (java and javac on the PATH)")
        return 0
    out = out_root / f"example{i + 1}"
    cmd = ["difuzzi", *args, "-o", str(out)]
    print(f"\n[{i + 1}] {title}\n    {what}\n\n$ cd {root}\n$ {shlex.join(cmd)}\n", flush=True)
    code = subprocess.call([sys.executable, "-m", "difuzzi", *args, "-o", str(out)], cwd=root)
    report = out / ("summary.html" if (out / "summary.html").exists() else "report.html")
    if report.exists():
        if Path("/.dockerenv").exists():
            print(f"\nOpen the report from your machine: {str(report).removeprefix('/work/')}")
        elif ask_open and input("\nOpen the report in a browser? [y/N] ").strip().lower() == "y":
            webbrowser.open(report.as_uri())
    return code


def main(argv=None):
    ap = argparse.ArgumentParser(description="Interactive tour of the bundled difuzzi examples (no LLM key needed).")
    ap.add_argument("number", nargs="?", type=int, help="run this example without the menu")
    ap.add_argument("--list", action="store_true", help="list the examples")
    ap.add_argument("--all", action="store_true", help="run every example")
    ap.add_argument("--examples-dir", help="the examples folder (default: found automatically)")
    ap.add_argument("-o", "--out", default="difuzzi-demo-out", help="where the reports go (default ./difuzzi-demo-out)")
    args = ap.parse_args(argv)
    root, out_root = examples_dir(args.examples_dir), Path(args.out).resolve()
    os.environ.setdefault("DIFUZZI_LLM_API_KEY", "")   # the examples never need the LLM

    if args.list:
        for i, (title, what, _, _) in enumerate(EXAMPLES, 1):
            print(f"{i:2d}. {title}\n    {what}")
        return 0
    if args.all:
        return max(run(i, root, out_root, False) not in (0, 3) for i in range(len(EXAMPLES)))
    if args.number:
        if not 1 <= args.number <= len(EXAMPLES):
            sys.exit(f"difuzzi-demo: choose an example between 1 and {len(EXAMPLES)}")
        return run(args.number - 1, root, out_root, sys.stdin.isatty())

    while True:
        print("\ndifuzzi examples (no LLM key needed):")
        for i, (title, _, _, _) in enumerate(EXAMPLES, 1):
            print(f"  {i}. {title}")
        choice = input("\nRun which example? [1-%d, q to quit] " % len(EXAMPLES)).strip().lower()
        if choice in ("q", "quit", ""):
            return 0
        if choice.isdigit() and 1 <= int(choice) <= len(EXAMPLES):
            run(int(choice) - 1, root, out_root, True)
        else:
            print("Please enter a number from the list, or q.")


if __name__ == "__main__":
    sys.exit(main())
