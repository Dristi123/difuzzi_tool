"""Command-line interface.

  difuzzi A.py B.py --examples examples.txt [--description desc.txt] [options]
  difuzzi A.py candidates/ --examples examples.txt     (every file in the folder is a candidate B)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import llm, pipeline, report


def _text_or_file(value: str) -> str:
    """A value given inline, or the contents of a file if the value names an existing file."""
    p = Path(value)
    return p.read_text(encoding="utf-8") if p.is_file() else value


def load_examples(files, level: str) -> list:
    """Example inputs from --examples (files).
    Function level: an examples file holds one argument tuple per line ('#' starts a comment).
    File level: each examples file (or each .txt file in a directory) is one standard input."""
    out = []
    for f in files or []:
        p = Path(f)
        if not p.exists():
            raise pipeline.PipelineError(f"examples file not found: {f}")
        if level == "file":
            paths = sorted(p.glob("*.txt")) if p.is_dir() else [p]
            out += [q.read_text(encoding="utf-8") for q in paths]
        else:
            out += [line.strip() for line in p.read_text(encoding="utf-8").splitlines()
                    if line.strip() and not line.lstrip().startswith("#")]
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="difuzzi",
        description="Compare a reference program A with a candidate B by coverage-guided differential fuzzing.")
    ap.add_argument("a", help="reference program A (.py or .java)")
    ap.add_argument("b", help="candidate program B, or a folder: then every file in it with A's extension is a "
                              "candidate, all fuzzed with the same input generator")
    ap.add_argument("--examples", nargs="+", metavar="FILE",
                    help="example inputs. Function level: a file with one argument tuple per line, "
                         "e.g. ([3, 1, 2],). File level: files (or a directory of .txt files), "
                         "each holding one standard input")
    ap.add_argument("--description", metavar="TEXT_OR_FILE",
                    help="natural-language description of A: text, or a file containing it")
    ap.add_argument("--llm", metavar="MODEL",
                    help="model that writes the input generator (default: $DIFUZZI_LLM_MODEL or 'Kimi K2.5'); "
                         "a Kimi or Gemini model; the key comes from $DIFUZZI_LLM_API_KEY")
    ap.add_argument("--level", choices=["function", "file"], default="function",
                    help="compare a function's return values (default) or a whole program's standard output")
    ap.add_argument("--early-stop", action="store_true",
                    help="stop at the first input on which A and B differ and report it as a counterexample "
                         "(when only the equivalent / not-equivalent decision is needed; the similarity score "
                         "is then not computed)")
    ap.add_argument("--mode", choices=["similarity", "equivalence"], default="similarity",
                    help=argparse.SUPPRESS)   # older spelling: --mode equivalence is --early-stop
    ap.add_argument("--entry", help="function to compare in A (and in B, unless --entry-b); default: first function")
    ap.add_argument("--entry-b", help="function to compare in B, if its name differs")
    ap.add_argument("--max-cases", type=int, default=1000, help="distinct inputs to test (default 1000)")
    ap.add_argument("--time", type=float, default=60, help="time limit in seconds (default 60)")
    ap.add_argument("--call-timeout", type=float, default=1.0, help="time limit per call of A or B (default 1 s)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--no-topup", action="store_true",
                    help="only coverage-guided inputs: stop when coverage stops growing instead of topping up "
                         "with random inputs")
    ap.add_argument("-o", "--out", default="difuzzi-out", help="output directory (default ./difuzzi-out)")
    ap.add_argument("--binding", help=argparse.SUPPRESS)   # a ready-made input generator (e.g. a shipped one)
    args = ap.parse_args(argv)
    if args.early_stop:
        args.mode = "equivalence"

    if args.llm:
        os.environ["DIFUZZI_LLM_MODEL"] = args.llm
    try:
        examples = load_examples(args.examples, args.level)
        if not examples:
            raise pipeline.PipelineError("at least one example input is required (--examples)")
        candidates = _candidates(args.a, args.b)

        def config(b_path: str, out_dir: str) -> pipeline.Config:
            return pipeline.Config(
                a_path=args.a, b_path=b_path, examples=examples, level=args.level, mode=args.mode,
                entry_a=args.entry, entry_b=args.entry_b or args.entry,
                description=_text_or_file(args.description) if args.description else None,
                binding_path=args.binding, max_cases=args.max_cases, time_budget=args.time,
                call_timeout=args.call_timeout, seed=args.seed, topup=not args.no_topup, out_dir=out_dir)

        if not Path(args.b).is_dir():
            res = pipeline.run(config(args.b, args.out), log=lambda m: print(m, file=sys.stderr))
        else:
            return _run_many(args, candidates, config)
    except (pipeline.PipelineError, llm.LLMError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(report.terminal_summary(res))
    print(f"Report:           {Path(args.out) / 'report.html'}")
    if res.get("status") != "done":
        return 1
    if res["mode"] == "equivalence" and res["verdict"] == "not_equivalent":
        return 3
    return 0


def _candidates(a: str, b: str) -> list:
    """The candidate files: B itself, or the files in folder B with A's extension (sorted)."""
    p = Path(b)
    if not p.is_dir():
        return [str(p)]
    ext = Path(a).suffix.lower()
    found = sorted(str(q) for q in p.iterdir() if q.is_file() and q.suffix.lower() == ext
                   and q.resolve() != Path(a).resolve())
    if not found:
        raise pipeline.PipelineError(f"no {ext} files in folder {b}")
    return found


def _run_many(args, candidates: list, config) -> int:
    """Every candidate against A with one input generator (written and checked once, then reused);
    one report per candidate in OUT/<candidate>/, and a ranked summary in OUT/summary.html."""
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    results, links = [], {}
    for i, b in enumerate(candidates, 1):
        name = Path(b).name
        print(f"[{i}/{len(candidates)}] {name}", file=sys.stderr)
        sub = out / Path(b).stem
        try:
            res = pipeline.run(config(b, str(sub)), log=lambda m: print(f"  {m}", file=sys.stderr))
        except llm.LLMError:
            raise              # the LLM is shared: if it fails, no candidate can be run
        except pipeline.PipelineError as e:
            if "input generator" in str(e):
                raise          # the generator is shared: if it cannot be built, no candidate can be run
            res = {"status": "error", "error": str(e)}
        except Exception as e:  # one candidate's failure does not stop the others
            res = {"status": "error", "error": f"{type(e).__name__}: {e}"}
        results.append((name, res))
        links[name] = f"{Path(b).stem}/report.html" if (sub / "report.html").exists() else None
    (out / "summary.html").write_text(report.render_summary_html(args.a, results, links, args.mode), encoding="utf-8")
    (out / "summary.json").write_text(json.dumps(report.summary_rows(results), indent=1), encoding="utf-8")
    print(report.summary_terminal(results, args.mode))
    print(f"Summary:          {out / 'summary.html'}")
    if any(r.get("status") != "done" for _, r in results):
        return 1
    if args.mode == "equivalence" and any(r.get("verdict") == "not_equivalent" for _, r in results):
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
