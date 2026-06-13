"""
src/main.py — Bond CLI.

    python -m src.main --alert alerts/edr_malware_malicious.json
    python -m src.main --alert alerts/edr_malware_benign.json --format md
    python -m src.main --alert alerts/suspicious_login.json --mock   # force mock tools

Note: the reasoning loop always calls the Claude API, so ANTHROPIC_API_KEY must be
set (in .env or the environment) even with --mock (which only forces the *tools*
onto their deterministic mocks).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .agent import investigate
from .report import render_markdown


def main(argv: list[str] | None = None) -> int:
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    parser = argparse.ArgumentParser(prog="bond", description="Bond — AI Security Analyst")
    parser.add_argument("--alert", required=True, help="Path to an alert JSON file")
    parser.add_argument("--format", choices=["both", "json", "md"], default="both",
                        help="Report output format (default: both)")
    parser.add_argument("--out", default="reports", help="Output directory (default: reports/)")
    parser.add_argument("--mock", action="store_true",
                        help="Force investigation tools onto deterministic mocks")
    parser.add_argument("--no-classifier", action="store_true",
                        help="Disable the LLM injection classifier (heuristic only)")
    args = parser.parse_args(argv)

    if args.mock:
        os.environ["BOND_FORCE_MOCK"] = "1"
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("ERROR: ANTHROPIC_API_KEY is not set. Add it to .env — the reasoning loop "
              "needs the Claude API (this is required even with --mock).", file=sys.stderr)
        return 2

    alert_path = Path(args.alert)
    if not alert_path.is_file():
        print(f"ERROR: alert file not found: {alert_path}", file=sys.stderr)
        return 2
    raw = json.loads(alert_path.read_text())

    # Live progress trace (rich if available, else plain print).
    try:
        from rich.console import Console
        from rich.markdown import Markdown
        console = Console()
    except ImportError:
        console = None

    def progress(msg: str) -> None:
        if console:
            console.print(f"  [dim]·[/dim] {msg}")
        else:
            print(f"  · {msg}")

    header = f"Investigating {raw.get('id', alert_path.stem)}"
    if console:
        console.rule(f"[bold]{header}")
    else:
        print(f"=== {header} ===")

    report = investigate(raw, progress=progress,
                         run_injection_classifier=not args.no_classifier)

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    md = render_markdown(report)
    written = []
    if args.format in ("both", "json"):
        p = outdir / f"{report.alert_id}.json"
        p.write_text(report.to_json())
        written.append(str(p))
    if args.format in ("both", "md"):
        p = outdir / f"{report.alert_id}.md"
        p.write_text(md)
        written.append(str(p))

    if console:
        console.print()
        console.print(Markdown(md))
    else:
        print("\n" + md)
    print(f"\nReport(s) written to: {', '.join(written)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
