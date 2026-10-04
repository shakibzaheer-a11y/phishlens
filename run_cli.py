#!/usr/bin/env python3
"""
PhishLens CLI Entry Point: Analyzes an .eml file and outputs a forensic security assessment.
"""

import argparse
import sys
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from phishlens.parser.email_parser import EmailParser
from phishlens.intel.intel_manager import IntelManager
from phishlens.scoring.engine import ScoringEngine
from phishlens.reports.generator import ReportGenerator
from phishlens.reports.terminal_view import TerminalReportViewer


def main():
    parser = argparse.ArgumentParser(
        description="PhishLens: Email Forensics & Threat Intel Pipeline",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("email_path", help="Path to .eml file to analyze")
    parser.add_argument("--html", help="Path to export HTML forensic report (optional)", default=None)
    parser.add_argument("--json", help="Path to export JSON report (optional)", default=None)
    parser.add_argument("--offline", action="store_true", help="Force offline mock mode (no network requests)")

    args = parser.parse_args()

    email_file = Path(args.email_path)
    if not email_file.is_file():
        print(f"Error: Email file '{args.email_path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    print(f"\n[*] PhishLens Forensics Pipeline v1.0")
    print(f"[*] Analyzing target: {email_file.name} ...")
    start_time = time.time()

    # Step 1: Backend Parsing
    parsed = EmailParser.parse_file(str(email_file))

    # Step 2: Threat Intelligence Enrichment
    intel_mgr = IntelManager(offline_mode=args.offline)
    intel = intel_mgr.enrich(parsed)

    # Step 3: Scoring & Classification
    scoring = ScoringEngine().evaluate(parsed, intel)

    # Step 4: Report Generation
    reporter = ReportGenerator()
    report_data = reporter.build_report_data(parsed, intel, scoring)
    elapsed = time.time() - start_time
    report_data["execution_time_seconds"] = round(elapsed, 2)

    # Terminal rendering
    viewer = TerminalReportViewer()
    viewer.render(report_data)

    print(f"[*] Forensics analysis completed in {elapsed:.2f} seconds.")

    # Optional Exports
    if args.html:
        out_html = reporter.export_html(report_data, args.html)
        print(f"[+] HTML Forensic Report saved: {out_html}")

    if args.json:
        out_json = reporter.export_json(report_data, args.json)
        print(f"[+] JSON Forensic Artifact saved: {out_json}")


if __name__ == "__main__":
    main()
