"""
Report Generator: Exports structured JSON and beautiful standalone HTML forensic reports.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Dict, Any
from jinja2 import Environment, FileSystemLoader

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


class ReportGenerator:
    """Generates forensic reports in HTML and JSON formats."""

    def __init__(self):
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=True
        )

    def build_report_data(
        self,
        parsed_email: Dict[str, Any],
        intel_results: Dict[str, Any],
        scoring_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Combines parser, intel, and scoring into a single unified forensic report structure."""
        # Convert raw headers to readable formatted string
        headers = parsed_email.get("raw_headers", {})
        header_lines = []
        for k, v in headers.items():
            if isinstance(v, list):
                for sub_v in v:
                    header_lines.append(f"{k}: {sub_v}")
            else:
                header_lines.append(f"{k}: {v}")

        return {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "metadata": parsed_email.get("metadata", {}),
            "sender_analysis": parsed_email.get("sender_analysis", {}),
            "authentication": parsed_email.get("authentication", {}),
            "received_chain": parsed_email.get("received_chain", {}),
            "body_analysis": parsed_email.get("body_analysis", {}),
            "urls": parsed_email.get("urls", []),
            "attachments": parsed_email.get("attachments", []),
            "threat_intel": intel_results,
            "scoring": scoring_results,
            "raw_headers_str": "\n".join(header_lines)
        }

    def export_html(self, report_data: Dict[str, Any], output_path: str) -> str:
        """Renders standalone HTML forensic report to output_path."""
        template = self.jinja_env.get_template("report_template.html")
        html_out = template.render(**report_data)
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(html_out)
        return str(out_file.resolve())

    def export_json(self, report_data: Dict[str, Any], output_path: str) -> str:
        """Exports report structure as JSON."""
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        return str(out_file.resolve())
