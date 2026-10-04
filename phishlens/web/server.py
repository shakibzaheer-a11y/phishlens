"""
Lightweight Web Server for PhishLens Interactive SOC Dashboard.
Built using Python standard library http.server for maximum reliability and zero external server dependencies.
"""

from http.server import HTTPServer, SimpleHTTPRequestHandler
import json
import urllib.parse
from pathlib import Path
import io
import time

from phishlens.parser.email_parser import EmailParser
from phishlens.intel.intel_manager import IntelManager
from phishlens.scoring.engine import ScoringEngine
from phishlens.scoring.evaluator import DatasetEvaluator
from phishlens.reports.generator import ReportGenerator

WEB_DIR = Path(__file__).resolve().parent
STATIC_DIR = WEB_DIR / "static"
PROJECT_ROOT = WEB_DIR.parent.parent
SAMPLES_DIR = PROJECT_ROOT / "samples"


class PhishLensRequestHandler(SimpleHTTPRequestHandler):
    """Handles REST API requests and serves static web assets."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query = urllib.parse.parse_qs(parsed_url.query)

        if path == "/api/samples":
            self._handle_get_samples()
        elif path == "/api/evaluate":
            self._handle_get_evaluate()
        elif path == "/api/sample-analyze":
            sample_name = query.get("name", [""])[0]
            self._handle_sample_analyze(sample_name)
        else:
            # Default static file handler
            super().do_GET()

    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == "/api/analyze":
            self._handle_post_analyze()
        else:
            self.send_error(404, "Endpoint not found")

    def _send_json(self, data: dict, status_code: int = 200):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def _handle_get_samples(self):
        samples = []
        for category in ["phishing", "legitimate"]:
            cat_dir = SAMPLES_DIR / category
            if cat_dir.is_dir():
                for f in cat_dir.glob("*.eml"):
                    samples.append({
                        "name": f.name,
                        "category": category,
                        "path": str(f)
                    })
        self._send_json({"samples": samples})

    def _handle_sample_analyze(self, sample_name: str):
        target_path = None
        for category in ["phishing", "legitimate"]:
            candidate = SAMPLES_DIR / category / sample_name
            if candidate.is_file():
                target_path = candidate
                break

        if not target_path:
            self._send_json({"error": "Sample file not found"}, status_code=404)
            return

        start_time = time.time()
        parsed = EmailParser.parse_file(str(target_path))
        intel_mgr = IntelManager(offline_mode=False)
        intel = intel_mgr.enrich(parsed)
        scoring = ScoringEngine().evaluate(parsed, intel)
        generator = ReportGenerator()
        report = generator.build_report_data(parsed, intel, scoring)
        report["execution_time_seconds"] = round(time.time() - start_time, 2)

        self._send_json(report)

    def _handle_post_analyze(self):
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length)

        # Handle multipart/form-data or raw bytes
        content_type = self.headers.get("Content-Type", "")
        email_bytes = b""

        if "multipart/form-data" in content_type:
            boundary = content_type.split("boundary=")[-1].strip()
            # Simple boundary splitting for uploaded file
            parts = raw_body.split(f"--{boundary}".encode())
            for part in parts:
                if b'filename="' in part:
                    header_and_body = part.split(b"\r\n\r\n", 1)
                    if len(header_and_body) == 2:
                        email_bytes = header_and_body[1].rstrip(b"\r\n--")
                        break
        else:
            email_bytes = raw_body

        if not email_bytes:
            self._send_json({"error": "No email content received"}, status_code=400)
            return

        try:
            start_time = time.time()
            parsed = EmailParser.parse_raw(email_bytes, source_filename="uploaded_email.eml")
            intel_mgr = IntelManager(offline_mode=False)
            intel = intel_mgr.enrich(parsed)
            scoring = ScoringEngine().evaluate(parsed, intel)
            generator = ReportGenerator()
            report = generator.build_report_data(parsed, intel, scoring)
            report["execution_time_seconds"] = round(time.time() - start_time, 2)
            self._send_json(report)
        except Exception as e:
            self._send_json({"error": f"Failed to analyze email: {str(e)}"}, status_code=500)

    def _handle_get_evaluate(self):
        evaluator = DatasetEvaluator(offline_mode=True)
        results = evaluator.evaluate_directories(
            phishing_dir=str(SAMPLES_DIR / "phishing"),
            benign_dir=str(SAMPLES_DIR / "legitimate")
        )
        self._send_json(results)


def start_server(port: int = 8080):
    server_address = ("127.0.0.1", port)
    httpd = HTTPServer(server_address, PhishLensRequestHandler)
    print(f"PhishLens Web Dashboard running at http://127.0.0.1:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        httpd.server_close()


if __name__ == "__main__":
    start_server()
