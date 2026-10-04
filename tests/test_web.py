"""
Unit tests for the Web API endpoints and server handlers.
"""

import threading
import time
import requests
from http.server import HTTPServer
from phishlens.web.server import PhishLensRequestHandler

TEST_PORT = 8999


def test_web_api_endpoints():
    server = HTTPServer(("127.0.0.1", TEST_PORT), PhishLensRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.5)

    base_url = f"http://127.0.0.1:{TEST_PORT}"

    try:
        # 1. Test GET /api/samples
        res = requests.get(f"{base_url}/api/samples", timeout=5)
        assert res.status_code == 200
        samples_data = res.json()
        assert "samples" in samples_data
        assert len(samples_data["samples"]) >= 4

        # 2. Test GET /api/sample-analyze
        res_analyze = requests.get(f"{base_url}/api/sample-analyze?name=m365_credential_harvest.eml", timeout=8)
        assert res_analyze.status_code == 200
        report = res_analyze.json()
        assert report["scoring"]["verdict"] == "MALICIOUS"
        assert report["scoring"]["risk_score"] >= 75
        assert "execution_time_seconds" in report

        # 3. Test GET /api/evaluate
        res_eval = requests.get(f"{base_url}/api/evaluate", timeout=8)
        assert res_eval.status_code == 200
        eval_data = res_eval.json()
        assert "metrics" in eval_data
        assert eval_data["metrics"]["accuracy"] > 0.8
    finally:
        server.shutdown()
        server.server_close()
