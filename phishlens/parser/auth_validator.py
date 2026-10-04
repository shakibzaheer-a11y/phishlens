"""
Authentication Validator: Parses and evaluates SPF, DKIM, and DMARC results from email headers.
"""

import re
from typing import Dict, Any, Optional


class AuthValidator:
    """Extracts and normalizes email authentication indicators (SPF, DKIM, DMARC)."""

    @staticmethod
    def parse_auth_headers(headers: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parses Authentication-Results, Received-SPF, and DKIM-Signature headers.
        Returns a normalized dict of verdicts and details.
        """
        auth_results_raw = headers.get("Authentication-Results", "")
        received_spf_raw = headers.get("Received-SPF", "")
        arc_auth_results_raw = headers.get("Arc-Authentication-Results", "")

        # Join if multiple headers exist as lists
        if isinstance(auth_results_raw, list):
            auth_results_raw = " ; ".join(auth_results_raw)
        if isinstance(received_spf_raw, list):
            received_spf_raw = " ; ".join(received_spf_raw)
        if isinstance(arc_auth_results_raw, list):
            arc_auth_results_raw = " ; ".join(arc_auth_results_raw)

        combined_auth = f"{auth_results_raw} {arc_auth_results_raw}"

        spf_result = AuthValidator._extract_spf(combined_auth, received_spf_raw)
        dkim_result = AuthValidator._extract_dkim(combined_auth, headers.get("DKIM-Signature", ""))
        dmarc_result = AuthValidator._extract_dmarc(combined_auth)

        # Composite evaluation
        all_passed = (spf_result["verdict"] == "pass") and (dkim_result["verdict"] == "pass")
        any_failed = (spf_result["verdict"] in ("fail", "softfail")) or (dkim_result["verdict"] == "fail") or (dmarc_result["verdict"] == "fail")

        return {
            "spf": spf_result,
            "dkim": dkim_result,
            "dmarc": dmarc_result,
            "all_passed": all_passed,
            "any_failed": any_failed,
            "summary": {
                "spf_verdict": spf_result["verdict"],
                "dkim_verdict": dkim_result["verdict"],
                "dmarc_verdict": dmarc_result["verdict"],
            }
        }

    @staticmethod
    def _extract_spf(auth_str: str, received_spf: str) -> Dict[str, Any]:
        result = {"verdict": "none", "details": "", "ip": None, "domain": None}

        # Check Received-SPF first (often more direct)
        if received_spf:
            match = re.match(r"^\s*([a-zA-Z]+)", received_spf)
            if match:
                result["verdict"] = match.group(1).lower()
                result["details"] = received_spf[:200]
                ip_match = re.search(r"client-ip=([0-9a-fA-F:.]+)", received_spf)
                if ip_match:
                    result["ip"] = ip_match.group(1)
                dom_match = re.search(r"envelope-from=([^; ]+)", received_spf)
                if dom_match:
                    result["domain"] = dom_match.group(1)
                return result

        # Check Authentication-Results: spf=pass (details...)
        match = re.search(r"\bspf=([a-zA-Z]+)(?:\s*\(([^)]*)\))?", auth_str, re.IGNORECASE)
        if match:
            result["verdict"] = match.group(1).lower()
            result["details"] = match.group(2) if match.group(2) else ""
            ip_match = re.search(r"client-ip=([0-9a-fA-F:.]+)", auth_str)
            if ip_match:
                result["ip"] = ip_match.group(1)
            return result

        return result

    @staticmethod
    def _extract_dkim(auth_str: str, dkim_sig: Any) -> Dict[str, Any]:
        result = {"verdict": "none", "details": "", "signature_present": bool(dkim_sig), "domain": None}

        match = re.search(r"\bdkim=([a-zA-Z]+)(?:\s*\(([^)]*)\))?", auth_str, re.IGNORECASE)
        if match:
            result["verdict"] = match.group(1).lower()
            result["details"] = match.group(2) if match.group(2) else ""
            header_d = re.search(r"header\.d=([a-zA-Z0-9.\-]+)", auth_str)
            if header_d:
                result["domain"] = header_d.group(1)
            return result

        if dkim_sig:
            result["verdict"] = "present_unverified"
            if isinstance(dkim_sig, str):
                d_match = re.search(r"\bd=([a-zA-Z0-9.\-]+)", dkim_sig)
                if d_match:
                    result["domain"] = d_match.group(1)
            return result

        return result

    @staticmethod
    def _extract_dmarc(auth_str: str) -> Dict[str, Any]:
        result = {"verdict": "none", "details": "", "action": None}

        match = re.search(r"\bdmarc=([a-zA-Z]+)(?:\s*\(action=([a-zA-Z]+)[^)]*\)|\s*\(([^)]*)\))?", auth_str, re.IGNORECASE)
        if match:
            result["verdict"] = match.group(1).lower()
            action = match.group(2) or match.group(3)
            result["details"] = action if action else ""
            action_match = re.search(r"action=([a-zA-Z]+)", auth_str, re.IGNORECASE)
            if action_match:
                result["action"] = action_match.group(1).lower()
            return result

        return result
