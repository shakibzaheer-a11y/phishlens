"""
URL Extractor: Extracts, defangs, normalizes, and inspects URLs from email body content.
Detects display text vs href mismatches, IP hosts, suspicious TLDs, and IDN homoglyphs.
"""

import re
import urllib.parse
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from config import SUSPICIOUS_TLDS, HTTP_TIMEOUT_SECONDS, MAX_REDIRECT_HOPS, OFFLINE_MODE

# Regex for plain text URL detection
URL_REGEX = re.compile(
    r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))",
    re.IGNORECASE
)

# Common URL shorteners
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "is.gd", "cutt.ly", "rebrand.ly", "tiny.cc", "s.id", "rotf.lol"
}


def defang_url(url: str) -> str:
    """Defangs a URL to make it safe for display and reporting."""
    if not url:
        return ""
    defanged = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    defanged = defanged.replace(".", "[.]").replace("://", "[://]")
    return defanged


def refang_url(defanged_url: str) -> str:
    """Reverts a defanged URL back to standard format for analysis."""
    if not defanged_url:
        return ""
    reverted = defanged_url.replace("hxxps[://]", "https://").replace("hxxp[://]", "http://")
    reverted = reverted.replace("[.]", ".").replace("[://]", "://")
    return reverted


class URLExtractor:
    """Extracts, categorizes, and assesses URLs within an email body."""

    @staticmethod
    def extract_from_html_and_text(html_content: str, text_content: str) -> List[Dict[str, Any]]:
        """Extracts and analyzes all URLs from both HTML and plaintext email parts."""
        found_urls: Dict[str, Dict[str, Any]] = {}

        # 1. Parse HTML anchors & media
        if html_content:
            try:
                soup = BeautifulSoup(html_content, "html.parser")
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    display_text = a.get_text(strip=True)
                    if href and not href.startswith(("mailto:", "tel:", "javascript:", "#")):
                        meta = URLExtractor._analyze_url(href, display_text=display_text, source="html_anchor")
                        found_urls[meta["url"]] = meta

                for img in soup.find_all("img", src=True):
                    src = img["src"].strip()
                    if src.startswith("http"):
                        meta = URLExtractor._analyze_url(src, display_text="[Image Source]", source="html_img")
                        if meta["url"] not in found_urls:
                            found_urls[meta["url"]] = meta

                for form in soup.find_all("form", action=True):
                    action = form["action"].strip()
                    if action.startswith("http"):
                        meta = URLExtractor._analyze_url(action, display_text="[Form Action]", source="html_form")
                        found_urls[meta["url"]] = meta
            except Exception:
                pass

        # 2. Parse Plaintext URLs
        if text_content:
            for match in URL_REGEX.finditer(text_content):
                raw = match.group(0).strip()
                if not raw.startswith(("http://", "https://")):
                    raw = "http://" + raw
                if raw not in found_urls:
                    found_urls[raw] = URLExtractor._analyze_url(raw, display_text=raw, source="plain_text")

        return list(found_urls.values())

    @staticmethod
    def _analyze_url(url: str, display_text: str = "", source: str = "text") -> Dict[str, Any]:
        """Analyzes a single URL for phishing indicators."""
        parsed = urllib.parse.urlparse(url)
        hostname = (parsed.hostname or "").lower()
        tld = hostname.split(".")[-1] if "." in hostname else ""

        is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname))
        is_suspicious_tld = tld in SUSPICIOUS_TLDS
        is_punycode = hostname.startswith("xn--") or ".xn--" in hostname
        is_shortener = hostname in SHORTENER_DOMAINS

        # Check for link text vs href mismatch
        text_mismatch = False
        mismatch_detail = ""
        if display_text and ("http" in display_text or "." in display_text):
            display_cleaned = display_text.strip()
            # If the user sees a legitimate URL in text, but href goes somewhere else:
            match = URL_REGEX.search(display_cleaned)
            if match:
                extracted_display_url = match.group(0)
                display_parsed = urllib.parse.urlparse(
                    extracted_display_url if "://" in extracted_display_url else "http://" + extracted_display_url
                )
                disp_host = (display_parsed.hostname or "").lower()
                if disp_host and hostname and disp_host != hostname:
                    text_mismatch = True
                    mismatch_detail = f"Anchor text shows '{disp_host}' but link points to '{hostname}'"

        # Check for lookalike / deceptive patterns in path or subdomain
        login_indicators = [kw for kw in ("login", "signin", "verify", "secure", "update", "banking", "account", "recover", "wallet") if kw in url.lower()]

        indicators = []
        if is_ip:
            indicators.append("Host is a raw IP address")
        if is_suspicious_tld:
            indicators.append(f"Suspicious high-risk TLD (.{tld})")
        if is_punycode:
            indicators.append("Internationalized/Punycode domain (possible IDN homoglyph spoof)")
        if is_shortener:
            indicators.append("URL Shortener used (hiding true destination)")
        if text_mismatch:
            indicators.append(f"Phishing Link Mismatch: {mismatch_detail}")
        if len(login_indicators) >= 2:
            indicators.append(f"Multiple credential targeting keywords: {', '.join(login_indicators)}")

        return {
            "url": url,
            "defanged_url": defang_url(url),
            "display_text": display_text,
            "source": source,
            "hostname": hostname,
            "domain": ".".join(hostname.split(".")[-2:]) if "." in hostname else hostname,
            "tld": tld,
            "path": parsed.path,
            "is_ip": is_ip,
            "is_suspicious_tld": is_suspicious_tld,
            "is_punycode": is_punycode,
            "is_shortener": is_shortener,
            "text_mismatch": text_mismatch,
            "mismatch_detail": mismatch_detail,
            "login_indicators": login_indicators,
            "indicators": indicators,
            "risk_score": (
                (40 if text_mismatch else 0) +
                (30 if is_ip else 0) +
                (25 if is_punycode else 0) +
                (20 if is_suspicious_tld else 0) +
                (15 if is_shortener else 0) +
                (min(len(login_indicators) * 10, 20))
            )
        }

    @staticmethod
    def trace_redirects(url: str, max_hops: int = MAX_REDIRECT_HOPS) -> Dict[str, Any]:
        """
        Safely traces redirect hops without executing scripts or downloading payloads.
        Returns the chain of hops and final landing URL.
        """
        if OFFLINE_MODE:
            return {
                "initial_url": url,
                "chain": [url],
                "final_url": url,
                "hop_count": 0,
                "status": "offline_mode"
            }

        chain = [url]
        current_url = url
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        try:
            for _ in range(max_hops):
                res = requests.head(
                    current_url,
                    headers=headers,
                    allow_redirects=False,
                    timeout=HTTP_TIMEOUT_SECONDS,
                    verify=False
                )
                if res.is_redirect and "Location" in res.headers:
                    next_url = urllib.parse.urljoin(current_url, res.headers["Location"])
                    chain.append(next_url)
                    current_url = next_url
                else:
                    break
        except Exception as e:
            return {
                "initial_url": url,
                "chain": chain,
                "final_url": chain[-1],
                "hop_count": len(chain) - 1,
                "error": str(e)
            }

        return {
            "initial_url": url,
            "chain": chain,
            "final_url": chain[-1],
            "hop_count": len(chain) - 1,
            "is_redirected": len(chain) > 1
        }
