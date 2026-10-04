"""
Attachment Extractor: Extracts email attachments, computes cryptographic hashes (MD5, SHA1, SHA256),
and flags high-risk extensions, double extensions, and macro-enabled documents.
"""

import hashlib
import os
import re
from typing import List, Dict, Any, Optional
from email.message import Message

from config import SUSPICIOUS_EXTENSIONS, MACRO_EXTENSIONS, ARCHIVE_EXTENSIONS


class AttachmentExtractor:
    """Extracts metadata and cryptographic hashes from email attachments."""

    @staticmethod
    def extract_attachments(msg: Message) -> List[Dict[str, Any]]:
        """Extracts and evaluates all attachments in the email."""
        attachments: List[Dict[str, Any]] = []

        for part in msg.walk():
            # Check content disposition
            content_disposition = str(part.get("Content-Disposition", ""))
            content_type = part.get_content_type()
            filename = part.get_filename()

            # If filename or attachment disposition exists
            if filename or "attachment" in content_disposition.lower() or (
                content_type != "text/plain" and content_type != "text/html" and
                content_type != "multipart/alternative" and content_type != "multipart/mixed" and
                content_type != "multipart/related" and not content_disposition.startswith("inline")
            ):
                payload = part.get_payload(decode=True)
                if not payload:
                    continue

                safe_name = filename or f"unnamed_attachment_{len(attachments) + 1}.bin"
                meta = AttachmentExtractor._analyze_attachment(safe_name, payload, content_type)
                attachments.append(meta)

        return attachments

    @staticmethod
    def _analyze_attachment(filename: str, payload: bytes, declared_type: str) -> Dict[str, Any]:
        """Calculates hashes and risk indicators for a single attachment."""
        size_bytes = len(payload)
        md5 = hashlib.md5(payload).hexdigest()
        sha1 = hashlib.sha1(payload).hexdigest()
        sha256 = hashlib.sha256(payload).hexdigest()

        # Extension checks
        _, ext = os.path.splitext(filename.lower())

        # Double extension check (e.g. document.pdf.exe or invoice.docx.vbs)
        double_ext_match = re.search(r"\.([a-zA-Z0-9]+)\.([a-zA-Z0-9]+)$", filename.lower())
        has_double_ext = False
        disguised_type = ""
        if double_ext_match:
            first_ext = f".{double_ext_match.group(1)}"
            second_ext = f".{double_ext_match.group(2)}"
            if second_ext in SUSPICIOUS_EXTENSIONS:
                has_double_ext = True
                disguised_type = f"Disguised as '{first_ext}', actual executable '{second_ext}'"

        is_suspicious_ext = ext in SUSPICIOUS_EXTENSIONS
        is_macro = ext in MACRO_EXTENSIONS
        is_archive = ext in ARCHIVE_EXTENSIONS

        indicators = []
        risk_score = 0

        if has_double_ext:
            indicators.append(f"Double extension attack detected: {disguised_type}")
            risk_score += 50
        elif is_suspicious_ext:
            indicators.append(f"Direct executable / script extension detected ({ext})")
            risk_score += 40

        if is_macro:
            indicators.append(f"Macro-enabled Office document ({ext}) — high risk for malicious VBA payload")
            risk_score += 35

        if is_archive:
            indicators.append(f"Compressed archive container ({ext}) — frequently used to evade perimeter scanners")
            risk_score += 15

        # Check for executable magic bytes (MZ for Windows PE)
        magic_mz = payload.startswith(b"MZ")
        if magic_mz and ext not in SUSPICIOUS_EXTENSIONS:
            indicators.append("Magic byte mismatch: File content is a Windows PE executable regardless of extension!")
            risk_score += 55

        return {
            "filename": filename,
            "declared_type": declared_type,
            "size_bytes": size_bytes,
            "size_kb": round(size_bytes / 1024, 2),
            "extension": ext,
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
            "has_double_ext": has_double_ext,
            "is_suspicious_ext": is_suspicious_ext,
            "is_macro": is_macro,
            "is_archive": is_archive,
            "magic_mz": magic_mz,
            "indicators": indicators,
            "risk_score": min(risk_score, 100),
            "threat_verdict": None  # Will be populated by Intel manager
        }
