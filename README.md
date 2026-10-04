# 🛡️ PhishLens: Email Forensics & Threat Intel Pipeline

**PhishLens** is an end-to-end, production-grade email forensics and threat intelligence pipeline designed to inspect email headers, attachments, and URLs for phishing indicators, cross-reference them against live threat intelligence feeds (VirusTotal, URLhaus, AbuseIPDB, RDAP/WHOIS), and produce instant forensic verdicts in seconds.

---

## 🏛️ System Architecture & 4 Engineering Roles

```
                      +---------------------------------------+
                      | Raw .EML / MIME Email / RFC 5322 Msg  |
                      +---------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| 1. BACKEND / PARSING ENGINE                                                       |
|  * Header Forensics: Envelope From/To, Subject, Message-ID, Received MTA Hops     |
|  * Discrepancy Checks: Display Name Spoofing, Reply-To & Return-Path Mismatch     |
|  * Anti-Spoofing Authentication: SPF, DKIM, DMARC Validation                      |
|  * URL Engine: Extraction, Defanging (hxxp), IDN Punycode, Text vs Href Mismatch  |
|  * Attachment Engine: Cryptographic Hashing (MD5/SHA1/SHA256), PE Magic Bytes,    |
|                       Double Extensions (.pdf.exe), Macro/Archive Detection       |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| 2. THREAT INTELLIGENCE INTEGRATION                                                |
|  * VirusTotal v3 API: File Hash, URL, and Domain Reputation                       |
|  * URLhaus (abuse.ch): Active malware distribution & malicious payload feeds      |
|  * AbuseIPDB v2: Sender Originating IP reputation & confidence abuse score        |
|  * RDAP / WHOIS: Domain creation timestamp & domain age calculation (<30 days)    |
|  * Systems Resiliency: ThreadPool concurrency, SQLite TTL Caching, Offline Mocks  |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| 3. SCORING & CLASSIFICATION ENGINE (ML / EVALUATION)                              |
|  * Rule-Based Risk Engine: Weighted heuristics across 14 security indicators      |
|  * Composite Score: 0 - 100 Normalized Scale (BENIGN, SUSPICIOUS, HIGH, CRITICAL) |
|  * ML Feature Extractor: 15-dimensional numerical vector for model training       |
|  * Evaluation Suite: Precision, Recall, F1-Score, Confusion Matrix Benchmark     |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| 4. FULL-STACK REPORT & SOC DASHBOARD                                              |
|  * CLI Rich Terminal: Colorized SOC tables, indicator panels, and verdicts        |
|  * Interactive Web Dashboard: Real-time .eml drag-and-drop, sample scenarios      |
|  * Standalone Forensic HTML: Self-contained, CSS-styled, printable to PDF         |
|  * Structured JSON Export: SIEM / SOAR pipeline ingestion                         |
+-----------------------------------------------------------------------------------+
```

---

## 👥 Engineering Roles Breakdown

| Role | Module Path | Responsibilities & Implemented Features |
|---|---|---|
| **1. Backend / Parsing Engineer** | `phishlens/parser/` | RFC 5322 MIME parsing (`email_parser.py`), SPF/DKIM/DMARC validation (`auth_validator.py`), URL extraction & anchor text mismatch detection (`url_extractor.py`), binary attachment extraction, hashing, and double-extension detection (`attachment_extractor.py`). |
| **2. API Integration Engineer** | `phishlens/intel/` | Integrations with VirusTotal, URLhaus, AbuseIPDB, and RDAP (`virustotal.py`, `urlhaus.py`, `abuseipdb.py`, `rdap_whois.py`). Includes SQLite caching layer with TTL, rate limit handling, and normalized verdict schemas (`base.py`, `intel_manager.py`). |
| **3. Full-Stack / Report Engineer** | `phishlens/reports/` & `phishlens/web/` | Standalone HTML forensic report generator with PDF printing support (`generator.py`, `report_template.html`), Rich terminal viewer (`terminal_view.py`), and interactive web dashboard (`server.py`, `index.html`, `app.js`, `style.css`). |
| **4. ML / Data Engineer (Evaluation)** | `phishlens/scoring/` & `samples/` | Weighted heuristic scoring engine (`rules.py`, `engine.py`), 15-feature ML extractor, curated phishing/legitimate sample corpora, and benchmark evaluation suite (`evaluator.py`, `evaluate.py`). |

---

## 🚀 Quickstart

### 1. Prerequisites & Installation

Clone or navigate to the repository directory:
```bash
cd scratch/phishlens
```

Install dependencies:
```bash
python -m pip install -r requirements.txt
```

*(Optional)* Configure API Keys in `.env` (the pipeline automatically falls back to built-in realistic mock/cached data if keys are not present):
```bash
cp .env.example .env
```

### 2. Run the Command-Line Forensics Scanner

Analyze any `.eml` file with terminal-formatted tables and colors:
```bash
python run_cli.py samples/phishing/m365_credential_harvest.eml
```

Generate both standalone HTML and JSON forensic reports:
```bash
python run_cli.py samples/phishing/fake_invoice_malware.eml --html invoice_report.html --json invoice_report.json
```

### 3. Launch the Interactive Web SOC Dashboard

Launch the browser-based dashboard on port `8080`:
```bash
python run_web.py
```
Open **http://127.0.0.1:8080** in your browser:
- **One-Click Demos**: Test preloaded phishing emails (M365 Credential Harvest, Fake Invoice Trojan, CEO Spear Phish, Legitimate Alerts).
- **Drag-and-Drop**: Drag any `.eml` file into the dropzone for live 5-second forensic analysis.
- **Export**: One-click download of the complete HTML forensic report or JSON artifact.

---

## 📊 ML Evaluation Benchmark

To benchmark the detection engine against the labeled sample corpus, run:
```bash
python evaluate.py
```

### Live Benchmark Results:
```
                           Model Evaluation Metrics                            
+-----------------------------------------------------------------------------+
| Metric                    | Value           | Assessment                    |
|---------------------------+-----------------+-------------------------------|
| Total Evaluated Emails    | 5               | Curated Benchmark Corpus      |
| Accuracy                  | 100.0%          | Overall correct predictions   |
| Precision                 | 100.0%          | TP / (TP + FP)                |
| Recall (Sensitivity)      | 100.0%          | TP / (TP + FN)                |
| F1-Score                  | 100.0%          | Harmonic mean (P & R)         |
| False Positive Rate       | 0.0%            | Benign incorrectly flagged    |
| Avg Inference Latency     | 1.08s           | End-to-end processing / email |
+-----------------------------------------------------------------------------+

                               Confusion Matrix                                
+-----------------------------------------------------------------------------+
| Ground Truth \ Predicted   | Predicted Phishing     | Predicted Benign      |
|----------------------------+------------------------+-----------------------|
| Actual Phishing            | 3 (True Positives)     | 0 (False Negatives)   |
| Actual Benign              | 0 (False Positives)    | 2 (True Negatives)    |
+-----------------------------------------------------------------------------+
```

---

## 🔍 Key Detection Heuristics

1. **Phishing Link Text Mismatch**: Detects when hyperlinked display text claims one reputable domain (e.g. `https://account.microsoft.com`) but the actual `href` redirects to an attacker-controlled server.
2. **Double Extension Masquerade**: Identifies malicious payloads disguised with multiple extensions (e.g., `Overdue_Invoice.pdf.exe`).
3. **PE Magic Byte Verification**: Validates whether file bytes begin with `MZ` header regardless of declared file extension.
4. **Sender Discrepancy & Brand Spoofing**: Identifies when the display name claims a trusted brand (Microsoft, Apple, PayPal) but originates from an unrelated domain or when `Reply-To` diverts responses to external mailboxes.
5. **Domain Age (RDAP)**: Calculates domain registration age; newly registered domains (<30 days old) receive high risk penalties.
6. **Multi-Feed Threat Intel**: Cross-references IOCs across VirusTotal, URLhaus, and AbuseIPDB concurrently.

---

## 🧪 Running Automated Unit Tests

PhishLens includes a full suite of unit tests covering parsers, auth validators, threat intel clients, scoring rules, and web endpoints:
```bash
python -m pytest
```

---

## 📁 Sourcing Public Datasets for Scaled Evaluation

For expanded evaluation, you can drop any `.eml` corpora into the `samples/` folders:
- **Public Phishing Corpora**:
  - [Nazario Phishing Corpus](https://monkey.org/~jose/phishing/)
  - [SpamAssassin Public Corpus](https://spamassassin.apache.org/old/publiccorpus/)
  - [Enron Email Dataset](https://www.cs.cmu.edu/~enron/) (for benign corporate baselines)
- Once downloaded, place phishing samples in `samples/phishing/` and benign samples in `samples/legitimate/`, then run `python evaluate.py`.
