"""
Terminal Report View: Renders forensic analysis into high-impact colorized console outputs using rich.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from typing import Dict, Any


class TerminalReportViewer:
    """Renders formatted forensic analysis into terminal using rich."""

    def __init__(self):
        self.console = Console()

    def render(self, report_data: Dict[str, Any]):
        """Prints full formatted forensic report."""
        meta = report_data.get("metadata", {})
        sender = report_data.get("sender_analysis", {})
        auth = report_data.get("authentication", {})
        score_info = report_data.get("scoring", {})
        intel = report_data.get("threat_intel", {})
        urls = report_data.get("urls", [])
        atts = report_data.get("attachments", [])
        rules = score_info.get("triggered_rules", [])

        # 1. Main Header Banner
        score = score_info.get("risk_score", 0)
        verdict = score_info.get("verdict", "UNKNOWN")
        color_map = {
            "MALICIOUS": "bold red",
            "HIGH RISK": "bold dark_orange",
            "SUSPICIOUS": "bold yellow",
            "BENIGN": "bold green"
        }
        style_color = color_map.get(verdict, "bold white")

        banner_text = Text()
        banner_text.append(f"\n  PHISHLENS FORENSIC VERDICT: {verdict}\n", style=style_color)
        banner_text.append(f"  Risk Score: {score}/100  |  Severity: {score_info.get('risk_level')}\n", style="bold")
        banner_text.append(f"  Target: {meta.get('source_filename')}  |  Subject: {meta.get('subject')}\n", style="italic")

        self.console.print(Panel(banner_text, border_style=style_color.split()[-1], title="[bold]SECURITY ASSESSMENT[/bold]"))

        # 2. Executive Recommendation
        rec = score_info.get("recommendation", "")
        self.console.print(Panel(f"[bold]Action Recommendation:[/bold] {rec}", style="italic cyan", border_style="cyan"))

        # 3. Email Metadata & Sender Analysis
        meta_table = Table(title="[bold cyan]Email & Sender Forensics[/bold cyan]", show_header=True, header_style="bold magenta")
        meta_table.add_column("Property", style="bold", width=22)
        meta_table.add_column("Details", style="white")

        meta_table.add_row("Subject", str(meta.get("subject")))
        meta_table.add_row("Date", str(meta.get("date")))
        meta_table.add_row("Envelope From", str(sender.get("from_raw")))
        meta_table.add_row("Sender Domain", str(sender.get("from_domain")))
        meta_table.add_row("Recipient To", str(sender.get("to_raw")))
        meta_table.add_row("Originating IP", str(sender.get("originating_ip") or "Not detected in hops"))

        if sender.get("reply_to_mismatch"):
            meta_table.add_row("Reply-To Mismatch", f"[bold red]ALERT: Replies route to {sender.get('reply_to_addr')}[/bold red]")
        if sender.get("display_name_spoof"):
            meta_table.add_row("Display Name Spoof", f"[bold red]{sender.get('spoof_indicator')}[/bold red]")

        self.console.print(meta_table)

        # 4. Authentication Posture (SPF, DKIM, DMARC)
        auth_table = Table(title="[bold cyan]Email Authentication (Anti-Spoofing)[/bold cyan]", show_header=True, header_style="bold magenta")
        auth_table.add_column("Protocol", style="bold", width=12)
        auth_table.add_column("Verdict", width=14)
        auth_table.add_column("Details", style="italic")

        spf = auth.get("spf", {})
        dkim = auth.get("dkim", {})
        dmarc = auth.get("dmarc", {})

        def _fmt_verdict(v):
            if v == "pass":
                return "[bold green]PASS[/bold green]"
            elif v in ("fail", "softfail", "reject", "quarantine"):
                return f"[bold red]{v.upper()}[/bold red]"
            return f"[yellow]{v.upper()}[/yellow]"

        auth_table.add_row("SPF", _fmt_verdict(spf.get("verdict", "none")), str(spf.get("details", "")))
        auth_table.add_row("DKIM", _fmt_verdict(dkim.get("verdict", "none")), str(dkim.get("details", "")))
        auth_table.add_row("DMARC", _fmt_verdict(dmarc.get("verdict", "none")), str(dmarc.get("details", "")))

        self.console.print(auth_table)

        # 5. Triggered Forensic Rules
        if rules:
            rule_table = Table(title=f"[bold red]Triggered Forensic Indicators ({len(rules)})[/bold red]", show_header=True, header_style="bold red")
            rule_table.add_column("ID", width=14)
            rule_table.add_column("Severity", width=10)
            rule_table.add_column("Indicator", style="bold", width=30)
            rule_table.add_column("Forensic Evidence", style="white")

            for r in rules:
                sev_color = "red" if r["severity"] == "CRITICAL" else ("dark_orange" if r["severity"] == "HIGH" else "yellow")
                rule_table.add_row(
                    r["rule_id"],
                    f"[{sev_color}]{r['severity']}[/{sev_color}]",
                    r["name"],
                    r.get("detail", r["description"])
                )
            self.console.print(rule_table)

        # 6. Extracted URLs & Defanging
        if urls:
            url_table = Table(title=f"[bold cyan]Extracted URLs & Hyperlinks ({len(urls)})[/bold cyan]", show_header=True, header_style="bold magenta")
            url_table.add_column("Defanged URL", style="white", width=42)
            url_table.add_column("Domain / TLD", width=20)
            url_table.add_column("Phishing Indicators", style="italic")

            for u in urls[:8]:
                inds = "; ".join(u.get("indicators", [])) or "[green]Clean structure[/green]"
                if u.get("text_mismatch"):
                    inds = f"[bold red]MISMATCH: {u.get('mismatch_detail')}[/bold red]"
                url_table.add_row(
                    u.get("defanged_url", u.get("url"))[:50],
                    f"{u.get('domain')} (.{u.get('tld')})",
                    inds
                )
            self.console.print(url_table)

        # 7. Attachment Hashes & Verdicts
        if atts:
            att_table = Table(title=f"[bold cyan]Attachment Artifacts & Hash Forensics ({len(atts)})[/bold cyan]", show_header=True, header_style="bold magenta")
            att_table.add_column("Filename", style="bold", width=22)
            att_table.add_column("Size", width=10)
            att_table.add_column("SHA-256 Hash", style="cyan", width=36)
            att_table.add_column("Risk Indicators", style="italic")

            for a in atts:
                inds = "; ".join(a.get("indicators", [])) or "[green]Normal document extension[/green]"
                att_table.add_row(
                    a.get("filename"),
                    f"{a.get('size_kb')} KB",
                    a.get("sha256")[:32] + "...",
                    inds
                )
            self.console.print(att_table)

        # 8. Threat Intelligence Summary
        intel_summary = Table(title="[bold cyan]Threat Intelligence Cross-Reference[/bold cyan]", show_header=True, header_style="bold magenta")
        intel_summary.add_column("Feed / Service", style="bold", width=18)
        intel_summary.add_column("Status", width=14)
        intel_summary.add_column("Intel Findings", style="white")

        # Sender IP
        ip_res = intel.get("sender_ip_intel")
        if ip_res:
            stat = "[red]MALICIOUS[/red]" if ip_res.get("is_malicious") else "[green]CLEAN[/green]"
            intel_summary.add_row("AbuseIPDB (IP)", stat, ip_res.get("details", ""))

        # Sender Domain Age
        age_res = intel.get("sender_domain_age")
        if age_res:
            stat = "[red]SUSPICIOUS[/red]" if age_res.get("is_malicious") else "[green]CLEAN[/green]"
            intel_summary.add_row("RDAP / WHOIS", stat, age_res.get("details", ""))

        # URL Intel
        for u in intel.get("url_intel", [])[:3]:
            stat = "[red]MALICIOUS[/red]" if u.get("is_malicious") else "[green]CLEAN[/green]"
            intel_summary.add_row("VirusTotal / URLhaus", stat, f"{u.get('url')[:35]}... -> {u.get('summary_details')}")

        self.console.print(intel_summary)
        self.console.print("\n")
