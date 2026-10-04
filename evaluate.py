#!/usr/bin/env python3
"""
PhishLens Dataset Evaluation Runner: Evaluates detection performance across test corpora.
Prints accuracy, precision, recall, F1, false positive rate, and confusion matrix using rich tables.
"""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from phishlens.scoring.evaluator import DatasetEvaluator
from rich.console import Console
from rich.table import Table
from rich.panel import Panel


def main():
    console = Console()
    console.print("\n[bold cyan]PhishLens ML / Heuristic Detection Benchmark Suite[/bold cyan]")
    console.print("[dim]Evaluating detection engine across phishing and benign email datasets...[/dim]\n")

    project_root = Path(__file__).resolve().parent
    phishing_dir = project_root / "samples" / "phishing"
    benign_dir = project_root / "samples" / "legitimate"

    evaluator = DatasetEvaluator(offline_mode=True)
    results = evaluator.evaluate_directories(str(phishing_dir), str(benign_dir))

    m = results["metrics"]
    cm = results["confusion_matrix"]

    # Metrics Summary Table
    metrics_table = Table(title="[bold green]Model Evaluation Metrics[/bold green]", show_header=True, header_style="bold magenta")
    metrics_table.add_column("Metric", style="bold", width=25)
    metrics_table.add_column("Value", style="cyan", width=15)
    metrics_table.add_column("Assessment", style="white")

    metrics_table.add_row("Total Evaluated Emails", str(m["total_evaluated"]), "Sample Corpus Size")
    metrics_table.add_row("Accuracy", f"{m['accuracy'] * 100:.1f}%", "Overall correct predictions")
    metrics_table.add_row("Precision", f"{m['precision'] * 100:.1f}%", "True Phish / (True Phish + False Alarms)")
    metrics_table.add_row("Recall (Sensitivity)", f"{m['recall'] * 100:.1f}%", "True Phish / Total Actual Phish")
    metrics_table.add_row("F1-Score", f"{m['f1_score'] * 100:.1f}%", "Harmonic mean of precision and recall")
    metrics_table.add_row("False Positive Rate", f"{m['false_positive_rate'] * 100:.1f}%", "Benign incorrectly flagged as phish")
    metrics_table.add_row("Avg Latency", f"{m['avg_seconds_per_email']}s", "End-to-end processing per email")

    console.print(metrics_table)

    # Confusion Matrix Table
    cm_table = Table(title="[bold yellow]Confusion Matrix[/bold yellow]", show_header=True, header_style="bold yellow")
    cm_table.add_column("Ground Truth \\ Predicted", style="bold", width=26)
    cm_table.add_column("Predicted Phishing", style="bold red", width=22)
    cm_table.add_column("Predicted Benign", style="bold green", width=22)

    cm_table.add_row("Actual Phishing", f"{cm['predicted_phish']['actual_phish']} (True Positives)", f"{cm['predicted_benign']['actual_phish']} (False Negatives)")
    cm_table.add_row("Actual Benign", f"{cm['predicted_phish']['actual_benign']} (False Positives)", f"{cm['predicted_benign']['actual_benign']} (True Negatives)")

    console.print(cm_table)

    # Predictions Table
    pred_table = Table(title="[bold]Per-Sample Breakdown[/bold]", show_header=True, header_style="bold")
    pred_table.add_column("Sample File", style="white", width=34)
    pred_table.add_column("Ground Truth", width=14)
    pred_table.add_column("Risk Score", width=12)
    pred_table.add_column("Verdict", width=14)
    pred_table.add_column("Evaluation Result", width=18)

    for p in results["predictions"]:
        status_style = "green" if "TP" in p.get("status", "") or "TN" in p.get("status", "") else "red"
        pred_table.add_row(
            p["file"],
            p["ground_truth"],
            f"{p.get('risk_score', 0)}/100",
            p.get("verdict", "N/A"),
            f"[{status_style}]{p.get('status', 'ERROR')}[/{status_style}]"
        )

    console.print(pred_table)
    console.print("\n")


if __name__ == "__main__":
    main()
