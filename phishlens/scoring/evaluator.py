"""
ML / Data Evaluation Suite: Evaluates detection performance across labeled datasets.
Calculates Precision, Recall, F1-Score, False Positive Rate, and Confusion Matrix.
"""

from pathlib import Path
from typing import List, Dict, Any, Tuple
import time

from phishlens.parser.email_parser import EmailParser
from phishlens.intel.intel_manager import IntelManager
from phishlens.scoring.engine import ScoringEngine


class DatasetEvaluator:
    """Evaluates the pipeline's detection accuracy on labeled corpora."""

    def __init__(self, offline_mode: bool = True):
        self.intel_manager = IntelManager(offline_mode=offline_mode)
        self.scoring_engine = ScoringEngine()

    def evaluate_directories(self, phishing_dir: str, benign_dir: str, threshold: int = 50) -> Dict[str, Any]:
        """Runs evaluation over phishing and benign email folders."""
        dataset = []

        phish_path = Path(phishing_dir)
        if phish_path.is_dir():
            for f in phish_path.glob("*.eml"):
                dataset.append((str(f), 1))  # 1 = Phishing

        benign_path = Path(benign_dir)
        if benign_path.is_dir():
            for f in benign_path.glob("*.eml"):
                dataset.append((str(f), 0))  # 0 = Benign

        return self.evaluate_dataset(dataset, threshold=threshold)

    def evaluate_dataset(self, labeled_files: List[Tuple[str, int]], threshold: int = 50) -> Dict[str, Any]:
        """
        Evaluates list of (file_path, ground_truth) tuples.
        Ground truth: 1 for Phishing, 0 for Legitimate.
        """
        tp = 0
        fp = 0
        tn = 0
        fn = 0
        predictions = []
        start_time = time.time()

        for file_path, label in labeled_files:
            try:
                parsed = EmailParser.parse_file(file_path)
                intel = self.intel_manager.enrich(parsed)
                score_res = self.scoring_engine.evaluate(parsed, intel)

                score = score_res["risk_score"]
                predicted_label = 1 if score >= threshold else 0

                if label == 1 and predicted_label == 1:
                    tp += 1
                    status = "TP (True Positive)"
                elif label == 0 and predicted_label == 1:
                    fp += 1
                    status = "FP (False Positive)"
                elif label == 0 and predicted_label == 0:
                    tn += 1
                    status = "TN (True Negative)"
                else:
                    fn += 1
                    status = "FN (False Negative)"

                predictions.append({
                    "file": Path(file_path).name,
                    "ground_truth": "Phishing" if label == 1 else "Benign",
                    "risk_score": score,
                    "verdict": score_res["verdict"],
                    "status": status,
                    "triggered_rules": [r["name"] for r in score_res["triggered_rules"]]
                })
            except Exception as e:
                predictions.append({
                    "file": Path(file_path).name,
                    "ground_truth": "Phishing" if label == 1 else "Benign",
                    "error": str(e)
                })

        total = tp + fp + tn + fn
        accuracy = (tp + tn) / total if total > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        elapsed = time.time() - start_time

        return {
            "metrics": {
                "total_evaluated": total,
                "true_positives": tp,
                "false_positives": fp,
                "true_negatives": tn,
                "false_negatives": fn,
                "accuracy": round(accuracy, 4),
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1_score": round(f1_score, 4),
                "false_positive_rate": round(fpr, 4),
                "threshold_used": threshold,
                "elapsed_seconds": round(elapsed, 2),
                "avg_seconds_per_email": round(elapsed / (total or 1), 3)
            },
            "confusion_matrix": {
                "predicted_phish": {"actual_phish": tp, "actual_benign": fp},
                "predicted_benign": {"actual_phish": fn, "actual_benign": tn}
            },
            "predictions": predictions
        }
