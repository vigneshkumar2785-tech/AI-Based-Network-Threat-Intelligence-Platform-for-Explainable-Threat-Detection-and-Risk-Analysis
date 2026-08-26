"""
Master Training Script — runs full Block B pipeline:
  1. Generate synthetic dataset
  2. Train Isolation Forest anomaly detector
  3. Train XGBoost threat classifier
  4. Print combined evaluation summary
Run: python ml/training/train_all.py
"""
import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "models")


def banner(msg: str):
    print("\n" + "=" * 60)
    print(f"  {msg}")
    print("=" * 60)


def main():
    banner("Step 1/3 — Generating Synthetic Dataset")
    from ml.datasets.generate_dataset import main as gen_main
    gen_main()

    banner("Step 2/3 — Training Isolation Forest Anomaly Detector")
    from ml.training.train_isolation_forest import main as if_main
    if_metrics = if_main()

    banner("Step 3/3 — Training XGBoost Threat Classifier")
    from ml.training.train_classifier import main as xgb_main
    xgb_metrics = xgb_main()

    banner("Training Complete — Summary")
    print(f"\n{'Isolation Forest':}")
    print(f"  Anomaly Precision: {if_metrics['anomaly_precision']:.4f}")
    print(f"  Anomaly Recall:    {if_metrics['anomaly_recall']:.4f}")
    print(f"  Anomaly F1:        {if_metrics['anomaly_f1']:.4f}")
    print(f"\n{'XGBoost Classifier':}")
    print(f"  Overall Accuracy:  {xgb_metrics['overall_accuracy']:.4f}")
    for label, scores in xgb_metrics['per_class'].items():
        print(f"  {label:20s}  F1={scores['f1']:.4f}")

    print("\n✓ All models saved to ml/models/")
    print("✓ Run the end-to-end pipeline test:")
    print("    python scripts/run_pipeline.py --event-type port_scan")


if __name__ == "__main__":
    main()
