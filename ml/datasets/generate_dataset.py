"""
Dataset generation script — writes training/validation CSVs from synthetic events.
Run: python ml/datasets/generate_dataset.py
"""
import sys
import os
import csv
import json

# Allow running from repo root or ml/ directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from simulation.network_events.generator import generate_dataset
from ml.preprocessing.preprocessor import extract_features, LABEL_TO_INT

DATASET_DIR = os.path.dirname(__file__)
TRAIN_FILE  = os.path.join(DATASET_DIR, "train.csv")
VAL_FILE    = os.path.join(DATASET_DIR, "val.csv")
EVENTS_FILE = os.path.join(DATASET_DIR, "events_raw.jsonl")


def main():
    print("Generating synthetic dataset…")
    events = generate_dataset(n_normal=3000, n_per_attack=400, seed=42)
    print(f"  Total events: {len(events)}")

    # Count per class
    from collections import Counter
    counts = Counter(e["label"] for e in events)
    for k, v in sorted(counts.items()):
        print(f"    {k:20s} {v}")

    # Split 80/20 train/val deterministically
    split = int(len(events) * 0.8)
    train_events = events[:split]
    val_events   = events[split:]

    # Compute features
    from ml.preprocessing.preprocessor import FEATURE_COLUMNS
    fieldnames = FEATURE_COLUMNS + ["label_str", "label_int"]

    def write_csv(filepath, subset):
        with open(filepath, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for e in subset:
                row = extract_features(e)
                row["label_str"] = e.get("label", "normal")
                row["label_int"] = LABEL_TO_INT.get(e.get("label", "normal"), 0)
                writer.writerow(row)

    write_csv(TRAIN_FILE, train_events)
    write_csv(VAL_FILE, val_events)

    # Save raw events as JSONL (for debugging & IOC demo)
    with open(EVENTS_FILE, "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")

    print(f"\nDataset written:")
    print(f"  Train: {TRAIN_FILE}  ({len(train_events)} rows)")
    print(f"  Val:   {VAL_FILE}   ({len(val_events)} rows)")
    print(f"  Raw:   {EVENTS_FILE}")


if __name__ == "__main__":
    main()
