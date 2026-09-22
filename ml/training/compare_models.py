import os
import sys
import time
import json
import datetime
import pandas as pd
import numpy as np

# Ensure UTF-8 output on Windows terminals
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

DATASET_PATH = os.path.join(PROJECT_ROOT, "ml", "datasets", "processed", "urls_dataset.csv")
CACHE_PATH = os.path.join(PROJECT_ROOT, "ml", "datasets", "processed", "features_cache.csv")
BENCHMARK_OUTPUT_PATH = os.path.join(PROJECT_ROOT, "ml", "models", "model_comparison.json")


def run_benchmark(sample_size: int = 80000) -> dict:
    print("=" * 70)
    print("      QR-QUISHING INSPECTOR - MULTI-MODEL BENCHMARK SUITE")
    print("=" * 70)

    if not os.path.exists(DATASET_PATH) or not os.path.exists(CACHE_PATH):
        raise FileNotFoundError(
            f"Required datasets not found. Ensure {DATASET_PATH} and {CACHE_PATH} exist."
        )

    print(f"Loading dataset and feature cache from disk...")
    df_y = pd.read_csv(DATASET_PATH, usecols=["label"])
    df_x = pd.read_csv(CACHE_PATH)
    total_samples = len(df_y)
    print(f"Total dataset: {total_samples:,} records with {df_x.shape[1]} features.")

    # Stratified subsampling for fast, repeatable benchmark training
    effective_n = min(sample_size, total_samples)
    if effective_n < total_samples:
        X_sub, _, y_sub, _ = train_test_split(
            df_x, df_y["label"],
            train_size=effective_n,
            random_state=42,
            stratify=df_y["label"]
        )
    else:
        X_sub, y_sub = df_x, df_y["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X_sub, y_sub, test_size=0.20, random_state=42, stratify=y_sub
    )
    print(f"Training split: {len(X_train):,} samples | Test split: {len(X_test):,} samples\n")

    models = {
        "Logistic Regression": make_pipeline(
            StandardScaler(),
            LogisticRegression(max_iter=1000, random_state=42)
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=100,
            max_depth=14,
            random_state=42,
            n_jobs=-1
        ),
        "Decision Tree": DecisionTreeClassifier(
            max_depth=12,
            random_state=42
        ),
        "SVM (Linear)": make_pipeline(
            StandardScaler(),
            SGDClassifier(loss="log_loss", max_iter=1000, random_state=42)
        ),
        "Gradient Boosting": HistGradientBoostingClassifier(
            max_iter=120,
            max_depth=8,
            random_state=42
        ),
    }

    results = []
    print("-" * 72)
    print(f"{'Model':<22} {'Accuracy':<10} {'Precision':<10} {'Recall':<10} {'F1':<10} {'Time':<8}")
    print("-" * 72)

    for name, clf in models.items():
        t0 = time.time()
        clf.fit(X_train, y_train)
        train_time = time.time() - t0

        y_pred = clf.predict(X_test)
        
        # Calculate probabilities for ROC-AUC if supported
        try:
            y_prob = clf.predict_proba(X_test)[:, 1]
            roc_auc = round(float(roc_auc_score(y_test, y_prob)) * 100, 2)
        except Exception:
            roc_auc = None

        acc = round(float(accuracy_score(y_test, y_pred)) * 100, 2)
        prec = round(float(precision_score(y_test, y_pred)) * 100, 2)
        rec = round(float(recall_score(y_test, y_pred)) * 100, 2)
        f1 = round(float(f1_score(y_test, y_pred)) * 100, 2)

        is_active = (name == "Gradient Boosting")

        entry = {
            "model": name,
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1": f1,
            "roc_auc": roc_auc,
            "training_time_sec": round(train_time, 2),
            "is_active": is_active,
            "active_badge": "Active Production Model" if is_active else None
        }
        results.append(entry)

        active_tag = " [ACTIVE]" if is_active else ""
        print(f"{name + active_tag:<22} {acc:>8.2f}% {prec:>9.2f}% {rec:>9.2f}% {f1:>8.2f}% {train_time:>6.2f}s")

    print("-" * 72)

    output_data = {
        "dataset": {
            "name": "PhiUSIIL Phishing URL Dataset & QR Attack Corpus",
            "total_samples": total_samples,
            "benchmark_samples": effective_n,
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "features_count": df_x.shape[1],
            "features_list": list(df_x.columns),
        },
        "active_model": "Gradient Boosting",
        "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "models": results
    }

    os.makedirs(os.path.dirname(BENCHMARK_OUTPUT_PATH), exist_ok=True)
    with open(BENCHMARK_OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)

    print(f"\n[+] Benchmark matrix saved to: {BENCHMARK_OUTPUT_PATH}")
    return output_data


if __name__ == "__main__":
    run_benchmark()
