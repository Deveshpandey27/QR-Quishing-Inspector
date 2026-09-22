import os
import sys
import datetime
import joblib
import pandas as pd
import numpy as np

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix, classification_report

from app.detection.features import extract_url_features

DATASET_PATH = os.path.join(PROJECT_ROOT, "ml", "datasets", "processed", "urls_dataset.csv")
CACHE_PATH = os.path.join(PROJECT_ROOT, "ml", "datasets", "processed", "features_cache.csv")
MODEL_OUTPUT_PATH = os.path.join(PROJECT_ROOT, "ml", "models", "qr_quishing_model.pkl")


def train():
    print("=" * 60)
    print("QR Quishing Inspector - Model Training Pipeline")
    print("=" * 60)

    if not os.path.exists(DATASET_PATH):
        print(f"Error: Dataset not found at {DATASET_PATH}. Run 'prepare_dataset.py' first.")
        return

    print("Loading processed dataset...")
    df = pd.read_csv(DATASET_PATH)
    print(f"Loaded {len(df):,} samples.")

    if os.path.exists(CACHE_PATH):
        print("Loading cached features from:", CACHE_PATH)
        X = pd.read_csv(CACHE_PATH)
    else:
        print("Extracting 24 cybersecurity features for all samples...")
        features_list = [extract_url_features(url) for url in df["url"]]
        X = pd.DataFrame(features_list)
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
        X.to_csv(CACHE_PATH, index=False)
        print("Saved features cache to:", CACHE_PATH)

    y = df["label"]
    feature_names = list(X.columns)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"Train set: {len(X_train):,} samples | Test set: {len(X_test):,} samples")

    print("Training HistGradientBoostingClassifier with regularized constraints...")
    model = HistGradientBoostingClassifier(
        max_iter=150,
        max_depth=8,
        min_samples_leaf=30,
        l2_regularization=1.0,
        learning_rate=0.1,
        random_state=42
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_prob)

    print("\n" + "=" * 45)
    print("     HELD-OUT EVALUATION METRICS")
    print("=" * 45)
    print(f"Accuracy  : {acc * 100:.2f}%")
    print(f"Precision : {prec * 100:.2f}%")
    print(f"Recall    : {rec * 100:.2f}%")
    print(f"F1-Score  : {f1:.4f}")
    print(f"ROC-AUC   : {roc_auc:.4f}")

    os.makedirs(os.path.dirname(MODEL_OUTPUT_PATH), exist_ok=True)
    payload = {
        "model": model,
        "feature_names": feature_names,
        "metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "roc_auc": round(roc_auc, 4),
            "test_samples": len(X_test),
        },
        "model_type": "HistGradientBoostingClassifier",
        "trained_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    joblib.dump(payload, MODEL_OUTPUT_PATH)
    print(f"
Model artifact saved to: {MODEL_OUTPUT_PATH}")


if __name__ == "__main__":
    train()
