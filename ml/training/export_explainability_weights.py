import os
import sys
import json
import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

FEATURES_CACHE_PATH = os.path.join(PROJECT_ROOT, "ml", "datasets", "processed", "features_cache.csv")
DATASET_PATH = os.path.join(PROJECT_ROOT, "ml", "datasets", "processed", "urls_dataset.csv")
OUTPUT_PATH = os.path.join(PROJECT_ROOT, "ml", "models", "explainability_weights.json")

FEATURE_HUMAN_NAMES = {
    "url_length": "URL length",
    "hostname_length": "Hostname length",
    "path_length": "URL path length",
    "query_length": "Query parameter length",
    "has_https": "HTTPS",
    "has_ip_address": "IP address",
    "dot_count_host": "Dot count",
    "dot_count_path": "Path dot count",
    "hyphen_count_host": "Hyphen count",
    "hyphen_count_path": "Path hyphen count",
    "underscore_count": "Underscore count",
    "slash_count": "Special characters (/ delimiter)",
    "question_mark_count": "Special characters (?)",
    "equals_count": "Special characters (=)",
    "at_symbol": "Special characters (@ symbol)",
    "percent_encoded": "Special characters (% hex)",
    "has_double_slash_path": "Double slash redirect",
    "subdomain_count": "Subdomain count",
    "num_digits_host": "Host digit count",
    "num_digits_url": "Total digit count",
    "entropy_hostname": "Hostname randomness (Entropy)",
    "is_shortener": "URL shortener",
    "is_punycode": "Punycode domain",
    "suspicious_keyword_count": "Suspicious keyword count"
}


def export_weights():
    print("=" * 60)
    print("Exporting Calibrated Feature Attribution Weights for Explainable ML")
    print("=" * 60)

    if not os.path.exists(FEATURES_CACHE_PATH) or not os.path.exists(DATASET_PATH):
        raise FileNotFoundError("Processed dataset and features cache required.")

    print("Loading features cache and labels...")
    df_x = pd.read_csv(FEATURES_CACHE_PATH)
    df_y = pd.read_csv(DATASET_PATH, usecols=["label"])["label"]

    feature_names = list(df_x.columns)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(df_x)

    print("Training calibrated log-odds surrogate...")
    clf = LogisticRegression(max_iter=1000, random_state=42)
    clf.fit(X_scaled, df_y)

    means = {f: float(scaler.mean_[i]) for i, f in enumerate(feature_names)}
    scales = {f: float(scaler.scale_[i]) for i, f in enumerate(feature_names)}
    coefs = {f: float(clf.coef_[0][i]) for i, f in enumerate(feature_names)}
    intercept = float(clf.intercept_[0])

    payload = {
        "model_type": "Standardized Log-Odds Linear Surrogate",
        "feature_names": feature_names,
        "intercept": intercept,
        "means": means,
        "scales": scales,
        "coefficients": coefs,
        "display_names": FEATURE_HUMAN_NAMES,
    }

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print(f"Explainability weights exported successfully to: {OUTPUT_PATH}")
    return payload


if __name__ == "__main__":
    export_weights()
