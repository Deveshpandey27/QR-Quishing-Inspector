import os
import sys
import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix, classification_report
from sklearn.model_selection import train_test_split

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.detection.features import extract_url_features
from app.detection.risk_engine import calculate_composite_risk

MODEL_PATH = os.path.join(PROJECT_ROOT, "ml", "models", "qr_quishing_model.pkl")
DATASET_PATH = os.path.join(PROJECT_ROOT, "ml", "datasets", "processed", "urls_dataset.csv")
CACHE_PATH = os.path.join(PROJECT_ROOT, "ml", "datasets", "processed", "features_cache.csv")


def evaluate():
    print("=" * 60)
    print("QR Quishing Inspector - Model Evaluation Report")
    print("=" * 60)

    if not os.path.exists(MODEL_PATH):
        print(f"Error: Model not found at {MODEL_PATH}.")
        return

    print(f"Loading trained model from {MODEL_PATH}...")
    saved_payload = joblib.load(MODEL_PATH)
    if isinstance(saved_payload, dict):
        model = saved_payload["model"]
        feature_names = saved_payload.get("feature_names", [])
        print(f"Model Type: {saved_payload.get('model_type')}")
        print(f"Trained At: {saved_payload.get('trained_at')}")
        print(f"Features  : {len(feature_names)}")
    else:
        model = saved_payload
        feature_names = None

    if not os.path.exists(DATASET_PATH):
        print("Dataset not found for independent test evaluation.")
        return

    if os.path.exists(CACHE_PATH):
        print(f"Loading features from {CACHE_PATH}...")
        X = pd.read_csv(CACHE_PATH)
        df = pd.read_csv(DATASET_PATH, usecols=["label"])
        y = df["label"]
    else:
        print("Features cache not found; loading sample from dataset...")
        df = pd.read_csv(DATASET_PATH).sample(n=10000, random_state=42)
        X = pd.DataFrame([extract_url_features(u) for u in df["url"]])
        y = df["label"]

    _, X_test, _, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_prob)

    print("\n" + "=" * 45)
    print("     TEST SET EVALUATION RESULTS")
    print("=" * 45)
    print(f"Test Samples : {len(X_test):,}")
    print(f"Accuracy     : {acc * 100:.2f}%")
    print(f"Precision    : {prec * 100:.2f}%")
    print(f"Recall       : {rec * 100:.2f}%")
    print(f"F1-Score     : {f1:.4f}")
    print(f"ROC-AUC      : {roc_auc:.4f}")

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    print("\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Safe (0)", "Phishing (1)"]))

    print("=" * 45)
    print("     BENCHMARK SANITY PREDICTIONS")
    print("=" * 45)
    benchmarks = [
        "https://google.com",
        "https://www.google.com",
        "https://github.com",
        "https://accounts.google.com/login",
        "https://www.southbankmosaics.com",
        "http://192.168.1.50/login/verify",
        "https://paypal.com.account-verify.xyz/login",
        "https://bit.ly/secure-token",
        "https://xn--pple-43d.com",
    ]
    test_feats = pd.DataFrame([extract_url_features(u) for u in benchmarks])
    if feature_names:
        test_feats = test_feats[feature_names]
    probs = model.predict_proba(test_feats)[:, 1]

    print(f"  {'Target Benchmark URL':<44} | {'Raw ML':<8} | {'Pipeline Verdict'}")
    print("  " + "-" * 75)
    for u, p in zip(benchmarks, probs):
        pipe = calculate_composite_risk(u)
        ml_txt = f"{p * 100:5.1f}%"
        verdict = f"Risk {pipe['score']:>3}/100 [{pipe['status'].upper()}]"
        if pipe.get("is_trusted"):
            verdict += " (Whitelist Guarded)"
        elif pipe.get("is_shortener"):
            verdict += " (Shortener Alert)"
        elif pipe.get("is_ip"):
            verdict += " (IP Alert)"
        print(f"  {u:<44} | {ml_txt:<8} | {verdict}")


if __name__ == "__main__":
    evaluate()
