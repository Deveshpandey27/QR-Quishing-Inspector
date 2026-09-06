import os
import joblib


MODEL_PATH = "model/qr_quishing_model.pkl"


def load_model():
    """
    Load the trained phishing detection model.
    """

    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Trained model not found: {MODEL_PATH}"
        )

    return joblib.load(MODEL_PATH)


def predict_url(url):
    """
    Predict whether a URL is safe or suspicious.

    Project label convention:
    0 = Safe
    1 = Suspicious / Phishing
    """

    model = load_model()

    prediction = model.predict([url])[0]

    probabilities = model.predict_proba([url])[0]

    suspicious_probability = probabilities[1]

    return {
        "prediction": int(prediction),
        "suspicious_probability": round(
            float(suspicious_probability) * 100,
            2
        )
    }