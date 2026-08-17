import os
import re
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


MODEL_DIR = "model"
MODEL_PATH = os.path.join(MODEL_DIR, "qr_quishing_model.pkl")


# Representative training examples for a college-project prototype.
# 0 = safer-looking URL
# 1 = suspicious/phishing-looking URL

TRAINING_DATA = [
    # Safer examples
    "https://www.google.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://www.amazon.com",
    "https://www.github.com",
    "https://www.wikipedia.org",
    "https://www.python.org",
    "https://www.mozilla.org",
    "https://www.linkedin.com",
    "https://www.instagram.com",
    "https://www.facebook.com",
    "https://www.microsoft.com/en-us/security",
    "https://support.google.com",
    "https://github.com/login",
    "https://www.amazon.com/products",
    "https://www.apple.com/shop",
    "https://www.wikipedia.org/wiki/Python",
    "https://www.python.org/downloads",
    "https://developer.mozilla.org",
    "https://www.google.com/search?q=cybersecurity",

    # Suspicious examples
    "http://google-login-security.com",
    "http://paypal-verify-account.com",
    "http://amazon-account-confirm.com",
    "http://microsoft-security-alert.com",
    "http://instagram-password-reset.com",
    "http://facebook-login-verification.com",
    "http://secure-bank-login.com",
    "http://account-verification-required.com",
    "http://verify-your-account-now.com",
    "http://login-confirm-security.com",
    "http://free-gift-card-winner.com",
    "http://claim-your-prize-now.com",
    "http://urgent-account-warning.com",
    "http://password-reset-alert.com",
    "http://banking-security-check.com",
    "http://paypal-security-confirmation.com",
    "http://google-account-security-check.com",
    "http://amazon-payment-verification.com",
    "http://secure-login-verification.com",
    "http://update-payment-information.com",
]


def train_model():
    os.makedirs(MODEL_DIR, exist_ok=True)

    labels = []

    for url in TRAINING_DATA:
        suspicious_words = [
            "verify",
            "verification",
            "security",
            "confirm",
            "login",
            "password",
            "account",
            "urgent",
            "winner",
            "prize",
            "payment",
            "reset",
            "alert",
        ]

        score = sum(word in url.lower() for word in suspicious_words)

        if score >= 2 or not url.startswith("https://"):
            labels.append(1)
        else:
            labels.append(0)

    model = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                analyzer="char",
                ngram_range=(2, 5),
                min_df=1
            )
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=1000,
                random_state=42
            )
        )
    ])

    model.fit(TRAINING_DATA, labels)

    joblib.dump(model, MODEL_PATH)

    return model


def load_model():
    if not os.path.exists(MODEL_PATH):
        return train_model()

    return joblib.load(MODEL_PATH)


def predict_url(url):
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