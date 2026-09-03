from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

from ml_model import TRAINING_DATA


# Create labels using the same labeling logic
# currently used by our prototype model.
def create_labels(urls):

    labels = []

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

    for url in urls:

        score = sum(
            word in url.lower()
            for word in suspicious_words
        )

        if score >= 2 or not url.startswith("https://"):
            labels.append(1)
        else:
            labels.append(0)

    return labels


# Create labels
labels = create_labels(TRAINING_DATA)


# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    TRAINING_DATA,
    labels,
    test_size=0.25,
    random_state=42,
    stratify=labels
)


print("Training samples:", len(X_train))
print("Testing samples:", len(X_test))


# Import the same model components
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


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


# Train model
model.fit(X_train, y_train)


# Predict test data
y_pred = model.predict(X_test)


# Calculate metrics
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, zero_division=0)
recall = recall_score(y_test, y_pred, zero_division=0)
f1 = f1_score(y_test, y_pred, zero_division=0)


print("\n===== MODEL EVALUATION =====")

print(f"Accuracy : {accuracy:.2f}")
print(f"Precision: {precision:.2f}")
print(f"Recall   : {recall:.2f}")
print(f"F1 Score : {f1:.2f}")


print("\n===== CONFUSION MATRIX =====")

print(confusion_matrix(y_test, y_pred))


print("\n===== CLASSIFICATION REPORT =====")

print(
    classification_report(
        y_test,
        y_pred,
        target_names=["Safe", "Suspicious"],
        zero_division=0
    )
)