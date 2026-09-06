import os
import sys
import pandas as pd
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)


DATASET_PATH = "data/processed/urls_dataset.csv"
MODEL_DIR = "model"
MODEL_PATH = os.path.join(
    MODEL_DIR,
    "qr_quishing_model.pkl"
)


def main():

    print("Loading processed dataset...")

    df = pd.read_csv(DATASET_PATH)

    print("Total URLs:", len(df))

    # Features
    X = df["url"]

    # Labels
    #
    # 0 = Safe / Legitimate
    # 1 = Suspicious / Phishing
    y = df["label"]

    print("\nSplitting dataset...")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    print("Training samples:", len(X_train))
    print("Testing samples:", len(X_test))

    print("\nCreating ML pipeline...")

    model = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                analyzer="char",
                ngram_range=(3, 5),
                min_df=2,
                max_features=50000,
                sublinear_tf=True
            )
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=1000,
                random_state=42,
                class_weight="balanced"
            )
        )
    ])

    print("\nTraining model...")
    print("This may take some time.")

    model.fit(
        X_train,
        y_train
    )

    print("\nTesting model...")

    predictions = model.predict(
        X_test
    )

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    precision = precision_score(
        y_test,
        predictions
    )

    recall = recall_score(
        y_test,
        predictions
    )

    f1 = f1_score(
        y_test,
        predictions
    )

    print("\n===== MODEL EVALUATION =====")

    print(
        "Accuracy :",
        round(accuracy, 4)
    )

    print(
        "Precision:",
        round(precision, 4)
    )

    print(
        "Recall   :",
        round(recall, 4)
    )

    print(
        "F1 Score :",
        round(f1, 4)
    )

    print("\n===== CONFUSION MATRIX =====")

    print(
        confusion_matrix(
            y_test,
            predictions
        )
    )

    print("\n===== CLASSIFICATION REPORT =====")

    print(
        classification_report(
            y_test,
            predictions,
            target_names=[
                "Safe",
                "Suspicious"
            ]
        )
    )

    print("\nSaving model...")

    os.makedirs(
        MODEL_DIR,
        exist_ok=True
    )

    joblib.dump(
        model,
        MODEL_PATH
    )

    print("\n===== TRAINING COMPLETE =====")

    print(
        "Model saved to:"
    )

    print(
        MODEL_PATH
    )


if __name__ == "__main__":
    main()