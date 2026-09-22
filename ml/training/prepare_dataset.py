import os
import pandas as pd

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RAW_DATASET = os.path.join(PROJECT_ROOT, "ml", "datasets", "raw", "PhiUSIIL_Phishing_URL_Dataset.csv")
OUTPUT_DATASET = os.path.join(PROJECT_ROOT, "ml", "datasets", "processed", "urls_dataset.csv")


def main():
    print("Loading raw dataset from:", RAW_DATASET)
    if not os.path.exists(RAW_DATASET):
        print(f"Error: Raw dataset not found at {RAW_DATASET}")
        return

    df = pd.read_csv(RAW_DATASET, usecols=["URL", "label"])
    print("Original rows:", len(df))

    df = df.rename(columns={"URL": "url"})
    df["label"] = 1 - df["label"]
    df = df.drop_duplicates(subset=["url"])
    df = df.dropna(subset=["url", "label"])
    df["url"] = df["url"].str.strip()
    df = df[df["url"] != ""]

    os.makedirs(os.path.dirname(OUTPUT_DATASET), exist_ok=True)
    df.to_csv(OUTPUT_DATASET, index=False)

    print("
===== DATASET PREPARATION COMPLETE =====")
    print("Processed rows:", len(df))
    print("
Label distribution:
", df["label"].value_counts())
    print("
Saved to:", OUTPUT_DATASET)


if __name__ == "__main__":
    main()
