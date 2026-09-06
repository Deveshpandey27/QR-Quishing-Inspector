import os
import pandas as pd


RAW_DATASET = "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv"
OUTPUT_DATASET = "data/processed/urls_dataset.csv"


def main():

    print("Loading raw dataset...")

    df = pd.read_csv(
        RAW_DATASET,
        usecols=["URL", "label"]
    )

    print("Original rows:", len(df))

    # Rename columns to match our project naming
    df = df.rename(
        columns={
            "URL": "url"
        }
    )

    # Convert dataset labels to project labels
    #
    # Original dataset:
    # 1 = legitimate
    # 0 = phishing
    #
    # Project convention:
    # 0 = safe
    # 1 = suspicious
    df["label"] = 1 - df["label"]

    # Remove duplicate URLs
    df = df.drop_duplicates(
        subset=["url"]
    )

    # Remove empty URLs
    df = df.dropna(
        subset=["url", "label"]
    )

    # Remove leading/trailing spaces
    df["url"] = df["url"].str.strip()

    # Remove empty strings
    df = df[
        df["url"] != ""
    ]

    # Ensure output directory exists
    os.makedirs(
        "data/processed",
        exist_ok=True
    )

    # Save processed dataset
    df.to_csv(
        OUTPUT_DATASET,
        index=False
    )

    print("\n===== DATASET PREPARATION COMPLETE =====")

    print("Processed rows:", len(df))

    print("\nLabel distribution:")
    print(
        df["label"].value_counts()
    )

    print("\nSaved to:")
    print(OUTPUT_DATASET)


if __name__ == "__main__":
    main()