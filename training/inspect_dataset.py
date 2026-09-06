import pandas as pd

DATASET_PATH = "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv"

df = pd.read_csv(DATASET_PATH)

print("Dataset shape:")
print(df.shape)

print("\nColumns:")
print(df.columns.tolist())

print("\nFirst 3 rows:")
print(df.head(3))

print("\nMissing values:")
print(df.isnull().sum())

print("\nDuplicate rows:")
print(df.duplicated().sum())

print("\n===== LABEL DISTRIBUTION =====")

print(df["label"].value_counts())

print("\n===== LABEL PERCENTAGE =====")

print(df["label"].value_counts(normalize=True) * 100)