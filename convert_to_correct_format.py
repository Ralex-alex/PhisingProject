import pandas as pd

# ---- 1. Load the source CSV ---------------------------------
# Replace 'original.csv' with the file you want to convert
src = pd.read_csv("spam.csv")

# ---- 2. Build the required columns --------------------------
# EXAMPLE — adjust to match your column names
# If your CSV already has a single column with the whole email text, skip the join.
src["text"] = src["Subject"].fillna("") + "\n" + src["Body"].fillna("")

# Map any existing label names/values to exactly 'phishing' or 'legitimate'
label_map = {
    "spam": "phishing",
    "ham": "legitimate",
    "phish": "phishing",
    "OK": "legitimate"
}
src["label"] = src["Label"].map(label_map)

# ---- 3. Keep only the two columns we need -------------------
dst = src[["text", "label"]]

# ---- 4. Save the new CSV ------------------------------------
dst.to_csv("emails_converted.csv", index=False)
print("✅  Saved emails_converted.csv with", len(dst), "rows")
