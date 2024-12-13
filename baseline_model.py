import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# Load the data
data = pd.read_csv("emails_from_spamassassin.csv")

# Split into features and labels
texts = data['text']
labels = data['label']

# Convert text into a matrix of token counts (simple approach)
vectorizer = CountVectorizer()
X = vectorizer.fit_transform(texts)

# Split into train and test sets
X_train, X_test, y_train, y_test = train_test_split(X, labels, test_size=0.5, random_state=42)

# Create and train the model
model = MultinomialNB()
model.fit(X_train, y_train)

# Evaluate
predictions = model.predict(X_test)
print("Baseline Model Results:")
print(classification_report(y_test, predictions))


# Precision: Of the emails the model flagged as phishing, how many are correct?

# Recall: Of all the actual phishing emails, how many did the model catch?

# F1-Score: A combined measure that balances precision and recall.

# Support: How many examples in the test set belong to each class