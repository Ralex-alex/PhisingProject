import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.linear_model import LogisticRegression
from transformers import AutoTokenizer, AutoModel
import torch

data = pd.read_csv("emails_from_spamassassin.csv")
texts = data['text'].tolist()
labels = data['label']
label_map = {'legitimate': 0, 'phishing': 1}
numeric_labels = [label_map[l] for l in labels]

X_train, X_test, y_train, y_test = train_test_split(texts, numeric_labels, test_size=0.5, random_state=42, stratify=numeric_labels)

# Train baseline model
vectorizer = CountVectorizer()
X_train_counts = vectorizer.fit_transform(X_train)
X_test_counts = vectorizer.transform(X_test)

nb_model = MultinomialNB()
nb_model.fit(X_train_counts, y_train)

# Prepare LLM embeddings
model_name = "distilbert-base-uncased"
tokenizer = AutoTokenizer.from_pretrained(model_name)
llm_model = AutoModel.from_pretrained(model_name)

def get_embeddings(texts):
    inputs = tokenizer(texts, return_tensors='pt', padding=True, truncation=True)
    with torch.no_grad():
        outputs = llm_model(**inputs)
    return outputs.last_hidden_state.mean(dim=1).numpy()

X_train_emb = get_embeddings(X_train)
X_test_emb = get_embeddings(X_test)

llm_clf = LogisticRegression()
llm_clf.fit(X_train_emb, y_train)

# Combined decision
nb_probs = nb_model.predict_proba(X_test_counts)
llm_predictions = llm_clf.predict(X_test_emb)

final_predictions = []
for i, probs in enumerate(nb_probs):
    phishing_prob = probs[1]  # Probability of phishing
    if phishing_prob > 0.9:
        final_predictions.append(1)
    elif phishing_prob < 0.1:
        final_predictions.append(0)
    else:
        final_predictions.append(llm_predictions[i])

y_pred = final_predictions  # Use final_predictions as y_pred

print("Combined Pipeline Results:")
print(classification_report(y_test, y_pred, target_names=["legitimate", "phishing"]))
