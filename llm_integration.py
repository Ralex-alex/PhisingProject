import pandas as pd 
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from transformers import AutoTokenizer, AutoModel
import torch

# Load data
data = pd.read_csv("emails.csv")
texts = data['text'].tolist()
labels = data['label']

# Convert labels to 0 (legitimate) and 1 (phishing) for training
# This is just to make it easier to work with numeric models.
label_map = {'legitimate': 0, 'phishing': 1}
numeric_labels = [label_map[l] for l in labels]

# Split into train/test
X_train, X_test, y_train, y_test = train_test_split(texts, numeric_labels, test_size=0.5, random_state=42)

# Load a pre-trained model for embeddings
model_name = "distilbert-base-uncased"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModel.from_pretrained(model_name)

def get_embeddings(texts):
    # Tokenize the text
    inputs = tokenizer(texts, return_tensors='pt', padding=True, truncation=True)
    with torch.no_grad():
        outputs = model(**inputs)
    # outputs.last_hidden_state is a tensor [batch_size, sequence_length, hidden_size]
    # We can mean-pool it to get a single vector per text
    embeddings = outputs.last_hidden_state.mean(dim=1)
    return embeddings.numpy()

# Get embeddings for train and test
train_embeddings = get_embeddings(X_train)
test_embeddings = get_embeddings(X_test)

# Training a simple classifier on top of embeddings
clf = LogisticRegression()
clf.fit(train_embeddings, y_train)

# Predict
y_pred = clf.predict(test_embeddings)

print("LLM-based Model Results:")
print(classification_report(y_test, y_pred, target_names=["legitimate", "phishing"]))

