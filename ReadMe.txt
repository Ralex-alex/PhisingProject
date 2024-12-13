Project : github : https://github.com/Ralex-alex/PhisingProject.git

Welcome to PhishSentinel !

This is just a Base model of the overall project with a lite version of bert 
there are 3 python scrips here: 

baseline_model.py which is used as the baseline metric for the dataset to be compared to this is used using simple text features like word counts 

llm_integration.py uses a small LLM distilbert-base which is a watered down version of bert for easier use Run this to see just the LLM in action 
without any algoritm in place and see the scoring.

combined_pipeline.py is where my project shines and differentiates from the rest of the spam filters - it combines the use of Algorithm and LLM 
to give the most precise weighting on this dataset.

Things to know : 

right now there is only the training mode of using the psudo database to teach the LLM
and the csv you need to build from the spam assasin psudo database that my project uses  
by running the prepare_spamassassin.py if its not with the project 
and then replacing data = pd.read_csv("emails.csv") with output_csv = "emails_from_spamassassin.csv"
in the baseline_model.py , llm_integration.py , combined_pipeline.py depending on which csv you want to use.

Depending on which data set you use the scanning will be different for the best results use the spamassassin.csv
but if your pc isn't well optimised use email.csv with very little examples but instantaneous response.

how to read the scores and what they mean so you can compare all 3 python scripts.

Precision:

What it Means:
Out of all the emails the model labeled as "phishing," what fraction were actually phishing?
In Other Words:
If the model says "this is phishing," how often is it correct?
Example:
If the model flagged 10 emails as phishing, and 8 of them were genuinely phishing, your precision is 8/10 = 0.8 or 80%.

Recall:

What it Means:
Out of all the actual phishing emails in the dataset, how many did the model correctly identify as phishing?
In Other Words:
If you had 20 phishing emails, and the model caught 16 of them, the recall would be 16/20 = 0.8 or 80%.

F1-Score:

What it Means:
It’s a single number that combines both precision and recall. It’s the harmonic mean of precision and recall.
Why It’s Useful:
Sometimes you want a balance: you don’t just want to be right when you say “phishing” (precision), and you don’t just want to catch most phishing emails (recall)—you want a good overall balance. The F1-score gives you a way to see that balance in one number.
If Precision = P and Recall = R:
F1 = 2 * (P * R) / (P + R)

Support:

What it Means:
The number of examples of each class that were present in the dataset’s test portion. For example, if "support" for phishing is 30, it means there were 30 phishing emails in the test set.
Why It’s Important:
Seeing the support helps you understand how many examples the scores are based on. If you have a high F1-score but the support is only 2 emails, that’s less trustworthy than if the support was 200 emails.



