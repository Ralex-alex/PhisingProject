#this is just a script to unpack the emails from spamassasin folders

import os
import csv
import email


# Directories :
ham_dirs = ["easy_ham", "easy_ham_2", "hard_ham"]
spam_dirs = ["spam", "spam_2"]

output_csv = "emails_from_spamassassin.csv"

with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["text", "label"])

    # Process all ham folders
    for ham_dir in ham_dirs:
        for filename in os.listdir(ham_dir):
            filepath = os.path.join(ham_dir, filename)
            if os.path.isfile(filepath):
                with open(filepath, 'r', encoding='latin-1') as f:
                    raw_email = f.read()
                    msg = email.message_from_string(raw_email)

                    subject = msg["Subject"] if msg["Subject"] else ""
                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() == "text/plain":
                                body += part.get_payload(decode=True).decode(errors='replace', encoding='latin-1')
                    else:
                        payload = msg.get_payload(decode=True)
                        if payload:
                            body = payload.decode(errors='replace', encoding='latin-1')

                    full_text = f"Subject: {subject}\n{body}"
                    writer.writerow([full_text, "legitimate"])

    # Process all spam folders
    for spam_dir in spam_dirs:
        for filename in os.listdir(spam_dir):
            filepath = os.path.join(spam_dir, filename)
            if os.path.isfile(filepath):
                with open(filepath, 'r', encoding='latin-1') as f:
                    raw_email = f.read()
                    msg = email.message_from_string(raw_email)

                    subject = msg["Subject"] if msg["Subject"] else ""
                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() == "text/plain":
                                body += part.get_payload(decode=True).decode(errors='replace', encoding='latin-1')
                    else:
                        payload = msg.get_payload(decode=True)
                        if payload:
                            body = payload.decode(errors='replace', encoding='latin-1')

                    full_text = f"Subject: {subject}\n{body}"
                    writer.writerow([full_text, "phishing"])
