import os
import email
from email import policy, parser
from bs4 import BeautifulSoup
from collections import defaultdict

# === Define categories and indicative keywords ===
CATEGORY_KEYWORDS = {
    "Impersonation": ["ceo", "urgent", "hr", "invoice", "request", "wire", "payment", "accounting", "boss"],
    "Phishing": ["verify", "update account", "password reset", "confirm", "bank", "login", "click here", "security alert"],
    "Promotional Ads": ["lose weight", "discount", "free trial", "special offer", "buy now", "order now", "sale", "fat burner"]
}

def extract_eml_text(eml_path):
    try:
        with open(eml_path, 'rb') as f:
            msg = email.parser.BytesParser(policy=policy.default).parse(f)

        subject = msg['Subject'] or ''
        body = ''

        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                try:
                    if ctype == 'text/plain':
                        body = part.get_content()
                        break
                    elif ctype == 'text/html' and not body:
                        html = part.get_content()
                        body = BeautifulSoup(html, 'html.parser').get_text()
                except Exception:
                    continue
        else:
            try:
                ctype = msg.get_content_type()
                if ctype == 'text/plain':
                    body = msg.get_content()
                elif ctype == 'text/html':
                    html = msg.get_content()
                    body = BeautifulSoup(html, 'html.parser').get_text()
            except Exception:
                return ""  

        return f"{subject}\n{body}"

    except Exception as e:
        print(f"[ERROR] {eml_path}: {e}")
        return "" 


def classify_email(text):
    text = text.lower()
    scores = {category: 0 for category in CATEGORY_KEYWORDS}

    for category, keywords in CATEGORY_KEYWORDS.items():
        for keyword in keywords:
            if keyword in text:
                scores[category] += 1

    # Return highest scoring category or 'Uncategorized'
    best_category = max(scores, key=scores.get)
    return best_category if scores[best_category] > 0 else "Uncategorized"

def process_folder(folder_path):
    results = defaultdict(list)

    for fname in os.listdir(folder_path):
        if not os.path.isfile(os.path.join(folder_path, fname)):
            continue
        path = os.path.join(folder_path, fname)
        content = extract_eml_text(path)
        category = classify_email(content)
        results[category].append(fname)

    return results

# === Run this ===
if __name__ == "__main__":
    FOLDER_PATH = "20050311_spam_2"
    results = process_folder(FOLDER_PATH)

    output_path = "categorized_results.txt"

    with open(output_path, "w", encoding="utf-8") as f:
        for category, files in results.items():
            f.write(f"\n{category} ({len(files)} emails):\n")
            for fname in files:
                f.write(f"  - {fname}\n")