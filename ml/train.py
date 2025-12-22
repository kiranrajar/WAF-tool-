import numpy as np
import joblib
import os
from sklearn.ensemble import IsolationForest

def calculate_entropy(text):
    if not text: return 0
    probabilities = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * np.log2(p) for p in probabilities)

def extract_features(payload):
    length = len(payload)
    special_chars = len([c for c in payload if c in "',<>()[]{}!@#$%^&*+-=/\\|_"])
    special_density = special_chars / length if length > 0 else 0
    sql_keywords = sum(1 for word in ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION', 'OR 1=1', '--'] if word in payload.upper())
    xss_keywords = sum(1 for word in ['<SCRIPT>', 'ALERT(', 'ONLOAD=', 'ONERROR=', 'JAVASCRIPT:', 'IMG', 'SVG'] if word in payload.upper())
    encoded_chars = payload.count('%')
    entropy = calculate_entropy(payload)
    return [length, special_density, sql_keywords, xss_keywords, encoded_chars, entropy]

def generate_data():
    data = []
    for _ in range(2000):
        length = np.random.randint(5, 100)
        payload = "".join(np.random.choice(list("abcdefghijklmnopqrstuvwxyz0123456789/._-"), length))
        data.append(extract_features(payload))
    attacks = [
        "' OR 1=1 --", "<script>alert(1)</script>", "../../etc/passwd", "exec('id')",
        "UNION SELECT NULL,NULL--", "<img src=x onerror=alert(1)>", "admin'--"
    ]
    for a in attacks: data.append(extract_features(a))
    return np.array(data)

if __name__ == "__main__":
    X = generate_data()
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X)
    joblib.dump(model, os.path.join(os.path.dirname(__file__), "model.pkl"))
    print("Model persistent.")
