"""
PhishGuard AI — Model Generator
Produces phishing_model.pkl with 12 features matching app.py extract_features().
Run once: python generate_model.py
"""
import pickle, numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# 12 features:
# url_length, dot_count, hyphen_count, slash_count,
# at_count, question_count, equals_count, digit_count,
# uses_https, keyword_count, subdomain_depth, tld_suspicious

np.random.seed(42)
N = 1000

# ── SAFE samples ─────────────────────────────────────────────────────────────
safe = np.column_stack([
    np.random.randint(15, 55,  N),   # url_length
    np.random.randint(1,  4,   N),   # dot_count
    np.random.randint(0,  2,   N),   # hyphen_count
    np.random.randint(1,  5,   N),   # slash_count
    np.zeros(N, int),                # at_count
    np.random.randint(0,  2,   N),   # question_count
    np.random.randint(0,  2,   N),   # equals_count
    np.random.randint(0,  5,   N),   # digit_count
    np.ones(N, int),                 # uses_https
    np.random.randint(0,  2,   N),   # keyword_count
    np.zeros(N, int),                # subdomain_depth
    np.zeros(N, int),                # tld_suspicious
])

# ── PHISHING samples ──────────────────────────────────────────────────────────
phish = np.column_stack([
    np.random.randint(80,  220, N),  # url_length
    np.random.randint(4,   10,  N),  # dot_count
    np.random.randint(3,   8,   N),  # hyphen_count
    np.random.randint(4,   12,  N),  # slash_count
    np.random.randint(0,   2,   N),  # at_count
    np.random.randint(1,   5,   N),  # question_count
    np.random.randint(1,   6,   N),  # equals_count
    np.random.randint(6,   22,  N),  # digit_count
    np.zeros(N, int),                # uses_https
    np.random.randint(3,   9,   N),  # keyword_count
    np.random.randint(2,   5,   N),  # subdomain_depth
    np.random.randint(0,   2,   N),  # tld_suspicious
])

X = np.vstack([safe, phish])
y = np.array([0]*N + [1]*N)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

clf = RandomForestClassifier(n_estimators=150, max_depth=12, random_state=42, n_jobs=-1)
clf.fit(X_train, y_train)

acc = clf.score(X_test, y_test)
print(f"Test accuracy : {acc:.4f}")

with open("phishing_model.pkl", "wb") as f:
    pickle.dump(clf, f)

print("Saved: phishing_model.pkl")
print(f"Features expected: {clf.n_features_in_}")
