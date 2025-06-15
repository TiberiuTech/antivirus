import os
import random
import pickle
from core.ml_features import extract_features
from sklearn.ensemble import RandomForestClassifier

print("Începe antrenarea modelului...")

DATA_DIR = "ai_model/demo_data"
MODEL_PATH = "ai_model/model.pkl"

print(f"Se creează directorul pentru date: {DATA_DIR}")
os.makedirs(DATA_DIR, exist_ok=True)

# Generează fișiere curate
print("Se generează fișiere curate...")
for i in range(10):
    with open(os.path.join(DATA_DIR, f"clean_{i}.txt"), "w") as f:
        f.write("Hello, this is a clean file!\n" * random.randint(1, 10))

# Generează fișiere infectate (cu cuvinte cheie suspecte)
print("Se generează fișiere infectate...")
for i in range(10):
    with open(os.path.join(DATA_DIR, f"malware_{i}.exe"), "wb") as f:
        content = b"malicious code " + random.choice([b"powershell", b"cmd.exe", b"curl", b"ftp"]) * 5
        f.write(content)

# Pregătește datele
print("Se pregătesc datele pentru antrenare...")
X = []
y = []
for fname in os.listdir(DATA_DIR):
    path = os.path.join(DATA_DIR, fname)
    print(f"Se extrag caracteristici pentru: {fname}")
    feats = extract_features(path)
    X.append(feats)
    if fname.startswith("malware"):
        y.append(1)  # 1 = malware
    else:
        y.append(0)  # 0 = curat

print(f"Număr de exemple: {len(X)}")
print(f"Număr de caracteristici per exemplu: {len(X[0]) if X else 0}")

# Antrenează modelul
print("Se antrenează modelul...")
clf = RandomForestClassifier(n_estimators=50, random_state=42)
clf.fit(X, y)

# Salvează modelul
print(f"Se salvează modelul în: {MODEL_PATH}")
with open(MODEL_PATH, "wb") as f:
    pickle.dump(clf, f)

print(f"Model antrenat și salvat în {MODEL_PATH}") 