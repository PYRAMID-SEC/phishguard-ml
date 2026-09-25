import argparse
from pathlib import Path
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, precision_score, recall_score, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

def main():
    parser = argparse.ArgumentParser(); parser.add_argument('csv'); parser.add_argument('--output', default='backend/models/email_model.joblib'); args = parser.parse_args()
    data = pd.read_csv(args.csv)
    if not {'text', 'label'}.issubset(data.columns): raise ValueError("CSV must contain {'text', 'label'}")
    data = data.dropna(subset=['text', 'label']); x_train, x_test, y_train, y_test = train_test_split(data.text, data.label.astype(int), test_size=.2, random_state=42, stratify=data.label)
    model = Pipeline([('tfidf', TfidfVectorizer(ngram_range=(1, 2), min_df=1, max_features=50_000)), ('classifier', LogisticRegression(max_iter=1000, random_state=42))]); model.fit(x_train, y_train)
    predictions = model.predict(x_test); probabilities = model.predict_proba(x_test)[:, 1]; print(classification_report(y_test, predictions)); print('precision', precision_score(y_test, predictions), 'recall', recall_score(y_test, predictions), 'f1', f1_score(y_test, predictions), 'roc_auc', roc_auc_score(y_test, probabilities)); print('confusion_matrix\n', confusion_matrix(y_test, predictions)); output = Path(args.output); output.parent.mkdir(parents=True, exist_ok=True); joblib.dump(model, output)
if __name__ == '__main__': main()
