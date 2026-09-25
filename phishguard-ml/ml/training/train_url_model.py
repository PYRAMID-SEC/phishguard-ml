import argparse
from pathlib import Path
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, precision_score, recall_score, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split
from backend.app.utils.url_features import extract_url_features
from backend.app.ml.predictor import FEATURE_NAMES

def main():
    parser = argparse.ArgumentParser(); parser.add_argument('csv'); parser.add_argument('--output', default='backend/models/url_model.joblib'); args = parser.parse_args()
    data = pd.read_csv(args.csv)
    required = {'url', 'label'}
    if not required.issubset(data.columns): raise ValueError(f'CSV must contain {required}')
    data = data.dropna(subset=['url', 'label'])
    x = pd.DataFrame([extract_url_features(value) for value in data.url])[FEATURE_NAMES]
    y = data.label.astype(int)
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=.2, random_state=42, stratify=y)
    model = RandomForestClassifier(n_estimators=300, random_state=42, class_weight='balanced', n_jobs=-1)
    model.fit(x_train, y_train); predictions = model.predict(x_test); probabilities = model.predict_proba(x_test)[:, 1]
    print(classification_report(y_test, predictions)); print('precision', precision_score(y_test, predictions), 'recall', recall_score(y_test, predictions), 'f1', f1_score(y_test, predictions), 'roc_auc', roc_auc_score(y_test, probabilities)); print('confusion_matrix\n', confusion_matrix(y_test, predictions))
    output = Path(args.output); output.parent.mkdir(parents=True, exist_ok=True); joblib.dump(model, output); output.with_suffix('.features.txt').write_text('\n'.join(FEATURE_NAMES))
if __name__ == '__main__': main()
