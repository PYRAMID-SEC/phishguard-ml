# Model training

Place private CSV datasets outside Git-tracked paths. URL data uses `url,label`; email data uses `text,label`, with `0` for legitimate and `1` for phishing.

From the repository root:

```bash
PYTHONPATH=. python ml/training/train_url_model.py path/to/urls.csv
PYTHONPATH=. python ml/training/train_email_model.py path/to/emails.csv
```

The scripts use a reproducible stratified split, report precision, recall, F1, ROC-AUC, and a confusion matrix, then save joblib artifacts under `backend/models/` (ignored by Git).