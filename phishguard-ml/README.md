# PhishGuard ML

PhishGuard ML is a defensive research and educational platform for analyzing potential phishing signals in URLs, email messages, `.eml` files, HTML, IP addresses, and domains. It is intentionally static: it never visits submitted URLs, renders uploaded HTML, executes JavaScript, opens attachments, scans ports, or attacks a host.

## Features

- URL feature extraction with an optional Random Forest model and conservative fallback heuristics.
- Email and `.eml` parsing with header mismatch, urgency, financial language, attachment, and link checks.
- Static BeautifulSoup HTML analysis for forms, password fields, scripts, iframes, and external destinations.
- Local-only IP/domain checks for malformed syntax, private addresses, punycode, depth, and unusual TLDs.
- SQLite history stores metadata and results, not full email bodies by default.
- Next.js dashboard with transparent findings, extracted features, and recommendations.

## Architecture

`frontend/` is a Next.js App Router client. `backend/` is a FastAPI service. `ml/` contains reproducible training scripts. The frontend calls `/api/analyze/*`; the backend returns one unified result schema and writes metadata to SQLite.

## Install and run

```bash
cd backend
python3.11 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:3000. The complete stack can also be started with `docker compose up`.

## Training

Keep datasets private and outside Git. URL CSVs require `url,label`; email CSVs require `text,label`. Train with:

```bash
PYTHONPATH=. python ml/training/train_url_model.py path/to/urls.csv
PYTHONPATH=. python ml/training/train_email_model.py path/to/emails.csv
```

Metrics printed include precision, recall, F1, ROC-AUC, and a confusion matrix. No unsupported accuracy claims are made. Model binaries and datasets are ignored by Git.

## API

- `POST /api/analyze/url` with `{ "url": "https://example.com" }`
- `POST /api/analyze/email` with subject, body, sender, and reply_to
- `POST /api/analyze/eml` multipart `.eml` upload
- `POST /api/analyze/html` multipart HTML upload
- `POST /api/analyze/ip` with `{ "value": "192.0.2.1" }`
- `POST /api/analyze/domain` with `{ "value": "example.com" }`
- `GET /api/history`
- `GET /api/health`

## Testing and build

```bash
cd backend && pytest ../tests
cd frontend && npm run build
```

## Security considerations and limitations

Inputs are untrusted and bounded by length and a 5 MB file limit. Parsing is static, attachments are not opened, and no submitted host is contacted. CORS is limited to local frontend origins. Configure deployment secrets through environment variables. Results are probabilistic signals, not verdicts; a low-risk result does not prove safety and a high-risk result does not establish malicious intent.

## Screenshots

Add deployment screenshots here when the research portfolio is published.

## Future improvements

Calibrate trained probabilities, add privacy-preserving enrichment as a separately permissioned service, add authenticated multi-user history, expand language coverage, and evaluate against a documented, representative dataset.
