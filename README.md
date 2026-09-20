# CareerPath-Pro

A Flask web app that helps users figure out a career direction: it runs AI-generated
self-assessments, analyses an uploaded resume, and pulls matching job listings.

## Features

- **Accounts** — registration and login with Flask-Login, passwords hashed with PBKDF2-SHA256.
- **Self-assessment** — Google Gemini generates questions for a chosen domain, scores
  answers across categories (Creativity, Public Speaking, Mathematics, Leadership,
  Management) and writes back dynamic insights. Past assessments are saved per user.
- **Resume analysis** — upload a PDF, DOCX or image. Text is extracted with PyPDF2,
  python-docx, or Tesseract OCR (via pdf2image for scanned PDFs), then sent to Gemini
  for feedback and improvement tips. The file is stored against the user record.
- **Job search** — scrapes LinkedIn's public job search for a query and location.
- **Dashboard** — assessment history and score charts.

## Tech stack

Flask · Flask-Login · Flask-SQLAlchemy · PostgreSQL · Google Gemini
(`google-generativeai`) · Tesseract OCR · Poppler · BeautifulSoup · gunicorn · Docker

## Configuration

Copy the example file and fill in real values:

```bash
cp .env.example .env
```

| Variable | Required | Purpose |
|---|---|---|
| `FLASK_SECRET_KEY` | yes | Signs session cookies. Generate per environment: `python -c "import secrets; print(secrets.token_hex(32))"` |
| `DATABASE_URL` | yes | SQLAlchemy connection string |
| `GOOGLE_GENAI_API_KEY` | yes | Google Gemini API key |
| `LINKEDIN_TOKEN` | no | Read by `app.py` but not used by any code path yet |

The app refuses to start if `FLASK_SECRET_KEY` or `DATABASE_URL` is missing, rather
than falling back to an insecure default.

**Never commit `.env`.** It is in `.gitignore`.

## Running locally

### With Docker (recommended — OCR dependencies are already in the image)

```bash
docker build -t careerpath-pro .
docker run -p 5000:5000 --env-file .env careerpath-pro
```

Open http://localhost:5000

### Without Docker

Requires Python 3.11+, plus **Tesseract OCR** and **Poppler** installed on the system
(the resume OCR path depends on both).

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Set `FLASK_DEBUG=1` if you want the reloader and debugger. Leave it unset otherwise —
the Werkzeug debugger allows code execution from the browser and must never be enabled
on anything reachable from outside your machine.

## Deployment

The image is based on `python:3.11-slim` and installs the system packages the OCR
pipeline needs (`tesseract-ocr`, `poppler-utils`). Python dependencies install from
`requirements.txt` in their own layer before the application code is copied, so
rebuilds reuse the cached dependency layer instead of reinstalling everything on
every code change.

The container serves the app with gunicorn (4 workers), binding to `$PORT` when the
host provides one and falling back to 5000 locally:

```
gunicorn -w 4 -b 0.0.0.0:${PORT:-5000} app:app
```

`.dockerignore` keeps `.env`, the local database, uploaded files and git history out
of the image.

Hosted on **Render**. Set every variable from `.env.example` in the Render dashboard —
the `.env` file is not shipped in the image.

### Note on uploads

Render's filesystem is ephemeral, so files written to `uploads/` do not survive a
redeploy. The durable copy is the one stored in the `resume` table.

## Contributors

- [Jyoti Prajapati](https://github.com/Jyotiprajapati6305) — application
- [Kashyap Patel](https://github.com/Kashyap-001) — containerisation and deployment
