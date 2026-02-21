# PhishingCheck4U
Hosted Email Phishing Detection and OSINT Intelligence Service

## Project Structure
```
PhishingCheck4U/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── config.py
│   ├── email_reader.py
│   ├── parser.py
│   ├── scoring_engine.py
│   ├── osint_module.py
│   ├── report_generator.py
│   ├── email_responder.py
│   ├── database.py
│   └── utils.py
├── start.py
├── run.bat
├── requirements.txt
├── .env.example
└── README.md
```

## Setup (Windows)

### Step 1: Install dependencies
```
pip install -r requirements.txt
```

### Step 2: Configure environment
```
copy .env.example .env
notepad .env
```
Fill in EMAIL_ADDRESS and EMAIL_APP_PASSWORD.

### Step 3: Run
```
.\venv\Scripts\python.exe start.py
```
Or double-click run.bat

### Step 4: Open API docs
http://localhost:8000/docs

## Gmail App Password Setup
1. Enable 2FA on your Google account
2. Go to: https://myaccount.google.com/apppasswords
3. Create a new app password named "PhishingCheck4U"
4. Copy the 16-character password into .env

## API Endpoints
- GET  /health       - Service health check
- POST /analyze      - Analyze an email for phishing
- GET  /logs         - View recent analysis history
- POST /trigger-poll - Manually poll inbox

## Risk Score Bands
- 0-25   Safe
- 26-50  Low Suspicion
- 51-75  Suspicious
- 76-100 Likely Phishing
