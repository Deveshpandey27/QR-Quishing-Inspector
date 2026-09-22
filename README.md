# QR Quishing Inspector (v2.0)

[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg?style=flat&logo=fastapi)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.12-blue.svg?style=flat&logo=python)](https://python.org)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.5+-orange.svg?style=flat&logo=scikit-learn)](https://scikit-learn.org)
[![Tests](https://img.shields.io/badge/Tests-38%20Passed-brightgreen.svg)](#testing)
[![OpenAPI](https://img.shields.io/badge/OpenAPI-3.1-informational.svg)](/docs)

A professional cybersecurity web application and REST API designed to detect **QR Phishing (Quishing)** attacks and malicious destination URLs using a hybrid detection engine of explainable heuristics and machine learning.

---

## 🎯 Project Overview
Quishing (QR Phishing) has emerged as a major physical-to-digital attack vector where attackers paste deceptive QR codes in public places, emails, and physical mail to bypass email security gateways and lure victims to credential-harvesting portals.

**QR Quishing Inspector** safeguards users by:
1. Decoding QR codes client-side (`jsQR`) via live webcam video or server-side (`OpenCV` / `pyzbar`) via image file upload.
2. Canonicalizing and analyzing the target destination using **explainable rule-based cybersecurity heuristics** (60% weight).
3. Classifying lexical and structural patterns using a **calibrated HistGradientBoosting machine learning model** (40% weight) trained on 235,000+ real-world URLs from the PhiUSIIL phishing dataset.
4. Outputting a transparent, actionable **Risk Score (0–100)** with clear threat indicators and reasons.

---

## 📊 Detection Flow Architecture

```text
             QR CODE
                │
                ▼
        ┌─────────────────┐
        │ Camera Scanner  │
        └────────┬────────┘
                 │
                 ▼
          Extract QR data
                 │
                 ▼
        ┌─────────────────┐
        │ URL Normalizer  │
        └────────┬────────┘
                 │
                 ▼
       ┌───────────────────┐
       │ Security Analysis │
       └─────────┬─────────┘
                 │
        ┌────────┴─────────┐
        ▼                  ▼
   Rule Engine          ML Model
        │                  │
        └────────┬─────────┘
                 ▼
          Risk Engine
                 │
                 ▼
       ┌───────────────────┐
       │ Security Report   │
       └───────────────────┘
```

---

## 🛡️ HOW QR QUISHING INSPECTOR WORKS

QR Quishing Inspector implements a comprehensive 7-stage cyber-inspection pipeline designed to detect and block evasive quishing attacks:

| Stage | Name | Core Cyber Functionality |
| :--- | :--- | :--- |
| **01** | **QR Detection** | Detect and decode the QR code via client-side `jsQR` webcam feed or server-side `OpenCV` / `pyzbar` image processing. |
| **02** | **URL Extraction** | Extract and normalize the destination via RFC 3986 canonicalization, scheme validation, and specialized payload routing (Wi-Fi, Mailto, vCard, Plain Text). |
| **03** | **Security Analysis** | Examine URL and domain characteristics across 13 heuristic rules, anti-obfuscation checks (punycode, hex IPs, nested URLs), brand impersonation detection, WHOIS age, DNS records, and TLS certificate validation. |
| **04** | **ML Classification** | Predict phishing probability via a 24-feature supervised `HistGradientBoosting` classifier trained on 235,000+ real-world URLs from the PhiUSIIL corpus with dual-probability output and feature importance explainability. |
| **05** | **Threat Intelligence** | Check available reputation signals across 5 global intelligence feeds (Google Safe Browsing, VirusTotal, URLhaus, PhishTank, and OpenPhish). |
| **06** | **Risk Engine** | Combine signals into a risk score using validation-calibrated empirical weights (35% Rule Heuristics + 45% Machine Learning + 20% Domain Signals) to yield a standardized 0–100 composite risk score. |
| **07** | **Security Recommendation** | Explain what the user should do with unambiguous actionable guidance (`LOW RISK`, `SUSPICIOUS`, `HIGH RISK`) and proactive user education against credential harvesting. |

### Actionable Security Guidance ("What should I do?")
- **✓ LOW RISK**: No significant indicators were detected. Still verify the destination before entering credentials or payment information.
- **⚠ SUSPICIOUS**: The URL contains characteristics commonly associated with phishing. Recommendation: Avoid entering sensitive information.
- **🚨 HIGH RISK**: Multiple phishing indicators were detected. Recommendation: Do not open the destination. Do not enter passwords, OTPs, card details, or banking information.

### User Education ("WHY IS THIS DANGEROUS?")
Contextual security advisory educating users on physical-to-digital attack vectors:
> **WHY IS THIS DANGEROUS?**
> QR phishing attacks can hide the destination URL from the user until the QR code is scanned.
> Never enter:
> • passwords
> • OTPs
> • banking credentials
> • card information
> unless you have verified the destination.

---

## 📁 Repository Structure

```text
QR-Quishing-Inspector/
│
├── app/
│   ├── main.py                        # FastAPI application & lifespan management
│   ├── api/
│   │   └── routes/
│   │       ├── analysis.py            # POST /api/v1/analyze, /api/v1/scan-image
│   │       ├── health.py              # GET /api/v1/health
│   │       └── pages.py               # GET / (Web Dashboard)
│   ├── detection/
│   │   ├── normalizer.py              # URL normalization & domain parsing
│   │   ├── features.py                # 24 ML feature extractors
│   │   ├── rules.py                   # Heuristic security rules (shorteners, evasion)
│   │   ├── reputation.py              # Whitelist & brand impersonation engine
│   │   ├── ml.py                      # Pre-trained ML inference
│   │   └── risk_engine.py             # Composite scoring (60% rules + 40% ML)
│   ├── schemas/
│   │   ├── analysis.py                # Request & response Pydantic schemas
│   │   └── health.py                  # Health check schema
│   └── services/
│       ├── qr_service.py              # Computer vision QR decoding (OpenCV / pyzbar)
│       └── inspector_service.py       # Detection orchestrator service
│
├── ml/
│   ├── datasets/
│   │   ├── raw/                       # PhiUSIIL_Phishing_URL_Dataset.csv
│   │   └── processed/                 # urls_dataset.csv, features_cache.csv
│   ├── training/
│   │   ├── prepare_dataset.py         # Dataset ETL script
│   │   ├── train_model.py             # HistGradientBoosting training script
│   │   └── evaluate_model.py          # Out-of-sample evaluation & benchmarks
│   └── models/
│       └── qr_quishing_model.pkl      # Trained model artifact
│
├── templates/
│   └── index.html                     # Responsive web interface
├── static/
│   ├── css/
│   │   └── style.css                  # Responsive CSS with mobile breakpoints
│   └── js/
│       └── scanner.js                 # Webcam & drag-and-drop QR engine
│
├── tests/
│   ├── test_fastapi.py                # API & endpoint tests
│   ├── test_rules.py                  # Security rules & normalizer tests
│   └── test_risk_engine.py            # Composite scoring unit tests
│
├── Dockerfile                         # Production container definition
├── requirements.txt                   # Production dependencies
├── README.md                          # Project documentation
└── .gitignore                         # Git exclusion rules
```

---

## 🚀 Key Features

- **Dual QR Input Engine**:
  - **Live Camera Scanner**: Instant in-browser scanning using HTML5 Canvas & `jsQR`.
  - **Drag-and-Drop Image Uploader**: Server-side decoding supporting PNG, JPG, WEBP, and BMP.
  - **Manual URL Inspector**: Direct URL analysis with keyboard shortcuts and Quick Test targets.
- **Explainable Cybersecurity Heuristics**:
  - URL shortener abuse detection (`bit.ly`, `tinyurl.com`, `t.co`, etc.).
  - Brand impersonation detection across subdomains and deceptive hostnames.
  - IP address host detection (IPv4 / IPv6).
  - Punycode / IDN homograph attack identification (`xn--...`).
  - RFC-compliant `@` symbol credential evasion detection.
  - Double-slash (`//`) evasion and path manipulation flags.
  - Boundary-aware keyword matching eliminating false positives (e.g. `southbank` is never flagged as `bank`).
  - Trusted domain recognition ensuring authentic services (`accounts.google.com/login`) are never misclassified.
- **Robust Machine Learning Model**:
  - Trained on 235,370 URLs from the **PhiUSIIL Phishing Dataset**.
  - Evaluated on a held-out test split of **47,074 samples**:
    - **Accuracy**: 99.47%
    - **Precision**: 99.71%
    - **Recall**: 99.04%
    - **F1-Score**: 0.9937
    - **ROC-AUC**: 0.9975
  - Hostname canonicalization eliminates `www.` shortcut bias.
- **Modern REST API & Interactive Documentation**:
  - Powered by **FastAPI** with async execution and Pydantic v2 validation schemas.
  - Interactive Swagger UI at `/docs` and ReDoc at `/redoc`.
  - Production containerized with multi-stage Docker build.

---

## 🛠️ Technology Stack

- **Backend**: FastAPI, Uvicorn, Pydantic, Starlette, Jinja2
- **Machine Learning**: Scikit-Learn (HistGradientBoostingClassifier), Pandas, NumPy, Joblib
- **Computer Vision & QR Decoding**: OpenCV (`cv2.QRCodeDetector`), `pyzbar`, `jsQR`
- **Frontend**: HTML5, CSS3, JavaScript (ES6+), Bootstrap 5.3.7, Bootstrap Icons
- **Deployment**: Docker, Uvicorn ASGI Server

---

## 📦 Getting Started

### 1. Prerequisites
- Python 3.12+
- Git

### 2. Installation
```powershell
# Clone the repository
git clone https://github.com/your-username/QR-Quishing-Inspector.git
cd QR-Quishing-Inspector

# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/macOS

# Install dependencies
pip install -r requirements.txt
```

### 3. Run the FastAPI Application
```powershell
# Start Uvicorn development server
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Open your browser to:
- **Web Dashboard**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive Swagger Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc Documentation**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)
- **Health Check**: [http://127.0.0.1:8000/api/v1/health](http://127.0.0.1:8000/api/v1/health)

---

## 🧪 Testing

Run the full automated test suite (38 unit and integration tests):
```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

Evaluate the ML model on held-out test data:
```powershell
python ml/training/evaluate_model.py
```

---

## 🐳 Docker Deployment

Build and launch the application in Docker:
```bash
docker build -t qr-quishing-inspector:2.0 .
docker run -p 8000:8000 qr-quishing-inspector:2.0
```

---

## 👤 Author
**Devesh Pandey**  
Cybersecurity & AI Portfolio Project