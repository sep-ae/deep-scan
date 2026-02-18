# Deep-Scan

Deep-Scan adalah aplikasi web security scanner berbasis Python dan Vue.js untuk melakukan pemindaian keamanan komprehensif terhadap website.

## Fitur

- Vulnerability Detection (SQL Injection, XSS, CSRF)
- Port Scanning & Service Detection
- Subdomain Enumeration
- DNS Analysis
- Technology Detection
- CVSS Risk Scoring
- PDF Report Export
- Real-time Progress Tracking
- User Authentication & History

## Tech Stack

Backend: Python, Flask, MySQL, SQLAlchemy, JWT
Frontend: Vue 3, Vite, TailwindCSS, shadcn-vue

## Installation

### Backend
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python run.py

### Frontend
cd frontend
npm install
npm run dev

## Configuration

Create .env in backend folder:
DATABASE_URL=mysql+pymysql://user:pass@localhost/deep_scan


## Usage

1. Register account
2. Login to dashboard
3. Enter target URL
4. Start scan
5. View results in Overview/Reconnaissance/Vulnerabilities/Recommendations tabs
6. Download PDF report

## API Endpoints

POST /api/auth/register
POST /api/auth/login
POST /api/scan/start
GET /api/scan/status/:id
GET /api/scan/:id
GET /api/scan/history
GET /api/scan/:id/report

## Disclaimer

Tool ini untuk educational purposes dan authorized security testing saja. Jangan gunakan tanpa izin.

## License

MIT License
