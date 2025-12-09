# backend/models.py
from extensions import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# 1. TABEL USER (Untuk Login)
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    scans = db.relationship('ScanHistory', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# 2. TABEL SCAN HISTORY (Riwayat Scan)
class ScanHistory(db.Model):
    __tablename__ = 'scan_history'

    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(200), nullable=False)
    
    # Status: 'Pending', 'Running', 'Completed', 'Failed'
    status = db.Column(db.String(20), default='Pending') 
    scan_date = db.Column(db.DateTime, default=datetime.now)
    finished_at = db.Column(db.DateTime, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    vulns = db.relationship('Vulnerability', backref='scan', lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "target": self.target_url,
            "status": self.status,
            "date": self.scan_date.strftime("%Y-%m-%d %H:%M"),
            "vuln_count": len(self.vulns)
        }

# 3. TABEL VULNERABILITY (Detail Temuan)
class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'

    id = db.Column(db.Integer, primary_key=True)
    
    # Jenis Celah: 'SQL Injection', 'XSS', 'Open Port'
    vuln_type = db.Column(db.String(100), nullable=False)
    
    # Tingkat Bahaya: 'Critical', 'High', 'Medium', 'Low', 'Info'
    severity = db.Column(db.String(20), default='Low')
    proof = db.Column(db.Text, nullable=True)
    description = db.Column(db.Text, nullable=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan_history.id'), nullable=False)

    def to_dict(self):
        return {
            "type": self.vuln_type,
            "severity": self.severity,
            "proof": self.proof,
            "desc": self.description
        }