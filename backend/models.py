# models.py
from extensions import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash


class User(db.Model):
    __tablename__ = 'users'
    
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(45), nullable=False)
    email = db.Column(db.String(45), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=True)
    auth_provider = db.Column(db.String(20), default='local')
    google_id = db.Column(db.String(255), unique=True, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)

    scans = db.relationship('Scan', backref='user', lazy=True)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


class Scan(db.Model):
    __tablename__ = 'scans'

    scan_id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(255), nullable=False)
    start_time = db.Column(db.DateTime, default=datetime.now)
    end_time = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(15), default='Pending')
    
    progress = db.Column(db.Integer, default=0)
    current_phase = db.Column(db.String(100), nullable=True)
    error_message = db.Column(db.Text, nullable=True)
    scope_mode = db.Column(db.String(20), default='wildcard')
    
    users_user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)

    result = db.relationship('ScanResult', backref='scan', uselist=False, cascade="all, delete-orphan")


class ScanResult(db.Model):
    __tablename__ = 'scan_results'

    result_id = db.Column(db.Integer, primary_key=True)
    summary = db.Column(db.Text, nullable=True)
    total_vulnerabilities = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.now)

    scans_scan_id = db.Column(db.Integer, db.ForeignKey('scans.scan_id'), unique=True, nullable=False)

    vulnerabilities = db.relationship('Vulnerability', backref='result', lazy=True, cascade="all, delete-orphan")
    recon_data = db.relationship('ReconData', backref='result', lazy=True, cascade="all, delete-orphan")


class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'

    vuln_id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(100), nullable=False)
    vuln_name = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(10), default='Low')
    description = db.Column(db.Text, nullable=True)
    recommendation = db.Column(db.Text, nullable=True)

    scan_results_result_id = db.Column(db.Integer, db.ForeignKey('scan_results.result_id'), nullable=False)

    poc = db.relationship('PoC', backref='vulnerability', uselist=False, cascade="all, delete-orphan")


class PoC(db.Model):
    __tablename__ = 'pocs'

    poc_id = db.Column(db.Integer, primary_key=True)
    payload = db.Column(db.Text, nullable=True)
    response = db.Column(db.Text, nullable=True)
    http_method = db.Column(db.String(10), default='GET')

    vulnerabilities_vuln_id = db.Column(db.Integer, db.ForeignKey('vulnerabilities.vuln_id'), unique=True, nullable=False)


class ReconData(db.Model):
    __tablename__ = 'recon_data'

    recon_id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(100), nullable=False)
    item = db.Column(db.String(255), nullable=False)
    details = db.Column(db.Text, nullable=True)

    scan_results_result_id = db.Column(db.Integer, db.ForeignKey('scan_results.result_id'), nullable=False)
