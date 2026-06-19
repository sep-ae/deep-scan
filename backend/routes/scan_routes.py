from flask import Blueprint, jsonify, request, send_file
from extensions import db
from models import Scan, ScanResult, Vulnerability
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime
from sqlalchemy import desc
from urllib.parse import urlparse
import validators
import ipaddress
import socket
import pytz
import logging
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.units import inch
from io import BytesIO
import threading
from core.scanner_engine import ScannerEngine
from core.report_generator import generate_pdf_report
from extensions import limiter

logger = logging.getLogger(__name__)

scan_bp = Blueprint('scan', __name__, url_prefix='/api/scan')


@scan_bp.before_request
def handle_preflight():
    """Otomatis jawab 200 untuk semua CORS preflight (OPTIONS) agar tidak diblokir JWT."""
    if request.method == 'OPTIONS':
        return '', 200


# Jaringan IP internal yang diblokir untuk mencegah SSRF
BLOCKED_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),       # Loopback
    ipaddress.ip_network('10.0.0.0/8'),        # Private Class A
    ipaddress.ip_network('172.16.0.0/12'),     # Private Class B
    ipaddress.ip_network('192.168.0.0/16'),    # Private Class C
    ipaddress.ip_network('169.254.0.0/16'),    # Link-local / AWS metadata
    ipaddress.ip_network('0.0.0.0/8'),         # Non-routable
    ipaddress.ip_network('100.64.0.0/10'),     # Shared address space
    ipaddress.ip_network('::1/128'),           # IPv6 loopback
    ipaddress.ip_network('fc00::/7'),          # IPv6 private
]

BLOCKED_HOSTNAMES = {'localhost', 'metadata.google.internal', 'instance-data'}


def is_valid_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return validators.url(url), url


def is_internal_target(url):
    """Cek apakah URL mengarah ke IP internal / localhost (SSRF protection)."""
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return True

        # Cek hostname yang diblokir
        if hostname.lower() in BLOCKED_HOSTNAMES:
            return True

        # Resolve hostname ke IP dan cek apakah internal
        resolved_ip = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(resolved_ip)
        return any(ip in net for net in BLOCKED_NETWORKS)
    except (socket.gaierror, ValueError):
        return False


def get_local_time():
    jakarta_tz = pytz.timezone('Asia/Jakarta')
    return datetime.now(jakarta_tz)


@scan_bp.route('/start', methods=['POST'])
@jwt_required()
@limiter.limit("5 per hour")
def start_scan():
    """
    Mulai Scan Baru
    ---
    tags:
      - Scan
    security:
      - Bearer: []
    summary: Memulai proses scanning target
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - target_url
            properties:
              target_url:
                type: string
                example: https://example.com
    responses:
      201:
        description: Scan berhasil dimulai
        schema:
          type: object
          properties:
            msg:
              type: string
            scan_id:
              type: integer
            target:
              type: string
            status:
              type: string
      400:
        description: Input tidak valid
      401:
        description: Unauthorized
      500:
        description: Gagal memulai scan
    """
    user_id = get_jwt_identity()
    data = request.json
    target_url = data.get('target_url', '').strip()
    scope_mode = data.get('scope_mode', 'wildcard').strip()

    if scope_mode not in ('strict', 'wildcard'):
        scope_mode = 'wildcard'

    if not target_url:
        return jsonify({"msg": "URL Target wajib diisi"}), 400

    is_valid, normalized_url = is_valid_url(target_url)
    if not is_valid:
        return jsonify({"msg": "Format URL tidak valid"}), 400

    # SSRF Protection: Blokir scan ke IP internal / localhost
    if is_internal_target(normalized_url):
        logger.warning(f"[SSRF BLOCKED] user_id={user_id} tried to scan internal target: {normalized_url}")
        return jsonify({"msg": "Tidak diizinkan memindai alamat internal atau localhost"}), 403

    # Cek apakah user masih punya scan yang berjalan (Batasan 1 active scan per user)
    active_scan = Scan.query.filter(
        Scan.users_user_id == int(user_id),
        Scan.status.in_(['pending', 'running'])
    ).first()

    if active_scan:
        return jsonify({
            "msg": "Harap tunggu pemindaian sebelumnya selesai atau batalkan terlebih dahulu.",
            "active_scan_id": active_scan.scan_id
        }), 409

    new_scan = Scan(
        target_url=normalized_url,
        users_user_id=int(user_id),
        status='pending',
        start_time=get_local_time(),
        progress=0,
        current_phase='Waiting to start...',
        scope_mode=scope_mode,
    )

    try:
        db.session.add(new_scan)
        db.session.commit()

        def run_scan_async(scan_id):
            from app import create_app
            app = create_app()
            with app.app_context():
                engine = ScannerEngine(scan_id)
                engine.run()

        scan_thread = threading.Thread(
            target=run_scan_async,
            args=(new_scan.scan_id,)
        )
        scan_thread.daemon = True
        scan_thread.start()

        return jsonify({
            "msg": "Scan berhasil dimulai",
            "scan_id": new_scan.scan_id,
            "target": normalized_url,
            "status": "pending"
        }), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"[SCAN START ERROR] user_id={user_id} | {e}")
        return jsonify({"msg": "Gagal memulai scan"}), 500


@scan_bp.route('/active', methods=['GET'])
@jwt_required()
def get_active_scan():
    """Mengecek apakah user memiliki scan yang sedang berjalan."""
    user_id = get_jwt_identity()
    active_scan = Scan.query.filter(
        Scan.users_user_id == int(user_id),
        Scan.status.in_(['pending', 'running'])
    ).first()

    if active_scan:
        return jsonify({
            "has_active_scan": True,
            "scan_id": active_scan.scan_id,
            "target": active_scan.target_url,
            "progress": active_scan.progress,
            "status": active_scan.status
        }), 200
    
    return jsonify({"has_active_scan": False}), 200


@scan_bp.route('/cancel/<int:scan_id>', methods=['POST', 'OPTIONS'])
@jwt_required()
def cancel_scan(scan_id):
    """Membatalkan paksa scan yang sedang berjalan."""
    user_id = get_jwt_identity()
    scan = Scan.query.filter_by(scan_id=scan_id, users_user_id=int(user_id)).first()

    if not scan:
        return jsonify({"msg": "Scan tidak ditemukan"}), 404

    if scan.status in ['completed', 'failed', 'cancelled']:
        return jsonify({"msg": f"Scan sudah dalam status {scan.status}"}), 400

    try:
        scan.status = 'cancelled'
        scan.end_time = get_local_time()
        scan.error_message = "Dibatalkan oleh pengguna"
        db.session.commit()
        return jsonify({"msg": "Scan berhasil dibatalkan"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": "Gagal membatalkan scan", "error": str(e)}), 500


@scan_bp.route('/status/<int:scan_id>', methods=['GET'])
@jwt_required()
@limiter.limit("500 per hour") 
def get_scan_status(scan_id):
    """
    Ambil Status Scan
    ---
    tags:
      - Scan
    security:
      - Bearer: []
    summary: Melihat progress scan secara realtime
    parameters:
      - name: scan_id
        in: path
        required: true
        type: integer
    responses:
      200:
        description: Status scan
      404:
        description: Scan tidak ditemukan
      401:
        description: Unauthorized
    """
    user_id = get_jwt_identity()

    scan = Scan.query.filter_by(
        scan_id=scan_id,
        users_user_id=int(user_id)
    ).first()

    if not scan:
        return jsonify({"msg": "Scan tidak ditemukan"}), 404

    db.session.refresh(scan)
    return jsonify({
        "scan_id": scan.scan_id,
        "target": scan.target_url,
        "status": scan.status,
        "progress": scan.progress or 0,
        "current_phase": scan.current_phase or "Initializing...",
        "start_time": scan.start_time.strftime("%Y-%m-%d %H:%M:%S") if scan.start_time else None,
        "end_time": scan.end_time.strftime("%Y-%m-%d %H:%M:%S") if scan.end_time else None,
        "error_message": scan.error_message
    }), 200


@scan_bp.route('/history', methods=['GET'])
@jwt_required()
def get_all_scans():
    """
    Ambil Semua Riwayat Scan
    ---
    tags:
      - Scan
    security:
      - Bearer: []
    summary: Menampilkan seluruh riwayat scan user
    responses:
      200:
        description: List riwayat scan
      401:
        description: Unauthorized
    """
    user_id = get_jwt_identity()

    all_scans = Scan.query.filter_by(users_user_id=int(user_id))\
        .order_by(desc(Scan.start_time))\
        .all()

    scans_data = []
    for scan in all_scans:
        scans_data.append({
            "scan_id": scan.scan_id,
            "target": scan.target_url,
            "status": scan.status,
            "date": scan.start_time.strftime("%d %b %Y, %H:%M") if scan.start_time else "N/A",
            "vuln_count": scan.result.total_vulnerabilities if scan.result else 0,
            "start_time": scan.start_time.isoformat() if scan.start_time else None
        })

    return jsonify(scans_data), 200


@scan_bp.route('/<int:scan_id>', methods=['GET'])
@jwt_required()
def get_scan_detail(scan_id):
    """
    Ambil Detail Scan
    ---
    tags:
      - Scan
    security:
      - Bearer: []
    summary: Melihat detail hasil scan termasuk vulnerability dan recon
    parameters:
      - name: scan_id
        in: path
        required: true
        type: integer
    responses:
      200:
        description: Detail scan
      404:
        description: Scan tidak ditemukan
      401:
        description: Unauthorized
    """
    user_id = get_jwt_identity()

    scan = Scan.query.filter_by(
        scan_id=scan_id,
        users_user_id=int(user_id)
    ).first()

    if not scan:
        return jsonify({"msg": "Scan tidak ditemukan"}), 404

    result_data = None
    vulnerabilities_data = []
    recon_data_list = []

    if scan.result:
        result_data = {
            "total_vulnerabilities": scan.result.total_vulnerabilities,
            "high_severity": 0,
            "medium_severity": 0,
            "low_severity": 0,
            "summary": scan.result.summary
        }

        if scan.result.vulnerabilities:
            for vuln in scan.result.vulnerabilities:
                poc_data = None
                if vuln.poc:
                    poc_data = {
                        "payload": vuln.poc.payload,
                        "response": vuln.poc.response,
                        "http_method": vuln.poc.http_method,
                    }

                vulnerabilities_data.append({
                    "vuln_id": vuln.vuln_id,
                    "name": vuln.vuln_name,
                    "category": vuln.category,
                    "severity": vuln.severity,
                    "description": vuln.description,
                    "recommendation": vuln.recommendation,
                    "poc": poc_data,
                })

                if vuln.severity.lower() in ('high', 'critical'):
                    result_data['high_severity'] += 1
                elif vuln.severity.lower() == 'medium':
                    result_data['medium_severity'] += 1
                elif vuln.severity.lower() == 'low':
                    result_data['low_severity'] += 1


        if scan.result.recon_data:
            for recon in scan.result.recon_data:
                recon_data_list.append({
                    "recon_id": recon.recon_id,
                    "category": recon.category,
                    "item": recon.item,
                    "details": recon.details
                })

    return jsonify({
        "scan_id": scan.scan_id,
        "target": scan.target_url,
        "status": scan.status,
        "start_time": scan.start_time.strftime("%d %b %Y, %H:%M:%S") if scan.start_time else None,
        "end_time": scan.end_time.strftime("%d %b %Y, %H:%M:%S") if scan.end_time else None,
        "duration": str(scan.end_time - scan.start_time) if scan.end_time and scan.start_time else None,
        "result": result_data,
        "vulnerabilities": vulnerabilities_data,
        "recon_data": recon_data_list
    }), 200


@scan_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_scan_stats():
    """
    Statistik Scan User
    ---
    tags:
      - Scan
    security:
      - Bearer: []
    summary: Mengambil statistik scan berdasarkan status dan hasil
    responses:
      200:
        description: Statistik scan
      401:
        description: Unauthorized
    """
    user_id = get_jwt_identity()

    user_scans = Scan.query.filter_by(users_user_id=int(user_id)).all()

    total_scan = len(user_scans)
    vulnerable_count = 0
    secure_count = 0
    pending_count = 0
    failed_count = 0

    for scan in user_scans:
        if scan.status == 'pending':
            pending_count += 1
        elif scan.status == 'failed':
            failed_count += 1
        elif scan.result:
            if scan.result.total_vulnerabilities > 0:
                vulnerable_count += 1
            else:
                secure_count += 1

    return jsonify({
        "total": total_scan,
        "vulnerable": vulnerable_count,
        "secure": secure_count,
        "pending": pending_count,
        "failed": failed_count
    }), 200


@scan_bp.route('/<int:scan_id>/report', methods=['GET'])
@jwt_required()
def download_report(scan_id):
    user_id = get_jwt_identity()
    scan = Scan.query.filter_by(
        scan_id=scan_id,
        users_user_id=int(user_id)
    ).first()

    if not scan:
        return jsonify({"msg": "Scan tidak ditemukan"}), 404

    buffer, filename = generate_pdf_report(scan)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,  
        mimetype='application/pdf'
    )