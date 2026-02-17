from flask import Blueprint, jsonify, request, send_file
from extensions import db
from models import Scan, ScanResult, Vulnerability
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime
from sqlalchemy import desc
import validators
import pytz
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.units import inch
from io import BytesIO
import threading

# Import Scanner Engine
from core.scanner_engine import ScannerEngine

scan_bp = Blueprint('scan', __name__, url_prefix='/api/scan')


def is_valid_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return validators.url(url), url


def get_local_time():
    """Get current time in Asia/Jakarta timezone (WIB)"""
    jakarta_tz = pytz.timezone('Asia/Jakarta')
    return datetime.now(jakarta_tz)


@scan_bp.route('/start', methods=['POST'])
@jwt_required()
def start_scan():
    """
    Mulai Scanning Baru
    ---
    tags:
      - Scanning
    security:
      - Bearer: []
    summary: Trigger proses scan
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - target_url
          properties:
            target_url:
              type: string
              example: "https://example.com"
    responses:
      201:
        description: Scan berhasil dimulai
      400:
        description: Validasi gagal
      500:
        description: Server error
    """
    user_id = get_jwt_identity()
    data = request.json
    target_url = data.get('target_url', '').strip()

    if not target_url:
        return jsonify({"msg": "URL Target wajib diisi"}), 400

    is_valid, normalized_url = is_valid_url(target_url)
    if not is_valid:
        return jsonify({"msg": "Format URL tidak valid"}), 400

    new_scan = Scan(
        target_url=normalized_url,
        users_user_id=int(user_id),
        status='pending',
        start_time=get_local_time() 
    )

    try:
        db.session.add(new_scan)
        db.session.commit()
        
        # ✅ TRIGGER SCANNER ENGINE IN BACKGROUND THREAD
        def run_scan_async(scan_id):
            """Run scan in background"""
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
        print(f"Error starting scan: {e}")
        return jsonify({"msg": "Gagal memulai scan", "error": str(e)}), 500


@scan_bp.route('/status/<int:scan_id>', methods=['GET'])
@jwt_required()
def get_scan_status(scan_id):
    """
    Cek Status Scan
    ---
    tags:
      - Scanning
    security:
      - Bearer: []
    summary: Mendapatkan status scan yang sedang berjalan
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
    """
    user_id = get_jwt_identity()
    
    scan = Scan.query.filter_by(
        scan_id=scan_id,
        users_user_id=int(user_id)
    ).first()
    
    if not scan:
        return jsonify({"msg": "Scan tidak ditemukan"}), 404
    
    progress = 0
    if scan.status == 'pending':
        progress = 0
    elif scan.status == 'running':
        progress = 50
    elif scan.status == 'completed':
        progress = 100
    
    return jsonify({
        "scan_id": scan.scan_id,
        "target": scan.target_url,
        "status": scan.status,
        "start_time": scan.start_time.strftime("%Y-%m-%d %H:%M:%S") if scan.start_time else None,
        "end_time": scan.end_time.strftime("%Y-%m-%d %H:%M:%S") if scan.end_time else None,
        "progress": progress
    }), 200


@scan_bp.route('/history', methods=['GET'])
@jwt_required()
def get_all_scans():
    """
    Get All Scan History
    ---
    tags:
      - Scanning
    security:
      - Bearer: []
    summary: Mendapatkan semua riwayat scan user
    responses:
      200:
        description: List semua scan
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
    Ambil Detail Hasil Scan
    ---
    tags:
      - Scanning
    security:
      - Bearer: []
    summary: Detail lengkap scan, vulnerabilities, dan recon data
    parameters:
      - name: scan_id
        in: path
        required: true
        type: integer
    responses:
      200:
        description: Detail scan lengkap
      404:
        description: Scan tidak ditemukan
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
            "high_severity": 0,  # Hitung manual dari vulnerabilities
            "medium_severity": 0,
            "low_severity": 0,
            "summary": scan.result.summary
        }
        
        # Hitung severity dari vulnerabilities
        if scan.result.vulnerabilities:
            for vuln in scan.result.vulnerabilities:
                vulnerabilities_data.append({
                    "vuln_id": vuln.vuln_id,
                    "name": vuln.vuln_name,
                    "category": vuln.category,
                    "severity": vuln.severity,
                    "description": vuln.description,
                    "recommendation": vuln.recommendation
                })
                
                # Count severity
                if vuln.severity.lower() == 'high':
                    result_data['high_severity'] += 1
                elif vuln.severity.lower() == 'medium':
                    result_data['medium_severity'] += 1
                elif vuln.severity.lower() == 'low':
                    result_data['low_severity'] += 1
        
        # Get recon data
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
    Get Scan Statistics
    ---
    tags:
      - Scanning
    security:
      - Bearer: []
    summary: Statistik scan user untuk dashboard
    responses:
      200:
        description: Statistik scan
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
    """
    Download PDF Report
    ---
    tags:
      - Scanning
    security:
      - Bearer: []
    summary: Download laporan scan dalam format PDF
    parameters:
      - name: scan_id
        in: path
        required: true
        type: integer
    responses:
      200:
        description: PDF file
      404:
        description: Scan tidak ditemukan
    """
    user_id = get_jwt_identity()
    
    scan = Scan.query.filter_by(
        scan_id=scan_id,
        users_user_id=int(user_id)
    ).first()
    
    if not scan:
        return jsonify({"msg": "Scan tidak ditemukan"}), 404
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1e40af'),
        spaceAfter=30,
        alignment=1
    )
    elements.append(Paragraph("Deep-Scan Security Report", title_style))
    elements.append(Spacer(1, 0.3 * inch))
    
    info_data = [
        ['Target URL:', scan.target_url],
        ['Scan ID:', str(scan.scan_id)],
        ['Scan Date:', scan.start_time.strftime("%d %b %Y, %H:%M:%S") if scan.start_time else 'N/A'],
        ['Status:', scan.status],
    ]
    
    info_table = Table(info_data, colWidths=[2*inch, 4*inch])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e5e7eb')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey)
    ]))
    elements.append(info_table)
    elements.append(Spacer(1, 0.5 * inch))
    
    if scan.result:
        elements.append(Paragraph("Vulnerability Summary", styles['Heading2']))
        elements.append(Spacer(1, 0.2 * inch))
        
        summary_data = [
            ['Total Vulnerabilities', str(scan.result.total_vulnerabilities)],
            ['High Severity', str(scan.result.high_severity_count or 0)],
            ['Medium Severity', str(scan.result.medium_severity_count or 0)],
            ['Low Severity', str(scan.result.low_severity_count or 0)]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 3*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        elements.append(summary_table)
        elements.append(PageBreak())
        
        if scan.result.vulnerabilities:
            elements.append(Paragraph("Vulnerability Details", styles['Heading2']))
            elements.append(Spacer(1, 0.2 * inch))
            
            for vuln in scan.result.vulnerabilities:
                vuln_data = [
                    ['Name:', vuln.vulnerability_name],
                    ['Severity:', vuln.severity.upper()],
                    ['Affected URL:', vuln.affected_url or 'N/A'],
                    ['Description:', vuln.description or 'N/A'],
                    ['Recommendation:', vuln.recommendation or 'N/A']
                ]
                
                vuln_table = Table(vuln_data, colWidths=[1.5*inch, 4.5*inch])
                vuln_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
                    ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP')
                ]))
                elements.append(vuln_table)
                elements.append(Spacer(1, 0.3 * inch))
    
    doc.build(elements)
    buffer.seek(0)
    
    filename = f"DeepScan_Report_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype='application/pdf'
    )
