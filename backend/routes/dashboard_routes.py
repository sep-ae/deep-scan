from flask import Blueprint, jsonify
from models import Scan
from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy import desc

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/api/dashboard')

@dashboard_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_dashboard_stats():
    """
    Ambil Statistik Dashboard
    ---
    tags:
      - Dashboard
    security:
      - Bearer: []
    summary: Data total scan, rentan, dan aman
    responses:
      200:
        description: Statistik User
    """
    user_id = get_jwt_identity()
    user_scans = Scan.query.filter_by(users_user_id=user_id).all()

    total_scan = len(user_scans)
    vulnerable_count = 0
    secure_count = 0

    for scan in user_scans:
        if scan.result: 
            if scan.result.total_vulnerabilities > 0:
                vulnerable_count += 1
            else:
                secure_count += 1

    return jsonify({
        "total": total_scan,
        "vulnerable": vulnerable_count,
        "secure": secure_count
    }), 200

@dashboard_bp.route('/history', methods=['GET'])
@jwt_required()
def get_scan_history():
    """
    Ambil Riwayat Scan
    ---
    tags:
      - Dashboard
    security:
      - Bearer: []
    summary: 5 Riwayat scan terakhir
    responses:
      200:
        description: List history
    """
    user_id = get_jwt_identity()

    recent_scans = Scan.query.filter_by(users_user_id=user_id)\
        .order_by(desc(Scan.start_time))\
        .limit(5)\
        .all()

    history_data = []
    for scan in recent_scans:
        history_data.append({
            "scan_id": scan.scan_id,
            "target": scan.target_url,
            "status": scan.status,
            "date": scan.start_time.strftime("%d %b %Y, %H:%M") if scan.start_time else "N/A",
            "vuln_count": scan.result.total_vulnerabilities if scan.result else 0
        })

    return jsonify(history_data), 200
