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
    summary: Mengambil jumlah total scan, scan rentan, dan scan aman milik user
    description: Endpoint ini digunakan untuk menampilkan statistik scan berdasarkan user yang sedang login.
    responses:
      200:
        description: Statistik berhasil diambil
        schema:
          type: object
          properties:
            total:
              type: integer
              example: 10
            vulnerable:
              type: integer
              example: 4
            secure:
              type: integer
              example: 6
      401:
        description: Token tidak valid atau tidak ditemukan
      500:
        description: Internal Server Error
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
    summary: Mengambil 5 riwayat scan terakhir milik user
    description: Endpoint ini menampilkan daftar 5 scan terbaru berdasarkan waktu mulai scan.
    responses:
      200:
        description: Riwayat scan berhasil diambil
        schema:
          type: array
          items:
            type: object
            properties:
              scan_id:
                type: integer
                example: 101
              target:
                type: string
                example: "https://example.com"
              status:
                type: string
                example: "completed"
              date:
                type: string
                example: "22 Feb 2026, 14:30"
              vuln_count:
                type: integer
                example: 3
      401:
        description: Token tidak valid atau tidak ditemukan
      500:
        description: Internal Server Error
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