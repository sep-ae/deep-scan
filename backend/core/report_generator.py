# core/report_generator.py
"""
PDF Report Generator — Deep-Scan
Desain: Professional enterprise-grade (ala Nessus/Qualys)
Palette: Navy blue + hitam + abu. Bersih, formal, mudah dibaca.
Struktur: Cover → Disclaimer & Scope → Vulnerability Details → Recon Data
"""
from io import BytesIO
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)


# ── Palette: Navy-biru profesional + hitam + abu ──────────────────────────────

C_NAVY       = colors.HexColor('#0f2b4c')   # navy gelap  — header, aksen utama
C_NAVY_MID   = colors.HexColor('#1a4070')   # navy sedang — sub-header table
C_BLUE_ACC   = colors.HexColor('#1e5fa8')   # biru aksen  — garis kiri finding
C_BLACK      = colors.HexColor('#111111')   # teks utama
C_GRAY_800   = colors.HexColor('#1f2937')   # teks gelap
C_GRAY_600   = colors.HexColor('#4b5563')   # teks sekunder
C_GRAY_400   = colors.HexColor('#9ca3af')   # teks light / meta
C_GRAY_200   = colors.HexColor('#e5e7eb')   # border tabel
C_GRAY_100   = colors.HexColor('#f3f4f6')   # background row alt
C_GRAY_50    = colors.HexColor('#f9fafb')   # background label col
C_WHITE      = colors.white

# Severity — tetap berwarna agar mudah dibedakan, tapi tone lebih tenang/formal
SEV_TEXT = {
    'critical': colors.HexColor('#6d1a1a'),  # merah tua
    'high':     colors.HexColor('#b91c1c'),  # merah
    'medium':   colors.HexColor('#b45309'),  # amber tua
    'low':      colors.HexColor('#166534'),  # hijau tua
    'info':     colors.HexColor('#1e4d8c'),  # biru tua
}

SEV_BG = {
    'critical': colors.HexColor('#fef2f2'),
    'high':     colors.HexColor('#fff5f5'),
    'medium':   colors.HexColor('#fffbeb'),
    'low':      colors.HexColor('#f0fdf4'),
    'info':     colors.HexColor('#eff6ff'),
}

SEV_LABEL = {
    'critical': 'CRITICAL',
    'high':     'HIGH',
    'medium':   'MEDIUM',
    'low':      'LOW',
    'info':     'INFO',
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get(obj, key, default='—'):
    if isinstance(obj, dict):
        return obj.get(key) or default
    return getattr(obj, key, None) or default


def _safe(val, limit=0):
    s = str(val) if val is not None else '—'
    return s[:limit] if limit else s


def _hex(c):
    return f'{int(c.red*255):02x}{int(c.green*255):02x}{int(c.blue*255):02x}'


def _format_recommendation(text, style):
    """Parse rekomendasi '1) ... 2) ... 3) ...' menjadi list bullet terpisah."""
    import re
    if not text:
        return Paragraph('—', style)
    text = str(text)
    # Split by pattern '1) ', '2) ', dst
    items = re.split(r'\s*\d+\)\s*', text)
    items = [item.strip() for item in items if item.strip()]
    if len(items) <= 1:
        return Paragraph(text, style)
    # Build numbered list HTML
    html_parts = []
    for i, item in enumerate(items, 1):
        html_parts.append(f'{i}. {item}')
    html = '<br/>'.join(html_parts)
    return Paragraph(html, style)


def _parse_cvss(description: str) -> str:
    """
    Ambil skor CVSS dari teks deskripsi.
    Pola yang didukung: 'Score: 9.8' atau 'Score:9.8'
    Karena model Vulnerability tidak punya kolom cvss_score.
    """
    import re
    if not description:
        return '—'
    m = re.search(r'Score:\s*([\d.]+)', description, re.IGNORECASE)
    return m.group(1) if m else '—'


def _domain_from_url(url: str) -> str:
    """Ambil hostname bersih dari URL untuk nama file."""
    import re
    url = url.strip().rstrip('/')
    # hapus scheme
    url = re.sub(r'^https?://', '', url)
    # ambil bagian sebelum / atau ?
    host = url.split('/')[0].split('?')[0]
    # sanitize — hanya huruf, angka, titik, strip
    host = re.sub(r'[^\w.\-]', '_', host)
    return host or 'report'


# Kategori data yang BUKAN reconnaissance murni — difilter dari halaman Recon PDF
_VULN_CATS_EXCLUDE = {
    'open redirect', 'open redirect:summary',
    'sql injection', 'sql injection:summary',
    'command injection', 'command injection:summary',
    'file upload', 'file upload:summary',
    'directory listing', 'directory listing:summary',
    'xss', 'reflected xss', 'reflected xss:summary',
    'brute force', 'rate limit',
    'web vulnerabilities', 'proteksi dan autentikasi',
}

# Kategori recon yang isinya bisa banyak baris — ditampilkan ringkas
_RECON_SUMMARY_CATS = {
    'subdomain enumeration', 'subdomains',
    'port scan', 'port scanning',
    'technology', 'technologies',
}


# ── Styles ────────────────────────────────────────────────────────────────────

def _styles():
    getSampleStyleSheet()
    return {
        # ── Cover ──────────────────────────────────────────────────────────
        'c_brand': ParagraphStyle(
            'c_brand', fontSize=8, fontName='Helvetica',
            textColor=C_GRAY_400, alignment=TA_CENTER, spaceAfter=2,
            tracking=2,
        ),
        'c_title': ParagraphStyle(
            'c_title', fontSize=22, fontName='Helvetica-Bold',
            textColor=C_NAVY, alignment=TA_CENTER, spaceAfter=6, leading=28,
        ),
        'c_sub': ParagraphStyle(
            'c_sub', fontSize=10, fontName='Helvetica',
            textColor=C_GRAY_600, alignment=TA_CENTER, spaceAfter=4,
        ),
        'c_meta': ParagraphStyle(
            'c_meta', fontSize=8.5, fontName='Helvetica',
            textColor=C_GRAY_400, alignment=TA_CENTER, spaceAfter=2,
        ),
        # ── Body ───────────────────────────────────────────────────────────
        'h1': ParagraphStyle(
            'h1', fontSize=12, fontName='Helvetica-Bold',
            textColor=C_NAVY, spaceBefore=14, spaceAfter=6,
        ),
        'h2': ParagraphStyle(
            'h2', fontSize=9.5, fontName='Helvetica-Bold',
            textColor=C_NAVY_MID, spaceBefore=10, spaceAfter=4,
        ),
        'body': ParagraphStyle(
            'body', fontSize=9, fontName='Helvetica',
            textColor=C_GRAY_800, leading=14, spaceAfter=3,
        ),
        'body_j': ParagraphStyle(
            'body_j', fontSize=9, fontName='Helvetica',
            textColor=C_GRAY_800, leading=14, spaceAfter=3, alignment=TA_JUSTIFY,
        ),
        'label': ParagraphStyle(
            'label', fontSize=7.5, fontName='Helvetica-Bold',
            textColor=C_GRAY_600, spaceAfter=2,
        ),
        'mono': ParagraphStyle(
            'mono', fontSize=7.5, fontName='Courier',
            textColor=C_GRAY_800, leading=11,
        ),
        'small': ParagraphStyle(
            'small', fontSize=7.5, fontName='Helvetica',
            textColor=C_GRAY_400,
        ),
        'notice': ParagraphStyle(
            'notice', fontSize=8.5, fontName='Helvetica',
            textColor=C_GRAY_800, leading=13, spaceAfter=4,
            alignment=TA_JUSTIFY,
        ),
    }


# ── Header / Footer ───────────────────────────────────────────────────────────

def _hf(canvas, doc):
    if doc.page == 1:
        return
    canvas.saveState()
    w, h = A4

    # ── Top bar: navy strip tipis
    canvas.setFillColor(C_NAVY)
    canvas.rect(0, h - 14*mm, w, 14*mm, fill=1, stroke=0)
    canvas.setFont('Helvetica-Bold', 7.5)
    canvas.setFillColor(C_WHITE)
    canvas.drawString(20*mm, h - 9*mm, 'DEEP-SCAN  |  Vulnerability Scan Report')
    canvas.setFont('Helvetica', 7.5)
    canvas.drawRightString(w - 20*mm, h - 9*mm,
                           f'Page {doc.page}   |   CONFIDENTIAL')

    # ── Bottom bar: garis abu tipis
    canvas.setStrokeColor(C_GRAY_200)
    canvas.setLineWidth(0.5)
    canvas.line(20*mm, 13*mm, w - 20*mm, 13*mm)
    canvas.setFont('Helvetica', 7)
    canvas.setFillColor(C_GRAY_400)
    canvas.drawString(20*mm, 9*mm, 'Deep-Scan Automated Vulnerability Scanner')
    canvas.drawRightString(w - 20*mm, 9*mm,
                           'Generated: ' + datetime.now().strftime('%d %b %Y, %H:%M'))
    canvas.restoreState()


# ── Cover ─────────────────────────────────────────────────────────────────────

def _cover(elements, st, scan, vc):
    w, h = A4

    total    = vc.get('total', 0)
    critical = vc.get('critical', 0)
    high     = vc.get('high', 0)
    medium   = vc.get('medium', 0)
    low      = vc.get('low', 0)

    scan_date = scan.start_time.strftime('%d %B %Y') if scan.start_time else '—'
    scan_time = scan.start_time.strftime('%H:%M WIB') if scan.start_time else '—'
    target    = scan.target_url or '—'
    username  = getattr(scan, 'user', None)
    if username:
        username = getattr(username, 'username', None) or getattr(username, 'email', None) or '—'
    else:
        username = '—'

    # Hitung durasi scan
    duration_str = '—'
    if scan.start_time and scan.end_time:
        delta = scan.end_time - scan.start_time
        mins, secs = divmod(int(delta.total_seconds()), 60)
        hrs, mins = divmod(mins, 60)
        if hrs > 0:
            duration_str = f'{hrs} jam {mins} menit {secs} detik'
        elif mins > 0:
            duration_str = f'{mins} menit {secs} detik'
        else:
            duration_str = f'{secs} detik'

    # Risk level
    risk_label = (
        'CRITICAL RISK'  if critical > 0 else
        'HIGH RISK'      if high     > 0 else
        'MEDIUM RISK'    if medium   > 0 else
        'LOW RISK'       if low      > 0 else
        'NO FINDINGS'
    )
    risk_sev = (
        'critical' if critical > 0 else
        'high'     if high     > 0 else
        'medium'   if medium   > 0 else
        'low'
    )
    risk_col  = SEV_TEXT.get(risk_sev, C_GRAY_600)
    risk_hex  = _hex(risk_col)

    # ── Spacer atas agar konten turun ke tengah halaman ────────────────────
    elements.append(Spacer(1, 60))

    # ── Garis navy tipis di atas sebagai aksen ────────────────────────────
    elements.append(HRFlowable(width='40%', thickness=2, color=C_NAVY))
    elements.append(Spacer(1, 20))

    # ── Brand ─────────────────────────────────────────────────────────────
    elements.append(Paragraph(
        '<font color="#0f2b4c"><b>DEEP-SCAN</b></font>',
        ParagraphStyle('cv_brand', fontSize=28, fontName='Helvetica-Bold',
                       textColor=C_NAVY, alignment=TA_CENTER, leading=32)
    ))
    elements.append(Paragraph(
        'Automated Vulnerability Scanner',
        ParagraphStyle('cv_tagline', fontSize=9, fontName='Helvetica',
                       textColor=C_GRAY_400, alignment=TA_CENTER,
                       spaceBefore=2, spaceAfter=0)
    ))
    elements.append(Spacer(1, 30))

    # ── Judul Laporan ─────────────────────────────────────────────────────
    elements.append(Paragraph(
        'Laporan Pemindaian Kerentanan',
        ParagraphStyle('cv_title', fontSize=16, fontName='Helvetica-Bold',
                       textColor=C_BLACK, alignment=TA_CENTER, leading=20)
    ))
    elements.append(Spacer(1, 4))
    elements.append(Paragraph(
        f'{_safe(target)}',
        ParagraphStyle('cv_target', fontSize=10, fontName='Helvetica',
                       textColor=C_GRAY_600, alignment=TA_CENTER)
    ))
    elements.append(Spacer(1, 20))

    # ── Risk badge — sederhana, hanya teks + garis bawah ──────────────────
    risk_badge = Table([[
        Paragraph(
            f'<font color="#{risk_hex}"><b>{risk_label}</b></font>',
            ParagraphStyle('cv_risk', fontSize=10, fontName='Helvetica-Bold',
                           textColor=risk_col, alignment=TA_CENTER),
        )
    ]], colWidths=[70*mm])
    risk_badge.setStyle(TableStyle([
        ('ALIGN',         (0,0), (-1,-1), 'CENTER'),
        ('TOPPADDING',    (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LINEBELOW',     (0,0), (-1,-1), 1.5, risk_col),
    ]))
    risk_wrap = Table([[risk_badge]], colWidths=[w - 40*mm])
    risk_wrap.setStyle(TableStyle([('ALIGN', (0,0), (-1,-1), 'CENTER')]))
    elements.append(risk_wrap)
    elements.append(Spacer(1, 30))

    # ── Divider tipis ─────────────────────────────────────────────────────
    elements.append(HRFlowable(width='100%', thickness=0.5, color=C_GRAY_200))
    elements.append(Spacer(1, 16))

    # ── Info table — minimalis, tanpa background label berwarna ────────────
    info_rows = [
        ['Target URL',     _safe(target)],
        ['Tanggal Scan',   f'{scan_date}, pukul {scan_time}'],
        ['Durasi Scan',    duration_str],
        ['Pengguna',       _safe(username)],
        ['Scan ID',        f'DS-{scan.scan_id:04d}'],
    ]

    info_table_data = [
        [
            Paragraph(f'<b>{label}</b>', ParagraphStyle(
                f'il_{i}', fontSize=8, fontName='Helvetica-Bold',
                textColor=C_GRAY_600)),
            Paragraph(value, ParagraphStyle(
                f'iv_{i}', fontSize=9, fontName='Helvetica',
                textColor=C_BLACK)),
        ]
        for i, (label, value) in enumerate(info_rows)
    ]

    info = Table(info_table_data, colWidths=[35*mm, 115*mm])
    info.setStyle(TableStyle([
        ('LINEBELOW',     (0, 0), (-1, -1), 0.3, C_GRAY_200),
        ('TOPPADDING',    (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING',   (0, 0), (-1, -1), 6),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
    ]))

    wrap = Table([[info]], colWidths=[w - 40*mm])
    wrap.setStyle(TableStyle([('ALIGN', (0,0), (-1,-1), 'CENTER')]))
    elements.append(wrap)
    elements.append(Spacer(1, 24))

    # ── Severity summary — satu baris angka minimalis ─────────────────────
    def _sev_cell(label, count, sev):
        col = SEV_TEXT[sev]
        hex_col = _hex(col)
        return Paragraph(
            f'<font size="18" color="#{hex_col}"><b>{count}</b></font><br/>'
            f'<font size="7" color="#{_hex(C_GRAY_400)}">{label}</font>',
            ParagraphStyle(f'cv_sc_{sev}', fontSize=7, alignment=TA_CENTER,
                           leading=14)
        )

    cell_w = (w - 44*mm) / 4
    sum_data = [[
        _sev_cell('CRITICAL', critical, 'critical'),
        _sev_cell('HIGH',     high,     'high'),
        _sev_cell('MEDIUM',   medium,   'medium'),
        _sev_cell('LOW',      low,      'low'),
    ]]
    sum_t = Table(sum_data, colWidths=[cell_w] * 4)
    sum_t.setStyle(TableStyle([
        ('ALIGN',         (0,0), (-1,-1), 'CENTER'),
        ('TOPPADDING',    (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('LINEBEFORE',    (1,0), (-1,-1), 0.3, C_GRAY_200),
    ]))
    sw = Table([[sum_t]], colWidths=[w - 40*mm])
    sw.setStyle(TableStyle([('ALIGN', (0,0), (-1,-1), 'CENTER')]))
    elements.append(sw)
    elements.append(Spacer(1, 20))

    # ── Garis navy bawah ──────────────────────────────────────────────────
    elements.append(HRFlowable(width='100%', thickness=0.5, color=C_GRAY_200))
    elements.append(Spacer(1, 8))

    # Confidential notice
    elements.append(Paragraph(
        '<i>Dokumen ini bersifat RAHASIA dan hanya ditujukan untuk pihak yang '
        'berwenang atas sistem yang diuji.</i>',
        ParagraphStyle('conf', fontSize=7, fontName='Helvetica',
                       textColor=C_GRAY_400, alignment=TA_CENTER)
    ))

    elements.append(PageBreak())


# ── Disclaimer & Scope ────────────────────────────────────────────────────────

def _disclaimer(elements, st, scan):
    elements.append(Paragraph('Catatan Penting & Ruang Lingkup Pemindaian', st['h1']))
    elements.append(HRFlowable(width='100%', thickness=1, color=C_NAVY))
    elements.append(Spacer(1, 12))

    # ── Pernyataan Keterbatasan ───────────────────────────────────────────────
    elements.append(Paragraph('Pernyataan Keterbatasan Alat', st['h2']))

    notice_text = (
        'Laporan ini dihasilkan secara <b>otomatis</b> oleh Deep-Scan Vulnerability Scanner. '
        'Pemindaian dilakukan menggunakan serangkaian teknik pengujian berbasis pola dan sinyal '
        'yang telah ditentukan sebelumnya. Oleh karena itu, <b>hasil pemindaian ini tidak '
        'menjamin kelengkapan atau keakuratan 100%</b> dan mungkin mengandung: '
    )
    elements.append(Paragraph(notice_text, st['notice']))

    caveats = [
        ['•', '<b>False Positive</b> — temuan yang dilaporkan sebagai kerentanan namun '
              'sebenarnya bukan ancaman nyata pada konteks aplikasi tersebut.'],
        ['•', '<b>False Negative</b> — kerentanan yang tidak terdeteksi karena berada '
              'di luar jangkauan atau pola yang didukung alat ini.'],
        ['•', '<b>Keterbatasan Otomasi</b> — beberapa kerentanan kompleks, seperti '
              'Business Logic Flaws atau kerentanan yang memerlukan konteks autentikasi '
              'mendalam, tidak dapat dideteksi sepenuhnya oleh pemindaian otomatis.'],
    ]

    for bullet, text in caveats:
        row = Table([[
            Paragraph(bullet, st['body']),
            Paragraph(text,   st['notice']),
        ]], colWidths=[6*mm, 154*mm])
        row.setStyle(TableStyle([
            ('VALIGN',     (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        elements.append(row)

    elements.append(Spacer(1, 6))
    elements.append(Paragraph(
        '<b>Sangat direkomendasikan</b> agar setiap temuan dalam laporan ini '
        'diverifikasi secara manual oleh tenaga ahli keamanan (penetration tester) '
        'sebelum dijadikan dasar tindakan remediasi. Laporan ini bersifat <b>RAHASIA</b> '
        'dan hanya diperuntukkan bagi pihak yang berwenang atas sistem yang diuji.',
        st['notice']
    ))

    elements.append(Spacer(1, 16))

    # ── Ruang Lingkup ─────────────────────────────────────────────────────────
    elements.append(Paragraph('Target & Ruang Lingkup', st['h2']))
    elements.append(Paragraph(
        f'Pemindaian dilakukan terhadap target: <b>{scan.target_url}</b>. '
        'Pengujian hanya mencakup URL/domain yang ditentukan dan tidak meluas ke '
        'subdomain, endpoint, atau sistem lain kecuali ditemukan secara otomatis '
        'dalam proses reconnaissance.',
        st['notice']
    ))

    elements.append(Spacer(1, 16))

    # ── Metode & Kategori Pemindaian ──────────────────────────────────────────
    elements.append(Paragraph('Metode & Kategori Pemindaian', st['h2']))
    elements.append(Paragraph(
        'Deep-Scan menjalankan pemindaian otomatis yang mengacu pada kerangka '
        '<b>OWASP Top 10</b> dan praktik keamanan industri. Berikut adalah '
        'kategori dan teknik yang digunakan dalam pemindaian ini:',
        st['notice']
    ))
    elements.append(Spacer(1, 8))

    # Header tabel modul
    module_header = [
        Paragraph('<b>No</b>', ParagraphStyle(
            'mh0', fontSize=8, fontName='Helvetica-Bold', textColor=C_WHITE, alignment=TA_CENTER)),
        Paragraph('<b>Kategori</b>', ParagraphStyle(
            'mh1', fontSize=8, fontName='Helvetica-Bold', textColor=C_WHITE)),
        Paragraph('<b>Teknik / Sub-Modul</b>', ParagraphStyle(
            'mh2', fontSize=8, fontName='Helvetica-Bold', textColor=C_WHITE)),
        Paragraph('<b>Referensi</b>', ParagraphStyle(
            'mh3', fontSize=8, fontName='Helvetica-Bold', textColor=C_WHITE)),
    ]

    modules = [
        ['1', 'Reconnaissance',
         'DNS Lookup, Subdomain Enumeration,\nPort Scanning, Technology Fingerprinting',
         'OWASP A05'],
        ['2', 'HTTP Security\nConfiguration',
         'Security Headers Analysis (CSP, HSTS,\nX-Frame-Options, X-Content-Type-Options),\n'
         'CORS Misconfiguration Check',
         'OWASP A05, A02'],
        ['3', 'Proteksi &\nAutentikasi',
         'WAF / Cloudflare Detection,\nRate Limiting Check,\nBrute-force Protection Check,\n'
         'Weak Password Indicator Check',
         'OWASP A07, A02'],
        ['4', 'Web Vulnerabilities',
         'SQL Injection (Error-based),\nReflected XSS,\nCommand Injection,\n'
         'Open Redirect,\nFile Upload Misconfiguration,\nDirectory Listing Enabled',
         'OWASP A03, A01'],
    ]

    rows = [module_header]
    for no, cat, tech, ref in modules:
        rows.append([
            Paragraph(no, ParagraphStyle(
                f'mn_{no}', fontSize=8.5, fontName='Helvetica-Bold',
                textColor=C_NAVY, alignment=TA_CENTER)),
            Paragraph(f'<b>{cat}</b>', ParagraphStyle(
                f'mc_{no}', fontSize=8.5, fontName='Helvetica-Bold',
                textColor=C_GRAY_800)),
            Paragraph(tech, st['body']),
            Paragraph(ref, ParagraphStyle(
                f'mr_{no}', fontSize=8, fontName='Helvetica',
                textColor=C_BLUE_ACC)),
        ])

    mod_t = Table(rows, colWidths=[10*mm, 38*mm, 90*mm, 22*mm])
    mod_t.setStyle(TableStyle([
        # Header row
        ('BACKGROUND',    (0,0), (-1,0),  C_NAVY),
        ('TEXTCOLOR',     (0,0), (-1,0),  C_WHITE),
        # Data rows alternating
        ('ROWBACKGROUNDS',(0,1), (-1,-1), [C_WHITE, C_GRAY_100]),
        # Grid
        ('GRID',          (0,0), (-1,-1), 0.4, C_GRAY_200),
        ('LINEABOVE',     (0,0), (-1,0),  1,   C_NAVY),
        ('LINEBELOW',     (0,-1),(-1,-1), 1,   C_GRAY_200),
        # Padding
        ('TOPPADDING',    (0,0), (-1,-1), 7),
        ('BOTTOMPADDING', (0,0), (-1,-1), 7),
        ('LEFTPADDING',   (0,0), (-1,-1), 8),
        ('VALIGN',        (0,0), (-1,-1), 'TOP'),
        ('ALIGN',         (0,0), (0,-1),  'CENTER'),
    ]))
    elements.append(mod_t)
    elements.append(Spacer(1, 12))

    # Catatan standar
    elements.append(Paragraph(
        '<i>Catatan: Standar OWASP Top 10 yang digunakan mengacu pada edisi terbaru. '
        'Pemindaian bersifat black-box dan tidak menggunakan kredensial akun untuk '
        'mengakses area yang memerlukan autentikasi kecuali disediakan secara eksplisit.</i>',
        st['small']
    ))

    elements.append(PageBreak())


# ── Executive Summary ─────────────────────────────────────────────────────────

def _exec_summary(elements, st, scan, vc, vulnerabilities):
    elements.append(Paragraph('Ringkasan Eksekutif', st['h1']))
    elements.append(HRFlowable(width='100%', thickness=1, color=C_NAVY))
    elements.append(Spacer(1, 10))

    total    = vc.get('total', 0)
    critical = vc.get('critical', 0)
    high     = vc.get('high', 0)
    medium   = vc.get('medium', 0)
    low      = vc.get('low', 0)

    # Risk assessment text
    if critical > 0:
        risk_text = (
            f'Pemindaian menemukan <b>{total} kerentanan</b> pada target, '
            f'termasuk <font color="#{_hex(SEV_TEXT["critical"])}"><b>{critical} kerentanan CRITICAL</b></font> '
            'yang memerlukan penanganan segera. Kerentanan critical dapat dieksploitasi '
            'oleh penyerang untuk mengambil alih sistem secara penuh.'
        )
    elif high > 0:
        risk_text = (
            f'Pemindaian menemukan <b>{total} kerentanan</b> pada target, '
            f'termasuk <font color="#{_hex(SEV_TEXT["high"])}"><b>{high} kerentanan HIGH</b></font>. '
            'Kerentanan dengan severity tinggi dapat berdampak signifikan terhadap '
            'kerahasiaan dan integritas data jika tidak segera ditangani.'
        )
    elif medium > 0:
        risk_text = (
            f'Pemindaian menemukan <b>{total} kerentanan</b> pada target dengan '
            f'severity tertinggi <font color="#{_hex(SEV_TEXT["medium"])}"><b>MEDIUM</b></font>. '
            'Disarankan untuk melakukan perbaikan sebagai bagian dari hardening keamanan.'
        )
    elif low > 0:
        risk_text = (
            f'Pemindaian menemukan <b>{total} temuan</b> dengan severity rendah. '
            'Risiko keseluruhan tergolong rendah namun tetap disarankan untuk diperbaiki.'
        )
    else:
        risk_text = 'Tidak ditemukan kerentanan pada pemindaian ini. Sistem tergolong aman.'

    elements.append(Paragraph(risk_text, st['notice']))
    elements.append(Spacer(1, 14))

    # Severity distribution table
    elements.append(Paragraph('Distribusi Severity', st['h2']))
    elements.append(Spacer(1, 6))

    sev_header = [
        Paragraph('<b>Severity</b>', ParagraphStyle(
            'sh1', fontSize=8, fontName='Helvetica-Bold', textColor=C_WHITE, alignment=TA_CENTER)),
        Paragraph('<b>Jumlah</b>', ParagraphStyle(
            'sh2', fontSize=8, fontName='Helvetica-Bold', textColor=C_WHITE, alignment=TA_CENTER)),
        Paragraph('<b>Skor CVSS</b>', ParagraphStyle(
            'sh3', fontSize=8, fontName='Helvetica-Bold', textColor=C_WHITE, alignment=TA_CENTER)),
        Paragraph('<b>Prioritas</b>', ParagraphStyle(
            'sh4', fontSize=8, fontName='Helvetica-Bold', textColor=C_WHITE, alignment=TA_CENTER)),
    ]

    sev_rows = [sev_header]
    sev_info = [
        ('Critical', critical, '9.0 – 10.0', 'Segera (< 24 jam)', 'critical'),
        ('High',     high,     '7.0 – 8.9',  'Prioritas (< 7 hari)', 'high'),
        ('Medium',   medium,   '4.0 – 6.9',  'Terjadwal (< 30 hari)', 'medium'),
        ('Low',      low,      '0.1 – 3.9',  'Perencanaan', 'low'),
    ]

    for label, count, score_range, priority, sev_key in sev_info:
        col = SEV_TEXT[sev_key]
        sev_rows.append([
            Paragraph(f'<font color="#{_hex(col)}"><b>{label}</b></font>',
                      ParagraphStyle(f'sl_{sev_key}', fontSize=9, fontName='Helvetica-Bold',
                                     textColor=col, alignment=TA_CENTER)),
            Paragraph(f'<b>{count}</b>',
                      ParagraphStyle(f'sc_{sev_key}', fontSize=9, fontName='Helvetica-Bold',
                                     textColor=C_BLACK, alignment=TA_CENTER)),
            Paragraph(score_range,
                      ParagraphStyle(f'sr_{sev_key}', fontSize=8.5, fontName='Helvetica',
                                     textColor=C_GRAY_600, alignment=TA_CENTER)),
            Paragraph(priority,
                      ParagraphStyle(f'sp_{sev_key}', fontSize=8.5, fontName='Helvetica',
                                     textColor=C_GRAY_600, alignment=TA_CENTER)),
        ])

    w_page = A4[0]
    sev_t = Table(sev_rows, colWidths=[35*mm, 25*mm, 40*mm, 50*mm])
    sev_t.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0), C_NAVY),
        ('TEXTCOLOR',     (0, 0), (-1, 0), C_WHITE),
        ('ROWBACKGROUNDS',(0, 1), (-1, -1), [C_WHITE, C_GRAY_100]),
        ('GRID',          (0, 0), (-1, -1), 0.4, C_GRAY_200),
        ('TOPPADDING',    (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elements.append(sev_t)
    elements.append(Spacer(1, 16))

    # Methodology note
    elements.append(Paragraph('Metodologi Penilaian', st['h2']))
    elements.append(Paragraph(
        'Penilaian severity setiap kerentanan menggunakan standar '
        '<b>CVSS v3.1 (Common Vulnerability Scoring System)</b> dari FIRST.org. '
        'Skor dihitung berdasarkan 8 metrik: Attack Vector (AV), Attack Complexity (AC), '
        'Privileges Required (PR), User Interaction (UI), Scope (S), Confidentiality (C), '
        'Integrity (I), dan Availability (A). Setiap kerentanan menghasilkan skor 0.0–10.0 '
        'yang dipetakan ke tingkat severity None, Low, Medium, High, atau Critical.',
        st['notice']
    ))

    elements.append(PageBreak())


# ── Vulnerability Details ─────────────────────────────────────────────────────

def _vulns(elements, st, vulnerabilities):
    elements.append(Paragraph('Detail Kerentanan', st['h1']))
    elements.append(HRFlowable(width='100%', thickness=1, color=C_NAVY))
    elements.append(Spacer(1, 10))

    if not vulnerabilities:
        elements.append(Paragraph(
            'Tidak ditemukan kerentanan pada pemindaian ini.', st['body']
        ))
        elements.append(PageBreak())
        return

    for idx, v in enumerate(vulnerabilities, 1):
        import re as _re

        sev      = (v.severity or 'info').lower()
        sev_col  = SEV_TEXT.get(sev, C_GRAY_600)
        sev_bg   = SEV_BG.get(sev, C_GRAY_50)
        sev_hex  = _hex(sev_col)
        cat      = getattr(v, 'category', '—') or '—'
        raw_desc = getattr(v, 'description', '') or ''

        # ── Parse & bersihkan deskripsi ───────────────────────────────────────
        # Pisahkan bagian Affected:, Vector:, Score: dari kalimat deskripsi utama
        def _extract(pattern, text):
            m = _re.search(pattern, text, _re.IGNORECASE)
            return m.group(1).strip() if m else None

        affected_parsed = _extract(r'Affected:\s*(.+?)(?=Vector:|Score:|Detail:|$)', raw_desc)
        vector_parsed   = _extract(r'Vector:\s*(CVSS:\S+)',                           raw_desc)
        score_parsed    = _extract(r'Score:\s*([\d.]+)',                              raw_desc)
        detail_parsed   = _extract(r'Detail:\s*(.+?)(?=Vector:|Score:|Affected:|$)', raw_desc)

        # Teks deskripsi bersih — buang bagian teknis yang akan tampil terpisah
        clean_desc = _re.sub(
            r'\s*(Affected|Vector|Score|Detail):\s*.+?(?=\s+(Affected|Vector|Score|Detail):|$)',
            '', raw_desc, flags=_re.IGNORECASE | _re.DOTALL
        ).strip() or raw_desc

        cvss_str = score_parsed or '—'

        # ── PoC dari relasi model (tabel pocs) ────────────────────────────────
        poc      = getattr(v, 'poc', None)
        poc_payload  = getattr(poc, 'payload',     None) if poc else None
        poc_response = getattr(poc, 'response',    None) if poc else None
        poc_method   = getattr(poc, 'http_method', None) if poc else None

        # ── Finding header ────────────────────────────────────────────────────
        header = Table([[
            Paragraph(
                f'<font color="#{_hex(C_NAVY)}">#{idx:02d}</font>  '
                f'<font color="#{sev_hex}"><b>{_safe(v.vuln_name, 70)}</b></font>',
                ParagraphStyle(f'fh_{idx}', fontSize=10, fontName='Helvetica-Bold',
                               textColor=sev_col, leading=14)
            ),
            Paragraph(
                f'<font color="#{sev_hex}"><b>{sev.upper()}</b></font>'
                f'<br/><font size="7.5" color="#{_hex(C_GRAY_600)}">CVSS {cvss_str}</font>',
                ParagraphStyle(f'fhb_{idx}', fontSize=9, fontName='Helvetica-Bold',
                               textColor=sev_col, alignment=TA_RIGHT, leading=13)
            ),
        ]], colWidths=[130*mm, 30*mm])
        header.setStyle(TableStyle([
            ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING',    (0,0), (-1,-1), 9),
            ('BOTTOMPADDING', (0,0), (-1,-1), 9),
            ('LEFTPADDING',   (0,0), (0,-1),  12),
            ('RIGHTPADDING',  (-1,0), (-1,-1), 10),
            ('LINEBEFORE',    (0,0), (0,-1),  4, sev_col),
            ('LINEBELOW',     (0,0), (-1,-1), 0.5, C_GRAY_200),
            ('BACKGROUND',    (0,0), (-1,-1), sev_bg),
        ]))

        # ── Finding detail — rapi, setiap field baris sendiri ─────────────────
        def _mono_p(text, limit=160):
            t = _safe(text, limit)
            return Paragraph(
                f'<font name="Courier" size="7.5">{t}</font>',
                ParagraphStyle(f'mono_p_{idx}', fontSize=7.5, fontName='Courier',
                               textColor=C_GRAY_800, leading=11, wordWrap='CJK')
            )

        rows = [
            [Paragraph('Kategori',    st['label']),
             Paragraph(_safe(cat),    st['body'])],
            [Paragraph('Deskripsi',   st['label']),
             Paragraph(_safe(clean_desc), st['body_j'])],
        ]

        # Affected — hasil parse dari deskripsi
        if affected_parsed:
            rows.append([
                Paragraph('Affected',  st['label']),
                _mono_p(affected_parsed, 160),
            ])

        # Detail tambahan (mis: "Access-Control-Allow-Origin tidak di-set")
        if detail_parsed:
            rows.append([
                Paragraph('Detail',    st['label']),
                Paragraph(_safe(detail_parsed), st['body_j']),
            ])

        # CVSS Vector
        if vector_parsed:
            rows.append([
                Paragraph('CVSS Vector', st['label']),
                _mono_p(vector_parsed, 200),
            ])

        rows.append([
            Paragraph('Rekomendasi', st['label']),
            _format_recommendation(v.recommendation, st['body_j']),
        ])

        # PoC dari tabel pocs (jika ada)
        if poc_payload:
            rows.append([
                Paragraph(
                    f'PoC Payload'
                    + (f'  <font size="7" color="#{_hex(C_GRAY_400)}">[{poc_method}]</font>'
                       if poc_method else ''),
                    st['label']
                ),
                _mono_p(poc_payload, 300),
            ])
        if poc_response:
            # Potong response panjang — cukup 3 baris pertama
            resp_lines = poc_response.strip().splitlines()
            resp_short = '\n'.join(resp_lines[:4])
            if len(resp_lines) > 4:
                resp_short += f'\n… ({len(resp_lines)-4} baris lainnya)'
            rows.append([
                Paragraph('PoC Response', st['label']),
                _mono_p(resp_short, 400),
            ])

        detail = Table(rows, colWidths=[35*mm, 125*mm])

        # Highlight baris CVSS Vector & PoC sedikit beda background
        style_cmds = [
            ('BACKGROUND',    (0,0),  (0,-1),  C_GRAY_50),
            ('GRID',          (0,0),  (-1,-1), 0.4, C_GRAY_200),
            ('TOPPADDING',    (0,0),  (-1,-1), 7),
            ('BOTTOMPADDING', (0,0),  (-1,-1), 7),
            ('LEFTPADDING',   (0,0),  (-1,-1), 10),
            ('VALIGN',        (0,0),  (-1,-1), 'TOP'),
        ]
        # Beri background sedikit beda pada baris PoC agar mudah dibedakan
        for ri, row in enumerate(rows):
            label_text = row[0].text if hasattr(row[0], 'text') else ''
            if 'PoC' in str(label_text):
                style_cmds.append(
                    ('BACKGROUND', (1, ri), (1, ri), colors.HexColor('#f0f4ff'))
                )

        detail.setStyle(TableStyle(style_cmds))

        elements.append(KeepTogether([header, detail, Spacer(1, 14)]))

    elements.append(PageBreak())


# ── Recon Data ────────────────────────────────────────────────────────────────

def _recon(elements, st, recon_data):
    elements.append(Paragraph('Data Rekognisi', st['h1']))
    elements.append(HRFlowable(width='100%', thickness=1, color=C_NAVY))
    elements.append(Spacer(1, 10))

    if not recon_data:
        elements.append(Paragraph('Tidak ada data rekognisi yang berhasil dikumpulkan.', st['body']))
        return

    # Group by category — filter out vulnerability categories
    grouped = {}
    for r in recon_data:
        cat = _get(r, 'category', 'Umum')
        # Skip kategori yang sebenarnya vulnerability, bukan recon
        if cat.lower() in _VULN_CATS_EXCLUDE:
            continue
        grouped.setdefault(cat, []).append(r)

    for cat, items in grouped.items():
        elements.append(Paragraph(cat, st['h2']))

        # Kategori yang berpotensi ratusan baris URL — tampilkan maks 5 + ringkasan
        is_bulky = cat.lower() in _RECON_SUMMARY_CATS
        MAX_ROWS = 5

        if is_bulky and len(items) > MAX_ROWS:
            display_items = items[:MAX_ROWS]
            hidden_count  = len(items) - MAX_ROWS
        else:
            display_items = items
            hidden_count  = 0

        header_row = [
            Paragraph('<b>Item</b>',   ParagraphStyle(
                f'rh1_{cat}', fontSize=8, fontName='Helvetica-Bold', textColor=C_WHITE)),
            Paragraph('<b>Detail</b>', ParagraphStyle(
                f'rh2_{cat}', fontSize=8, fontName='Helvetica-Bold', textColor=C_WHITE)),
        ]
        rows = [header_row]
        for item in display_items:
            raw_item   = _safe(_get(item, 'item'),    0)
            raw_detail = _safe(_get(item, 'details'), 0)

            # Potong URL/item panjang agar tidak overflow kolom
            item_text   = raw_item[:90]   + ('…' if len(raw_item)   > 90  else '')
            detail_text = raw_detail[:220] + ('…' if len(raw_detail) > 220 else '')

            rows.append([
                Paragraph(
                    f'<font name="Courier" size="7.5">{item_text}</font>'
                    if raw_item.startswith('http') else item_text,
                    st['body']
                ),
                Paragraph(detail_text, st['body']),
            ])

        # Baris info jika ada data tersembunyi
        if hidden_count:
            rows.append([
                Paragraph(
                    f'<i>… dan {hidden_count} entri lainnya</i>',
                    ParagraphStyle(f'rmore_{cat}', fontSize=8, fontName='Helvetica',
                                   textColor=C_GRAY_400, alignment=TA_CENTER)
                ),
                Paragraph(
                    '<i>Lihat hasil pemindaian lengkap di dashboard untuk detail seluruh temuan.</i>',
                    ParagraphStyle(f'rmored_{cat}', fontSize=8, fontName='Helvetica',
                                   textColor=C_GRAY_400)
                ),
            ])

        t = Table(rows, colWidths=[58*mm, 102*mm])
        style_cmds = [
            ('BACKGROUND',    (0,0),  (-1,0),  C_NAVY_MID),
            ('TEXTCOLOR',     (0,0),  (-1,0),  C_WHITE),
            ('ROWBACKGROUNDS',(0,1),  (-1,-1), [C_WHITE, C_GRAY_100]),
            ('GRID',          (0,0),  (-1,-1), 0.4, C_GRAY_200),
            ('LINEABOVE',     (0,0),  (-1,0),  1,   C_NAVY),
            ('FONTSIZE',      (0,0),  (-1,-1), 8.5),
            ('TOPPADDING',    (0,0),  (-1,-1), 7),
            ('BOTTOMPADDING', (0,0),  (-1,-1), 7),
            ('LEFTPADDING',   (0,0),  (-1,-1), 8),
            ('VALIGN',        (0,0),  (-1,-1), 'TOP'),
            ('WORDWRAP',      (0,0),  (-1,-1), True),
        ]
        if hidden_count:
            # baris terakhir (ringkasan) — background sedikit berbeda
            last = len(rows) - 1
            style_cmds += [
                ('BACKGROUND',  (0, last), (-1, last), C_GRAY_50),
                ('SPAN',        (0, last), (-1, last)),
                ('ALIGN',       (0, last), (-1, last), 'LEFT'),
            ]
        t.setStyle(TableStyle(style_cmds))
        elements.append(t)
        elements.append(Spacer(1, 12))


# ── Public API ────────────────────────────────────────────────────────────────

def generate_pdf_report(scan) -> tuple[BytesIO, str]:
    """

    Returns:
        (buffer, filename) — buffer siap send_file, filename pakai domain target.

    Usage:
        buffer, filename = generate_pdf_report(scan)
        return send_file(buffer, as_attachment=True,
                         download_name=filename,
                         mimetype='application/pdf')
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=20*mm,  bottomMargin=22*mm,
    )

    st              = _styles()
    elements        = []
    vc              = {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    vulnerabilities = []
    recon_data      = []

    if scan.result:
        vc['total'] = scan.result.total_vulnerabilities or 0
        if scan.result.vulnerabilities:
            vulnerabilities = list(scan.result.vulnerabilities)
            for v in vulnerabilities:
                s = (v.severity or '').lower()
                if s in vc:
                    vc[s] += 1
        if scan.result.recon_data:
            recon_data = list(scan.result.recon_data)

    _cover(elements, st, scan, vc)
    _disclaimer(elements, st, scan)
    _exec_summary(elements, st, scan, vc, vulnerabilities)
    _vulns(elements, st, vulnerabilities)
    _recon(elements, st, recon_data)

    doc.build(elements, onFirstPage=_hf, onLaterPages=_hf)
    buffer.seek(0)

    # Nama file: DeepScan_blog.septito.my.id_DS0107_20260413.pdf
    domain    = _domain_from_url(scan.target_url or 'report')
    date_str  = datetime.now().strftime('%Y%m%d')
    scan_code = f'DS{scan.scan_id:04d}'
    filename  = f'DeepScan_{domain}_{scan_code}_{date_str}.pdf'

    return buffer, filename