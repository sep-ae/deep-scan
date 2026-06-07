# core/report_generator.py
"""
PDF Report Generator — Deep-Scan
Desain: Professional enterprise-grade (ala Nessus/Qualys/Capture The Bug)
Palette: Navy blue + hitam + abu. Bersih, formal, mudah dibaca.
Struktur: Cover → TOC → Disclaimer & Scope → Executive Summary
          → Vulnerability Details → Reconnaissance Data
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
            textColor=C_GRAY_800, leading=14, spaceAfter=6,
            alignment=TA_JUSTIFY, firstLineIndent=20,
        ),
        'toc_item': ParagraphStyle(
            'toc_item', fontSize=9, fontName='Helvetica',
            textColor=C_GRAY_800, leading=18, spaceAfter=2,
        ),
        'toc_sub': ParagraphStyle(
            'toc_sub', fontSize=9, fontName='Helvetica',
            textColor=C_GRAY_600, leading=18, spaceAfter=1,
        ),
        'toc_h': ParagraphStyle(
            'toc_h', fontSize=9, fontName='Helvetica-Bold',
            textColor=C_NAVY, leading=18, spaceAfter=2,
        ),
    }


# ── Header / Footer ───────────────────────────────────────────────────────────

def _hf(canvas, doc):
    """Header dan footer minimal — no top header bar, footer with date (left) and page number (right)."""
    if doc.page == 1:
        return
    canvas.saveState()
    w, h = A4

    # ── Bottom bar: garis abu tipis
    canvas.setStrokeColor(C_GRAY_200)
    canvas.setLineWidth(0.5)
    canvas.line(20*mm, 13*mm, w - 20*mm, 13*mm)
    
    canvas.setFont('Helvetica', 8)
    canvas.setFillColor(C_GRAY_600)
    
    # Left: Date of report generation
    date_str = datetime.now().strftime('%d %b %Y')
    canvas.drawString(20*mm, 8*mm, f'Date: {date_str}')
    
    # Right: Page number
    canvas.drawRightString(w - 20*mm, 8*mm, f'Page {doc.page}')
    canvas.restoreState()


# ── Cover ─────────────────────────────────────────────────────────────────────

def _cover(elements):
    """Reserve page 1 for the canvas-drawn cover — content via onFirstPage."""
    elements.append(Spacer(1, 1))
    elements.append(PageBreak())


def _draw_shield(canvas, x, y, size, fill_color):
    """Draw a simple shield icon at (x, y) with given size."""
    canvas.saveState()
    s = size
    canvas.setFillColor(fill_color)
    p = canvas.beginPath()
    p.moveTo(x + s * 0.5, y + s)         # top center
    p.lineTo(x + s,       y + s * 0.72)  # top-right
    p.lineTo(x + s,       y + s * 0.32)  # mid-right
    p.lineTo(x + s * 0.5, y)             # bottom point
    p.lineTo(x,           y + s * 0.32)  # mid-left
    p.lineTo(x,           y + s * 0.72)  # top-left
    p.close()
    canvas.drawPath(p, fill=1, stroke=0)
    canvas.restoreState()


def _draw_city_silhouette(canvas, page_w, base_y):
    """Draw abstract geometric building silhouette above the footer bar."""
    canvas.saveState()
    # (x_ratio, width_pt, height_pt, hex_color)
    # Three layers create depth: back (dark), mid, front (lighter)
    blocks = [
        # Back layer — wider, shorter, darkest
        (0.12, 60, 120, '#0a2e3a'),
        (0.35, 65, 140, '#0b3040'),
        (0.58, 70, 125, '#0a2c38'),
        (0.80, 60, 145, '#0b3242'),
        # Mid layer
        (0.22, 45, 175, '#104a58'),
        (0.45, 50, 195, '#125060'),
        (0.68, 48, 180, '#114c5a'),
        (0.88, 42, 165, '#135462'),
        # Front layer — narrower, taller, lightest
        (0.18, 35, 215, '#186070'),
        (0.40, 38, 240, '#1a6878'),
        (0.60, 40, 225, '#196575'),
        (0.78, 36, 250, '#1b7080'),
    ]
    for x_ratio, bw, bh, col in blocks:
        bx = page_w * x_ratio - bw / 2
        canvas.setFillColor(colors.HexColor(col))
        canvas.rect(bx, base_y, bw, bh, fill=1, stroke=0)
    canvas.restoreState()


def _draw_cover(canvas, doc, scan):
    """Draw full cover page on canvas — Canva-inspired gradient + city silhouette."""
    w, h = A4
    canvas.saveState()

    footer_h = 42 * mm  # dark footer bar height

    # ── 1. Gradient background (dark navy → teal) ────────────────────────
    top_rgb = (11, 25, 46)    # #0b192e
    bot_rgb = (16, 72, 92)    # #10485c
    steps = 100
    strip = (h - footer_h) / steps
    for i in range(steps):
        t = i / max(steps - 1, 1)
        r = (top_rgb[0] + t * (bot_rgb[0] - top_rgb[0])) / 255
        g = (top_rgb[1] + t * (bot_rgb[1] - top_rgb[1])) / 255
        b = (top_rgb[2] + t * (bot_rgb[2] - top_rgb[2])) / 255
        canvas.setFillColorRGB(r, g, b)
        y = h - (i + 1) * strip
        canvas.rect(0, y, w, strip + 0.5, fill=1, stroke=0)

    # ── 2. Dark footer bar ────────────────────────────────────────────────
    canvas.setFillColor(colors.HexColor('#091220'))
    canvas.rect(0, 0, w, footer_h, fill=1, stroke=0)

    # Accent line at top of footer
    canvas.setStrokeColor(colors.HexColor('#1a5a9c'))
    canvas.setLineWidth(1.5)
    canvas.line(0, footer_h, w, footer_h)

    # ── 3. Geometric city silhouette ──────────────────────────────────────
    _draw_city_silhouette(canvas, w, footer_h)

    # ── 4. Brand / Logo ───────────────────────────────────────────────────
    lx = 25 * mm
    brand_y = h - 28 * mm
    _draw_shield(canvas, lx, brand_y - 2, 14, colors.HexColor('#2196F3'))
    canvas.setFillColor(C_WHITE)
    canvas.setFont('Helvetica-Bold', 12)
    canvas.drawString(lx + 18, brand_y, 'Deep-Scan')

    # ── 5. Main title ─────────────────────────────────────────────────────
    canvas.setFillColor(C_WHITE)
    canvas.setFont('Helvetica-Bold', 32)
    title_y = h - 72 * mm
    canvas.drawString(lx, title_y, 'Web Vulnerability')
    canvas.drawString(lx, title_y - 14 * mm, 'Scan Report')

    # ── 6. Subtitle ───────────────────────────────────────────────────────
    domain = _domain_from_url(scan.target_url or 'target')
    canvas.setFillColor(colors.HexColor('#94b8d8'))
    canvas.setFont('Helvetica', 13)
    sub_y = title_y - 32 * mm
    canvas.drawString(lx, sub_y, 'Security Assessment Report')
    canvas.drawString(lx, sub_y - 6 * mm, f'for {domain}')

    # Thin accent line below subtitle
    canvas.setStrokeColor(colors.HexColor('#1e5fa8'))
    canvas.setLineWidth(1)
    canvas.line(lx, sub_y - 14 * mm, lx + 100 * mm, sub_y - 14 * mm)

    # ── 7. Footer content ─────────────────────────────────────────────────
    # Left: metadata
    canvas.setFillColor(C_WHITE)
    canvas.setFont('Helvetica-Bold', 10)
    canvas.drawString(lx, 30 * mm, 'Deep-Scan Security Scanner')

    canvas.setFillColor(colors.HexColor('#7a90a8'))
    canvas.setFont('Helvetica', 8.5)
    canvas.drawString(lx, 22 * mm, scan.target_url or '\u2014')
    date_str = datetime.now().strftime('%d %B %Y')
    canvas.drawString(lx, 14 * mm, f'Generated: {date_str}')

    # Right: year
    canvas.setFillColor(C_WHITE)
    canvas.setFont('Helvetica-Bold', 28)
    canvas.drawRightString(w - 25 * mm, 22 * mm, datetime.now().strftime('%Y'))

    canvas.restoreState()


# ── Table of Contents ─────────────────────────────────────────────────────────

def _toc(elements, st, has_vulns, has_recon):
    elements.append(Paragraph('Table of Contents', st['h1']))
    elements.append(HRFlowable(width='100%', thickness=1, color=C_NAVY))
    elements.append(Spacer(1, 10))

    # (level, number, title, show)  — level 0 = main, level 1 = sub
    sections = [
        (0, '1',   'Important Notes & Scan Scope',          True),
        (1, '1.1', 'Tool Limitations Disclaimer',            True),
        (1, '1.2', 'Target & Scope',                         True),
        (1, '1.3', 'Scanning Methods & Categories',          True),
        (0, '2',   'Executive Summary',                      True),
        (1, '2.1', 'Severity Distribution',                  True),
        (1, '2.2', 'Assessment Methodology (CVSS v3.1)',     True),
        (0, '3',   'Vulnerability Details',                  has_vulns),
        (0, '4',   'Reconnaissance Data',                   has_recon),
    ]

    for level, num, title, show in sections:
        if not show:
            continue
        is_main = (level == 0)
        indent = 10 * mm * level  # sub-items indented

        # Number column
        num_style = ParagraphStyle(
            f'toc_n_{num}', fontSize=9,
            fontName='Helvetica-Bold' if is_main else 'Helvetica',
            textColor=C_NAVY if is_main else C_GRAY_600,
        )
        # Title column
        title_style = st['toc_h'] if is_main else st['toc_sub']
        title_html  = f'<b>{title}</b>' if is_main else title

        row = Table(
            [[Paragraph(num, num_style), Paragraph(title_html, title_style)]],
            colWidths=[12 * mm + indent, 148 * mm - indent],
        )
        row_cmds = [
            ('LEFTPADDING',   (0, 0), (0, 0), 4 + indent),
            ('TOPPADDING',    (0, 0), (-1, -1), 4 if is_main else 2),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4 if is_main else 2),
            ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ]
        if is_main:
            row_cmds.append(('LINEBELOW', (0, 0), (-1, -1), 0.4, C_GRAY_200))
        row.setStyle(TableStyle(row_cmds))
        elements.append(row)

    elements.append(PageBreak())


# ── Disclaimer & Scope ────────────────────────────────────────────────────────

def _disclaimer(elements, st, scan):
    elements.append(Paragraph('1. Important Notes & Scan Scope', st['h1']))
    elements.append(HRFlowable(width='100%', thickness=1, color=C_NAVY))
    elements.append(Spacer(1, 10))

    # ── 1.1 Pernyataan Keterbatasan ───────────────────────────────────────────
    elements.append(Paragraph('1.1 Tool Limitations Disclaimer', st['h2']))

    notice_p1 = (
        'Dokumen ini merupakan laporan hasil pemindaian keamanan yang dihasilkan secara '
        '<b>otomatis</b> oleh <b>Deep-Scan Vulnerability Scanner</b>, sebuah alat pengujian '
        'keamanan aplikasi web yang dirancang untuk mengidentifikasi potensi kerentanan pada '
        'target yang telah ditentukan. Pemindaian dilakukan dengan menggunakan serangkaian '
        'teknik pengujian berbasis pola (<i>pattern-based</i>), analisis sinyal '
        '(<i>signature matching</i>), serta simulasi serangan pasif yang telah dikonfigurasi '
        'sesuai dengan standar pengujian keamanan industri.'
    )
    elements.append(Paragraph(notice_p1, st['notice']))

    notice_p2 = (
        'Penting untuk dipahami bahwa setiap alat pemindaian otomatis memiliki batasan '
        'inheren dalam hal cakupan dan akurasi deteksi. <b>Hasil pemindaian ini tidak '
        'menjamin kelengkapan atau keakuratan 100%</b> terhadap seluruh potensi kerentanan '
        'yang mungkin ada pada sistem target. Laporan ini sebaiknya digunakan sebagai '
        'panduan awal (<i>initial assessment</i>) dan bukan sebagai pengganti pengujian '
        'penetrasi manual yang komprehensif oleh tenaga ahli keamanan siber. Beberapa '
        'keterbatasan utama yang perlu diperhatikan antara lain:'
    )
    elements.append(Paragraph(notice_p2, st['notice']))

    caveats = [
        ['•', '<b>False Positive</b> — Terdapat kemungkinan bahwa beberapa temuan yang '
              'dilaporkan dalam dokumen ini merupakan kerentanan yang terdeteksi secara keliru. '
              'Hal ini dapat terjadi karena pola respons server yang menyerupai indikator '
              'kerentanan, namun pada konteks implementasi aktual tidak menimbulkan risiko '
              'keamanan yang nyata. Setiap temuan perlu divalidasi terhadap lingkungan '
              'produksi untuk memastikan relevansinya.'],
        ['•', '<b>False Negative</b> — Beberapa kerentanan yang ada pada sistem target '
              'mungkin tidak terdeteksi oleh pemindaian ini. Hal ini dapat disebabkan oleh '
              'berbagai faktor, termasuk kerentanan yang berada di luar jangkauan teknik '
              'pemindaian yang digunakan, konfigurasi <i>Web Application Firewall</i> (WAF) '
              'yang memblokir payload pengujian, atau kerentanan yang memerlukan kondisi '
              'spesifik tertentu untuk dapat teridentifikasi.'],
        ['•', '<b>Keterbatasan Pemindaian Otomatis</b> — Sejumlah kategori kerentanan yang '
              'bersifat kompleks, seperti <i>Business Logic Flaws</i>, <i>Race Conditions</i>, '
              'kerentanan pada mekanisme otorisasi multi-level, serta kelemahan yang memerlukan '
              'pemahaman mendalam terhadap alur bisnis aplikasi, tidak dapat dideteksi secara '
              'memadai melalui pendekatan otomatis. Jenis kerentanan tersebut umumnya '
              'memerlukan pengujian manual oleh profesional keamanan berpengalaman.'],
    ]

    for bullet, text in caveats:
        row = Table([[
            Paragraph(bullet, st['body']),
            Paragraph(text,   st['notice']),
        ]], colWidths=[6*mm, 154*mm])
        row.setStyle(TableStyle([
            ('VALIGN',     (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING', (0,0), (-1,-1), 2),
            ('BOTTOMPADDING', (0,0), (-1,-1), 2),
        ]))
        elements.append(row)

    elements.append(Spacer(1, 8))

    notice_closing = (
        'Mengingat keterbatasan-keterbatasan yang telah disebutkan di atas, <b>sangat '
        'direkomendasikan</b> agar setiap temuan yang tercantum dalam laporan ini '
        'diverifikasi dan divalidasi secara manual oleh tenaga ahli keamanan siber atau '
        '<i>penetration tester</i> yang berkompeten sebelum dijadikan dasar untuk '
        'pengambilan keputusan remediasi. Tindakan perbaikan sebaiknya diprioritaskan '
        'berdasarkan tingkat severity, dampak bisnis, serta konteks teknis masing-masing '
        'temuan.'
    )
    elements.append(Paragraph(notice_closing, st['notice']))

    notice_confidential = (
        'Dokumen ini bersifat <b>RAHASIA</b> (<i>Confidential</i>) dan ditujukan '
        'secara eksklusif kepada pihak-pihak yang memiliki wewenang dan tanggung jawab '
        'atas pengelolaan keamanan sistem yang diuji. Penyebarluasan, penggandaan, atau '
        'penggunaan informasi dalam laporan ini oleh pihak yang tidak berwenang merupakan '
        'pelanggaran terhadap ketentuan kerahasiaan dan dapat menimbulkan risiko keamanan '
        'tambahan bagi organisasi terkait.'
    )
    elements.append(Paragraph(notice_confidential, st['notice']))

    elements.append(Spacer(1, 14))

    # ── 1.2 Ruang Lingkup ─────────────────────────────────────────────────────
    elements.append(Paragraph('1.2 Target & Scope', st['h2']))

    scope_p1 = (
        f'Pemindaian keamanan ini dilakukan terhadap target utama: '
        f'<b>{scan.target_url}</b>. Ruang lingkup pengujian mencakup seluruh '
        'URL dan domain utama yang telah ditentukan, termasuk subdomain, endpoint API, '
        'serta komponen infrastruktur lain yang berhasil diidentifikasi secara otomatis '
        'melalui proses <i>reconnaissance</i> dan <i>enumeration</i> pada tahap awal '
        'pemindaian.'
    )
    elements.append(Paragraph(scope_p1, st['notice']))

    scope_p2 = (
        'Pendekatan pemindaian yang digunakan bersifat <i>black-box assessment</i>, di mana '
        'pengujian dilakukan tanpa akses ke kode sumber, dokumentasi internal, atau '
        'kredensial autentikasi sistem — kecuali jika secara eksplisit disediakan oleh '
        'pemilik sistem. Dengan demikian, cakupan pemindaian terbatas pada area yang '
        'dapat diakses secara publik dan endpoint yang berhasil ditemukan melalui teknik '
        'enumerasi otomatis. Area yang memerlukan autentikasi atau otorisasi khusus '
        'mungkin tidak tercakup dalam pemindaian ini.'
    )
    elements.append(Paragraph(scope_p2, st['notice']))

    elements.append(Spacer(1, 14))

    # ── 1.3 Metode & Kategori Pemindaian ──────────────────────────────────────
    elements.append(Paragraph('1.3 Scanning Methods & Categories', st['h2']))

    method_p1 = (
        'Deep-Scan menjalankan serangkaian modul pemindaian otomatis yang dirancang '
        'dengan mengacu pada kerangka kerja <b>OWASP Top 10</b> — standar industri yang '
        'diakui secara global untuk klasifikasi risiko keamanan aplikasi web. Setiap modul '
        'pemindaian dioptimalkan untuk mendeteksi kategori kerentanan tertentu dengan '
        'menggunakan kombinasi teknik <i>active probing</i>, analisis respons, dan '
        '<i>pattern matching</i> terhadap indikator kerentanan yang telah terdokumentasi.'
    )
    elements.append(Paragraph(method_p1, st['notice']))

    method_p2 = (
        'Tabel berikut menyajikan ringkasan kategori pemindaian beserta teknik dan '
        'sub-modul yang digunakan dalam proses asesmen keamanan ini, disertai dengan '
        'referensi terhadap standar OWASP yang relevan:'
    )
    elements.append(Paragraph(method_p2, st['notice']))

    # Header tabel modul
    module_header = [
        Paragraph('<b>No</b>', ParagraphStyle(
            'mh0', fontSize=8, fontName='Helvetica-Bold', textColor=C_WHITE, alignment=TA_CENTER)),
        Paragraph('<b>Category</b>', ParagraphStyle(
            'mh1', fontSize=8, fontName='Helvetica-Bold', textColor=C_WHITE)),
        Paragraph('<b>Techniques / Sub-Modules</b>', ParagraphStyle(
            'mh2', fontSize=8, fontName='Helvetica-Bold', textColor=C_WHITE)),
        Paragraph('<b>Reference</b>', ParagraphStyle(
            'mh3', fontSize=8, fontName='Helvetica-Bold', textColor=C_WHITE)),
    ]

    modules = [
        ['1', 'Reconnaissance',
         'DNS Lookup, Subdomain Enumeration,\nPort Scanning, Technology Fingerprinting',
         'OWASP A05'],
        ['2', 'HTTP Security\nConfiguration',
         'Security Headers Analysis (CSP, HSTS,\nX-Frame-Options, X-Content-Type-Options,\n'
         'Cache-Control, X-XSS-Protection),\n'
         'CORS Misconfiguration Check',
         'OWASP A05,\nA02'],
        ['3', 'Authentication\n& Protection',
         'WAF / Cloudflare Detection,\nRate Limiting Check,\nBrute-force Protection Check,\n'
         'Weak Password Indicator Check',
         'OWASP A07,\nA02'],
        ['4', 'Web\nVulnerabilities',
         'SQL Injection (Error-based, Boolean-based,\nTime-based Blind),\n'
         'Reflected XSS, Command Injection,\n'
         'Open Redirect, File Upload Misconfiguration,\n'
         'Path Traversal, SSRF,\nDirectory Listing Enabled',
         'OWASP A03,\nA01'],
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

    mod_t = Table(rows, colWidths=[10*mm, 32*mm, 92*mm, 26*mm])
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
        ('TOPPADDING',    (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING',   (0,0), (-1,-1), 6),
        ('VALIGN',        (0,0), (-1,-1), 'TOP'),
        ('ALIGN',         (0,0), (0,-1),  'CENTER'),
    ]))
    elements.append(mod_t)
    elements.append(Spacer(1, 8))

    # Catatan standar
    elements.append(Paragraph(
        '<i>Note: OWASP Top 10 standards referenced are based on the latest edition. '
        'Scanning is performed as a black-box assessment and does not use account credentials '
        'to access authenticated areas unless explicitly provided.</i>',
        st['small']
    ))

    elements.append(PageBreak())


# ── Executive Summary ─────────────────────────────────────────────────────────

def _exec_summary(elements, st, scan, vc, vulnerabilities):
    elements.append(Paragraph('2. Executive Summary', st['h1']))
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
    elements.append(Spacer(1, 12))

    # Severity distribution table
    elements.append(Paragraph('2.1 Severity Distribution', st['h2']))
    elements.append(Spacer(1, 6))

    sev_header = [
        Paragraph('<b>Severity</b>', ParagraphStyle(
            'sh1', fontSize=8, fontName='Helvetica-Bold', textColor=C_WHITE, alignment=TA_CENTER)),
        Paragraph('<b>Count</b>', ParagraphStyle(
            'sh2', fontSize=8, fontName='Helvetica-Bold', textColor=C_WHITE, alignment=TA_CENTER)),
        Paragraph('<b>CVSS Score</b>', ParagraphStyle(
            'sh3', fontSize=8, fontName='Helvetica-Bold', textColor=C_WHITE, alignment=TA_CENTER)),
        Paragraph('<b>Priority</b>', ParagraphStyle(
            'sh4', fontSize=8, fontName='Helvetica-Bold', textColor=C_WHITE, alignment=TA_CENTER)),
    ]

    sev_rows = [sev_header]
    sev_info = [
        ('Critical', critical, '9.0 – 10.0', 'Immediate (< 24 hours)', 'critical'),
        ('High',     high,     '7.0 – 8.9',  'Priority (< 7 days)',    'high'),
        ('Medium',   medium,   '4.0 – 6.9',  'Scheduled (< 30 days)',  'medium'),
        ('Low',      low,      '0.1 – 3.9',  'Planning',               'low'),
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
    sev_t = Table(sev_rows, colWidths=[30*mm, 20*mm, 40*mm, 60*mm])
    sev_t.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0), C_NAVY),
        ('TEXTCOLOR',     (0, 0), (-1, 0), C_WHITE),
        ('ROWBACKGROUNDS',(0, 1), (-1, -1), [C_WHITE, C_GRAY_100]),
        ('GRID',          (0, 0), (-1, -1), 0.4, C_GRAY_200),
        ('TOPPADDING',    (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elements.append(sev_t)
    elements.append(Spacer(1, 14))

    # Methodology note
    elements.append(Paragraph('2.2 Assessment Methodology (CVSS v3.1)', st['h2']))
    elements.append(Paragraph(
        'Penilaian severity setiap kerentanan menggunakan standar '
        '<b>CVSS v3.1 (Common Vulnerability Scoring System)</b> dari FIRST.org. '
        'Skor dihitung berdasarkan 8 metrik: Attack Vector (AV), Attack Complexity (AC), '
        'Privileges Required (PR), User Interaction (UI), Scope (S), Confidentiality (C), '
        'Integrity (I), dan Availability (A). Setiap kerentanan menghasilkan skor 0.0–10.0 '
        'yang dipetakan ke tingkat severity None, Low, Medium, High, atau Critical.',
        st['notice']
    ))
    elements.append(Spacer(1, 8))

    # CVSS Metrics table
    cvss_header = [
        Paragraph('<b>Metric</b>', ParagraphStyle(
            'ch1', fontSize=8, fontName='Helvetica-Bold', textColor=C_WHITE)),
        Paragraph('<b>Code</b>', ParagraphStyle(
            'ch2', fontSize=8, fontName='Helvetica-Bold', textColor=C_WHITE, alignment=TA_CENTER)),
        Paragraph('<b>Description</b>', ParagraphStyle(
            'ch3', fontSize=8, fontName='Helvetica-Bold', textColor=C_WHITE)),
    ]

    cvss_data = [cvss_header]
    metrics_info = [
        ('Attack Vector',       'AV', 'Reflects the context by which vulnerability exploitation is possible (Network, Adjacent, Local, Physical).'),
        ('Attack Complexity',   'AC', 'Describes the conditions beyond the attacker\'s control that must exist to exploit the vulnerability (Low, High).'),
        ('Privileges Required', 'PR', 'Describes the level of privileges an attacker must possess before exploiting the vulnerability (None, Low, High).'),
        ('User Interaction',    'UI', 'Captures whether exploitation requires a human user to participate (None, Required).'),
        ('Scope',               'S',  'Determines whether a vulnerability in one component impacts resources beyond its security scope (Unchanged, Changed).'),
        ('Confidentiality',     'C',  'Measures the impact to the confidentiality of information managed by the system (None, Low, High).'),
        ('Integrity',           'I',  'Measures the impact to the integrity of information (None, Low, High).'),
        ('Availability',        'A',  'Measures the impact to the availability of the affected system (None, Low, High).'),
    ]

    for name, code, desc in metrics_info:
        cvss_data.append([
            Paragraph(f'<b>{name}</b>', ParagraphStyle(
                f'cm_{code}', fontSize=8, fontName='Helvetica-Bold', textColor=C_GRAY_800)),
            Paragraph(code, ParagraphStyle(
                f'cc_{code}', fontSize=8.5, fontName='Courier-Bold', textColor=C_NAVY, alignment=TA_CENTER)),
            Paragraph(desc, ParagraphStyle(
                f'cd_{code}', fontSize=8, fontName='Helvetica', textColor=C_GRAY_600, leading=12)),
        ])

    cvss_t = Table(cvss_data, colWidths=[35*mm, 12*mm, 113*mm])
    cvss_t.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0), C_NAVY_MID),
        ('TEXTCOLOR',     (0, 0), (-1, 0), C_WHITE),
        ('ROWBACKGROUNDS',(0, 1), (-1, -1), [C_WHITE, C_GRAY_100]),
        ('GRID',          (0, 0), (-1, -1), 0.4, C_GRAY_200),
        ('TOPPADDING',    (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING',   (0, 0), (-1, -1), 6),
        ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
    ]))
    elements.append(cvss_t)

    elements.append(PageBreak())


# ── Vulnerability Details ─────────────────────────────────────────────────────

def _vulns(elements, st, vulnerabilities):
    elements.append(Paragraph('3. Vulnerability Details', st['h1']))
    elements.append(HRFlowable(width='100%', thickness=1, color=C_NAVY))
    elements.append(Spacer(1, 10))

    if not vulnerabilities:
        elements.append(Paragraph(
            'No vulnerabilities were identified during this scan.', st['body']
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
            [Paragraph('Category',    st['label']),
             Paragraph(_safe(cat),    st['body'])],
            [Paragraph('Description', st['label']),
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
            Paragraph('Recommendation', st['label']),
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
                resp_short += f'\n… ({len(resp_lines)-4} more lines)'
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
    elements.append(Paragraph('4. Reconnaissance Data', st['h1']))
    elements.append(HRFlowable(width='100%', thickness=1, color=C_NAVY))
    elements.append(Spacer(1, 10))

    if not recon_data:
        elements.append(Paragraph('No reconnaissance data was collected during this scan.', st['body']))
        return

    # Group by category — filter out vulnerability categories
    grouped = {}
    for r in recon_data:
        cat = _get(r, 'category', 'General')
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
            Paragraph('<b>Details</b>', ParagraphStyle(
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
                    f'<i>… and {hidden_count} more entries</i>',
                    ParagraphStyle(f'rmore_{cat}', fontSize=8, fontName='Helvetica',
                                   textColor=C_GRAY_400, alignment=TA_CENTER)
                ),
                Paragraph(
                    '<i>See full scan results on the dashboard for complete details.</i>',
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
        elements.append(Spacer(1, 10))


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

    has_vulns = len(vulnerabilities) > 0
    has_recon = len(recon_data) > 0

    _cover(elements)
    _toc(elements, st, has_vulns, has_recon)
    _disclaimer(elements, st, scan)
    _exec_summary(elements, st, scan, vc, vulnerabilities)
    _vulns(elements, st, vulnerabilities)
    _recon(elements, st, recon_data)

    _on_cover = lambda c, d: _draw_cover(c, d, scan)
    doc.build(elements, onFirstPage=_on_cover, onLaterPages=_hf)
    buffer.seek(0)

    # Nama file: DeepScan_blog.septito.my.id_DS0107_20260413.pdf
    domain    = _domain_from_url(scan.target_url or 'report')
    date_str  = datetime.now().strftime('%Y%m%d')
    scan_code = f'DS{scan.scan_id:04d}'
    filename  = f'DeepScan_{domain}_{scan_code}_{date_str}.pdf'

    return buffer, filename