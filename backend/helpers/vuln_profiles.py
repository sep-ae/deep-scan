VULN_PROFILES = {
    # ============================================================
    # RECONNAISSANCE
    # ============================================================

    "DNS_LOOKUP": {
        "name": "DNS Information Disclosure",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"
        },
        "description": "DNS records publicly expose internal infrastructure details (Zone Transfer, Internal IP).",
        "recommendation": "Lakukan split DNS untuk memisahkan zona internal dan eksternal. Gunakan DNSSEC. Batasi Zone Transfer hanya ke secondary DNS server terpercaya."
    },

    "DNS_ZONE_TRANSFER": {
        "name": "DNS Zone Transfer Allowed",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "H", "i": "N", "a": "N"
        },
        "description": "Server DNS mengizinkan Zone Transfer (AXFR) dari sembarang host. Attacker dapat mengunduh seluruh isi zona DNS termasuk subdomain internal.",
        "recommendation": "Batasi AXFR hanya ke IP secondary DNS yang terpercaya. Konfigurasi allow-transfer pada BIND/PowerDNS."
    },

    "DNS_DNSSEC_MISSING": {
        "name": "DNSSEC Not Enabled",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "H", "pr": "N",
            "ui": "N", "s": "U", "c": "L", "i": "L", "a": "N"
        },
        "description": "Domain tidak mengaktifkan DNSSEC sehingga rentan terhadap DNS Spoofing dan Cache Poisoning.",
        "recommendation": "Aktifkan DNSSEC pada domain registrar dan konfigurasikan DS record. Validasi menggunakan NSEC/NSEC3."
    },

    "DNS_SPF_MISSING": {
        "name": "SPF Record Not Found",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "L", "i": "L", "a": "N"
        },
        "description": "Domain tidak memiliki SPF record. Attacker dapat melakukan email spoofing mengatasnamakan domain ini.",
        "recommendation": "Tambahkan SPF record pada DNS: v=spf1 include:_spf.google.com ~all. Kombinasikan dengan DKIM dan DMARC."
    },

    "DNS_DMARC_MISSING": {
        "name": "DMARC Record Not Found",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "L", "i": "L", "a": "N"
        },
        "description": "Domain tidak memiliki DMARC record sehingga tidak ada kebijakan penanganan email yang gagal validasi SPF/DKIM.",
        "recommendation": "Tambahkan TXT record _dmarc.domain.com dengan nilai v=DMARC1; p=reject; rua=mailto:dmarc@domain.com."
    },

    "DNS_DKIM_MISSING": {
        "name": "DKIM Record Not Found",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "L", "i": "L", "a": "N"
        },
        "description": "Domain tidak memiliki DKIM record. Email dapat dipalsukan atau dimodifikasi tanpa terdeteksi.",
        "recommendation": "Aktifkan DKIM pada mail server dan publikasikan public key di DNS TXT record."
    },

    "DNS_WILDCARD_RECORD": {
        "name": "Wildcard DNS Record Detected",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "L", "i": "L", "a": "N"
        },
        "description": "Domain menggunakan wildcard DNS record (*.domain.com). Semua subdomain apapun akan resolve ke IP yang sama, berpotensi disalahgunakan.",
        "recommendation": "Hindari penggunaan wildcard DNS kecuali benar-benar diperlukan. Gunakan subdomain spesifik yang terdaftar."
    },

    "DNS_INTERNAL_IP_EXPOSED": {
        "name": "Internal IP Address Exposed via DNS",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"
        },
        "description": "Record DNS mengandung IP address internal (RFC1918: 10.x, 172.16.x, 192.168.x) yang seharusnya tidak dipublikasikan.",
        "recommendation": "Hapus record DNS yang mengarah ke IP internal. Gunakan split-horizon DNS untuk memisahkan zona internal dan eksternal."
    },

    "SUBDOMAIN_GAMBLING": {
        "name": "Gambling/Spam Subdomain Detected",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "H", "i": "H", "a": "N"
        },
        "description": "Ditemukan subdomain dengan keyword perjudian (slot, casino, gacor). Indikasi kuat kompromi server atau defacement.",
        "recommendation": "Segera hapus A Record DNS terkait. Lakukan audit log server untuk mencari celah masuk. Ganti kredensial akses panel hosting/DNS."
    },

    "SUBDOMAIN_TAKEOVER": {
        "name": "Subdomain Takeover Risk",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "H", "i": "H", "a": "N"
        },
        "description": "Subdomain memiliki CNAME record yang mengarah ke layanan eksternal yang sudah tidak aktif (dangling DNS). Attacker dapat mengklaim layanan tersebut.",
        "recommendation": "Hapus CNAME record yang mengarah ke layanan tidak aktif. Audit seluruh subdomain secara berkala."
    },

    "SUBDOMAIN_DEV_EXPOSED": {
        "name": "Development/Staging Subdomain Exposed",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "L", "i": "L", "a": "N"
        },
        "description": "Ditemukan subdomain development/staging yang dapat diakses publik (dev., staging., test., uat., demo.). Environment ini biasanya memiliki konfigurasi keamanan lebih lemah.",
        "recommendation": "Batasi akses subdomain dev/staging dengan IP whitelist atau HTTP Basic Auth. Jangan deploy data sensitif di environment non-production."
    },

    "SUBDOMAIN_ADMIN_EXPOSED": {
        "name": "Admin Panel Subdomain Exposed",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "H", "i": "H", "a": "N"
        },
        "description": "Ditemukan subdomain panel administrasi yang dapat diakses publik (admin., cp., panel., manage., backend.).",
        "recommendation": "Batasi akses panel admin hanya dari IP terpercaya. Aktifkan MFA. Pertimbangkan memindahkan admin panel ke port non-standard."
    },

    "PORT_SCANNING": {
        "name": "Risky Open Ports Detected",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"
        },
        "description": "Port layanan sensitif (SSH, RDP, Database) terbuka ke publik.",
        "recommendation": "Tutup port yang tidak digunakan dengan Firewall. Gunakan VPN/Bastion Host untuk akses manajemen. Ubah port default jika memungkinkan."
    },

    "PORT_SSH_EXPOSED": {
        "name": "SSH Port Exposed to Public (22)",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"
        },
        "description": "Port SSH (22) terbuka ke publik tanpa pembatasan IP. Rentan terhadap brute force dan eksploitasi kelemahan OpenSSH.",
        "recommendation": "Batasi akses SSH dengan firewall (whitelist IP). Gunakan SSH key authentication, nonaktifkan password login. Pertimbangkan port non-default."
    },

    "PORT_RDP_EXPOSED": {
        "name": "RDP Port Exposed to Public (3389)",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"
        },
        "description": "Port RDP (3389) terbuka ke publik. Rentan terhadap BlueKeep (CVE-2019-0708), brute force, dan credential stuffing.",
        "recommendation": "Blokir port 3389 dari internet. Gunakan VPN untuk akses RDP. Aktifkan NLA (Network Level Authentication)."
    },

    "PORT_DATABASE_EXPOSED": {
        "name": "Database Port Exposed to Public",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"
        },
        "description": "Port database (MySQL/3306, PostgreSQL/5432, MSSQL/1433, MongoDB/27017, Redis/6379) terbuka ke internet. Attacker dapat langsung mencoba akses database.",
        "recommendation": "Blokir semua port database dari akses publik. Bind database hanya ke localhost (127.0.0.1). Gunakan tunnel SSH jika perlu akses remote."
    },

    "PORT_FTP_EXPOSED": {
        "name": "FTP Port Exposed to Public (21)",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "H", "i": "H", "a": "N"
        },
        "description": "Port FTP (21) terbuka ke publik. FTP mengirimkan kredensial dalam plaintext dan rentan terhadap brute force.",
        "recommendation": "Ganti FTP dengan SFTP atau FTPS. Nonaktifkan anonymous FTP login. Batasi akses dengan IP whitelist."
    },

    "PORT_TELNET_EXPOSED": {
        "name": "Telnet Port Exposed to Public (23)",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "H", "i": "H", "a": "N"
        },
        "description": "Port Telnet (23) terbuka ke publik. Telnet adalah protokol tidak terenkripsi yang mengirimkan semua data termasuk password dalam plaintext.",
        "recommendation": "Segera nonaktifkan Telnet dan ganti dengan SSH. Blokir port 23 di firewall."
    },

    "PORT_SMTP_EXPOSED": {
        "name": "SMTP Port Open Relay Risk (25/465/587)",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "L", "i": "L", "a": "N"
        },
        "description": "Port SMTP terbuka ke publik tanpa konfigurasi yang tepat. Berpotensi disalahgunakan sebagai open relay untuk spam.",
        "recommendation": "Konfigurasi SMTP relay restriction. Aktifkan STARTTLS/SSL. Pastikan tidak berfungsi sebagai open relay."
    },

    "PORT_ELASTICSEARCH_EXPOSED": {
        "name": "Elasticsearch Port Exposed (9200/9300)",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"
        },
        "description": "Port Elasticsearch (9200/9300) terbuka ke publik tanpa autentikasi. Seluruh data index dapat diakses dan dihapus tanpa kredensial.",
        "recommendation": "Blokir port Elasticsearch dari publik. Aktifkan X-Pack Security. Bind ke localhost saja."
    },

    "PORT_MEMCACHED_EXPOSED": {
        "name": "Memcached Port Exposed (11211)",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"
        },
        "description": "Port Memcached (11211) terbuka ke publik. Dapat digunakan untuk DDoS amplification attack dan pembacaan data cache.",
        "recommendation": "Blokir port 11211 dari internet. Bind Memcached ke localhost. Aktifkan autentikasi SASL."
    },

    "TECH_FINGERPRINTING": {
        "name": "Technology Version Disclosure",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"
        },
        "description": "Informasi versi server/framework terekspos (misal: Apache 2.4.49, PHP 7.4).",
        "recommendation": "Nonaktifkan banner grabbing (ServerTokens Prod, expose_php = Off). Gunakan security headers untuk menyamarkan identitas server."
    },

    "TECH_OUTDATED_SERVER": {
        "name": "Outdated Web Server Detected",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"
        },
        "description": "Web server menggunakan versi lama yang sudah End-of-Life dan memiliki CVE kritikal yang diketahui publik.",
        "recommendation": "Segera update web server ke versi terbaru yang didukung. Pantau security advisory dari vendor secara berkala."
    },

    "TECH_OUTDATED_PHP": {
        "name": "Outdated PHP Version Detected",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"
        },
        "description": "Server menggunakan PHP versi lama (< 8.1) yang sudah tidak mendapat security update.",
        "recommendation": "Upgrade PHP ke versi yang masih didukung (minimal PHP 8.1). Uji kompatibilitas aplikasi sebelum upgrade."
    },

    "TECH_WORDPRESS_EXPOSED": {
        "name": "WordPress Version Disclosed",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "L", "i": "L", "a": "N"
        },
        "description": "Versi WordPress terekspos di meta generator tag atau file readme.html. Memudahkan attacker mencari exploit spesifik versi tersebut.",
        "recommendation": "Hapus meta generator tag dari header. Hapus atau batasi akses ke readme.html, license.txt. Update WordPress ke versi terbaru."
    },

    "TECH_JQUERY_OUTDATED": {
        "name": "Outdated jQuery Version Detected",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "R", "s": "U", "c": "L", "i": "L", "a": "N"
        },
        "description": "Website menggunakan jQuery versi lama yang memiliki kerentanan XSS yang diketahui.",
        "recommendation": "Update jQuery ke versi terbaru (3.7+). Pertimbangkan menggunakan vanilla JavaScript untuk mengurangi dependensi."
    },

    "TECH_SSL_EXPIRED": {
        "name": "SSL Certificate Expired or Invalid",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "H", "pr": "N",
            "ui": "R", "s": "U", "c": "H", "i": "H", "a": "N"
        },
        "description": "Sertifikat SSL sudah expired, self-signed, atau tidak valid. Koneksi rentan terhadap Man-in-the-Middle attack.",
        "recommendation": "Perbarui sertifikat SSL sebelum expired. Gunakan Let's Encrypt untuk sertifikat gratis. Aktifkan auto-renewal."
    },

    "TECH_SSL_WEAK_PROTOCOL": {
        "name": "Weak SSL/TLS Protocol Enabled",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "H", "pr": "N",
            "ui": "N", "s": "U", "c": "H", "i": "H", "a": "N"
        },
        "description": "Server mendukung protokol SSL/TLS yang sudah deprecated (SSLv2, SSLv3, TLS 1.0, TLS 1.1) yang rentan terhadap POODLE dan BEAST attack.",
        "recommendation": "Nonaktifkan SSLv2, SSLv3, TLS 1.0, TLS 1.1. Hanya aktifkan TLS 1.2 dan TLS 1.3. Konfigurasi cipher suite yang kuat."
    },

    "TECH_HTTP_NO_REDIRECT": {
        "name": "HTTP to HTTPS Redirect Not Configured",
        "category": "Reconnaissance",
        "metrics": {
            "av": "N", "ac": "H", "pr": "N",
            "ui": "R", "s": "U", "c": "L", "i": "L", "a": "N"
        },
        "description": "Website dapat diakses melalui HTTP tanpa redirect ke HTTPS. Koneksi tidak terenkripsi rentan terhadap penyadapan.",
        "recommendation": "Konfigurasi redirect 301 dari HTTP ke HTTPS. Aktifkan HSTS untuk mencegah downgrade attack."
    },

    # ============================================================
    # HTTP SECURITY CONFIGURATION
    # ============================================================

    "missing_security_headers": {
        "name": "Missing HTTP Security Headers",
        "category": "HTTP Security Configuration",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"
        },
        "description": "Beberapa HTTP security header penting tidak ditemukan pada response server.",
        "recommendation": "Tambahkan header: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Referrer-Policy, Permissions-Policy."
    },

    "HEADER_CSP_MISSING": {
        "name": "Content-Security-Policy Header Missing",
        "category": "HTTP Security Configuration",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "R", "s": "U", "c": "L", "i": "L", "a": "N"
        },
        "description": "Header Content-Security-Policy tidak ditemukan. Tanpa CSP, browser tidak memiliki kebijakan untuk memblokir resource berbahaya sehingga meningkatkan risiko XSS.",
        "recommendation": "Tambahkan header CSP yang ketat: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'."
    },

    "HEADER_XFRAME_MISSING": {
        "name": "X-Frame-Options Header Missing",
        "category": "HTTP Security Configuration",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "R", "s": "U", "c": "L", "i": "L", "a": "N"
        },
        "description": "Header X-Frame-Options tidak ditemukan. Halaman dapat di-embed dalam iframe oleh situs lain, membuka celah clickjacking attack.",
        "recommendation": "Tambahkan header: X-Frame-Options: DENY atau X-Frame-Options: SAMEORIGIN."
    },

    "HEADER_XCTO_MISSING": {
        "name": "X-Content-Type-Options Header Missing",
        "category": "HTTP Security Configuration",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "R", "s": "U", "c": "L", "i": "L", "a": "N"
        },
        "description": "Header X-Content-Type-Options tidak ditemukan. Browser dapat melakukan MIME sniffing dan mengeksekusi file berbahaya dengan tipe konten yang salah.",
        "recommendation": "Tambahkan header: X-Content-Type-Options: nosniff."
    },

    "HEADER_HSTS_MISSING": {
        "name": "Strict-Transport-Security Header Missing",
        "category": "HTTP Security Configuration",
        "metrics": {
            "av": "N", "ac": "H", "pr": "N",
            "ui": "R", "s": "U", "c": "H", "i": "H", "a": "N"
        },
        "description": "Header HSTS tidak ditemukan. Browser tidak dipaksa menggunakan HTTPS sehingga rentan terhadap SSL stripping dan downgrade attack.",
        "recommendation": "Tambahkan header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload."
    },

    "HEADER_REFERRER_MISSING": {
        "name": "Referrer-Policy Header Missing",
        "category": "HTTP Security Configuration",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "R", "s": "U", "c": "L", "i": "N", "a": "N"
        },
        "description": "Header Referrer-Policy tidak ditemukan. Informasi URL sensitif dapat bocor ke situs pihak ketiga melalui referrer header.",
        "recommendation": "Tambahkan header: Referrer-Policy: strict-origin-when-cross-origin."
    },

    "HEADER_PERMISSIONS_MISSING": {
        "name": "Permissions-Policy Header Missing",
        "category": "HTTP Security Configuration",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "R", "s": "U", "c": "L", "i": "N", "a": "N"
        },
        "description": "Header Permissions-Policy tidak ditemukan. Tidak ada pembatasan akses fitur browser sensitif (kamera, mikrofon, geolokasi) oleh script pihak ketiga.",
        "recommendation": "Tambahkan header: Permissions-Policy: geolocation=(), microphone=(), camera=()."
    },

    "cors_misconfiguration": {
        "name": "CORS Misconfiguration",
        "category": "HTTP Security Configuration",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "R", "s": "U", "c": "H", "i": "L", "a": "N"
        },
        "description": "Konfigurasi CORS tidak aman, berpotensi mengizinkan akses dari origin tidak trusted.",
        "recommendation": "Konfigurasi Access-Control-Allow-Origin hanya untuk origin yang trusted. Hindari penggunaan wildcard (*)."
    },

    "CORS_WILDCARD_WITH_CREDENTIALS": {
        "name": "CORS Wildcard with Credentials Enabled",
        "category": "HTTP Security Configuration",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "R", "s": "U", "c": "H", "i": "H", "a": "N"
        },
        "description": "Server mengizinkan Access-Control-Allow-Origin: * bersamaan dengan Access-Control-Allow-Credentials: true. Attacker dapat membaca response terautentikasi dari domain manapun.",
        "recommendation": "Jangan gunakan wildcard (*) jika credentials diaktifkan. Tentukan origin spesifik yang diizinkan."
    },

    "CORS_ARBITRARY_ORIGIN": {
        "name": "CORS Arbitrary Origin Reflected",
        "category": "HTTP Security Configuration",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "R", "s": "U", "c": "H", "i": "H", "a": "N"
        },
        "description": "Server merefleksikan nilai Origin header dari request secara langsung tanpa validasi. Setiap domain dapat mengakses resource dengan credentials.",
        "recommendation": "Implementasikan whitelist origin yang ketat. Validasi nilai Origin header sebelum di-set pada response."
    },

    # ============================================================
    # PROTEKSI DAN AUTENTIKASI
    # ============================================================

    "WAF_NOT_DETECTED": {
        "name": "No WAF/Firewall Detected",
        "category": "Proteksi dan Autentikasi",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "L", "i": "L", "a": "L"
        },
        "description": "Tidak terdeteksi adanya Web Application Firewall (WAF) atau CDN security di depan server. Server terekspos langsung ke internet tanpa lapisan perlindungan tambahan.",
        "recommendation": "Pertimbangkan implementasi WAF seperti Cloudflare, AWS WAF, ModSecurity, atau Imperva untuk memfilter traffic berbahaya sebelum mencapai aplikasi."
    },

    "RATE_LIMIT_NOT_DETECTED": {
        "name": "Rate Limiting Not Implemented",
        "category": "Proteksi dan Autentikasi",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "H", "i": "H", "a": "N"
        },
        "description": "Endpoint login/API tidak memiliki mekanisme rate limiting. Attacker dapat melakukan brute force atau credential stuffing tanpa pembatasan.",
        "recommendation": "Implementasikan rate limiting pada semua endpoint sensitif. Tambahkan CAPTCHA setelah beberapa kali percobaan gagal. Gunakan flask-limiter atau nginx limit_req."
    },

    "BRUTE_FORCE_NO_LOCKOUT": {
        "name": "Account Lockout Not Implemented",
        "category": "Proteksi dan Autentikasi",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "H", "i": "H", "a": "N"
        },
        "description": "Tidak ada mekanisme penguncian akun setelah beberapa kali percobaan login gagal. Memungkinkan serangan brute force tanpa hambatan.",
        "recommendation": "Implementasikan account lockout setelah 5-10 percobaan gagal. Kirim notifikasi email ke pemilik akun. Gunakan progressive delay antara percobaan."
    },

    "WEAK_PASSWORD_ACCEPTED": {
        "name": "Weak Password Policy",
        "category": "Proteksi dan Autentikasi",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "H", "i": "H", "a": "N"
        },
        "description": "Sistem menerima password yang lemah dan mudah ditebak (seperti: password, 123456, admin). Tidak ada kebijakan kompleksitas password yang memadai.",
        "recommendation": "Terapkan kebijakan password: minimal 8 karakter, kombinasi huruf besar/kecil, angka, dan karakter khusus. Cek terhadap daftar password yang umum dipakai."
    },

    "MFA_NOT_IMPLEMENTED": {
        "name": "Multi-Factor Authentication Not Available",
        "category": "Proteksi dan Autentikasi",
        "metrics": {
            "av": "N", "ac": "H", "pr": "N",
            "ui": "R", "s": "U", "c": "H", "i": "H", "a": "N"
        },
        "description": "Sistem autentikasi hanya mengandalkan username dan password tanpa faktor autentikasi tambahan. Jika kredensial bocor, akun langsung dapat diambil alih.",
        "recommendation": "Implementasikan MFA menggunakan TOTP (Google Authenticator), SMS OTP, atau hardware key (YubiKey) untuk akun dengan privilege tinggi."
    },

    "SESSION_NO_SECURE_FLAG": {
        "name": "Session Cookie Missing Secure Flag",
        "category": "Proteksi dan Autentikasi",
        "metrics": {
            "av": "N", "ac": "H", "pr": "N",
            "ui": "R", "s": "U", "c": "H", "i": "N", "a": "N"
        },
        "description": "Cookie session tidak memiliki flag Secure. Cookie dapat dikirim melalui koneksi HTTP yang tidak terenkripsi dan dicegat oleh attacker.",
        "recommendation": "Set flag Secure pada semua cookie sensitif: Set-Cookie: session=xxx; Secure; HttpOnly; SameSite=Strict."
    },

    "SESSION_NO_HTTPONLY_FLAG": {
        "name": "Session Cookie Missing HttpOnly Flag",
        "category": "Proteksi dan Autentikasi",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "R", "s": "U", "c": "H", "i": "N", "a": "N"
        },
        "description": "Cookie session tidak memiliki flag HttpOnly. Cookie dapat diakses melalui JavaScript dan dicuri melalui serangan XSS.",
        "recommendation": "Tambahkan flag HttpOnly pada semua session cookie. Ini mencegah akses JavaScript ke cookie meskipun XSS berhasil."
    },

    "SESSION_NO_SAMESITE": {
        "name": "Session Cookie Missing SameSite Attribute",
        "category": "Proteksi dan Autentikasi",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "R", "s": "U", "c": "H", "i": "H", "a": "N"
        },
        "description": "Cookie session tidak memiliki atribut SameSite. Cookie dikirim pada setiap cross-site request sehingga rentan terhadap CSRF attack.",
        "recommendation": "Set SameSite=Strict atau SameSite=Lax pada semua session cookie untuk mencegah CSRF."
    },

    "DEFAULT_CREDENTIALS": {
        "name": "Default Credentials Accepted",
        "category": "Proteksi dan Autentikasi",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"
        },
        "description": "Sistem menerima kredensial default yang umum diketahui (admin/admin, admin/password, root/root). Ini merupakan celah keamanan kritikal.",
        "recommendation": "Segera ganti semua kredensial default. Paksa pengguna baru untuk mengganti password saat pertama kali login. Audit semua akun default."
    },

    "LOGIN_NO_CAPTCHA": {
        "name": "Login Form Without CAPTCHA",
        "category": "Proteksi dan Autentikasi",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "L", "i": "L", "a": "N"
        },
        "description": "Form login tidak dilindungi CAPTCHA. Memudahkan automated bot melakukan credential stuffing atau brute force attack.",
        "recommendation": "Implementasikan CAPTCHA (reCAPTCHA v3/v2) pada form login, registrasi, dan reset password. Aktifkan setelah beberapa kali percobaan gagal."
    },

    # ============================================================
    # WEB VULNERABILITIES
    # ============================================================

    "SQL_INJECTION": {
        "name": "SQL Injection (Error-based)",
        "category": "Web Vulnerabilities",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"
        },
        "description": "Parameter input tidak disanitasi dengan benar sehingga memungkinkan injeksi perintah SQL. Attacker dapat membaca, memodifikasi, atau menghapus data database.",
        "recommendation": "Gunakan Prepared Statements / Parameterized Queries. Jangan pernah menggabungkan input user langsung ke query SQL. Terapkan principle of least privilege pada user database."
    },

    "SQL_INJECTION_BLIND": {
        "name": "Blind SQL Injection",
        "category": "Web Vulnerabilities",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"
        },
        "description": "Terdeteksi kemungkinan Blind SQL Injection dimana hasil query tidak langsung ditampilkan namun dapat diinferensikan dari perbedaan response atau waktu respon.",
        "recommendation": "Gunakan Prepared Statements. Implementasikan WAF. Audit seluruh query database dan sanitasi semua input pengguna."
    },

    "REFLECTED_XSS": {
        "name": "Reflected Cross-Site Scripting (XSS)",
        "category": "Web Vulnerabilities",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "R", "s": "U", "c": "L", "i": "L", "a": "N"
        },
        "description": "Input pengguna di-reflect ke halaman tanpa encoding yang tepat. Attacker dapat menyisipkan script berbahaya yang dieksekusi di browser korban melalui URL berbahaya.",
        "recommendation": "Encode semua output ke HTML entities. Implementasikan Content-Security-Policy yang ketat. Gunakan library templating yang auto-escape."
    },

    "STORED_XSS": {
        "name": "Stored Cross-Site Scripting (XSS)",
        "category": "Web Vulnerabilities",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "R", "s": "C", "c": "H", "i": "H", "a": "N"
        },
        "description": "Input berbahaya disimpan di database dan ditampilkan ke pengguna lain tanpa sanitasi. Lebih berbahaya dari Reflected XSS karena tidak memerlukan interaksi link khusus.",
        "recommendation": "Sanitasi semua input sebelum disimpan ke database. Encode semua output saat ditampilkan. Implementasikan CSP yang ketat."
    },

    "OPEN_REDIRECT": {
        "name": "Open Redirect",
        "category": "Web Vulnerabilities",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "R", "s": "U", "c": "L", "i": "L", "a": "N"
        },
        "description": "Aplikasi menerima URL tujuan redirect dari parameter tanpa validasi. Attacker dapat membuat link yang terlihat sah namun mengarahkan korban ke situs phishing.",
        "recommendation": "Validasi dan whitelist semua URL redirect. Jangan gunakan input user secara langsung sebagai tujuan redirect. Gunakan mapping ID ke URL yang diizinkan."
    },

    "COMMAND_INJECTION": {
        "name": "Command Injection",
        "category": "Web Vulnerabilities",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"
        },
        "description": "Input pengguna diteruskan langsung ke system command tanpa sanitasi. Attacker dapat mengeksekusi perintah sistem operasi secara remote (Remote Code Execution).",
        "recommendation": "Hindari penggunaan fungsi exec/system/shell_exec dengan input user. Jika diperlukan, gunakan whitelist input yang ketat dan jalankan dengan privilege minimal."
    },

    "FILE_UPLOAD_MISCONFIGURATION": {
        "name": "File Upload Misconfiguration",
        "category": "Web Vulnerabilities",
        "metrics": {
            "av": "N", "ac": "L", "pr": "L",
            "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"
        },
        "description": "Fitur upload file tidak membatasi tipe file yang diizinkan. Attacker dapat mengupload file berbahaya (webshell PHP, script) dan mengeksekusinya untuk mendapatkan akses server.",
        "recommendation": "Validasi tipe file menggunakan MIME type dan magic bytes, bukan hanya ekstensi. Simpan file di luar document root. Rename file secara random. Nonaktifkan eksekusi script di folder upload."
    },

    "DIRECTORY_LISTING": {
        "name": "Directory Listing Enabled",
        "category": "Web Vulnerabilities",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"
        },
        "description": "Server menampilkan daftar file dan direktori secara publik. Attacker dapat menemukan file sensitif seperti backup, konfigurasi, atau file yang seharusnya tidak publik.",
        "recommendation": "Nonaktifkan directory listing di web server (Options -Indexes untuk Apache, autoindex off untuk Nginx). Tambahkan file index.html kosong di setiap direktori."
    },

    "PATH_TRAVERSAL": {
        "name": "Path Traversal",
        "category": "Web Vulnerabilities",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "H", "i": "N", "a": "N"
        },
        "description": "Aplikasi menggunakan input pengguna untuk mengakses file tanpa validasi path. Attacker dapat menggunakan ../../../etc/passwd untuk membaca file di luar document root.",
        "recommendation": "Validasi dan sanitasi semua path input. Gunakan realpath() untuk menormalisasi path. Pastikan path yang diakses berada dalam direktori yang diizinkan (chroot jail)."
    },

    "SSRF": {
        "name": "Server-Side Request Forgery (SSRF)",
        "category": "Web Vulnerabilities",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "H", "i": "H", "a": "N"
        },
        "description": "Aplikasi melakukan request HTTP berdasarkan input pengguna tanpa validasi. Attacker dapat memaksa server melakukan request ke jaringan internal atau metadata cloud (169.254.169.254).",
        "recommendation": "Validasi dan whitelist semua URL yang diizinkan. Blokir akses ke IP internal/loopback. Gunakan DNS allowlist. Nonaktifkan redirect pada HTTP client."
    },

    "IDOR": {
        "name": "Insecure Direct Object Reference (IDOR)",
        "category": "Web Vulnerabilities",
        "metrics": {
            "av": "N", "ac": "L", "pr": "L",
            "ui": "N", "s": "U", "c": "H", "i": "H", "a": "N"
        },
        "description": "Aplikasi menggunakan identifier yang dapat diprediksi (ID berurutan) untuk mengakses objek tanpa validasi kepemilikan. User dapat mengakses data milik user lain dengan mengubah ID.",
        "recommendation": "Implementasikan authorization check pada setiap akses resource. Gunakan UUID/GUID sebagai identifier publik. Validasi kepemilikan resource sebelum memberikan akses."
    },

    "CSRF": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "category": "Web Vulnerabilities",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "R", "s": "U", "c": "H", "i": "H", "a": "N"
        },
        "description": "Endpoint state-changing tidak dilindungi CSRF token. Attacker dapat membuat halaman web yang secara diam-diam mengirim request berbahaya atas nama user yang sedang login.",
        "recommendation": "Implementasikan CSRF token pada semua form dan state-changing request. Gunakan SameSite cookie attribute. Validasi Origin/Referer header."
    },

    "XXE_INJECTION": {
        "name": "XML External Entity (XXE) Injection",
        "category": "Web Vulnerabilities",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"
        },
        "description": "Parser XML mengizinkan pemrosesan external entity. Attacker dapat membaca file sistem, melakukan SSRF, atau denial of service melalui Billion Laughs attack.",
        "recommendation": "Nonaktifkan pemrosesan external entity pada XML parser. Gunakan format JSON sebagai alternatif. Update library XML ke versi terbaru."
    },

    "SENSITIVE_DATA_EXPOSURE": {
        "name": "Sensitive Data Exposure",
        "category": "Web Vulnerabilities",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N",
            "ui": "N", "s": "U", "c": "H", "i": "N", "a": "N"
        },
        "description": "Ditemukan file atau endpoint yang mengekspos data sensitif secara publik: file .env, backup database (.sql), file konfigurasi, API key, atau credential di response.",
        "recommendation": "Audit semua file yang dapat diakses publik. Hapus atau batasi akses ke file sensitif. Gunakan .gitignore untuk mencegah commit file sensitif. Rotasi semua credential yang terekspos."
    },

    "INSECURE_DESERIALIZATION": {
        "name": "Insecure Deserialization",
        "category": "Web Vulnerabilities",
        "metrics": {
            "av": "N", "ac": "H", "pr": "N",
            "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"
        },
        "description": "Aplikasi melakukan deserialisasi data dari sumber tidak terpercaya tanpa validasi integritas. Dapat menyebabkan Remote Code Execution, privilege escalation, atau replay attack.",
        "recommendation": "Hindari deserialisasi data dari sumber tidak terpercaya. Implementasikan signature/HMAC untuk memvalidasi integritas data sebelum deserialisasi. Jalankan proses deserialisasi dengan privilege minimal."
    },
}
