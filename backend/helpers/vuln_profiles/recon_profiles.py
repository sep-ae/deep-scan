RECON_PROFILES = {
    "DNS_LOOKUP": {
        "name": "DNS Information Disclosure",
        "category": "Reconnaissance",
        "metrics": {"av": "N","ac": "L","pr": "N","ui": "N","s": "U","c": "L","i": "N","a": "N"},
        "description": "DNS records publicly expose internal infrastructure details.",
        "recommendation": "Lakukan split DNS. Gunakan DNSSEC. Batasi Zone Transfer hanya ke secondary DNS terpercaya."
    },

    "DNS_ZONE_TRANSFER": {
        "name": "DNS Zone Transfer Allowed",
        "category": "Reconnaissance",
        "metrics": {"av": "N","ac": "L","pr": "N","ui": "N","s": "U","c": "H","i": "N","a": "N"},
        "description": "Server DNS mengizinkan Zone Transfer (AXFR) dari sembarang host.",
        "recommendation": "Batasi AXFR hanya ke IP secondary DNS terpercaya."
    },

    "PORT_SSH_EXPOSED": {
        "name": "SSH Port Exposed to Public (22)",
        "category": "Reconnaissance",
        "metrics": {"av": "N","ac": "L","pr": "N","ui": "N","s": "U","c": "L","i": "N","a": "N"},
        "description": "Port SSH (22) terbuka ke publik. Rentan brute force dan eksploitasi OpenSSH.",
        "recommendation": "Whitelist IP untuk SSH. Gunakan key authentication. Nonaktifkan password login."
    },

    "PORT_RDP_EXPOSED": {
        "name": "RDP Port Exposed to Public (3389)",
        "category": "Reconnaissance",
        "metrics": {"av": "N","ac": "L","pr": "N","ui": "N","s": "U","c": "L","i": "N","a": "N"},
        "description": "Port RDP (3389) terbuka ke publik. Rentan BlueKeep dan brute force.",
        "recommendation": "Blokir port 3389 dari internet. Gunakan VPN. Aktifkan NLA."
    },

    "PORT_DATABASE_EXPOSED": {
        "name": "Database Port Exposed to Public",
        "category": "Reconnaissance",
        "metrics": {"av": "N","ac": "L","pr": "N","ui": "N","s": "U","c": "L","i": "N","a": "N"},
        "description": "Port database (MySQL/3306, PostgreSQL/5432, Redis/6379, MongoDB/27017) terbuka ke internet.",
        "recommendation": "Blokir semua port database dari publik. Bind ke localhost. Gunakan tunnel SSH."
    },

    "PORT_FTP_EXPOSED": {
        "name": "FTP Port Exposed to Public (21)",
        "category": "Reconnaissance",
        "metrics": {"av": "N","ac": "L","pr": "N","ui": "N","s": "U","c": "L","i": "N","a": "N"},
        "description": "Port FTP (21) terbuka ke publik. Kredensial dikirim dalam plaintext.",
        "recommendation": "Ganti FTP dengan SFTP/FTPS. Nonaktifkan anonymous login."
    },

    "PORT_TELNET_EXPOSED": {
        "name": "Telnet Port Exposed to Public (23)",
        "category": "Reconnaissance",
        "metrics": {"av": "N","ac": "L","pr": "N","ui": "N","s": "U","c": "L","i": "N","a": "N"},
        "description": "Port Telnet (23) terbuka ke publik. Semua data dikirim plaintext.",
        "recommendation": "Nonaktifkan Telnet, ganti dengan SSH. Blokir port 23."
    },

    "PORT_MEMCACHED_EXPOSED": {
        "name": "Memcached Port Exposed (11211)",
        "category": "Reconnaissance",
        "metrics": {"av": "N","ac": "L","pr": "N","ui": "N","s": "U","c": "N","i": "N","a": "H"},
        "description": "Port Memcached terbuka. Dapat digunakan untuk DDoS amplification.",
        "recommendation": "Blokir port 11211. Bind ke localhost. Aktifkan SASL."
    },

    "PORT_ELASTICSEARCH_EXPOSED": {
        "name": "Elasticsearch Port Exposed (9200/9300)",
        "category": "Reconnaissance",
        "metrics": {"av": "N","ac": "L","pr": "N","ui": "N","s": "U","c": "H","i": "H","a": "H"},
        "description": "Port Elasticsearch terbuka tanpa autentikasi. Seluruh data dapat diakses.",
        "recommendation": "Blokir dari publik. Aktifkan X-Pack Security. Bind ke localhost."
    },
    
    "SUBDOMAIN_GAMBLING": {
        "name": "Gambling/Spam Subdomain Detected",
        "category": "Reconnaissance",
        "metrics": {"av": "N","ac": "L","pr": "N","ui": "N","s": "U","c": "H","i": "H","a": "N"},
        "description": "Ditemukan subdomain dengan keyword perjudian. Indikasi kompromi server.",
        "recommendation": "Hapus A Record DNS terkait. Audit log server. Ganti kredensial panel hosting/DNS."
    },

    "SUBDOMAIN_DEV_EXPOSED": {
        "name": "Development/Staging Subdomain Exposed",
        "category": "Reconnaissance",
        "metrics": {"av": "N","ac": "L","pr": "N","ui": "N","s": "U","c": "L","i": "L","a": "N"},
        "description": "Subdomain dev/staging dapat diakses publik dengan konfigurasi keamanan lebih lemah.",
        "recommendation": "Batasi akses dengan IP whitelist atau HTTP Basic Auth."
    },

    "SUBDOMAIN_ADMIN_EXPOSED": {
        "name": "Admin Panel Subdomain Exposed",
        "category": "Reconnaissance",
        "metrics": {"av": "N","ac": "L","pr": "N","ui": "N","s": "U","c": "H","i": "H","a": "N"},
        "description": "Subdomain panel administrasi dapat diakses publik.",
        "recommendation": "Batasi akses hanya dari IP terpercaya. Aktifkan MFA."
    },

    "SUBDOMAIN_TAKEOVER": {
        "name": "Subdomain Takeover Risk",
        "category": "Reconnaissance",
        "metrics": {"av": "N","ac": "L","pr": "N","ui": "N","s": "U","c": "H","i": "H","a": "N"},
        "description": "Subdomain memiliki CNAME ke layanan eksternal yang sudah tidak aktif (dangling DNS).",
        "recommendation": "Hapus CNAME record yang mengarah ke layanan tidak aktif. Audit subdomain secara berkala."
    }
}