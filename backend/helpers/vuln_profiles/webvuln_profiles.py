WEBVULN_PROFILES = {
    "SQL_INJECTION": {
        "name": "SQL Injection (Error-based)",
        "category": "Web Vulnerabilities",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"},
        "description": "Parameter input tidak disanitasi, memungkinkan injeksi perintah SQL.",
        "recommendation": "Gunakan Prepared Statements. Jangan gabungkan input user langsung ke query SQL."
    },
    "REFLECTED_XSS": {
        "name": "Reflected Cross-Site Scripting (XSS)",
        "category": "Web Vulnerabilities",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "U", "c": "L", "i": "L", "a": "N"},
        "description": "Input pengguna di-reflect ke halaman tanpa encoding. Script berbahaya dapat dieksekusi.",
        "recommendation": "Encode semua output ke HTML entities. Implementasikan CSP yang ketat."
    },
    "OPEN_REDIRECT": {
        "name": "Open Redirect",
        "category": "Web Vulnerabilities",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "U", "c": "L", "i": "L", "a": "N"},
        "description": "Aplikasi menerima URL redirect dari parameter tanpa validasi.",
        "recommendation": "Whitelist semua URL redirect. Jangan gunakan input user langsung sebagai tujuan redirect."
    },
    "COMMAND_INJECTION": {
        "name": "Command Injection",
        "category": "Web Vulnerabilities",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"},
        "description": "Input diteruskan ke system command tanpa sanitasi. Rentan Remote Code Execution.",
        "recommendation": "Hindari exec/system dengan input user. Gunakan whitelist input yang ketat."
    },
    "FILE_UPLOAD_MISCONFIGURATION": {
        "name": "File Upload Misconfiguration",
        "category": "Web Vulnerabilities",
        "metrics": {"av": "N", "ac": "L", "pr": "L", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"},
        "description": "Upload file tidak membatasi tipe file. Attacker dapat upload webshell.",
        "recommendation": "Validasi MIME type dan magic bytes. Simpan file di luar document root. Rename file secara random."
    },
    "DIRECTORY_LISTING": {
        "name": "Directory Listing Enabled",
        "category": "Web Vulnerabilities",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
        "description": "Server menampilkan daftar file secara publik. File sensitif dapat ditemukan.",
        "recommendation": "Nonaktifkan directory listing (Options -Indexes / autoindex off). Tambahkan index.html di setiap direktori."
    },
    "PATH_TRAVERSAL": {
        "name": "Path Traversal",
        "category": "Web Vulnerabilities",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "N", "a": "N"},
        "description": "Input digunakan untuk akses file tanpa validasi path. Rentan baca file di luar document root.",
        "recommendation": "Validasi semua path input. Gunakan realpath(). Pastikan path dalam direktori yang diizinkan."
    },
    "SSRF": {
        "name": "Server-Side Request Forgery (SSRF)",
        "category": "Web Vulnerabilities",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "N"},
        "description": "Aplikasi melakukan HTTP request berdasarkan input user. Rentan akses jaringan internal.",
        "recommendation": "Whitelist URL yang diizinkan. Blokir akses ke IP internal/loopback."
    },
    "SENSITIVE_DATA_EXPOSURE": {
        "name": "Sensitive Data Exposure",
        "category": "Web Vulnerabilities",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "N", "a": "N"},
        "description": "Ditemukan file sensitif publik: .env, backup DB, config, API key.",
        "recommendation": "Hapus/batasi akses file sensitif. Rotasi semua credential yang terekspos."
    },
}
