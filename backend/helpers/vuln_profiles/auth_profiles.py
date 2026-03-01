AUTH_PROFILES = {
    "WAF_NOT_DETECTED": {
        "name": "No WAF/Firewall Detected",
        "category": "Proteksi dan Autentikasi",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "L", "i": "L", "a": "L"},
        "description": "Tidak terdeteksi WAF. Server terekspos langsung ke internet.",
        "recommendation": "Implementasikan WAF: Cloudflare, AWS WAF, atau ModSecurity."
    },
    "RATE_LIMIT_NOT_DETECTED": {
        "name": "Rate Limiting Not Implemented",
        "category": "Proteksi dan Autentikasi",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "N"},
        "description": "Endpoint login/API tidak memiliki rate limiting. Rentan brute force.",
        "recommendation": "Implementasikan rate limiting. Tambahkan CAPTCHA setelah beberapa kali gagal."
    },
    "BRUTE_FORCE_NO_LOCKOUT": {
        "name": "Account Lockout Not Implemented",
        "category": "Proteksi dan Autentikasi",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "N"},
        "description": "Tidak ada penguncian akun setelah percobaan login gagal berulang.",
        "recommendation": "Lockout akun setelah 5-10 percobaan gagal. Kirim notifikasi ke pemilik akun."
    },
    "WEAK_PASSWORD_ACCEPTED": {
        "name": "Weak Password Policy",
        "category": "Proteksi dan Autentikasi",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "N"},
        "description": "Sistem menerima password lemah (123456, password, admin).",
        "recommendation": "Terapkan kebijakan password kuat: min 8 karakter, kombinasi huruf besar/kecil, angka, karakter khusus."
    },
    "DEFAULT_CREDENTIALS": {
        "name": "Default Credentials Accepted",
        "category": "Proteksi dan Autentikasi",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"},
        "description": "Sistem menerima kredensial default (admin/admin, root/root).",
        "recommendation": "Ganti semua kredensial default. Paksa pengguna baru ganti password saat pertama login."
    },
    "SESSION_NO_SECURE_FLAG": {
        "name": "Session Cookie Missing Secure Flag",
        "category": "Proteksi dan Autentikasi",
        "metrics": {"av": "N", "ac": "H", "pr": "N", "ui": "R", "s": "U", "c": "H", "i": "N", "a": "N"},
        "description": "Cookie session tidak memiliki flag Secure. Bisa dicegat via HTTP.",
        "recommendation": "Set Secure flag: Set-Cookie: session=xxx; Secure; HttpOnly; SameSite=Strict."
    },
    "SESSION_NO_HTTPONLY_FLAG": {
        "name": "Session Cookie Missing HttpOnly Flag",
        "category": "Proteksi dan Autentikasi",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "U", "c": "H", "i": "N", "a": "N"},
        "description": "Cookie session bisa diakses JavaScript. Rentan dicuri via XSS.",
        "recommendation": "Tambahkan HttpOnly flag pada semua session cookie."
    },
    "LOGIN_NO_CAPTCHA": {
        "name": "Login Form Without CAPTCHA",
        "category": "Proteksi dan Autentikasi",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "L", "i": "L", "a": "N"},
        "description": "Form login tidak dilindungi CAPTCHA. Rentan automated bot attack.",
        "recommendation": "Implementasikan reCAPTCHA v3 pada form login, registrasi, dan reset password."
    },
}
