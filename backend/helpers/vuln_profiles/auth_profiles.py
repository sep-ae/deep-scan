AUTH_PROFILES = {
    "WAF_NOT_DETECTED": {
        "name": "No WAF/Firewall Detected",
        "category": "Proteksi dan Autentikasi",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "N", "i": "N", "a": "L"},
        "description": (
            "Tidak terdeteksi Web Application Firewall (WAF) yang melindungi server. "
            "WAF berfungsi sebagai lapisan pertahanan pertama yang memfilter request berbahaya "
            "seperti SQL Injection, XSS, dan serangan otomatis sebelum mencapai aplikasi. "
            "Tanpa WAF, semua request langsung diteruskan ke server aplikasi, "
            "meningkatkan risiko eksploitasi jika terdapat kerentanan pada kode aplikasi."
        ),
        "recommendation": (
            "Implementasikan WAF untuk melindungi aplikasi dari serangan umum. "
            "Pilihan WAF yang tersedia: 1) Cloudflare WAF (cloud-based, mudah dikonfigurasi). "
            "2) AWS WAF untuk infrastruktur AWS. 3) ModSecurity (open-source, dapat dipasang "
            "di Apache/Nginx). 4) Sucuri untuk WordPress. "
            "Pastikan WAF dikonfigurasi dengan ruleset OWASP Core Rule Set (CRS) "
            "dan diupdate secara berkala."
        ),
    },

    "RATE_LIMIT_NOT_DETECTED": {
        "name": "Rate Limiting Not Implemented",
        "category": "Proteksi dan Autentikasi",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "L", "i": "L", "a": "N"},
        "description": (
            "Endpoint login atau API tidak memiliki mekanisme rate limiting yang membatasi "
            "jumlah request per waktu tertentu. Penyerang dapat melakukan brute force attack "
            "dengan mengirimkan ribuan kombinasi username dan password dalam waktu singkat "
            "tanpa dibatasi. Selain itu, endpoint API tanpa rate limit rentan terhadap "
            "abuse dan Denial of Service karena tidak ada pembatasan frekuensi akses."
        ),
        "recommendation": (
            "Implementasikan rate limiting pada endpoint kritis: "
            "1) Login: maksimal 5 percobaan per menit per IP. "
            "2) API: 100 request per menit per user/IP. "
            "3) Gunakan library seperti Flask-Limiter, express-rate-limit, atau nginx limit_req. "
            "4) Tambahkan CAPTCHA setelah 3 kali gagal login. "
            "5) Kembalikan response HTTP 429 (Too Many Requests) saat limit tercapai. "
            "6) Pertimbangkan progressive delay (semakin sering gagal, semakin lama harus menunggu)."
        ),
    },

    "BRUTE_FORCE_NO_LOCKOUT": {
        "name": "Account Lockout Not Implemented",
        "category": "Proteksi dan Autentikasi",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "L", "i": "L", "a": "N"},
        "description": (
            "Sistem tidak menerapkan penguncian akun (account lockout) setelah percobaan login "
            "gagal berulang kali. Penyerang dapat melakukan serangan brute force tanpa henti "
            "untuk menebak password pengguna. Tanpa mekanisme lockout, setiap akun menjadi "
            "target potensial serangan credential stuffing dan dictionary attack "
            "menggunakan daftar password yang umum digunakan."
        ),
        "recommendation": (
            "Implementasikan mekanisme penguncian akun bertahap: "
            "1) Setelah 5 percobaan gagal: kunci akun selama 15 menit. "
            "2) Setelah 10 percobaan gagal: kunci selama 1 jam dan kirim notifikasi email. "
            "3) Setelah 20 percobaan gagal: kunci permanen sampai admin membuka atau user reset password. "
            "4) Catat semua percobaan login gagal di log untuk keperluan audit. "
            "5) Pertimbangkan penggunaan MFA (Multi-Factor Authentication) untuk akun penting."
        ),
    },

    "WEAK_PASSWORD_ACCEPTED": {
        "name": "Weak Password Policy",
        "category": "Proteksi dan Autentikasi",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "L", "i": "L", "a": "N"},
        "description": (
            "Sistem menerima password yang lemah dan mudah ditebak seperti '123456', 'password', "
            "'admin', 'qwerty', atau password yang terlalu pendek. Password lemah dapat ditebak "
            "oleh penyerang menggunakan serangan dictionary attack dalam hitungan detik. "
            "Menurut data dari breach database, password-password tersebut adalah yang paling "
            "umum digunakan dan menjadi target utama serangan credential stuffing."
        ),
        "recommendation": (
            "Terapkan kebijakan password yang kuat: "
            "1) Minimal 8 karakter (direkomendasikan 12 karakter). "
            "2) Wajib kombinasi huruf besar, huruf kecil, angka, dan karakter khusus. "
            "3) Blokir password yang terdapat dalam daftar breach (Have I Been Pwned API). "
            "4) Jangan izinkan password yang sama dengan username atau email. "
            "5) Implementasikan password strength meter di frontend. "
            "6) Pertimbangkan passphrase sebagai alternatif password tradisional."
        ),
    },

    "DEFAULT_CREDENTIALS": {
        "name": "Default Credentials Accepted",
        "category": "Proteksi dan Autentikasi",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "L"},
        "description": (
            "Sistem menerima login menggunakan kredensial default seperti admin/admin, "
            "root/root, atau administrator/password. Kredensial default adalah target pertama "
            "yang dicoba oleh penyerang karena banyak sistem yang tidak mengganti kredensial "
            "bawaan setelah instalasi. Akses dengan kredensial default biasanya memberikan "
            "hak akses administrator penuh yang memungkinkan penyerang mengambil alih "
            "seluruh sistem tanpa perlu melakukan eksploitasi teknis."
        ),
        "recommendation": (
            "1) Ganti semua kredensial default segera setelah instalasi sistem. "
            "2) Paksa pengguna baru untuk mengganti password saat pertama kali login. "
            "3) Blokir semua kombinasi kredensial yang terdapat dalam daftar default credentials. "
            "4) Audit secara berkala apakah ada akun yang masih menggunakan password default. "
            "5) Gunakan random-generated password untuk akun sistem dan simpan di password manager."
        ),
    },

    "SESSION_NO_SECURE_FLAG": {
        "name": "Session Cookie Missing Secure Flag",
        "category": "Proteksi dan Autentikasi",
        "metrics": {"av": "N", "ac": "H", "pr": "N", "ui": "R", "s": "U", "c": "L", "i": "N", "a": "N"},
        "description": (
            "Cookie session tidak memiliki atribut Secure. Tanpa flag ini, cookie dapat "
            "dikirimkan melalui koneksi HTTP yang tidak terenkripsi. Jika pengguna mengakses "
            "situs melalui HTTP (misalnya di WiFi publik), penyerang yang melakukan "
            "network sniffing dapat menangkap cookie session dan menggunakannya untuk "
            "mengakses akun korban tanpa perlu mengetahui password (session hijacking)."
        ),
        "recommendation": (
            "Tambahkan flag Secure pada semua cookie session: "
            "Set-Cookie: session=xxx; Secure; HttpOnly; SameSite=Strict. "
            "Flag Secure memastikan browser hanya mengirimkan cookie melalui koneksi HTTPS. "
            "Pastikan juga HSTS diaktifkan agar browser selalu menggunakan HTTPS."
        ),
    },

    "SESSION_NO_HTTPONLY_FLAG": {
        "name": "Session Cookie Missing HttpOnly Flag",
        "category": "Proteksi dan Autentikasi",
        "metrics": {"av": "N", "ac": "H", "pr": "N", "ui": "R", "s": "U", "c": "L", "i": "N", "a": "N"},
        "description": (
            "Cookie session tidak memiliki atribut HttpOnly. Tanpa flag ini, cookie dapat "
            "diakses oleh JavaScript melalui document.cookie. Jika terdapat kerentanan XSS "
            "pada aplikasi, penyerang dapat mencuri cookie session melalui payload JavaScript "
            "dan mengirimkannya ke server yang dikontrol penyerang untuk melakukan "
            "session hijacking."
        ),
        "recommendation": (
            "Tambahkan flag HttpOnly pada semua cookie session: "
            "Set-Cookie: session=xxx; HttpOnly; Secure; SameSite=Strict. "
            "Flag HttpOnly mencegah akses cookie dari JavaScript, sehingga meskipun terjadi XSS, "
            "penyerang tidak dapat mencuri cookie session melalui document.cookie."
        ),
    },

    "LOGIN_NO_CAPTCHA": {
        "name": "Login Form Without CAPTCHA",
        "category": "Proteksi dan Autentikasi",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "N", "i": "L", "a": "N"},
        "description": (
            "Form login tidak dilindungi oleh CAPTCHA atau mekanisme challenge-response lainnya. "
            "Tanpa CAPTCHA, bot otomatis dapat melakukan serangan brute force atau credential "
            "stuffing dengan mengirimkan ribuan kombinasi login secara otomatis. "
            "CAPTCHA berfungsi sebagai pembatas yang memastikan bahwa request login "
            "berasal dari manusia, bukan script otomatis."
        ),
        "recommendation": (
            "Implementasikan CAPTCHA pada form login, registrasi, dan reset password: "
            "1) Google reCAPTCHA v3 (invisible, berbasis skor — tidak mengganggu UX). "
            "2) hCaptcha sebagai alternatif privasi-friendly. "
            "3) Tampilkan CAPTCHA setelah 3 kali percobaan login gagal (adaptive CAPTCHA). "
            "4) Kombinasikan dengan rate limiting untuk proteksi berlapis."
        ),
    },

    "LOGIN_NO_CSRF": {
        "name": "Login Form Without CSRF Protection",
        "category": "Proteksi dan Autentikasi",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "U", "c": "N", "i": "L", "a": "N"},
        "description": (
            "Form login tidak memiliki proteksi Cross-Site Request Forgery (CSRF). "
            "Penyerang dapat membuat halaman web berbahaya yang secara otomatis "
            "mengirimkan request login atas nama korban. Pada kasus login CSRF, "
            "penyerang dapat memaksa korban login ke akun yang dikontrol penyerang, "
            "sehingga aktivitas korban terekam di akun penyerang (login CSRF attack)."
        ),
        "recommendation": (
            "Implementasikan proteksi CSRF pada semua form: "
            "1) Gunakan CSRF token unik per session yang disisipkan dalam hidden field. "
            "2) Validasi token di sisi server sebelum memproses request. "
            "3) Gunakan atribut SameSite=Strict pada cookie session. "
            "4) Framework seperti Flask-WTF, Django, dan Laravel sudah menyediakan CSRF protection bawaan."
        ),
    },
}
