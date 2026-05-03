HTTP_PROFILES = {
    "missing_security_headers": {
        "name": "Missing HTTP Security Headers",
        "category": "HTTP Security Configuration",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "N", "i": "L", "a": "N"},
        "description": (
            "Beberapa HTTP security header penting tidak ditemukan pada response server. "
            "Header keamanan berfungsi sebagai lapisan pertahanan tambahan yang menginstruksikan "
            "browser untuk mengaktifkan fitur keamanan bawaan seperti pencegahan XSS, clickjacking, "
            "dan MIME sniffing. Tanpa header ini, browser akan menggunakan perilaku default "
            "yang lebih permisif dan rentan terhadap serangan sisi klien."
        ),
        "recommendation": (
            "Tambahkan header berikut pada konfigurasi web server atau middleware aplikasi: "
            "1) Content-Security-Policy untuk membatasi sumber resource yang diizinkan. "
            "2) X-Frame-Options: DENY atau SAMEORIGIN untuk mencegah clickjacking. "
            "3) X-Content-Type-Options: nosniff untuk mencegah MIME sniffing. "
            "4) Strict-Transport-Security: max-age=31536000; includeSubDomains untuk memaksa HTTPS. "
            "5) Referrer-Policy: strict-origin-when-cross-origin untuk membatasi kebocoran URL."
        ),
    },

    "HEADER_CSP_MISSING": {
        "name": "Content-Security-Policy Header Missing",
        "category": "HTTP Security Configuration",
        "metrics": {"av": "N", "ac": "H", "pr": "N", "ui": "R", "s": "U", "c": "L", "i": "N", "a": "N"},
        "description": (
            "Header Content-Security-Policy (CSP) tidak ditemukan pada response server. "
            "CSP berfungsi membatasi sumber resource (script, style, image, font, iframe) "
            "yang diizinkan dimuat oleh browser. Tanpa CSP, jika terdapat kerentanan XSS, "
            "penyerang dapat memuat script eksternal dari domain manapun, "
            "memperbesar dampak serangan seperti pencurian data dan session hijacking."
        ),
        "recommendation": (
            "Tambahkan header CSP pada konfigurasi web server atau response middleware. "
            "Contoh konfigurasi dasar: Content-Security-Policy: default-src 'self'; "
            "script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "object-src 'none'; frame-ancestors 'none'. "
            "Gunakan report-uri atau report-to untuk memonitor pelanggaran CSP sebelum enforcement."
        ),
    },

    "HEADER_XFRAME_MISSING": {
        "name": "X-Frame-Options Header Missing",
        "category": "HTTP Security Configuration",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "U", "c": "N", "i": "L", "a": "N"},
        "description": (
            "Header X-Frame-Options tidak ditemukan pada response server. "
            "Tanpa header ini, halaman web dapat di-embed ke dalam iframe oleh situs pihak ketiga. "
            "Penyerang dapat memanfaatkan ini untuk serangan clickjacking, yaitu meletakkan "
            "halaman target secara transparan di atas halaman palsu sehingga korban tanpa sadar "
            "mengklik tombol atau link di halaman target (misalnya tombol transfer, delete, "
            "atau perubahan pengaturan akun)."
        ),
        "recommendation": (
            "Tambahkan header X-Frame-Options pada konfigurasi web server: "
            "X-Frame-Options: DENY (melarang semua framing) atau SAMEORIGIN (hanya izinkan "
            "framing dari domain yang sama). Sebagai alternatif modern, gunakan directive "
            "frame-ancestors pada Content-Security-Policy: frame-ancestors 'self'."
        ),
    },

    "HEADER_XCTO_MISSING": {
        "name": "X-Content-Type-Options Header Missing",
        "category": "HTTP Security Configuration",
        "metrics": {"av": "N", "ac": "H", "pr": "N", "ui": "R", "s": "U", "c": "N", "i": "L", "a": "N"},
        "description": (
            "Header X-Content-Type-Options tidak ditemukan pada response server. "
            "Tanpa header ini, browser dapat melakukan MIME type sniffing — yaitu menginterpretasikan "
            "konten file berdasarkan isi file, bukan berdasarkan Content-Type yang dikirim server. "
            "Hal ini memungkinkan penyerang mengupload file berbahaya (misalnya file JavaScript "
            "yang di-rename menjadi .txt) dan browser akan tetap mengeksekusinya sebagai script."
        ),
        "recommendation": (
            "Tambahkan header X-Content-Type-Options: nosniff pada semua response HTTP. "
            "Header ini menginstruksikan browser untuk selalu mematuhi Content-Type yang "
            "dikirim server dan tidak melakukan MIME sniffing. Pastikan juga server mengirimkan "
            "Content-Type yang benar untuk setiap resource yang disajikan."
        ),
    },

    "HEADER_HSTS_MISSING": {
        "name": "Strict-Transport-Security Header Missing",
        "category": "HTTP Security Configuration",
        "metrics": {"av": "N", "ac": "H", "pr": "N", "ui": "R", "s": "U", "c": "L", "i": "N", "a": "N"},
        "description": (
            "Header HTTP Strict-Transport-Security (HSTS) tidak ditemukan pada response server. "
            "HSTS menginstruksikan browser untuk selalu mengakses situs melalui HTTPS dan menolak "
            "koneksi HTTP biasa. Tanpa HSTS, pengguna yang mengakses situs via HTTP atau mengikuti "
            "link HTTP rentan terhadap serangan SSL stripping, di mana penyerang di jaringan "
            "yang sama (misalnya WiFi publik) dapat mengintersep dan menurunkan koneksi HTTPS "
            "menjadi HTTP untuk membaca data yang ditransmisikan."
        ),
        "recommendation": (
            "Tambahkan header HSTS pada response HTTPS: "
            "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload. "
            "Pastikan seluruh situs sudah berfungsi dengan benar melalui HTTPS sebelum "
            "mengaktifkan HSTS. Pertimbangkan untuk mendaftarkan domain ke HSTS preload list "
            "browser (https://hstspreload.org) untuk proteksi sejak kunjungan pertama."
        ),
    },

    "HEADER_REFERRER_MISSING": {
        "name": "Referrer-Policy Header Missing",
        "category": "HTTP Security Configuration",
        "metrics": {"av": "N", "ac": "H", "pr": "N", "ui": "R", "s": "U", "c": "L", "i": "N", "a": "N"},
        "description": (
            "Header Referrer-Policy tidak ditemukan pada response server. "
            "Secara default, browser mengirimkan URL lengkap halaman sebelumnya (referrer) "
            "saat pengguna mengklik link ke situs lain. URL tersebut dapat mengandung "
            "informasi sensitif seperti token reset password, session ID dalam query string, "
            "atau path halaman internal yang seharusnya tidak diketahui pihak ketiga."
        ),
        "recommendation": (
            "Tambahkan header Referrer-Policy: strict-origin-when-cross-origin atau "
            "no-referrer pada konfigurasi web server. Policy strict-origin-when-cross-origin "
            "hanya mengirimkan origin (tanpa path dan query) saat navigasi ke situs lain, "
            "namun tetap mengirimkan referrer lengkap untuk navigasi dalam domain yang sama."
        ),
    },

    "cors_misconfiguration": {
        "name": "CORS Misconfiguration",
        "category": "HTTP Security Configuration",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "U", "c": "L", "i": "N", "a": "N"},
        "description": (
            "Konfigurasi Cross-Origin Resource Sharing (CORS) pada server tidak aman. "
            "Server mengizinkan akses dari origin yang tidak terpercaya melalui header "
            "Access-Control-Allow-Origin yang terlalu permisif (wildcard * atau mirror origin). "
            "Hal ini memungkinkan situs pihak ketiga mengirim request ke API dan membaca "
            "response-nya, yang dapat berisi data sensitif pengguna seperti profil, "
            "riwayat transaksi, atau informasi pribadi lainnya."
        ),
        "recommendation": (
            "Batasi Access-Control-Allow-Origin hanya ke domain frontend yang sah. "
            "Jangan gunakan wildcard (*) — tentukan origin spesifik yang diizinkan. "
            "Implementasikan whitelist origin yang divalidasi di sisi server. "
            "Jangan mengizinkan Access-Control-Allow-Credentials: true bersamaan "
            "dengan Access-Control-Allow-Origin: * karena kombinasi ini sangat berbahaya."
        ),
    },

    "CORS_WILDCARD_WITH_CREDENTIALS": {
        "name": "CORS Wildcard with Credentials Enabled",
        "category": "HTTP Security Configuration",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "U", "c": "H", "i": "L", "a": "N"},
        "description": (
            "Server mengembalikan Access-Control-Allow-Origin yang permisif bersamaan dengan "
            "Access-Control-Allow-Credentials: true. Kombinasi ini sangat berbahaya karena "
            "memungkinkan situs pihak ketiga mengirimkan request terautentikasi (membawa cookie "
            "session pengguna) dan membaca response-nya. Penyerang dapat membuat halaman web "
            "yang secara diam-diam mengakses API atas nama korban dan mencuri data sensitif "
            "seperti informasi akun, data keuangan, atau token autentikasi."
        ),
        "recommendation": (
            "Jangan pernah menggunakan wildcard atau mirror origin bersamaan dengan credentials. "
            "Tentukan origin spesifik yang diizinkan melalui whitelist yang divalidasi di server. "
            "Pastikan konfigurasi CORS hanya mengizinkan domain frontend yang sah. "
            "Audit semua endpoint API yang mengembalikan data sensitif."
        ),
    },
}