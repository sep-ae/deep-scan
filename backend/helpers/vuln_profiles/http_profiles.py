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

    "HEADER_CSP_UNSAFE": {
        "name": "Content-Security-Policy Contains Unsafe Directives",
        "category": "HTTP Security Configuration",
        "metrics": {"av": "N", "ac": "H", "pr": "N", "ui": "R", "s": "U", "c": "L", "i": "L", "a": "N"},
        "description": (
            "Header Content-Security-Policy (CSP) ditemukan namun mengandung directive yang "
            "tidak aman seperti 'unsafe-inline', 'unsafe-eval', atau wildcard (*) pada source "
            "directive krusial (script-src, default-src). Konfigurasi ini memperlemah "
            "efektivitas CSP sebagai lapisan pertahanan terhadap serangan XSS. Dengan "
            "'unsafe-inline', penyerang dapat mengeksekusi script inline yang diinjeksi melalui "
            "kerentanan XSS. Dengan 'unsafe-eval', fungsi eval() dan konstruktor Function() "
            "tetap dapat digunakan untuk mengeksekusi kode dinamis."
        ),
        "recommendation": (
            "1) Hapus 'unsafe-inline' dari script-src — gunakan nonce atau hash untuk script inline. "
            "2) Hapus 'unsafe-eval' — refactor kode yang menggunakan eval() ke pendekatan statis. "
            "3) Ganti wildcard (*) dengan domain spesifik yang diizinkan. "
            "4) Gunakan CSP report-uri untuk memonitor pelanggaran sebelum menerapkan strict policy. "
            "5) Pertimbangkan strict-dynamic untuk kompatibilitas dengan framework JavaScript modern."
        ),
    },

    "HEADER_HSTS_WEAK": {
        "name": "Strict-Transport-Security Misconfigured",
        "category": "HTTP Security Configuration",
        "metrics": {"av": "N", "ac": "H", "pr": "N", "ui": "R", "s": "U", "c": "L", "i": "N", "a": "N"},
        "description": (
            "Header Strict-Transport-Security (HSTS) ditemukan namun konfigurasinya tidak "
            "optimal. Nilai max-age terlalu pendek (kurang dari 6 bulan) atau tidak menyertakan "
            "directive includeSubDomains. HSTS dengan max-age pendek hanya memberikan proteksi "
            "sementara terhadap serangan SSL stripping — setelah masa berlaku habis, browser "
            "akan kembali mengizinkan koneksi HTTP biasa sehingga pengguna rentan terhadap "
            "serangan downgrade di jaringan publik."
        ),
        "recommendation": (
            "1) Tingkatkan max-age minimal ke 15768000 (6 bulan) atau 31536000 (1 tahun). "
            "2) Tambahkan directive includeSubDomains untuk melindungi seluruh subdomain. "
            "3) Pertimbangkan menambahkan directive preload dan mendaftarkan domain ke "
            "HSTS preload list browser (https://hstspreload.org). "
            "4) Pastikan seluruh resource (gambar, CSS, JS) sudah dimuat melalui HTTPS "
            "sebelum menerapkan HSTS ketat."
        ),
    },

    "HEADER_PERMISSIVE_CACHE": {
        "name": "Missing or Permissive Cache-Control Header",
        "category": "HTTP Security Configuration",
        "metrics": {"av": "N", "ac": "H", "pr": "N", "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
        "description": (
            "Header Cache-Control tidak ditemukan atau tidak mengandung directive 'no-store' "
            "atau 'no-cache'. Tanpa pembatasan caching yang tepat, response HTTP yang berisi "
            "data sensitif (informasi profil pengguna, token, data transaksi) dapat disimpan "
            "oleh proxy server, CDN, atau cache browser. Data yang ter-cache dapat diakses oleh "
            "pengguna lain pada perangkat bersama atau oleh penyerang yang memiliki akses ke "
            "proxy/cache intermediary."
        ),
        "recommendation": (
            "1) Tambahkan Cache-Control: no-store, no-cache pada response yang berisi data sensitif. "
            "2) Untuk halaman dinamis: Cache-Control: no-store, no-cache, must-revalidate. "
            "3) Tambahkan Pragma: no-cache untuk kompatibilitas dengan HTTP/1.0. "
            "4) Untuk resource statis (CSS, JS, gambar), gunakan caching dengan versioning."
        ),
    },

    "CORS_ORIGIN_REFLECTION": {
        "name": "CORS Origin Reflection Vulnerability",
        "category": "HTTP Security Configuration",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "U", "c": "H", "i": "L", "a": "N"},
        "description": (
            "Server memantulkan (reflect) nilai Origin header dari request ke dalam "
            "Access-Control-Allow-Origin response. Ini berarti server menerima origin apapun "
            "yang dikirim oleh attacker tanpa validasi. Jika dikombinasikan dengan "
            "Access-Control-Allow-Credentials: true, penyerang dapat membuat halaman web "
            "yang melakukan request terautentikasi ke API target dan membaca seluruh response "
            "(termasuk data pribadi pengguna, session token, dan informasi sensitif lainnya). "
            "Ini adalah bentuk miskonfigurasi CORS paling berbahaya."
        ),
        "recommendation": (
            "1) Jangan pernah memantulkan nilai Origin header secara langsung ke ACAO response. "
            "2) Implementasikan whitelist origin yang divalidasi secara ketat di sisi server. "
            "3) Jangan gunakan regex/suffix matching yang lemah (misal: endsWith(target.com)). "
            "4) Nonaktifkan Access-Control-Allow-Credentials jika tidak diperlukan. "
            "5) Audit seluruh middleware/framework CORS yang digunakan untuk memastikan "
            "tidak ada konfigurasi auto-reflect."
        ),
    },

    "CORS_NULL_ORIGIN_ALLOWED": {
        "name": "CORS Null Origin Accepted",
        "category": "HTTP Security Configuration",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "U", "c": "L", "i": "N", "a": "N"},
        "description": (
            "Server menerima request dengan Origin: null dan mengembalikan "
            "Access-Control-Allow-Origin: null. Origin null dikirim oleh browser dalam "
            "beberapa kondisi khusus seperti iframe sandboxed, redirect lintas origin, dan "
            "file lokal (file://). Penyerang dapat memanfaatkan iframe sandboxed untuk membuat "
            "request cross-origin dari halaman berbahaya dengan origin null dan membaca "
            "response dari server target."
        ),
        "recommendation": (
            "1) Jangan pernah mengizinkan 'null' sebagai origin yang valid dalam konfigurasi CORS. "
            "2) Hapus 'null' dari whitelist origin di server. "
            "3) Pastikan framework CORS tidak mengizinkan null origin secara default. "
            "4) Validasi bahwa origin selalu berupa URL yang valid (bukan string 'null')."
        ),
    },
}