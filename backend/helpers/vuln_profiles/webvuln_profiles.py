WEBVULN_PROFILES = {
    "SQLI_CRITICAL": {
        "name": "SQL Injection (Critical — Auth/Admin Path)",
        "category": "Web Vulnerabilities",
        "description": (
            "SQL Injection ditemukan pada endpoint autentikasi atau panel admin. "
            "Penyerang dapat mem-bypass mekanisme login tanpa mengetahui kredensial yang valid, "
            "mengekstrak seluruh isi database termasuk data pengguna dan informasi sensitif, "
            "serta berpotensi melakukan eskalasi ke Remote Code Execution melalui fitur database "
            "seperti xp_cmdshell (MSSQL) atau INTO OUTFILE (MySQL). Kerentanan ini tergolong "
            "paling berbahaya karena berada di jalur autentikasi yang merupakan gerbang utama sistem."
        ),
        "recommendation": (
            "1) Gunakan Prepared Statements / Parameterized Query pada semua query database, terutama endpoint auth. "
            "2) Terapkan least-privilege pada akun database — jangan gunakan root/sa untuk koneksi aplikasi. "
            "3) Sembunyikan error database dari response (aktifkan production mode). "
            "4) Implementasikan Web Application Firewall (WAF) dengan ruleset SQLi. "
            "5) Audit seluruh query yang menerima input dari request pengguna. "
            "6) Terapkan input validation dan whitelist tipe data pada setiap parameter."
        ),
        "metrics": {
            "av": "N", "ac": "L", "pr": "N", "ui": "N",
            "s": "U", "c": "H", "i": "H", "a": "N"
        },
    },

    "SQLI_HIGH": {
        "name": "SQL Injection (Error-based / Boolean-based)",
        "category": "Web Vulnerabilities",
        "description": (
            "SQL Injection terdeteksi melalui error message database atau perbedaan response boolean. "
            "Penyerang dapat mengekstrak struktur tabel, nama kolom, dan isi database secara langsung "
            "melalui pesan error yang dikembalikan server, atau secara bertahap melalui teknik boolean-based "
            "yang menganalisis perbedaan response (true/false) untuk setiap karakter data. "
            "Teknik ini memungkinkan penyerang mendapatkan data sensitif seperti kredensial pengguna, "
            "informasi pribadi, dan konfigurasi sistem yang tersimpan di database. OR '1'='1'--"
        ),
        "recommendation": (
            "1) Gunakan Prepared Statements di semua query tanpa terkecuali. "
            "2) Sembunyikan error database dari response — aktifkan production mode dan custom error page. "
            "3) Terapkan input validation: whitelist tipe data, panjang maksimum, dan format yang diharapkan. "
            "4) Gunakan ORM (Object-Relational Mapping) sebagai lapisan abstraksi database. "
            "5) Batasi privilege akun database sesuai kebutuhan (SELECT only untuk endpoint read). "
            "6) Implementasikan logging dan monitoring untuk mendeteksi pola serangan SQLi."
        ),
        "metrics": {
            "av": "N", "ac": "L", "pr": "N", "ui": "N",
            "s": "U", "c": "H", "i": "L", "a": "N"
        },
    },

    "SQLI_MEDIUM": {
        "name": "SQL Injection (Time-based Blind)",
        "category": "Web Vulnerabilities",
        "description": (
            "SQL Injection terdeteksi melalui teknik time-based blind, yaitu dengan menginjeksi "
            "perintah delay (SLEEP, WAITFOR DELAY, pg_sleep) dan mengukur perbedaan waktu response. "
            "Eksploitasi teknik ini lebih lambat dibandingkan error-based karena data diekstrak "
            "karakter per karakter berdasarkan waktu response, namun tetap memungkinkan penyerang "
            "mengekstrak seluruh isi database jika diberi waktu yang cukup. "
            "Teknik ini sering digunakan saat error message sudah disembunyikan oleh aplikasi."
        ),
        "recommendation": (
            "1) Gunakan Prepared Statements untuk semua query database. "
            "2) Terapkan query timeout di level database untuk membatasi eksekusi query yang terlalu lama. "
            "3) Monitor anomali response time yang tidak wajar sebagai indikator serangan. "
            "4) Implementasikan rate limiting pada endpoint yang rentan. "
            "5) Terapkan input validation ketat pada semua parameter yang masuk ke query."
        ),
        "metrics": {
            "av": "N", "ac": "H", "pr": "N", "ui": "N",
            "s": "U", "c": "H", "i": "N", "a": "N"
        },
    },

    "SQLI_LOW": {
        "name": "SQL Injection (Potential/Unconfirmed)",
        "category": "Web Vulnerabilities",
        "description": (
            "Indikasi SQL Injection ditemukan namun belum terkonfirmasi sepenuhnya. "
            "Response server menunjukkan anomali yang konsisten dengan pola SQL Injection "
            "(perubahan perilaku saat karakter khusus diinjeksi) namun tidak ditemukan "
            "error database eksplisit atau delay waktu yang terukur. "
            "Diperlukan pengujian manual lebih lanjut untuk memastikan apakah kerentanan "
            "ini benar-benar dapat dieksploitasi atau merupakan false positive."
        ),
        "recommendation": (
            "1) Audit kode sumber pada endpoint dan parameter yang terindikasi. "
            "2) Terapkan Prepared Statements sebagai tindakan pencegahan meskipun belum terkonfirmasi. "
            "3) Lakukan manual testing lebih lanjut menggunakan tools seperti sqlmap untuk konfirmasi. "
            "4) Review apakah input pengguna langsung dikonkatenasi ke string query SQL."
        ),
        "metrics": {
            "av": "N", "ac": "H", "pr": "N", "ui": "N",
            "s": "U", "c": "L", "i": "N", "a": "N"
        },
    },
    
    "XSS_CRITICAL": {
        "name": "Reflected XSS (Critical — Auth/Redirect Parameter)",
        "category": "Web Vulnerabilities",
        "description": (
            "Reflected XSS ditemukan pada endpoint autentikasi atau parameter redirect "
            "(url, next, return, callback). Penyerang dapat membuat link berbahaya yang ketika diklik "
            "oleh korban akan mengeksekusi JavaScript di konteks halaman login, mencuri session token "
            "atau kredensial yang diinput, melakukan account takeover, atau mengarahkan korban ke "
            "situs phishing setelah proses login. Kerentanan ini sangat berbahaya karena berada di "
            "jalur autentikasi yang secara alami menangani data sensitif pengguna."
        ),
        "recommendation": (
            "1) Encode semua output ke HTML entities sebelum ditampilkan di halaman. "
            "2) Whitelist nilai parameter redirect — hanya izinkan path internal (relative path). "
            "3) Implementasikan Content-Security-Policy (CSP) header yang ketat tanpa unsafe-inline. "
            "4) Gunakan HttpOnly dan Secure flag pada cookie session agar tidak bisa dicuri via XSS. "
            "5) Gunakan library sanitasi seperti DOMPurify untuk konten HTML dinamis. "
            "6) Validasi dan sanitasi semua input sebelum di-render ke halaman."
        ),
        "metrics": {
            "av": "N", "ac": "L", "pr": "N", "ui": "R",
            "s": "C", "c": "L", "i": "L", "a": "N"
        },
    },

    "XSS_HIGH": {
        "name": "Reflected XSS (Script/Event Handler Injection)",
        "category": "Web Vulnerabilities",
        "description": (
            "Reflected XSS ditemukan dengan payload script tag atau event handler "
            "(<script>, onerror, onload, svg/onload). Script berbahaya langsung dieksekusi "
            "di browser korban tanpa encoding atau sanitasi, memungkinkan pencurian cookie, "
            "keylogging input pengguna, defacement halaman, atau pengalihan ke situs phishing. "
            "Serangan ini memerlukan korban untuk mengklik link berbahaya yang disiapkan penyerang."
        ),
        "recommendation": (
            "1) Encode semua output ke HTML entities menggunakan fungsi bawaan framework. "
            "2) Gunakan DOMPurify atau library serupa untuk sanitasi HTML dinamis di sisi klien. "
            "3) Implementasikan CSP dengan script-src 'self' tanpa 'unsafe-inline'. "
            "4) Validasi dan sanitasi semua input sebelum di-render ke halaman. "
            "5) Gunakan template engine yang auto-escape secara default (Jinja2, Blade, dll)."
        ),
        "metrics": {
            "av": "N", "ac": "L", "pr": "N", "ui": "R",
            "s": "U", "c": "L", "i": "L", "a": "N"
        },
    },

    "XSS_MEDIUM": {
        "name": "Reflected XSS (Attribute Injection)",
        "category": "Web Vulnerabilities",
        "description": (
            "Reflected XSS terdeteksi melalui injeksi atribut HTML event handler "
            "(onmouseover, onclick, onfocus, atau atribut event lainnya). Eksploitasi "
            "memerlukan interaksi pengguna seperti hover atau klik pada elemen yang terinjeksi. "
            "Meskipun lebih sulit dieksploitasi dibandingkan script tag injection, kerentanan ini "
            "tetap dapat digunakan untuk session hijacking dan phishing."
        ),
        "recommendation": (
            "1) Encode output dalam konteks atribut HTML menggunakan HTML attribute encoding. "
            "2) Hindari menyisipkan input user langsung ke dalam atribut HTML. "
            "3) Terapkan CSP untuk membatasi eksekusi script inline. "
            "4) Gunakan framework yang auto-escape atribut HTML secara default."
        ),
        "metrics": {
            "av": "N", "ac": "L", "pr": "N", "ui": "R",
            "s": "U", "c": "L", "i": "N", "a": "N"
        },
    },

    "XSS_LOW": {
        "name": "Reflected XSS (Potential/Partial Reflection)",
        "category": "Web Vulnerabilities",
        "description": (
            "Input pengguna terdeteksi di-reflect ke response namun dalam konteks yang sulit "
            "dieksploitasi (encoding parsial, konteks JavaScript string, atau hanya marker yang "
            "muncul tanpa eksekusi script penuh). Diperlukan investigasi manual lebih lanjut "
            "untuk memastikan apakah kerentanan ini dapat dieksploitasi secara nyata."
        ),
        "recommendation": (
            "1) Terapkan output encoding sebagai best practice meski belum terkonfirmasi exploitable. "
            "2) Audit konteks rendering input yang terindikasi (HTML body, atribut, JavaScript, CSS). "
            "3) Lakukan manual testing untuk konfirmasi exploitability. "
            "4) Pertimbangkan penggunaan CSP sebagai lapisan pertahanan tambahan."
        ),
        "metrics": {
            "av": "N", "ac": "H", "pr": "N", "ui": "R",
            "s": "U", "c": "L", "i": "N", "a": "N"
        },
    },
        
    
    "OPEN_REDIRECT_HIGH": {
        "name": "Open Redirect (Auth Path)",
        "category": "Web Vulnerabilities",
        "description": (
            "Open Redirect ditemukan pada endpoint autentikasi (login, OAuth, callback). "
            "Penyerang dapat membuat URL yang tampak sah dari domain target namun mengarahkan "
            "korban ke situs berbahaya setelah proses login. Teknik ini digunakan untuk mencuri "
            "token OAuth, session cookie post-authentication, atau mengarahkan korban ke halaman "
            "phishing yang identik dengan halaman asli untuk mencuri kredensial."
        ),
        "recommendation": (
            "1) Whitelist URL redirect yang diizinkan — hanya izinkan domain internal. "
            "2) Jangan terima URL absolut dari parameter pada endpoint login/callback. "
            "3) Gunakan mapping internal (ID -> URL) sebagai alternatif parameter redirect langsung. "
            "4) Validasi host tujuan sebelum melakukan redirect post-authentication. "
            "5) Tolak redirect ke URL yang mengandung @ atau encoded characters."
        ),
        "metrics": {
            "av": "N", "ac": "L", "pr": "N", "ui": "R",
            "s": "U", "c": "L", "i": "L", "a": "N"
        },
    },

    "OPEN_REDIRECT_MEDIUM": {
        "name": "Open Redirect (JS/Meta Redirect)",
        "category": "Web Vulnerabilities",
        "description": (
            "Open Redirect terdeteksi melalui JavaScript (window.location) atau meta refresh di body response. "
            "Penyerang dapat membuat URL yang terlihat sah dan mengarahkan korban ke situs phishing. "
            "Berbeda dengan header redirect, teknik ini terjadi di sisi klien setelah halaman dimuat, "
            "sehingga WAF berbasis header mungkin tidak mendeteksinya."
        ),
        "recommendation": (
            "1) Hindari penggunaan window.location atau meta refresh dengan nilai dari input pengguna. "
            "2) Gunakan whitelist domain yang diizinkan untuk semua operasi redirect. "
            "3) Sanitasi dan validasi semua parameter URL sebelum digunakan sebagai tujuan redirect. "
            "4) Gunakan relative path sebagai pengganti URL absolut untuk navigasi internal."
        ),
        "metrics": {
            "av": "N", "ac": "L", "pr": "N", "ui": "R",
            "s": "U", "c": "N", "i": "L", "a": "N"
        },
    },

    "OPEN_REDIRECT_LOW": {
        "name": "Open Redirect (General Path)",
        "category": "Web Vulnerabilities",
        "description": (
            "Open Redirect ditemukan pada path umum yang bukan endpoint autentikasi. "
            "Kerentanan ini memiliki dampak lebih rendah karena tidak melibatkan proses login, "
            "namun tetap dapat digunakan untuk phishing atau distribusi malware melalui URL "
            "yang tampak sah dari domain target. Penyerang memanfaatkan reputasi domain korban "
            "untuk meningkatkan kepercayaan terhadap link berbahaya."
        ),
        "recommendation": (
            "1) Whitelist semua URL redirect yang diizinkan. "
            "2) Jangan gunakan input pengguna secara langsung sebagai tujuan redirect. "
            "3) Gunakan mapping internal (ID -> URL) sebagai alternatif parameter redirect langsung. "
            "4) Validasi bahwa URL tujuan berada dalam domain yang sama sebelum redirect."
        ),
        "metrics": {
            "av": "N", "ac": "L", "pr": "N", "ui": "R",
            "s": "U", "c": "N", "i": "L", "a": "N"
        },
    },
        
    
    # Tambahkan ke WEBVULN_PROFILES di webvuln_profiles.py

    "CMDI_CRITICAL": {
        "name": "Command Injection (RCE Confirmed)",
        "category": "Web Vulnerabilities",
        "description": (
            "Command Injection terkonfirmasi — penyerang dapat mengeksekusi perintah sistem operasi "
            "secara langsung di server melalui input yang tidak disanitasi. Signature RCE berhasil "
            "terdeteksi dalam response, membuktikan bahwa perintah yang diinjeksi benar-benar dieksekusi. "
            "Dampak kerentanan ini sangat serius: penyerang dapat membaca file konfigurasi, "
            "menginstall backdoor, mengakses database internal, atau melakukan lateral movement "
            "ke server lain dalam jaringan yang sama."
        ),
        "recommendation": (
            "1) Hindari penggunaan fungsi exec(), system(), shell_exec(), popen() dengan input pengguna. "
            "2) Gunakan whitelist ketat untuk nilai parameter yang diterima — tolak karakter shell metacharacter. "
            "3) Jalankan aplikasi dengan privilege minimal (non-root/non-administrator). "
            "4) Gunakan library atau API bawaan bahasa pemrograman sebagai pengganti shell command. "
            "5) Implementasikan sandboxing atau containerization untuk membatasi dampak RCE. "
            "6) Audit semua endpoint yang menerima input dan diteruskan ke proses sistem."
        ),
        "metrics": {
            "av": "N", "ac": "L", "pr": "N", "ui": "N",
            "s": "U", "c": "H", "i": "H", "a": "L"
        },
    },

    "CMDI_HIGH": {
        "name": "Command Injection (Blind/Time-based)",
        "category": "Web Vulnerabilities",
        "description": (
            "Command Injection terdeteksi melalui delay response atau perbedaan output yang "
            "mengindikasikan eksekusi command di server. Eksploitasi memerlukan lebih banyak percobaan "
            "karena output command tidak langsung terlihat di response, namun penyerang tetap dapat "
            "melakukan exfiltration data melalui teknik out-of-band (DNS lookup, HTTP callback) "
            "atau blind time-based extraction."
        ),
        "recommendation": (
            "1) Hindari penggunaan fungsi shell dengan input pengguna tanpa terkecuali. "
            "2) Terapkan input validation dan whitelist karakter yang diizinkan. "
            "3) Monitor process spawning yang tidak wajar di server (child process dari web server). "
            "4) Implementasikan logging untuk mendeteksi pola command injection. "
            "5) Gunakan AppArmor atau SELinux untuk membatasi aksi yang dapat dilakukan proses web."
        ),
        "metrics": {
            "av": "N", "ac": "L", "pr": "N", "ui": "N",
            "s": "U", "c": "H", "i": "L", "a": "N"
        },
    },

    "CMDI_MEDIUM": {
        "name": "Command Injection (Potential/Unconfirmed)",
        "category": "Web Vulnerabilities",
        "description": (
            "Indikasi Command Injection ditemukan namun belum terkonfirmasi secara penuh. "
            "Response server menunjukkan anomali yang konsisten dengan pola injeksi command "
            "(perubahan perilaku saat shell metacharacter diinjeksi) namun tidak ditemukan output "
            "command atau delay yang terukur secara pasti. Diperlukan pengujian manual lebih lanjut "
            "untuk memastikan apakah kerentanan ini benar-benar dapat dieksploitasi."
        ),
        "recommendation": (
            "1) Audit endpoint yang menerima input dan diteruskan ke proses sistem. "
            "2) Terapkan input validation sebagai tindakan pencegahan. "
            "3) Lakukan manual testing untuk konfirmasi exploitability. "
            "4) Review penggunaan fungsi exec/system dalam kode sumber."
        ),
        "metrics": {
            "av": "N", "ac": "H", "pr": "N", "ui": "N",
            "s": "U", "c": "L", "i": "L", "a": "N"
        },
    },

    "CMDI_LOW": {
        "name": "Command Injection (Anomaly Detected)",
        "category": "Web Vulnerabilities",
        "description": (
            "Anomali response terdeteksi pada parameter yang berpotensi diteruskan ke shell. "
            "Perubahan perilaku server mengindikasikan bahwa input mungkin diproses oleh fungsi "
            "sistem, namun belum dapat dikonfirmasi sebagai Command Injection aktif. "
            "Memerlukan investigasi kode sumber dan pengujian manual lebih lanjut."
        ),
        "recommendation": (
            "1) Review kode pada parameter yang terindikasi — pastikan tidak ada fungsi exec/system. "
            "2) Terapkan principle of least privilege pada proses server. "
            "3) Lakukan code review dan manual testing untuk konfirmasi. "
            "4) Implementasikan input sanitization sebagai pencegahan."
        ),
        "metrics": {
            "av": "N", "ac": "H", "pr": "N", "ui": "N",
            "s": "U", "c": "L", "i": "N", "a": "N"
        },
    },
    
    
    "FILE_UPLOAD_MISCONFIGURATION": {
        "name": "File Upload Misconfiguration",
        "category": "Web Vulnerabilities",
        "metrics": {"av": "N", "ac": "L", "pr": "L", "ui": "N", "s": "U", "c": "L", "i": "L", "a": "N"},
        "description": (
            "Konfigurasi upload file pada server tidak aman. Server tidak melakukan validasi "
            "tipe file yang diupload, sehingga penyerang dapat mengupload file berbahaya "
            "seperti webshell (.php, .asp, .jsp) yang jika dapat diakses dan dieksekusi, "
            "akan memberikan penyerang kontrol penuh atas server."
        ),
        "recommendation": (
            "1) Validasi MIME type dan magic bytes file (bukan hanya ekstensi atau Content-Type header). "
            "2) Simpan file upload di luar document root agar tidak dapat diakses langsung via URL. "
            "3) Rename file secara random saat disimpan untuk mencegah path guessing. "
            "4) Batasi ukuran file maksimum yang dapat diupload. "
            "5) Nonaktifkan eksekusi script di direktori upload."
        ),
    },

    "DIR_LISTING_CRITICAL": {
        "name": "Directory Listing Exposed (Critical Path)",
        "category": "Web Vulnerabilities",
        "description": (
            "Directory listing aktif pada path kritis seperti backup, database, config, atau secret. "
            "Penyerang dapat melihat daftar file dalam direktori dan mengunduh file sensitif "
            "seperti database dump, file konfigurasi, private key, atau backup yang berisi "
            "kredensial dan data rahasia secara langsung tanpa autentikasi."
        ),
        "recommendation": (
            "1) Nonaktifkan directory listing di konfigurasi web server. "
            "2) Apache: tambahkan 'Options -Indexes' di .htaccess atau httpd.conf. "
            "3) Nginx: hapus directive 'autoindex on' dari konfigurasi. "
            "4) Pindahkan file sensitif ke luar document root. "
            "5) Hapus semua file backup, dump, dan config dari direktori web yang dapat diakses publik."
        ),
        "metrics": {
            "av": "N", "ac": "L", "pr": "N", "ui": "N",
            "s": "U", "c": "H", "i": "N", "a": "N"
        },
    },

    "DIR_LISTING_HIGH": {
        "name": "Directory Listing Exposed (Sensitive Files)",
        "category": "Web Vulnerabilities",
        "description": (
            "Directory listing aktif dan mengekspos file dengan ekstensi sensitif "
            "seperti .sql, .env, .key, .zip, .bak, dan .log. File-file ini dapat berisi "
            "kredensial database, API key, private key, atau backup data yang seharusnya "
            "tidak dapat diakses oleh publik."
        ),
        "recommendation": (
            "1) Nonaktifkan directory listing pada web server. "
            "2) Audit semua file yang terekspos dan hapus atau pindahkan file sensitif. "
            "3) Tambahkan autentikasi pada direktori yang memerlukan akses terbatas. "
            "4) Konfigurasikan web server untuk menolak akses ke file dengan ekstensi sensitif."
        ),
        "metrics": {
            "av": "N", "ac": "L", "pr": "N", "ui": "N",
            "s": "U", "c": "L", "i": "N", "a": "N"
        },
    },

    "DIR_LISTING_MEDIUM": {
        "name": "Directory Listing Exposed (Media/Upload)",
        "category": "Web Vulnerabilities",
        "description": (
            "Directory listing aktif pada direktori upload atau media. "
            "Semua file yang diupload oleh pengguna dapat dilihat dan diakses oleh siapa saja, "
            "termasuk file pribadi atau dokumen yang seharusnya hanya dapat diakses oleh "
            "pemilik file. Hal ini juga dapat mengekspos struktur penamaan file internal."
        ),
        "recommendation": (
            "1) Nonaktifkan directory listing pada direktori upload dan media. "
            "2) Implementasikan access control agar file hanya dapat diakses oleh pemiliknya. "
            "3) Gunakan random filename untuk semua file upload. "
            "4) Sajikan file melalui endpoint API dengan validasi otorisasi."
        ),
        "metrics": {
            "av": "N", "ac": "L", "pr": "N", "ui": "N",
            "s": "U", "c": "L", "i": "N", "a": "N"
        },
    },

    "DIR_LISTING_LOW": {
        "name": "Directory Listing Exposed (General)",
        "category": "Web Vulnerabilities",
        "description": (
            "Directory listing aktif pada path umum yang tidak berisi file sensitif. "
            "Meskipun tidak ada data rahasia yang terekspos secara langsung, struktur "
            "direktori aplikasi yang terlihat dapat membantu penyerang dalam fase "
            "reconnaissance untuk memahami arsitektur aplikasi dan menemukan endpoint tersembunyi."
        ),
        "recommendation": (
            "1) Nonaktifkan directory listing sebagai best practice keamanan. "
            "2) Apache: tambahkan 'Options -Indexes' pada konfigurasi. "
            "3) Nginx: pastikan tidak ada directive 'autoindex on'. "
            "4) Tambahkan file index.html kosong pada direktori yang perlu diproteksi."
        ),
        "metrics": {
            "av": "N", "ac": "L", "pr": "N", "ui": "N",
            "s": "U", "c": "L", "i": "N", "a": "N"
        },
    },

    "PATH_TRAVERSAL": {
        "name": "Path Traversal",
        "category": "Web Vulnerabilities",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "N", "a": "N"},
        "description": (
            "Input pengguna digunakan untuk mengakses file di server tanpa validasi path yang memadai. "
            "Penyerang dapat menggunakan karakter traversal (../) untuk keluar dari document root "
            "dan membaca file sistem sensitif seperti /etc/passwd, /etc/shadow, file konfigurasi "
            "database, atau source code aplikasi."
        ),
        "recommendation": (
            "1) Validasi semua path input dan tolak karakter traversal (../, ..\\ dll). "
            "2) Gunakan fungsi realpath() untuk resolve path dan validasi hasilnya. "
            "3) Pastikan path yang di-resolve berada dalam direktori yang diizinkan. "
            "4) Gunakan chroot atau sandboxing untuk membatasi akses file system."
        ),
    },

    "SSRF": {
        "name": "Server-Side Request Forgery (SSRF)",
        "category": "Web Vulnerabilities",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "L", "i": "L", "a": "N"},
        "description": (
            "Aplikasi melakukan HTTP request ke URL yang ditentukan oleh input pengguna "
            "tanpa validasi yang memadai. Penyerang dapat memanfaatkan ini untuk mengakses "
            "layanan internal yang tidak terekspos ke internet (metadata cloud, database, "
            "admin panel internal), melakukan port scanning pada jaringan internal, "
            "atau membaca file lokal melalui protokol file://."
        ),
        "recommendation": (
            "1) Whitelist URL atau domain yang diizinkan untuk request server-side. "
            "2) Blokir akses ke IP internal, loopback (127.0.0.1), dan link-local (169.254.x.x). "
            "3) Blokir protokol selain HTTP/HTTPS (file://, gopher://, dict:// dll). "
            "4) Gunakan DNS resolution validation untuk mencegah DNS rebinding. "
            "5) Batasi port tujuan hanya ke 80 dan 443."
        ),
    },

    "SENSITIVE_DATA_EXPOSURE": {
        "name": "Sensitive Data Exposure",
        "category": "Web Vulnerabilities",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "N", "a": "N"},
        "description": (
            "Ditemukan file sensitif yang dapat diakses secara publik seperti .env (berisi "
            "kredensial dan API key), backup database (.sql, .dump), file konfigurasi "
            "(config.php, settings.py), atau private key (.pem, .key). File-file ini "
            "berisi informasi rahasia yang jika diakses oleh penyerang dapat digunakan "
            "untuk mengakses sistem secara penuh."
        ),
        "recommendation": (
            "1) Hapus atau batasi akses ke semua file sensitif yang terekspos. "
            "2) Rotasi semua kredensial, API key, dan secret yang terdapat dalam file tersebut. "
            "3) Konfigurasikan web server untuk menolak akses ke file dengan ekstensi sensitif. "
            "4) Simpan file konfigurasi di luar document root. "
            "5) Gunakan environment variable atau vault untuk menyimpan secret."
        ),
    },

    "FILE_UPLOAD_CRITICAL": {
        "name": "File Upload — Remote Code Execution (Webshell)",
        "category": "Web Vulnerabilities",
        "description": (
            "Upload file berbahaya berhasil dan file terkonfirmasi dapat dieksekusi di server. "
            "Penyerang telah mengupload webshell (.php, .asp, .jsp) yang dapat diakses dan "
            "dieksekusi melalui URL, memberikan kemampuan Remote Code Execution penuh. "
            "Dengan webshell, penyerang dapat menjalankan perintah OS, membaca/menulis file, "
            "mengakses database, dan melakukan lateral movement ke server lain."
        ),
        "recommendation": (
            "1) Validasi MIME type dan magic bytes file (bukan hanya ekstensi atau Content-Type). "
            "2) Simpan file upload di luar document root agar tidak dapat diakses langsung via URL. "
            "3) Rename file secara random saat disimpan. "
            "4) Nonaktifkan eksekusi script di direktori upload (PHP: php_flag engine off). "
            "5) Terapkan Content-Disposition: attachment pada serving file upload. "
            "6) Gunakan object storage terpisah (S3, MinIO) untuk penyimpanan file."
        ),
        "metrics": {
            "av": "N", "ac": "L", "pr": "L", "ui": "N",
            "s": "C", "c": "H", "i": "H", "a": "L"
        },
    },

    "FILE_UPLOAD_HIGH": {
        "name": "File Upload — Dangerous File Type Accepted",
        "category": "Web Vulnerabilities",
        "description": (
            "Server menerima upload file berbahaya (script server-side, executable) namun "
            "belum terkonfirmasi apakah file dapat dieksekusi secara langsung. File tetap "
            "tersimpan di server dan berpotensi dieksekusi jika direktori penyimpanan "
            "dapat diakses melalui web dan eksekusi script diizinkan."
        ),
        "recommendation": (
            "1) Whitelist ekstensi file yang diizinkan (hanya .jpg, .png, .pdf, .docx, dll). "
            "2) Validasi magic bytes file, jangan hanya mengandalkan ekstensi atau Content-Type header. "
            "3) Simpan file di luar document root atau gunakan object storage (S3). "
            "4) Rename file secara random dan hapus metadata EXIF/metadata lainnya. "
            "5) Nonaktifkan eksekusi script pada direktori upload."
        ),
        "metrics": {
            "av": "N", "ac": "L", "pr": "L", "ui": "N",
            "s": "U", "c": "L", "i": "H", "a": "N"
        },
    },

    "FILE_UPLOAD_MEDIUM": {
        "name": "File Upload — Unrestricted File Type",
        "category": "Web Vulnerabilities",
        "description": (
            "Server tidak membatasi tipe file yang dapat diupload. Meskipun belum ditemukan "
            "file executable yang berhasil diterima, tidak adanya validasi tipe file "
            "membuka kemungkinan penyerang mengupload file berbahaya melalui teknik bypass "
            "seperti double extension (.php.jpg) atau null byte injection."
        ),
        "recommendation": (
            "1) Implementasikan whitelist ekstensi file yang diizinkan secara ketat. "
            "2) Tambahkan validasi MIME type dan magic bytes di sisi server. "
            "3) Batasi ukuran file maksimum yang dapat diupload. "
            "4) Tolak file dengan double extension atau karakter khusus pada nama file."
        ),
        "metrics": {
            "av": "N", "ac": "L", "pr": "L", "ui": "N",
            "s": "U", "c": "L", "i": "L", "a": "N"
        },
    },

    "FILE_UPLOAD_LOW": {
        "name": "File Upload — Misconfiguration Detected",
        "category": "Web Vulnerabilities",
        "description": (
            "Terdeteksi endpoint upload file dengan konfigurasi yang kurang aman. "
            "Validasi file upload tidak memadai namun belum terkonfirmasi apakah "
            "file berbahaya dapat diupload dan dieksekusi. Diperlukan investigasi "
            "lebih lanjut untuk menentukan tingkat risiko sesungguhnya."
        ),
        "recommendation": (
            "1) Audit konfigurasi endpoint upload secara menyeluruh. "
            "2) Terapkan validasi file upload sebagai best practice (whitelist ekstensi, MIME, magic bytes). "
            "3) Review access control pada direktori penyimpanan file. "
            "4) Lakukan manual testing untuk konfirmasi exploitability."
        ),
        "metrics": {
            "av": "N", "ac": "H", "pr": "L", "ui": "N",
            "s": "U", "c": "L", "i": "L", "a": "N"
        },
    },
}
