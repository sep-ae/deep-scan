RECON_PROFILES = {
    "DNS_LOOKUP": {
        "name": "DNS Information Disclosure",
        "category": "Reconnaissance",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
        "description": (
            "DNS records yang tersedia secara publik mengekspos detail infrastruktur internal "
            "seperti alamat IP server, mail server, nameserver, dan layanan terkait. "
            "Informasi ini dapat digunakan oleh penyerang pada fase reconnaissance untuk "
            "memetakan infrastruktur target, mengidentifikasi layanan yang berjalan, "
            "dan merencanakan serangan yang lebih terarah terhadap komponen tertentu."
        ),
        "recommendation": (
            "1) Terapkan split-horizon DNS untuk memisahkan record internal dan eksternal. "
            "2) Aktifkan DNSSEC untuk mencegah DNS spoofing dan cache poisoning. "
            "3) Batasi Zone Transfer (AXFR) hanya ke secondary DNS server terpercaya. "
            "4) Minimalkan informasi yang tersedia pada record TXT (hapus SPF yang terlalu detail). "
            "5) Audit DNS records secara berkala dan hapus record yang sudah tidak digunakan."
        ),
    },

    "DNS_ZONE_TRANSFER": {
        "name": "DNS Zone Transfer Allowed",
        "category": "Reconnaissance",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
        "description": (
            "Server DNS mengizinkan Zone Transfer (AXFR) dari sembarang host tanpa pembatasan. "
            "Zone Transfer memungkinkan siapa saja mengunduh seluruh daftar record DNS termasuk "
            "subdomain internal, alamat IP private, dan konfigurasi mail server. "
            "Informasi ini sangat berguna bagi penyerang untuk memetakan seluruh infrastruktur "
            "dan menemukan entry point yang mungkin tidak terlindungi dengan baik."
        ),
        "recommendation": (
            "1) Batasi AXFR hanya ke IP address secondary DNS server terpercaya. "
            "2) Pada BIND: tambahkan allow-transfer { IP_SECONDARY; }; di konfigurasi zone. "
            "3) Pada Windows DNS: konfigurasi Zone Transfer hanya ke specific servers. "
            "4) Gunakan TSIG (Transaction Signature) untuk autentikasi antar DNS server. "
            "5) Monitor log DNS untuk mendeteksi percobaan Zone Transfer yang tidak sah."
        ),
    },

    "PORT_SSH_EXPOSED": {
        "name": "SSH Port Exposed to Public (22)",
        "category": "Reconnaissance",
        "metrics": {"av": "N", "ac": "H", "pr": "N", "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
        "description": (
            "Port SSH (22) terbuka dan dapat diakses dari internet publik. "
            "SSH yang terbuka ke publik menjadi target utama serangan brute force otomatis "
            "yang terus-menerus mencoba kombinasi username dan password. Selain itu, "
            "versi OpenSSH yang tidak diperbarui dapat memiliki kerentanan yang "
            "memungkinkan penyerang mendapatkan akses shell ke server. "
            "Port 22 termasuk port yang paling sering di-scan oleh bot otomatis di internet."
        ),
        "recommendation": (
            "1) Batasi akses SSH hanya dari IP address terpercaya menggunakan firewall (iptables/ufw). "
            "2) Gunakan key-based authentication dan nonaktifkan password authentication. "
            "3) Ubah port SSH ke port non-standar (misalnya 2222) untuk mengurangi scan otomatis. "
            "4) Nonaktifkan root login: PermitRootLogin no di sshd_config. "
            "5) Implementasikan fail2ban untuk memblokir IP yang melakukan brute force. "
            "6) Gunakan VPN atau bastion host sebagai gateway akses SSH."
        ),
    },

    "PORT_RDP_EXPOSED": {
        "name": "RDP Port Exposed to Public (3389)",
        "category": "Reconnaissance",
        "metrics": {"av": "N", "ac": "H", "pr": "N", "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
        "description": (
            "Port Remote Desktop Protocol (3389) terbuka dan dapat diakses dari internet publik. "
            "RDP yang terekspos sangat berbahaya karena merupakan target utama serangan "
            "ransomware dan brute force. Kerentanan RDP seperti BlueKeep (CVE-2019-0708) "
            "memungkinkan eksekusi kode jarak jauh tanpa autentikasi. "
            "Banyak serangan ransomware berskala besar dimulai dari RDP yang terbuka ke internet."
        ),
        "recommendation": (
            "1) Blokir port 3389 dari akses internet menggunakan firewall. "
            "2) Gunakan VPN sebagai syarat untuk mengakses RDP. "
            "3) Aktifkan Network Level Authentication (NLA) untuk memerlukan autentikasi "
            "sebelum koneksi RDP terbentuk. "
            "4) Terapkan pembatasan jumlah percobaan login gagal. "
            "5) Pastikan patch keamanan Windows selalu diperbarui (terutama BlueKeep fix). "
            "6) Pertimbangkan alternatif seperti Apache Guacamole untuk remote access berbasis web."
        ),
    },

    "PORT_DATABASE_EXPOSED": {
        "name": "Database Port Exposed to Public",
        "category": "Reconnaissance",
        "metrics": {"av": "N", "ac": "H", "pr": "N", "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
        "description": (
            "Port database (MySQL/3306, PostgreSQL/5432, Redis/6379, MongoDB/27017) "
            "terbuka dan dapat diakses dari internet publik. Database yang terekspos ke internet "
            "memungkinkan penyerang melakukan brute force kredensial, mengakses data tanpa "
            "autentikasi (pada konfigurasi default Redis dan MongoDB), "
            "atau mengeksploitasi kerentanan pada versi database yang tidak diperbarui. "
            "Banyak kasus kebocoran data besar disebabkan oleh database yang terbuka ke publik."
        ),
        "recommendation": (
            "1) Blokir semua port database dari akses internet menggunakan firewall. "
            "2) Bind database ke localhost (127.0.0.1) atau private network saja. "
            "3) Gunakan SSH tunnel atau VPN untuk akses database dari jarak jauh. "
            "4) Terapkan autentikasi yang kuat pada semua database (terutama Redis dan MongoDB "
            "yang secara default tidak memerlukan autentikasi). "
            "5) Gunakan SSL/TLS untuk enkripsi koneksi database. "
            "6) Batasi privilege akun database sesuai kebutuhan (principle of least privilege)."
        ),
    },

    "PORT_FTP_EXPOSED": {
        "name": "FTP Port Exposed to Public (21)",
        "category": "Reconnaissance",
        "metrics": {"av": "N", "ac": "H", "pr": "N", "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
        "description": (
            "Port FTP (21) terbuka dan dapat diakses dari internet publik. "
            "FTP mentransmisikan kredensial (username dan password) serta data file "
            "dalam bentuk plaintext tanpa enkripsi. Penyerang yang melakukan network sniffing "
            "dapat menangkap kredensial FTP dengan mudah. Selain itu, banyak server FTP "
            "yang masih mengizinkan anonymous login yang memungkinkan akses tanpa autentikasi."
        ),
        "recommendation": (
            "1) Ganti FTP dengan SFTP (SSH File Transfer Protocol) atau FTPS (FTP over TLS). "
            "2) Nonaktifkan anonymous login pada konfigurasi FTP. "
            "3) Jika FTP masih diperlukan, batasi akses hanya dari IP terpercaya. "
            "4) Gunakan chroot untuk membatasi akses direktori pengguna FTP. "
            "5) Audit log FTP secara berkala untuk mendeteksi akses yang tidak sah."
        ),
    },

    "PORT_TELNET_EXPOSED": {
        "name": "Telnet Port Exposed to Public (23)",
        "category": "Reconnaissance",
        "metrics": {"av": "N", "ac": "H", "pr": "N", "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
        "description": (
            "Port Telnet (23) terbuka dan dapat diakses dari internet publik. "
            "Telnet mengirimkan semua data termasuk username, password, dan perintah "
            "dalam bentuk plaintext tanpa enkripsi apapun. Protokol ini sudah dianggap "
            "obsolete dan sangat tidak aman untuk digunakan. "
            "Penyerang dapat dengan mudah menangkap kredensial melalui packet capture."
        ),
        "recommendation": (
            "1) Nonaktifkan layanan Telnet sepenuhnya dan blokir port 23 di firewall. "
            "2) Ganti Telnet dengan SSH yang menyediakan enkripsi end-to-end. "
            "3) Jika Telnet diperlukan untuk perangkat legacy, batasi akses hanya dari "
            "jaringan internal melalui VLAN terpisah. "
            "4) Pertimbangkan penggunaan serial console untuk akses emergency sebagai alternatif."
        ),
    },

    "PORT_SMTP_EXPOSED": {
        "name": "SMTP Port Exposed to Public (25)",
        "category": "Reconnaissance",
        "metrics": {"av": "N", "ac": "H", "pr": "N", "ui": "N", "s": "U", "c": "N", "i": "L", "a": "N"},
        "description": (
            "Port SMTP (25) terbuka dan dapat diakses dari internet publik. "
            "SMTP yang terbuka tanpa konfigurasi yang tepat dapat disalahgunakan sebagai "
            "open relay untuk mengirimkan email spam atau phishing melalui server target. "
            "Hal ini dapat menyebabkan domain dan IP server masuk ke blacklist email "
            "dan merusak reputasi domain."
        ),
        "recommendation": (
            "1) Pastikan SMTP tidak dikonfigurasi sebagai open relay. "
            "2) Implementasikan autentikasi SMTP (SMTP AUTH) untuk pengiriman email. "
            "3) Batasi akses port 25 hanya untuk mail server yang dikenal. "
            "4) Konfigurasikan SPF, DKIM, dan DMARC untuk mencegah spoofing. "
            "5) Monitor log SMTP untuk mendeteksi aktivitas pengiriman email yang mencurigakan."
        ),
    },

    "PORT_DNS_EXPOSED": {
        "name": "DNS Port Exposed to Public (53)",
        "category": "Reconnaissance",
        "metrics": {"av": "N", "ac": "H", "pr": "N", "ui": "N", "s": "U", "c": "N", "i": "N", "a": "L"},
        "description": (
            "Port DNS (53) terbuka dan dapat diakses dari internet publik. "
            "Jika ini bukan DNS server yang memang ditujukan untuk publik, port yang terbuka "
            "dapat disalahgunakan untuk DNS amplification attack (jenis serangan DDoS) "
            "di mana penyerang mengirimkan query DNS kecil dengan spoofed source IP "
            "dan server merespons dengan data yang jauh lebih besar ke IP korban."
        ),
        "recommendation": (
            "1) Jika bukan public DNS server, blokir port 53 dari akses publik. "
            "2) Batasi recursive query hanya untuk jaringan internal. "
            "3) Implementasikan response rate limiting (RRL) pada DNS server. "
            "4) Pastikan DNS server tidak menjadi open resolver. "
            "5) Monitor traffic DNS untuk mendeteksi anomali volume query."
        ),
    },

    "PORT_MEMCACHED_EXPOSED": {
        "name": "Memcached Port Exposed (11211)",
        "category": "Reconnaissance",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "N", "i": "N", "a": "L"},
        "description": (
            "Port Memcached (11211) terbuka dan dapat diakses dari internet publik. "
            "Memcached secara default tidak memiliki mekanisme autentikasi. "
            "Server Memcached yang terekspos dapat disalahgunakan untuk serangan "
            "DDoS amplification yang menghasilkan traffic hingga 51.000 kali lipat "
            "dari request awal. Selain itu, data cache yang tersimpan "
            "dapat dibaca oleh siapa saja tanpa autentikasi."
        ),
        "recommendation": (
            "1) Blokir port 11211 dari akses internet dan bind ke localhost. "
            "2) Aktifkan autentikasi SASL pada Memcached. "
            "3) Nonaktifkan protokol UDP pada Memcached untuk mencegah amplification. "
            "4) Jalankan Memcached dalam firewall zone yang terpisah. "
            "5) Monitor koneksi ke Memcached untuk mendeteksi akses yang tidak sah."
        ),
    },

    "PORT_ELASTICSEARCH_EXPOSED": {
        "name": "Elasticsearch Port Exposed (9200/9300)",
        "category": "Reconnaissance",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "L", "a": "N"},
        "description": (
            "Port Elasticsearch (9200 untuk HTTP API, 9300 untuk cluster communication) "
            "terbuka dan dapat diakses dari internet publik. Elasticsearch secara default "
            "tidak memerlukan autentikasi, sehingga siapa saja yang mengetahui IP dan port "
            "dapat mengakses, membaca, memodifikasi, atau menghapus seluruh data indeks. "
            "Banyak kasus kebocoran data besar melibatkan Elasticsearch yang terekspos ke publik."
        ),
        "recommendation": (
            "1) Blokir port 9200 dan 9300 dari akses internet. "
            "2) Bind Elasticsearch ke localhost atau private network. "
            "3) Aktifkan Elasticsearch Security (X-Pack/OpenSearch Security) untuk autentikasi. "
            "4) Terapkan role-based access control (RBAC) untuk membatasi akses per indeks. "
            "5) Gunakan reverse proxy (Nginx) dengan autentikasi untuk akses web dashboard."
        ),
    },

    "SUBDOMAIN_GAMBLING": {
        "name": "Gambling/Spam Subdomain Detected",
        "category": "Reconnaissance",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "L", "i": "H", "a": "N"},
        "description": (
            "Ditemukan subdomain yang mengandung keyword perjudian atau spam (slot, togel, casino, dll). "
            "Keberadaan subdomain semacam ini merupakan indikasi kuat bahwa server atau panel "
            "DNS telah dikompromikan oleh penyerang. Penyerang biasanya menambahkan subdomain "
            "perjudian untuk tujuan SEO spam (parasit SEO) yang memanfaatkan reputasi domain "
            "korban untuk meningkatkan peringkat situs perjudian ilegal di mesin pencari."
        ),
        "recommendation": (
            "1) Hapus segera semua DNS A Record yang mengarah ke subdomain perjudian. "
            "2) Audit log akses panel DNS/hosting untuk mengetahui sumber kompromi. "
            "3) Ganti semua kredensial panel DNS, hosting, dan registrar domain. "
            "4) Aktifkan two-factor authentication pada panel manajemen DNS. "
            "5) Laporkan ke Google Search Console jika situs sudah terindeks. "
            "6) Monitor DNS secara berkala menggunakan tools seperti SecurityTrails atau DNSdumpster."
        ),
    },

    "SUBDOMAIN_DEV_EXPOSED": {
        "name": "Development/Staging Subdomain Exposed",
        "category": "Reconnaissance",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
        "description": (
            "Subdomain pengembangan atau staging (dev, staging, test, uat, sandbox) "
            "ditemukan dapat diakses dari internet publik. Lingkungan non-production biasanya "
            "memiliki konfigurasi keamanan yang lebih lemah, fitur debug yang aktif, "
            "kredensial default, dan data yang mungkin sensitif. Penyerang dapat memanfaatkan "
            "kerentanan di lingkungan staging untuk mendapatkan informasi yang berguna "
            "untuk menyerang lingkungan production."
        ),
        "recommendation": (
            "1) Batasi akses subdomain dev/staging menggunakan IP whitelist atau VPN. "
            "2) Tambahkan HTTP Basic Auth sebagai lapisan proteksi tambahan. "
            "3) Jangan gunakan data production asli di lingkungan staging (gunakan data dummy). "
            "4) Nonaktifkan debug mode dan error display pada staging yang dapat diakses publik. "
            "5) Pertimbangkan penggunaan subdomain yang tidak mudah ditebak (random string)."
        ),
    },

    "SUBDOMAIN_ADMIN_EXPOSED": {
        "name": "Admin Panel Subdomain Exposed",
        "category": "Reconnaissance",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "L", "i": "L", "a": "N"},
        "description": (
            "Subdomain panel administrasi (admin, panel, dashboard, cms, backend, cpanel) "
            "ditemukan dan dapat diakses dari internet publik. Panel admin yang terekspos "
            "menjadi target utama serangan brute force dan credential stuffing. "
            "Jika penyerang berhasil mengakses panel admin, mereka mendapatkan kontrol "
            "penuh atas konten, konfigurasi, dan data aplikasi."
        ),
        "recommendation": (
            "1) Batasi akses panel admin hanya dari IP address terpercaya. "
            "2) Implementasikan Multi-Factor Authentication (MFA) untuk semua akun admin. "
            "3) Gunakan URL admin yang tidak mudah ditebak (bukan /admin atau /panel). "
            "4) Tambahkan rate limiting dan CAPTCHA pada halaman login admin. "
            "5) Monitor dan alert untuk percobaan login gagal pada panel admin. "
            "6) Pertimbangkan VPN sebagai syarat mengakses panel admin."
        ),
    },

    "SUBDOMAIN_TAKEOVER": {
        "name": "Subdomain Takeover Risk",
        "category": "Reconnaissance",
        "metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "L", "i": "H", "a": "N"},
        "description": (
            "Subdomain memiliki CNAME record yang mengarah ke layanan eksternal yang sudah "
            "tidak aktif (dangling DNS). Penyerang dapat mengklaim layanan tersebut dan "
            "mengambil alih subdomain, menampilkan konten berbahaya di bawah domain "
            "organisasi. Subdomain takeover dapat digunakan untuk phishing yang sangat "
            "meyakinkan, pencurian cookie (jika cookie di-scope ke parent domain), "
            "atau merusak reputasi organisasi."
        ),
        "recommendation": (
            "1) Hapus segera CNAME record yang mengarah ke layanan yang sudah tidak digunakan. "
            "2) Audit seluruh subdomain dan CNAME record secara berkala (minimal bulanan). "
            "3) Sebelum menghapus layanan eksternal, selalu hapus DNS record terlebih dahulu. "
            "4) Gunakan monitoring tool untuk mendeteksi dangling DNS secara otomatis. "
            "5) Dokumentasikan semua subdomain aktif dan layanan yang terkait."
        ),
    },
}