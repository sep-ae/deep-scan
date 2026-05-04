<script setup>
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'

import { 
  Shield, Zap, Target, CheckCircle2, 
  ArrowRight, Scan, Lock, Activity,
  Globe, Search, FileText, AlertTriangle,
  Database, Wifi, Server, Code2, Upload,
  FolderOpen, ExternalLink, KeyRound,
  ShieldAlert, BarChart3, Cpu
} from 'lucide-vue-next'
</script>

<template>
  <div class="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50">
    
    <!-- Navbar -->
    <header class="border-b bg-white/80 backdrop-blur-md sticky top-0 z-50">
      <div class="container mx-auto px-4 py-4 flex items-center justify-between">
        <div class="flex items-center gap-2">
          <div class="h-10 w-10 rounded-lg bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center">
            <Shield class="h-6 w-6 text-white" />
          </div>
          <span class="text-xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
            Deep-Scan
          </span>
        </div>

        <div class="flex items-center gap-3">
          <router-link to="/login">
            <Button variant="ghost" class="text-neutral-700 hover:text-blue-600">
              Login
            </Button>
          </router-link>
          <router-link to="/register">
            <Button class="bg-blue-600 hover:bg-blue-700 text-white shadow-md">
              Daftar Gratis
            </Button>
          </router-link>
        </div>
      </div>
    </header>

    <!-- Hero Section -->
    <section class="container mx-auto px-4 py-16 md:py-24">
      <div class="max-w-4xl mx-auto text-center space-y-8">
        
        <Badge variant="secondary" class="bg-blue-100 text-blue-700 border-blue-200 px-4 py-1">
          <Zap class="h-3 w-3 mr-1" />
          Automated Vulnerability Scanner
        </Badge>

        <h1 class="text-4xl md:text-6xl font-bold text-neutral-900 leading-tight">
          Platform Deteksi Kerentanan
          <span class="block mt-2 bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
            Website Otomatis
          </span>
        </h1>

        <p class="text-lg md:text-xl text-neutral-600 max-w-2xl mx-auto">
          Deep-Scan memindai website Anda secara otomatis menggunakan 
          <strong>59 profil kerentanan</strong> berdasarkan standar 
          <strong>OWASP Top 10</strong> dan penilaian <strong>CVSS v3.1</strong>.
        </p>

        <div class="flex flex-col sm:flex-row gap-4 justify-center items-center pt-4">
          <router-link to="/register">
            <Button class="bg-blue-600 hover:bg-blue-700 text-white px-8 py-6 text-lg shadow-lg hover:shadow-xl transition-all">
              Mulai Scan Gratis
              <ArrowRight class="h-5 w-5 ml-2" />
            </Button>
          </router-link>

          <router-link to="/login">
            <Button variant="outline" class="border-blue-200 text-blue-700 hover:bg-blue-50 px-8 py-6 text-lg">
              Sudah Punya Akun
            </Button>
          </router-link>
        </div>

        <!-- Stats -->
        <div class="grid grid-cols-3 gap-4 max-w-2xl mx-auto pt-8">
          <div class="text-center p-4 rounded-xl bg-white/70 border border-blue-100">
            <div class="text-3xl font-bold text-blue-600">59</div>
            <div class="text-sm text-neutral-600">Profil Kerentanan</div>
          </div>
          <div class="text-center p-4 rounded-xl bg-white/70 border border-blue-100">
            <div class="text-3xl font-bold text-blue-600">4</div>
            <div class="text-sm text-neutral-600">Fase Pemindaian</div>
          </div>
          <div class="text-center p-4 rounded-xl bg-white/70 border border-blue-100">
            <div class="text-3xl font-bold text-blue-600">CVSS 3.1</div>
            <div class="text-sm text-neutral-600">Standar Scoring</div>
          </div>
        </div>

      </div>
    </section>

    <!-- Scan Modules Section -->
    <section class="container mx-auto px-4 py-16">
      <div class="max-w-6xl mx-auto">
        
        <div class="text-center mb-14">
          <Badge variant="secondary" class="bg-indigo-100 text-indigo-700 border-indigo-200 px-4 py-1 mb-4">
            <Search class="h-3 w-3 mr-1" />
            Modul Pemindaian
          </Badge>
          <h2 class="text-3xl md:text-4xl font-bold text-neutral-900 mb-3">
            Apa yang Deep-Scan Periksa?
          </h2>
          <p class="text-neutral-600 text-lg max-w-2xl mx-auto">
            Pemindaian dilakukan dalam 4 fase secara berurutan untuk hasil yang komprehensif
          </p>
        </div>

        <!-- Phase 1: Reconnaissance -->
        <div class="mb-8">
          <div class="flex items-center gap-3 mb-4">
            <div class="h-8 w-8 rounded-full bg-blue-600 text-white flex items-center justify-center text-sm font-bold">1</div>
            <h3 class="text-xl font-bold text-neutral-900">Reconnaissance</h3>
            <Badge variant="outline" class="text-blue-600 border-blue-200">Fase 1</Badge>
          </div>
          <div class="grid md:grid-cols-2 lg:grid-cols-4 gap-4 ml-11">
            <Card class="border border-blue-100 bg-white hover:shadow-md hover:border-blue-300 transition-all">
              <CardContent class="pt-5 pb-4 space-y-2">
                <div class="flex items-center gap-2">
                  <Globe class="h-5 w-5 text-blue-600" />
                  <h4 class="font-semibold text-sm text-neutral-900">DNS Lookup</h4>
                </div>
                <p class="text-xs text-neutral-500">Menganalisis record DNS (A, MX, NS, TXT, CNAME) untuk memetakan infrastruktur target</p>
              </CardContent>
            </Card>
            <Card class="border border-blue-100 bg-white hover:shadow-md hover:border-blue-300 transition-all">
              <CardContent class="pt-5 pb-4 space-y-2">
                <div class="flex items-center gap-2">
                  <Search class="h-5 w-5 text-blue-600" />
                  <h4 class="font-semibold text-sm text-neutral-900">Subdomain Finder</h4>
                </div>
                <p class="text-xs text-neutral-500">Enumerasi subdomain untuk menemukan aset tersembunyi, staging, dan panel admin</p>
              </CardContent>
            </Card>
            <Card class="border border-blue-100 bg-white hover:shadow-md hover:border-blue-300 transition-all">
              <CardContent class="pt-5 pb-4 space-y-2">
                <div class="flex items-center gap-2">
                  <Wifi class="h-5 w-5 text-blue-600" />
                  <h4 class="font-semibold text-sm text-neutral-900">Port Scanner</h4>
                </div>
                <p class="text-xs text-neutral-500">Memindai port terbuka (SSH, FTP, RDP, Database, SMTP) untuk deteksi layanan terekspos</p>
              </CardContent>
            </Card>
            <Card class="border border-blue-100 bg-white hover:shadow-md hover:border-blue-300 transition-all">
              <CardContent class="pt-5 pb-4 space-y-2">
                <div class="flex items-center gap-2">
                  <Cpu class="h-5 w-5 text-blue-600" />
                  <h4 class="font-semibold text-sm text-neutral-900">Tech Fingerprint</h4>
                </div>
                <p class="text-xs text-neutral-500">Identifikasi web server, framework, CMS, bahasa pemrograman, dan CDN yang digunakan</p>
              </CardContent>
            </Card>
          </div>
        </div>

        <!-- Phase 2: HTTP Security -->
        <div class="mb-8">
          <div class="flex items-center gap-3 mb-4">
            <div class="h-8 w-8 rounded-full bg-purple-600 text-white flex items-center justify-center text-sm font-bold">2</div>
            <h3 class="text-xl font-bold text-neutral-900">HTTP Security Configuration</h3>
            <Badge variant="outline" class="text-purple-600 border-purple-200">Fase 2</Badge>
          </div>
          <div class="grid md:grid-cols-2 gap-4 ml-11">
            <Card class="border border-purple-100 bg-white hover:shadow-md hover:border-purple-300 transition-all">
              <CardContent class="pt-5 pb-4 space-y-2">
                <div class="flex items-center gap-2">
                  <ShieldAlert class="h-5 w-5 text-purple-600" />
                  <h4 class="font-semibold text-sm text-neutral-900">Security Headers</h4>
                </div>
                <p class="text-xs text-neutral-500">Memeriksa CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy</p>
              </CardContent>
            </Card>
            <Card class="border border-purple-100 bg-white hover:shadow-md hover:border-purple-300 transition-all">
              <CardContent class="pt-5 pb-4 space-y-2">
                <div class="flex items-center gap-2">
                  <ExternalLink class="h-5 w-5 text-purple-600" />
                  <h4 class="font-semibold text-sm text-neutral-900">CORS Checker</h4>
                </div>
                <p class="text-xs text-neutral-500">Mendeteksi miskonfigurasi CORS yang memungkinkan akses data lintas domain tidak sah</p>
              </CardContent>
            </Card>
          </div>
        </div>

        <!-- Phase 3: Auth & Protection -->
        <div class="mb-8">
          <div class="flex items-center gap-3 mb-4">
            <div class="h-8 w-8 rounded-full bg-amber-600 text-white flex items-center justify-center text-sm font-bold">3</div>
            <h3 class="text-xl font-bold text-neutral-900">Proteksi & Autentikasi</h3>
            <Badge variant="outline" class="text-amber-600 border-amber-200">Fase 3</Badge>
          </div>
          <div class="grid md:grid-cols-2 lg:grid-cols-3 gap-4 ml-11">
            <Card class="border border-amber-100 bg-white hover:shadow-md hover:border-amber-300 transition-all">
              <CardContent class="pt-5 pb-4 space-y-2">
                <div class="flex items-center gap-2">
                  <Shield class="h-5 w-5 text-amber-600" />
                  <h4 class="font-semibold text-sm text-neutral-900">WAF Detection</h4>
                </div>
                <p class="text-xs text-neutral-500">Deteksi keberadaan Web Application Firewall (Cloudflare, Sucuri, dll)</p>
              </CardContent>
            </Card>
            <Card class="border border-amber-100 bg-white hover:shadow-md hover:border-amber-300 transition-all">
              <CardContent class="pt-5 pb-4 space-y-2">
                <div class="flex items-center gap-2">
                  <Activity class="h-5 w-5 text-amber-600" />
                  <h4 class="font-semibold text-sm text-neutral-900">Rate Limiting</h4>
                </div>
                <p class="text-xs text-neutral-500">Memeriksa apakah server membatasi jumlah request untuk mencegah brute-force</p>
              </CardContent>
            </Card>
            <Card class="border border-amber-100 bg-white hover:shadow-md hover:border-amber-300 transition-all">
              <CardContent class="pt-5 pb-4 space-y-2">
                <div class="flex items-center gap-2">
                  <KeyRound class="h-5 w-5 text-amber-600" />
                  <h4 class="font-semibold text-sm text-neutral-900">Login Security</h4>
                </div>
                <p class="text-xs text-neutral-500">Uji perlindungan brute-force, weak password, CAPTCHA, CSRF token, dan cookie flags</p>
              </CardContent>
            </Card>
          </div>
        </div>

        <!-- Phase 4: Web Vulnerabilities -->
        <div class="mb-8">
          <div class="flex items-center gap-3 mb-4">
            <div class="h-8 w-8 rounded-full bg-red-600 text-white flex items-center justify-center text-sm font-bold">4</div>
            <h3 class="text-xl font-bold text-neutral-900">Web Vulnerabilities</h3>
            <Badge variant="outline" class="text-red-600 border-red-200">Fase 4</Badge>
          </div>
          <div class="grid md:grid-cols-2 lg:grid-cols-3 gap-4 ml-11">
            <Card class="border border-red-100 bg-white hover:shadow-md hover:border-red-300 transition-all">
              <CardContent class="pt-5 pb-4 space-y-2">
                <div class="flex items-center gap-2">
                  <Database class="h-5 w-5 text-red-600" />
                  <h4 class="font-semibold text-sm text-neutral-900">SQL Injection</h4>
                </div>
                <p class="text-xs text-neutral-500">Deteksi kerentanan injeksi SQL pada parameter URL dan form input (Error-based & Blind)</p>
              </CardContent>
            </Card>
            <Card class="border border-red-100 bg-white hover:shadow-md hover:border-red-300 transition-all">
              <CardContent class="pt-5 pb-4 space-y-2">
                <div class="flex items-center gap-2">
                  <Code2 class="h-5 w-5 text-red-600" />
                  <h4 class="font-semibold text-sm text-neutral-900">Cross-Site Scripting</h4>
                </div>
                <p class="text-xs text-neutral-500">Mendeteksi kerentanan XSS Reflected yang memungkinkan injeksi script berbahaya</p>
              </CardContent>
            </Card>
            <Card class="border border-red-100 bg-white hover:shadow-md hover:border-red-300 transition-all">
              <CardContent class="pt-5 pb-4 space-y-2">
                <div class="flex items-center gap-2">
                  <Server class="h-5 w-5 text-red-600" />
                  <h4 class="font-semibold text-sm text-neutral-900">Command Injection</h4>
                </div>
                <p class="text-xs text-neutral-500">Mendeteksi kerentanan eksekusi perintah OS melalui input yang tidak tersanitasi</p>
              </CardContent>
            </Card>
            <Card class="border border-red-100 bg-white hover:shadow-md hover:border-red-300 transition-all">
              <CardContent class="pt-5 pb-4 space-y-2">
                <div class="flex items-center gap-2">
                  <ExternalLink class="h-5 w-5 text-red-600" />
                  <h4 class="font-semibold text-sm text-neutral-900">Open Redirect</h4>
                </div>
                <p class="text-xs text-neutral-500">Mendeteksi redirect ke domain eksternal yang dapat digunakan untuk phishing</p>
              </CardContent>
            </Card>
            <Card class="border border-red-100 bg-white hover:shadow-md hover:border-red-300 transition-all">
              <CardContent class="pt-5 pb-4 space-y-2">
                <div class="flex items-center gap-2">
                  <Upload class="h-5 w-5 text-red-600" />
                  <h4 class="font-semibold text-sm text-neutral-900">File Upload</h4>
                </div>
                <p class="text-xs text-neutral-500">Memeriksa validasi upload file untuk mencegah upload webshell dan file berbahaya</p>
              </CardContent>
            </Card>
            <Card class="border border-red-100 bg-white hover:shadow-md hover:border-red-300 transition-all">
              <CardContent class="pt-5 pb-4 space-y-2">
                <div class="flex items-center gap-2">
                  <FolderOpen class="h-5 w-5 text-red-600" />
                  <h4 class="font-semibold text-sm text-neutral-900">Directory Listing</h4>
                </div>
                <p class="text-xs text-neutral-500">Mendeteksi direktori terbuka yang mengekspos file sensitif ke publik</p>
              </CardContent>
            </Card>
          </div>
        </div>

      </div>
    </section>

    <!-- Features Section -->
    <section class="container mx-auto px-4 py-16 bg-white/50">
      <div class="max-w-5xl mx-auto">
        
        <div class="text-center mb-12">
          <h2 class="text-3xl md:text-4xl font-bold text-neutral-900 mb-3">
            Fitur Unggulan
          </h2>
          <p class="text-neutral-600 text-lg">
            Dirancang untuk kemudahan dan hasil yang profesional
          </p>
        </div>

        <div class="grid md:grid-cols-3 gap-6">
          
          <Card class="border border-blue-200 bg-gradient-to-b from-blue-50 to-white hover:shadow-lg transition-all">
            <CardContent class="pt-6 space-y-3">
              <div class="h-12 w-12 rounded-xl bg-blue-100 flex items-center justify-center">
                <Scan class="h-6 w-6 text-blue-600" />
              </div>
              <h3 class="font-semibold text-lg text-neutral-900">Pemindaian Otomatis</h3>
              <p class="text-sm text-neutral-600">
                Cukup masukkan URL target — Deep-Scan menjalankan 4 fase pemindaian secara otomatis tanpa konfigurasi rumit
              </p>
            </CardContent>
          </Card>

          <Card class="border border-purple-200 bg-gradient-to-b from-purple-50 to-white hover:shadow-lg transition-all">
            <CardContent class="pt-6 space-y-3">
              <div class="h-12 w-12 rounded-xl bg-purple-100 flex items-center justify-center">
                <BarChart3 class="h-6 w-6 text-purple-600" />
              </div>
              <h3 class="font-semibold text-lg text-neutral-900">Scoring CVSS v3.1</h3>
              <p class="text-sm text-neutral-600">
                Setiap kerentanan dinilai menggunakan standar industri CVSS v3.1 dari FIRST.org dengan severity otomatis
              </p>
            </CardContent>
          </Card>

          <Card class="border border-green-200 bg-gradient-to-b from-green-50 to-white hover:shadow-lg transition-all">
            <CardContent class="pt-6 space-y-3">
              <div class="h-12 w-12 rounded-xl bg-green-100 flex items-center justify-center">
                <FileText class="h-6 w-6 text-green-600" />
              </div>
              <h3 class="font-semibold text-lg text-neutral-900">Laporan PDF Profesional</h3>
              <p class="text-sm text-neutral-600">
                Generate laporan PDF lengkap dengan deskripsi kerentanan, skor CVSS, proof-of-concept, dan rekomendasi perbaikan
              </p>
            </CardContent>
          </Card>

        </div>
      </div>
    </section>

    <!-- How It Works -->
    <section class="container mx-auto px-4 py-16">
      <div class="max-w-4xl mx-auto">
        <div class="text-center mb-12">
          <h2 class="text-3xl md:text-4xl font-bold text-neutral-900 mb-3">
            Cara Kerja
          </h2>
          <p class="text-neutral-600 text-lg">
            Tiga langkah mudah untuk memindai website Anda
          </p>
        </div>

        <div class="grid md:grid-cols-3 gap-8">
          <div class="text-center space-y-3">
            <div class="h-14 w-14 rounded-2xl bg-blue-100 flex items-center justify-center mx-auto">
              <span class="text-2xl font-bold text-blue-600">1</span>
            </div>
            <h3 class="font-semibold text-neutral-900">Masukkan URL</h3>
            <p class="text-sm text-neutral-600">Daftar akun lalu masukkan URL website yang ingin dipindai</p>
          </div>
          <div class="text-center space-y-3">
            <div class="h-14 w-14 rounded-2xl bg-indigo-100 flex items-center justify-center mx-auto">
              <span class="text-2xl font-bold text-indigo-600">2</span>
            </div>
            <h3 class="font-semibold text-neutral-900">Tunggu Hasil</h3>
            <p class="text-sm text-neutral-600">Deep-Scan menjalankan 4 fase pemindaian otomatis secara berurutan</p>
          </div>
          <div class="text-center space-y-3">
            <div class="h-14 w-14 rounded-2xl bg-green-100 flex items-center justify-center mx-auto">
              <span class="text-2xl font-bold text-green-600">3</span>
            </div>
            <h3 class="font-semibold text-neutral-900">Download Laporan</h3>
            <p class="text-sm text-neutral-600">Lihat hasil di dashboard dan unduh laporan PDF profesional</p>
          </div>
        </div>
      </div>
    </section>

    <!-- CTA Section -->
    <section class="container mx-auto px-4 py-16">
      <div class="max-w-4xl mx-auto">
        
        <Card class="border-none shadow-xl bg-gradient-to-br from-blue-600 to-indigo-700 text-white overflow-hidden relative">
          <div class="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHZpZXdCb3g9IjAgMCA2MCA2MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZyBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxnIGZpbGw9IiNmZmYiIGZpbGwtb3BhY2l0eT0iMC4wNSI+PHBhdGggZD0iTTM2IDM0djItSDI0di0yaDEyek0zNiAyNHYySDI0di0yaDE/Ii8+PC9nPjwvZz48L3N2Zz4=')] opacity-30"></div>
          <CardContent class="py-12 text-center space-y-6 relative z-10">
            
            <h2 class="text-3xl md:text-4xl font-bold">
              Siap Mengamankan Website Anda?
            </h2>
            
            <p class="text-lg text-blue-100 max-w-2xl mx-auto">
              Daftar sekarang dan mulai pemindaian kerentanan pertama Anda.
              Temukan celah keamanan sebelum penyerang menemukannya.
            </p>

            <router-link to="/register">
              <Button class="bg-white text-blue-600 hover:bg-blue-50 px-8 py-6 text-lg shadow-lg hover:shadow-xl transition-all">
                Daftar Gratis Sekarang
                <ArrowRight class="h-5 w-5 ml-2" />
              </Button>
            </router-link>

          </CardContent>
        </Card>

      </div>
    </section>

    <!-- Footer -->
    <footer class="border-t bg-white/80 backdrop-blur-md mt-8">
      <div class="container mx-auto px-4 py-8">
        <div class="flex flex-col md:flex-row items-center justify-between gap-4">
          
          <div class="flex items-center gap-2">
            <div class="h-8 w-8 rounded-lg bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center">
              <Shield class="h-5 w-5 text-white" />
            </div>
            <span class="font-semibold text-neutral-700">Deep-Scan</span>
          </div>

          <div class="text-center md:text-right">
            <p class="text-sm text-neutral-600">
              © 2026 Deep-Scan — Tugas Akhir Politeknik Negeri Madiun
            </p>
            <p class="text-xs text-neutral-400 mt-1">
              Built with Flask, Vue.js & ReportLab · Scoring CVSS v3.1
            </p>
          </div>

        </div>
      </div>
    </footer>

  </div>
</template>
