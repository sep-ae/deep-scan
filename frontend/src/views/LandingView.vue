<script setup>
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'

import { 
  Shield, Zap, Target, CheckCircle2, 
  ArrowRight, Scan, Lock, Activity
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
        
        <!-- Badge -->
        <Badge variant="secondary" class="bg-blue-100 text-blue-700 border-blue-200 px-4 py-1">
          <Zap class="h-3 w-3 mr-1" />
          Automated Security Scanner
        </Badge>

        <!-- Heading -->
        <h1 class="text-4xl md:text-6xl font-bold text-neutral-900 leading-tight">
          Platform Deteksi Kerentanan Website
          <span class="block mt-2 bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
            Cepat, Akurat & Otomatis
          </span>
        </h1>

        <!-- Description -->
        <p class="text-lg md:text-xl text-neutral-600 max-w-2xl mx-auto">
          Deep-Scan membantu Anda menemukan celah keamanan pada website secara otomatis 
          menggunakan teknologi berbasis OWASP Top 10 dan best practices security testing.
        </p>

        <!-- CTA Buttons -->
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
          <div class="text-center">
            <div class="text-3xl font-bold text-blue-600">100+</div>
            <div class="text-sm text-neutral-600">Vulnerability Checks</div>
          </div>
          <div class="text-center">
            <div class="text-3xl font-bold text-blue-600">5 Min</div>
            <div class="text-sm text-neutral-600">Average Scan Time</div>
          </div>
          <div class="text-center">
            <div class="text-3xl font-bold text-blue-600">99%</div>
            <div class="text-sm text-neutral-600">Accuracy Rate</div>
          </div>
        </div>

      </div>
    </section>

    <!-- Features Section -->
    <section class="container mx-auto px-4 py-16">
      <div class="max-w-5xl mx-auto">
        
        <div class="text-center mb-12">
          <h2 class="text-3xl md:text-4xl font-bold text-neutral-900 mb-3">
            Fitur Unggulan
          </h2>
          <p class="text-neutral-600 text-lg">
            Teknologi terdepan untuk keamanan website Anda
          </p>
        </div>

        <div class="grid md:grid-cols-3 gap-6">
          
          <!-- Feature 1 -->
          <Card class="border border-blue-200 bg-blue-50 hover:shadow-lg transition-all">
            <CardContent class="pt-6 space-y-3">
              <div class="h-12 w-12 rounded-xl bg-blue-200 flex items-center justify-center">
                <Scan class="h-6 w-6 text-blue-700" />
              </div>
              <h3 class="font-semibold text-lg text-blue-900">Automated Scanning</h3>
              <p class="text-sm text-blue-700">
                Pemindaian otomatis untuk mendeteksi kerentanan keamanan tanpa perlu keahlian teknis
              </p>
            </CardContent>
          </Card>

          <!-- Feature 2 -->
          <Card class="border border-purple-200 bg-purple-50 hover:shadow-lg transition-all">
            <CardContent class="pt-6 space-y-3">
              <div class="h-12 w-12 rounded-xl bg-purple-200 flex items-center justify-center">
                <Target class="h-6 w-6 text-purple-700" />
              </div>
              <h3 class="font-semibold text-lg text-purple-900">OWASP Based</h3>
              <p class="text-sm text-purple-700">
                Mengikuti standar keamanan OWASP Top 10 untuk deteksi kerentanan yang komprehensif
              </p>
            </CardContent>
          </Card>

          <!-- Feature 3 -->
          <Card class="border border-green-200 bg-green-50 hover:shadow-lg transition-all">
            <CardContent class="pt-6 space-y-3">
              <div class="h-12 w-12 rounded-xl bg-green-200 flex items-center justify-center">
                <Lock class="h-6 w-6 text-green-700" />
              </div>
              <h3 class="font-semibold text-lg text-green-900">Detailed Reports</h3>
              <p class="text-sm text-green-700">
                Laporan lengkap dengan rekomendasi perbaikan untuk setiap kerentanan yang ditemukan
              </p>
            </CardContent>
          </Card>

        </div>
      </div>
    </section>

    <!-- What We Check Section -->
    <section class="container mx-auto px-4 py-16">
      <div class="max-w-4xl mx-auto">
        
        <Card class="border-none shadow-xl bg-white">
          <CardContent class="pt-8 space-y-6">
            
            <div class="text-center mb-6">
              <div class="h-16 w-16 rounded-2xl bg-blue-100 flex items-center justify-center mx-auto mb-4">
                <Activity class="h-8 w-8 text-blue-600" />
              </div>
              <h2 class="text-2xl md:text-3xl font-bold text-neutral-900 mb-2">
                Apa yang Kami Periksa?
              </h2>
              <p class="text-neutral-600">
                Deep-Scan melakukan pemeriksaan menyeluruh pada website Anda
              </p>
            </div>

            <div class="grid md:grid-cols-2 gap-4">
              
              <div class="flex items-start gap-3 p-4 rounded-lg bg-neutral-50 border border-neutral-200">
                <CheckCircle2 class="h-5 w-5 text-green-600 shrink-0 mt-0.5" />
                <div>
                  <h4 class="font-semibold text-neutral-900">Reconnaissance</h4>
                  <p class="text-sm text-neutral-600">DNS Lookup, Subdomain Finder, Port Scanning</p>
                </div>
              </div>

              <div class="flex items-start gap-3 p-4 rounded-lg bg-neutral-50 border border-neutral-200">
                <CheckCircle2 class="h-5 w-5 text-green-600 shrink-0 mt-0.5" />
                <div>
                  <h4 class="font-semibold text-neutral-900">HTTP Security</h4>
                  <p class="text-sm text-neutral-600">Security Headers, CORS Configuration</p>
                </div>
              </div>

              <div class="flex items-start gap-3 p-4 rounded-lg bg-neutral-50 border border-neutral-200">
                <CheckCircle2 class="h-5 w-5 text-green-600 shrink-0 mt-0.5" />
                <div>
                  <h4 class="font-semibold text-neutral-900">Authentication</h4>
                  <p class="text-sm text-neutral-600">WAF Detection, Brute-force Protection</p>
                </div>
              </div>

              <div class="flex items-start gap-3 p-4 rounded-lg bg-neutral-50 border border-neutral-200">
                <CheckCircle2 class="h-5 w-5 text-green-600 shrink-0 mt-0.5" />
                <div>
                  <h4 class="font-semibold text-neutral-900">Web Vulnerabilities</h4>
                  <p class="text-sm text-neutral-600">SQL Injection, XSS, Command Injection</p>
                </div>
              </div>

            </div>

          </CardContent>
        </Card>

      </div>
    </section>

    <!-- CTA Section -->
    <section class="container mx-auto px-4 py-16">
      <div class="max-w-4xl mx-auto">
        
        <Card class="border-none shadow-xl bg-gradient-to-br from-blue-500 to-indigo-600 text-white">
          <CardContent class="py-12 text-center space-y-6">
            
            <h2 class="text-3xl md:text-4xl font-bold">
              Siap Mengamankan Website Anda?
            </h2>
            
            <p class="text-lg text-blue-100 max-w-2xl mx-auto">
              Daftar sekarang dan dapatkan akses gratis ke platform Deep-Scan. 
              Mulai scanning dalam hitungan menit!
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
    <footer class="border-t bg-white/80 backdrop-blur-md mt-16">
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
              © 2026 Deep-Scan. Tugas Akhir Politeknik Negeri Madiun
            </p>
            <p class="text-xs text-neutral-500 mt-1">
              Built with Flask & Vue.js
            </p>
          </div>

        </div>
      </div>
    </footer>

  </div>
</template>
