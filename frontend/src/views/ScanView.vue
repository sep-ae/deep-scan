<script setup>
import { ref } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { toast } from 'vue-sonner'
import api from '@/services/api'

import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { Progress } from '@/components/ui/progress'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuItem } from '@/components/ui/dropdown-menu'
import { Sheet, SheetContent, SheetTrigger } from '@/components/ui/sheet'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Separator } from '@/components/ui/separator'


import {
  Scan, Loader2, CheckCircle2, Globe, Shield,
  CircleUser, Menu, Package2, Home, History,
  Crosshair, Globe2, XCircle, AlertTriangle, LogOut, Sun, Moon
} from 'lucide-vue-next'

import { useDarkMode } from '@/composables/useDarkMode'
const { isDark, toggleDark } = useDarkMode()

import { onMounted } from 'vue'

const router = useRouter()
const route = useRoute()
const username = ref('Pengguna')

const targetUrl = ref('')
const scopeMode = ref('wildcard')
const isScanning = ref(false)
const isCheckingActive = ref(true)
const scanProgress = ref(0)
const currentScanId = ref(null)
const currentPhase = ref('')
const showCancelDialog = ref(false)
const isCancelling = ref(false)
const isMobileMenuOpen = ref(false)


let pollTimer = null
let pollInterval = 8000
const MIN_INTERVAL = 3000
const MAX_INTERVAL = 15000

const userEmail = ref('user@deepscan.local')

const storedUser = localStorage.getItem('user')
if (storedUser) {
  try {
    const user = JSON.parse(storedUser)
    username.value = user.username || 'Pengguna'
    userEmail.value = user.email || 'user@deepscan.local'
  } catch (e) {
    console.error('Error parsing user data:', e)
  }
}

const checkActiveScan = async () => {
  try {
    const response = await api.get('/scan/active')
    if (response.data.has_active_scan) {
      isScanning.value = true
      currentScanId.value = response.data.scan_id
      targetUrl.value = response.data.target
      scanProgress.value = response.data.progress
      currentPhase.value = 'Melanjutkan progress...'
      pollInterval = MIN_INTERVAL
      schedulePoll()
    }
  } catch (error) {
    console.error('Gagal mengecek scan aktif:', error)
  } finally {
    isCheckingActive.value = false
  }
}

onMounted(() => {
  checkActiveScan()
})

const handleStartScan = async () => {
  if (!targetUrl.value.trim()) {
    toast('Validasi Gagal', { description: 'URL target wajib diisi.' })
    return
  }

  try {
    isScanning.value = true
    scanProgress.value = 0
    currentPhase.value = 'Starting scan...'
    pollInterval = MIN_INTERVAL

    const response = await api.post('/scan/start', {
      target_url: targetUrl.value,
      scope_mode: scopeMode.value,
    })
    currentScanId.value = response.data.scan_id

    toast('Scan Dimulai', { description: `Memindai ${response.data.target}...` })

    schedulePoll()

  } catch (error) {
    const msg = error.response?.data?.msg || 'Gagal memulai scan'
    toast('Scan Gagal', { description: msg })
    isScanning.value = false
    scanProgress.value = 0
  }
}

const schedulePoll = () => {
  pollTimer = setTimeout(executePoll, pollInterval)
}

const executePoll = async () => {
  try {
    const response = await api.get(`/scan/status/${currentScanId.value}`)
    const data = response.data

    scanProgress.value = data.progress || 0
    currentPhase.value = data.current_phase || 'Processing...'

    if (data.status === 'completed') {
      stopPolling()
      scanProgress.value = 100
      currentPhase.value = 'Scan selesai! Mengalihkan ke hasil...'
      toast('Scan Selesai', { description: 'Pemindaian berhasil diselesaikan!' })
      setTimeout(() => {
        isScanning.value = false
        router.push(`/history/${currentScanId.value}`)
      }, 1500)
      return
    }

    if (data.status === 'failed') {
      stopPolling()
      toast('Scan Gagal', { description: data.error_message || 'Terjadi kesalahan saat scanning' })
      isScanning.value = false
      scanProgress.value = 0
      return
    }

    if (data.status === 'cancelled') {
      stopPolling()
      isScanning.value = false
      scanProgress.value = 0
      return
    }

    if (data.progress > 50) {
      pollInterval = Math.min(pollInterval * 1.5, MAX_INTERVAL)
    }

    schedulePoll()

  } catch (error) {
    if (error.response?.status === 429) {
      pollInterval = MAX_INTERVAL
      console.warn('Rate limited, slowing down polling...')
      schedulePoll()
      return
    }

    stopPolling()
    toast('Error', { description: 'Gagal mengambil status scan' })
    isScanning.value = false
  }
}

const stopPolling = () => {
  if (pollTimer) {
    clearTimeout(pollTimer)
    pollTimer = null
  }
}

const handleCancelScan = async () => {
  if (!currentScanId.value) return
  isCancelling.value = true

  try {
    await api.post(`/scan/cancel/${currentScanId.value}`)
    stopPolling()
    showCancelDialog.value = false
    toast('Scan Dibatalkan', { description: 'Pemindaian dihentikan paksa oleh pengguna.' })
    isScanning.value = false
    scanProgress.value = 0
    currentPhase.value = ''
  } catch (error) {
    const msg = error.response?.data?.msg || 'Gagal membatalkan scan'
    toast('Error', { description: msg })
  } finally {
    isCancelling.value = false
  }
}

const goToDashboard = () => { isMobileMenuOpen.value = false; router.push('/dashboard') }
const goToScan = () => { isMobileMenuOpen.value = false; router.push('/scan') }
const goToHistory = () => { isMobileMenuOpen.value = false; router.push('/history') }


const handleLogout = () => {
  stopPolling()
  localStorage.removeItem('token')
  localStorage.removeItem('user')
  toast('Logout Berhasil', { description: 'Anda telah keluar dari sistem.' })
  router.push('/login')
}

const isActive = (path) => route.path === path
</script>

<template>
  <div class="flex min-h-screen w-full flex-col bg-neutral-50/50 dark:bg-slate-950 transition-colors duration-300">

    <header class="sticky top-0 z-50 flex h-16 items-center gap-4 border-b border-neutral-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-4 md:px-6">

      <nav class="hidden flex-col gap-6 text-lg font-medium md:flex md:flex-row md:items-center md:gap-5 md:text-sm lg:gap-6">
        <a href="#" class="flex items-center gap-2 text-lg font-semibold md:text-base">
          <Package2 class="h-6 w-6" />
          <span class="sr-only">Deep Scan</span>
        </a>
        <a
          @click="goToDashboard"
          href="#"
          :class="isActive('/dashboard') ? 'text-foreground' : 'text-muted-foreground'"
          class="transition-colors hover:text-foreground"
        >Dashboard</a>
        <a
          @click="goToScan"
          href="#"
          :class="isActive('/scan') ? 'text-foreground' : 'text-muted-foreground'"
          class="transition-colors hover:text-foreground"
        >Scan</a>
        <a
          @click="goToHistory"
          href="#"
          :class="isActive('/history') ? 'text-foreground' : 'text-muted-foreground'"
          class="transition-colors hover:text-foreground"
        >Riwayat</a>
      </nav>

      <Sheet v-model:open="isMobileMenuOpen">
        <SheetTrigger as-child>
          <Button variant="outline" size="icon" class="shrink-0 md:hidden">
            <Menu class="h-5 w-5" />
          </Button>
        </SheetTrigger>
        <SheetContent side="left" class="p-0 gap-0">
          <div class="flex flex-col h-full">
            <div class="px-6 py-5 bg-white dark:bg-slate-900 border-b border-neutral-100 dark:border-slate-800">
              <div class="flex items-center gap-3">
                <div class="h-11 w-11 rounded-2xl bg-blue-50 dark:bg-blue-900/30 flex items-center justify-center ring-1 ring-blue-100 dark:ring-blue-800">
                  <Package2 class="h-5 w-5 text-blue-600 dark:text-blue-400" />
                </div>
                <div>
                  <h2 class="text-neutral-900 dark:text-white font-bold text-lg leading-tight">Deep Scan</h2>
                  <p class="text-neutral-500 dark:text-slate-400 text-xs">Security Scanner</p>
                </div>
              </div>
            </div>
            <nav class="flex-1 px-4 py-5 space-y-1 overflow-y-auto">
              <p class="text-[11px] font-semibold text-neutral-400 dark:text-slate-500 uppercase tracking-widest px-3 mb-3">Menu</p>
              <a @click="goToDashboard" href="#" :class="[isActive('/dashboard') ? 'bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-400 font-semibold shadow-sm' : 'text-neutral-600 dark:text-slate-400 hover:bg-neutral-100 dark:hover:bg-slate-800', 'flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all duration-200 text-sm']">
                <div :class="[isActive('/dashboard') ? 'bg-blue-100 dark:bg-blue-900/40' : 'bg-neutral-100 dark:bg-slate-800', 'h-8 w-8 rounded-lg flex items-center justify-center transition-colors']">
                  <Home :class="[isActive('/dashboard') ? 'text-blue-600 dark:text-blue-400' : 'text-neutral-500 dark:text-slate-400', 'h-4 w-4']" />
                </div>
                Dashboard
              </a>
              <a @click="goToScan" href="#" :class="[isActive('/scan') ? 'bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-400 font-semibold shadow-sm' : 'text-neutral-600 dark:text-slate-400 hover:bg-neutral-100 dark:hover:bg-slate-800', 'flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all duration-200 text-sm']">
                <div :class="[isActive('/scan') ? 'bg-blue-100 dark:bg-blue-900/40' : 'bg-neutral-100 dark:bg-slate-800', 'h-8 w-8 rounded-lg flex items-center justify-center transition-colors']">
                  <Scan :class="[isActive('/scan') ? 'text-blue-600 dark:text-blue-400' : 'text-neutral-500 dark:text-slate-400', 'h-4 w-4']" />
                </div>
                Scan
              </a>
              <a @click="goToHistory" href="#" :class="[isActive('/history') ? 'bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-400 font-semibold shadow-sm' : 'text-neutral-600 dark:text-slate-400 hover:bg-neutral-100 dark:hover:bg-slate-800', 'flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all duration-200 text-sm']">
                <div :class="[isActive('/history') ? 'bg-blue-100 dark:bg-blue-900/40' : 'bg-neutral-100 dark:bg-slate-800', 'h-8 w-8 rounded-lg flex items-center justify-center transition-colors']">
                  <History :class="[isActive('/history') ? 'text-blue-600 dark:text-blue-400' : 'text-neutral-500 dark:text-slate-400', 'h-4 w-4']" />
                </div>
                Riwayat
              </a>
            </nav>
            <div class="px-4 pb-5">
              <Separator class="mb-4 bg-neutral-200 dark:bg-slate-800" />
              <div class="flex items-center gap-3 p-3 rounded-2xl bg-neutral-50 dark:bg-slate-800/50 border border-neutral-100 dark:border-slate-700 mb-3">
                <div class="h-10 w-10 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center shadow-md">
                  <span class="text-white font-bold text-sm">{{ username.charAt(0).toUpperCase() }}</span>
                </div>
                <div class="flex-1 min-w-0">
                  <p class="font-semibold text-sm text-neutral-900 dark:text-white truncate">{{ username }}</p>
                  <p class="text-xs text-neutral-500 dark:text-slate-400 truncate">{{ userEmail }}</p>
                </div>
              </div>
              <button @click="handleLogout" class="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 transition-all duration-200 text-sm font-medium">
                <div class="h-8 w-8 rounded-lg bg-red-50 dark:bg-red-900/30 flex items-center justify-center">
                  <LogOut class="h-4 w-4 text-red-500 dark:text-red-400" />
                </div>
                Logout
              </button>
            </div>
          </div>
        </SheetContent>
      </Sheet>


      <div class="flex w-full items-center gap-4 md:ml-auto md:gap-2 lg:gap-4">
        <div class="ml-auto flex items-center gap-2">
          <button @click="toggleDark" class="p-2 rounded-full hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors" :title="isDark ? 'Light mode' : 'Dark mode'">
            <Sun v-if="isDark" class="h-4 w-4 text-amber-500" />
            <Moon v-else class="h-4 w-4 text-slate-500" />
          </button>
        </div>
        <DropdownMenu>
          <DropdownMenuTrigger as-child>
            <Button variant="secondary" class="rounded-full h-10 w-10 p-0 overflow-hidden bg-gradient-to-br from-blue-500 to-purple-600 border-0 hover:opacity-90">
              <span class="text-white font-bold">{{ username.charAt(0).toUpperCase() }}</span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" class="w-64 dark:bg-slate-900 dark:border-slate-800">
            <DropdownMenuLabel class="p-4">
              <div class="flex flex-col space-y-1.5">
                <p class="text-sm font-semibold text-neutral-900 dark:text-white leading-none">{{ username }}</p>
                <p class="text-xs text-neutral-500 dark:text-slate-400 leading-none">{{ userEmail }}</p>
              </div>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem @click="handleLogout" class="text-red-600 cursor-pointer font-medium">
              Logout
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>

    <main class="flex-1 py-8 px-4">

      <div class="max-w-2xl mx-auto mb-6">
        <div class="flex items-center gap-3 mb-2">
          <div class="h-12 w-12 rounded-xl bg-blue-100 dark:bg-blue-900/30 flex items-center justify-center">
            <Scan class="h-6 w-6 text-blue-600 dark:text-blue-400" />
          </div>
          <div>
            <h1 class="text-2xl font-bold text-neutral-900 dark:text-white">Website Scanner</h1>
            <p class="text-sm text-neutral-600 dark:text-slate-400">Deteksi kerentanan keamanan secara otomatis</p>
          </div>
        </div>
      </div>

      <div class="max-w-2xl mx-auto space-y-6">

        <!-- Loading saat cek active scan -->
        <div v-if="isCheckingActive" class="flex flex-col items-center justify-center py-16">
          <Loader2 class="h-8 w-8 animate-spin text-blue-600 mb-3" />
          <p class="text-sm text-neutral-500">Memuat...</p>
        </div>

        <Card class="border border-neutral-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm" v-else-if="!isScanning">
          <CardHeader>
            <CardTitle class="text-lg dark:text-white">Mulai Pemindaian Baru</CardTitle>
            <CardDescription class="dark:text-slate-400">Masukkan URL website yang ingin dipindai</CardDescription>
          </CardHeader>
          <CardContent class="space-y-4">
            <div class="space-y-2">
              <Label for="url" class="flex items-center gap-2 dark:text-slate-300">
                <Globe class="h-4 w-4" />
                Target URL
              </Label>
              <Input
                id="url"
                v-model="targetUrl"
                type="text"
                placeholder="https://example.com"
                :disabled="isScanning"
                class="focus-visible:ring-blue-600 bg-neutral-50 dark:bg-slate-800 border-neutral-200 dark:border-slate-700 dark:text-white dark:placeholder:text-slate-500"
                @keyup.enter="handleStartScan"
              />
              <p class="text-xs text-neutral-500 dark:text-slate-400">Contoh: https://example.com atau example.com</p>
            </div>

            <!-- Scope Mode -->
            <div class="space-y-2">
              <Label class="flex items-center gap-2 dark:text-slate-300">
                <Crosshair class="h-4 w-4" />
                Scope Domain
              </Label>
              <div class="grid grid-cols-2 gap-3">
                <label
                  :class="[
                    'flex items-start gap-3 p-3 rounded-lg border-2 cursor-pointer transition-all',
                    scopeMode === 'strict'
                      ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20'
                      : 'border-neutral-200 dark:border-slate-700 hover:border-neutral-300 dark:hover:border-slate-600 dark:bg-slate-800/50'
                  ]"
                >
                  <input
                    type="radio"
                    v-model="scopeMode"
                    value="strict"
                    class="mt-1 accent-blue-600"
                  />
                  <div>
                    <p class="text-sm font-medium text-neutral-900 dark:text-white">Domain Utama</p>
                    <p class="text-xs text-neutral-500 dark:text-slate-400">Hanya scan domain yang diinput</p>
                  </div>
                </label>
                <label
                  :class="[
                    'flex items-start gap-3 p-3 rounded-lg border-2 cursor-pointer transition-all',
                    scopeMode === 'wildcard'
                      ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20'
                      : 'border-neutral-200 dark:border-slate-700 hover:border-neutral-300 dark:hover:border-slate-600 dark:bg-slate-800/50'
                  ]"
                >
                  <input
                    type="radio"
                    v-model="scopeMode"
                    value="wildcard"
                    class="mt-1 accent-blue-600"
                  />
                  <div>
                    <p class="text-sm font-medium text-neutral-900 dark:text-white">Termasuk Subdomain</p>
                    <p class="text-xs text-neutral-500 dark:text-slate-400">Scan semua subdomain terkait</p>
                  </div>
                </label>
              </div>
            </div>
            <Button
              @click="handleStartScan"
              :disabled="!targetUrl.trim() || isScanning"
              class="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold shadow-md dark:bg-blue-600 dark:hover:bg-blue-700"
            >
              <Scan class="h-4 w-4 mr-2" />
              Mulai Pemindaian
            </Button>
          </CardContent>
        </Card>

        <Card class="border border-neutral-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm" v-if="isScanning">
          <CardHeader>
            <CardTitle class="text-lg flex items-center gap-2 dark:text-white">
              <Loader2 class="h-5 w-5 animate-spin text-blue-600 dark:text-blue-400" />
              Pemindaian Sedang Berjalan...
            </CardTitle>
            <CardDescription class="mt-1 dark:text-slate-400">{{ targetUrl }}</CardDescription>
          </CardHeader>
          <CardContent class="space-y-6">
            <div class="space-y-2">
              <div class="flex items-center justify-between text-sm">
                <span class="text-neutral-600 dark:text-slate-400">Progress</span>
                <span class="font-semibold text-blue-600 dark:text-blue-400">{{ scanProgress }}%</span>
              </div>
              <Progress :model-value="scanProgress" class="h-2" />
            </div>

            <div class="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-3">
              <p class="text-sm font-medium text-blue-900 dark:text-blue-300">{{ currentPhase }}</p>
            </div>

            <div class="space-y-3">
              <div class="flex items-center gap-2 text-sm" :class="scanProgress >= 10 ? 'text-green-600 dark:text-green-400' : 'text-neutral-400 dark:text-slate-500'">
                <CheckCircle2 v-if="scanProgress >= 25" class="h-4 w-4" />
                <Loader2 v-else class="h-4 w-4 animate-spin" />
                <span>Reconnaissance & Information Gathering</span>
              </div>
              <div class="flex items-center gap-2 text-sm" :class="scanProgress >= 40 ? 'text-green-600 dark:text-green-400' : 'text-neutral-400 dark:text-slate-500'">
                <CheckCircle2 v-if="scanProgress >= 60" class="h-4 w-4" />
                <Loader2 v-else class="h-4 w-4" :class="scanProgress >= 10 ? 'animate-spin' : ''" />
                <span>HTTP Security Configuration Check</span>
              </div>
              <div class="flex items-center gap-2 text-sm" :class="scanProgress >= 60 ? 'text-green-600 dark:text-green-400' : 'text-neutral-400 dark:text-slate-500'">
                <CheckCircle2 v-if="scanProgress >= 85" class="h-4 w-4" />
                <Loader2 v-else class="h-4 w-4" :class="scanProgress >= 40 ? 'animate-spin' : ''" />
                <span>Protection & Authentication Testing</span>
              </div>
              <div class="flex items-center gap-2 text-sm" :class="scanProgress >= 85 ? 'text-green-600 dark:text-green-400' : 'text-neutral-400 dark:text-slate-500'">
                <CheckCircle2 v-if="scanProgress >= 100" class="h-4 w-4" />
                <Loader2 v-else class="h-4 w-4" :class="scanProgress >= 60 ? 'animate-spin' : ''" />
                <span>Web Vulnerabilities Detection</span>
              </div>
            </div>

            <Alert class="bg-blue-50 border-blue-200 dark:bg-blue-900/10 dark:border-blue-900/30">
              <AlertDescription class="text-sm text-blue-800 dark:text-blue-400">
                Proses pemindaian dapat memakan waktu beberapa menit. Harap menunggu...
              </AlertDescription>
            </Alert>
            
            <Button
              @click="showCancelDialog = true"
              variant="destructive"
              class="w-full font-semibold shadow-sm"
            >
              <XCircle class="h-4 w-4 mr-2" />
              Batalkan Pemindaian
            </Button>
          </CardContent>
        </Card>

        <Card class="border border-blue-200 dark:border-blue-900/30 bg-blue-50 dark:bg-blue-900/10" v-if="!isScanning">
          <CardContent class="pt-6">
            <div class="flex items-start gap-3">
              <div class="h-10 w-10 rounded-lg bg-blue-200 dark:bg-blue-900/50 flex items-center justify-center shrink-0">
                <Shield class="h-5 w-5 text-blue-700 dark:text-blue-400" />
              </div>
              <div>
                <h3 class="font-semibold text-blue-900 dark:text-blue-300 mb-1">Apa yang akan dipindai?</h3>
                <ul class="text-xs text-blue-700 dark:text-blue-500 space-y-1">
                  <li>Kerentanan keamanan umum (OWASP Top 10)</li>
                  <li>Konfigurasi HTTP Security Headers</li>
                  <li>Proteksi & Autentikasi</li>
                  <li>SQL Injection, XSS, dan kerentanan lainnya</li>
                </ul>
              </div>
            </div>
          </CardContent>
        </Card>

      </div>
    </main>

  </div>

    <!-- Cancel Confirmation Dialog -->
    <Dialog :open="showCancelDialog" @update:open="showCancelDialog = $event">
      <DialogContent class="sm:max-w-md dark:bg-slate-900 dark:border-slate-800">
        <DialogHeader>
          <div class="flex items-center gap-3 mb-2">
            <div class="h-12 w-12 rounded-full bg-red-100 dark:bg-red-900/30 flex items-center justify-center">
              <AlertTriangle class="h-6 w-6 text-red-600 dark:text-red-400" />
            </div>
            <div>
              <DialogTitle class="text-lg font-bold text-neutral-900 dark:text-white">Batalkan Pemindaian?</DialogTitle>
              <DialogDescription class="text-sm text-neutral-500 dark:text-slate-400 mt-1">
                Tindakan ini tidak dapat dibatalkan
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>
        <div class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-900/30 rounded-lg p-4 my-2">
          <p class="text-sm text-red-800 dark:text-red-400">
            Pemindaian yang sedang berjalan akan dihentikan secara paksa.
            Hasil yang sudah terdeteksi <strong>tidak akan disimpan</strong> dan Anda
            harus memulai ulang dari awal.
          </p>
        </div>
        <DialogFooter class="flex gap-3 sm:justify-end mt-4">
          <Button
            variant="outline"
            class="dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
            @click="showCancelDialog = false"
            :disabled="isCancelling"
          >
            Kembali
          </Button>
          <Button
            variant="destructive"
            @click="handleCancelScan"
            :disabled="isCancelling"
            class="font-semibold"
          >
            <Loader2 v-if="isCancelling" class="h-4 w-4 mr-2 animate-spin" />
            <XCircle v-else class="h-4 w-4 mr-2" />
            {{ isCancelling ? 'Membatalkan...' : 'Ya, Batalkan' }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

</template>
