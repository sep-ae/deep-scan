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

import {
  Scan, Loader2, CheckCircle2, Globe, Shield,
  CircleUser, Menu, Package2, Home, History
} from 'lucide-vue-next'

const router = useRouter()
const route = useRoute()
const username = ref('Pengguna')

const targetUrl = ref('')
const isScanning = ref(false)
const scanProgress = ref(0)
const currentScanId = ref(null)
const currentPhase = ref('')

let pollTimer = null
let pollInterval = 8000
const MIN_INTERVAL = 8000
const MAX_INTERVAL = 15000

const storedUser = localStorage.getItem('user')
if (storedUser) {
  try {
    const user = JSON.parse(storedUser)
    username.value = user.username || 'Pengguna'
  } catch (e) {
    console.error('Error parsing user data:', e)
  }
}

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

    const response = await api.post('/scan/start', { target_url: targetUrl.value })
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
      toast('Scan Selesai', { description: 'Pemindaian berhasil diselesaikan!' })
      setTimeout(() => router.push(`/history/${currentScanId.value}`), 1500)
      return
    }

    if (data.status === 'failed') {
      stopPolling()
      toast('Scan Gagal', { description: data.error_message || 'Terjadi kesalahan saat scanning' })
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
  isScanning.value = false
}

const goToDashboard = () => router.push('/dashboard')
const goToScan = () => router.push('/scan')
const goToHistory = () => router.push('/history')

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
  <div class="flex min-h-screen w-full flex-col bg-neutral-50/50">

    <header class="sticky top-0 z-50 flex h-16 items-center gap-4 border-b bg-background px-4 md:px-6">

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

      <Sheet>
        <SheetTrigger as-child>
          <Button variant="outline" size="icon" class="shrink-0 md:hidden">
            <Menu class="h-5 w-5" />
          </Button>
        </SheetTrigger>
        <SheetContent side="left">
          <nav class="grid gap-6 text-lg font-medium">
            <a href="#" class="flex items-center gap-2 text-lg font-semibold">
              <Package2 class="h-6 w-6" />
              <span>Deep Scan</span>
            </a>
            <a @click="goToDashboard" href="#" class="hover:text-foreground flex items-center gap-2">
              <Home class="h-5 w-5" />
              Dashboard
            </a>
            <a @click="goToScan" href="#" class="hover:text-foreground flex items-center gap-2">
              <Scan class="h-5 w-5" />
              Scan
            </a>
            <a @click="goToHistory" href="#" class="hover:text-foreground flex items-center gap-2">
              <History class="h-5 w-5" />
              Riwayat
            </a>
          </nav>
        </SheetContent>
      </Sheet>

      <div class="flex w-full items-center gap-4 md:ml-auto md:gap-2 lg:gap-4">
        <div class="ml-auto"></div>
        <DropdownMenu>
          <DropdownMenuTrigger as-child>
            <Button variant="secondary" size="icon" class="rounded-full">
              <CircleUser class="h-5 w-5" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" class="w-56">
            <DropdownMenuLabel>
              <div class="flex flex-col space-y-1">
                <p class="text-sm font-medium">{{ username }}</p>
                <p class="text-xs text-muted-foreground">Deep-Scan User</p>
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
          <div class="h-12 w-12 rounded-xl bg-blue-100 flex items-center justify-center">
            <Scan class="h-6 w-6 text-blue-600" />
          </div>
          <div>
            <h1 class="text-2xl font-bold text-neutral-900">Website Scanner</h1>
            <p class="text-sm text-neutral-600">Deteksi kerentanan keamanan secara otomatis</p>
          </div>
        </div>
      </div>

      <div class="max-w-2xl mx-auto space-y-6">

        <Card class="border-none shadow-lg" v-if="!isScanning">
          <CardHeader>
            <CardTitle class="text-lg">Mulai Pemindaian Baru</CardTitle>
            <CardDescription>Masukkan URL website yang ingin dipindai</CardDescription>
          </CardHeader>
          <CardContent class="space-y-4">
            <div class="space-y-2">
              <Label for="url" class="flex items-center gap-2">
                <Globe class="h-4 w-4" />
                Target URL
              </Label>
              <Input
                id="url"
                v-model="targetUrl"
                type="text"
                placeholder="https://example.com"
                :disabled="isScanning"
                class="focus-visible:ring-blue-600"
                @keyup.enter="handleStartScan"
              />
              <p class="text-xs text-neutral-500">Contoh: https://example.com atau example.com</p>
            </div>
            <Button
              @click="handleStartScan"
              :disabled="!targetUrl.trim() || isScanning"
              class="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold shadow-md"
            >
              <Scan class="h-4 w-4 mr-2" />
              Mulai Pemindaian
            </Button>
          </CardContent>
        </Card>

        <Card class="border-none shadow-lg" v-if="isScanning">
          <CardHeader>
            <CardTitle class="text-lg flex items-center gap-2">
              <Loader2 class="h-5 w-5 animate-spin text-blue-600" />
              Pemindaian Sedang Berjalan...
            </CardTitle>
            <CardDescription class="mt-1">{{ targetUrl }}</CardDescription>
          </CardHeader>
          <CardContent class="space-y-6">
            <div class="space-y-2">
              <div class="flex items-center justify-between text-sm">
                <span class="text-neutral-600">Progress</span>
                <span class="font-semibold text-blue-600">{{ scanProgress }}%</span>
              </div>
              <Progress :model-value="scanProgress" class="h-2" />
            </div>

            <div class="bg-blue-50 border border-blue-200 rounded-lg p-3">
              <p class="text-sm font-medium text-blue-900">{{ currentPhase }}</p>
            </div>

            <div class="space-y-3">
              <div class="flex items-center gap-2 text-sm" :class="scanProgress >= 10 ? 'text-green-600' : 'text-neutral-400'">
                <CheckCircle2 v-if="scanProgress >= 25" class="h-4 w-4" />
                <Loader2 v-else class="h-4 w-4 animate-spin" />
                <span>Reconnaissance & Information Gathering</span>
              </div>
              <div class="flex items-center gap-2 text-sm" :class="scanProgress >= 40 ? 'text-green-600' : 'text-neutral-400'">
                <CheckCircle2 v-if="scanProgress >= 60" class="h-4 w-4" />
                <Loader2 v-else class="h-4 w-4" :class="scanProgress >= 10 ? 'animate-spin' : ''" />
                <span>HTTP Security Configuration Check</span>
              </div>
              <div class="flex items-center gap-2 text-sm" :class="scanProgress >= 60 ? 'text-green-600' : 'text-neutral-400'">
                <CheckCircle2 v-if="scanProgress >= 85" class="h-4 w-4" />
                <Loader2 v-else class="h-4 w-4" :class="scanProgress >= 40 ? 'animate-spin' : ''" />
                <span>Protection & Authentication Testing</span>
              </div>
              <div class="flex items-center gap-2 text-sm" :class="scanProgress >= 85 ? 'text-green-600' : 'text-neutral-400'">
                <CheckCircle2 v-if="scanProgress >= 100" class="h-4 w-4" />
                <Loader2 v-else class="h-4 w-4" :class="scanProgress >= 60 ? 'animate-spin' : ''" />
                <span>Web Vulnerabilities Detection</span>
              </div>
            </div>

            <Alert class="bg-blue-50 border-blue-200">
              <AlertDescription class="text-sm text-blue-800">
                Proses pemindaian dapat memakan waktu beberapa menit. Harap menunggu...
              </AlertDescription>
            </Alert>
          </CardContent>
        </Card>

        <Card class="border border-blue-200 bg-blue-50" v-if="!isScanning">
          <CardContent class="pt-6">
            <div class="flex items-start gap-3">
              <div class="h-10 w-10 rounded-lg bg-blue-200 flex items-center justify-center shrink-0">
                <Shield class="h-5 w-5 text-blue-700" />
              </div>
              <div>
                <h3 class="font-semibold text-blue-900 mb-1">Apa yang akan dipindai?</h3>
                <ul class="text-xs text-blue-700 space-y-1">
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
</template>
