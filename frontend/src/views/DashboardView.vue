<script setup>
import { ref, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { toast } from 'vue-sonner'
import api from '@/services/api'

import { Button } from '@/components/ui/button'
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuItem } from '@/components/ui/dropdown-menu'
import { Sheet, SheetContent, SheetTrigger } from '@/components/ui/sheet'
import { Skeleton } from '@/components/ui/skeleton'
import { Separator } from '@/components/ui/separator'


import { 
  CircleUser, Menu, Package2, 
  Activity, AlertTriangle, Shield,
  Scan, History, ArrowRight, Clock, Home, LogOut
} from 'lucide-vue-next'


const router = useRouter()
const route = useRoute()
const username = ref('Pengguna')

const stats = ref({
  total: 0,
  vulnerable: 0,
  secure: 0
})
const recentScans = ref([])
const isLoading = ref(true)
const error = ref(null)
const isMobileMenuOpen = ref(false)


const fetchDashboardData = async () => {
  try {
    isLoading.value = true
    error.value = null
    
    const token = localStorage.getItem('token')
    if (!token) {
      toast('Session Expired', {
        description: 'Silakan login kembali.'
      })
      router.push('/login')
      return
    }

    const [statsRes, historyRes] = await Promise.all([
      api.get('/scan/stats'),
      api.get('/scan/history')
    ])

    stats.value = statsRes.data
    recentScans.value = historyRes.data.slice(0, 5)

  } catch (err) {
    console.error('Error fetching dashboard data:', err)
    
    const errorMsg = err.response?.data?.msg || 'Gagal memuat data dashboard'
    error.value = errorMsg
    
    toast('Error', {
      description: errorMsg
    })
    
    if (err.response?.status === 401) {
      localStorage.removeItem('token')
      localStorage.removeItem('user')
      toast('Session Expired', {
        description: 'Silakan login kembali.'
      })
      router.push('/login')
    }
  } finally {
    isLoading.value = false
  }
}

onMounted(() => {
  const storedUser = localStorage.getItem('user')
  if (storedUser) {
    try {
      const user = JSON.parse(storedUser)
      username.value = user.username || 'Pengguna'
    } catch (e) {
      console.error('Error parsing user data:', e)
    }
  }
  
  fetchDashboardData()
})

const handleLogout = () => {
  localStorage.removeItem('token')
  localStorage.removeItem('user')
  
  toast('Logout Berhasil', {
    description: 'Anda telah keluar dari sistem.'
  })
  
  router.push('/login')
}

const goToScan = () => { isMobileMenuOpen.value = false; router.push('/scan') }
const goToHistory = () => { isMobileMenuOpen.value = false; router.push('/history') }
const goToDashboard = () => { isMobileMenuOpen.value = false; router.push('/dashboard') }
const goToDetail = (scanId) => router.push(`/history/${scanId}`)


const isActive = (path) => route.path === path

const getStatusBadge = (vulnCount) => {
  if (vulnCount === 0) {
    return { text: 'Aman', class: 'bg-green-200 text-green-800 border-green-300' }
  } else if (vulnCount <= 2) {
    return { text: 'Warning', class: 'bg-yellow-200 text-yellow-800 border-yellow-300' }
  } else {
    return { text: 'Critical', class: 'bg-red-200 text-red-800 border-red-300' }
  }
}

const getStatusIcon = (vulnCount) => {
  return vulnCount === 0 ? Shield : AlertTriangle
}

const getStatusColor = (vulnCount) => {
  if (vulnCount === 0) return 'green'
  else if (vulnCount <= 2) return 'yellow'
  else return 'red'
}
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
        >
          Dashboard
        </a>
        <a 
          @click="goToScan" 
          href="#" 
          :class="isActive('/scan') ? 'text-foreground' : 'text-muted-foreground'"
          class="transition-colors hover:text-foreground"
        >
          Scan
        </a>
        <a 
          @click="goToHistory" 
          href="#" 
          :class="isActive('/history') ? 'text-foreground' : 'text-muted-foreground'"
          class="transition-colors hover:text-foreground"
        >
          Riwayat
        </a>
      </nav>

      <Sheet v-model:open="isMobileMenuOpen">
        <SheetTrigger as-child>
          <Button variant="outline" size="icon" class="shrink-0 md:hidden">
            <Menu class="h-5 w-5" />
          </Button>
        </SheetTrigger>
        <SheetContent side="left" class="p-0 gap-0">
          <div class="flex flex-col h-full">
            <!-- Header with gradient -->
            <div class="px-6 py-5 bg-white border-b border-neutral-100">
              <div class="flex items-center gap-3">
                <div class="h-11 w-11 rounded-2xl bg-blue-50 flex items-center justify-center ring-1 ring-blue-100">
                  <Package2 class="h-5 w-5 text-blue-600" />
                </div>
                <div>
                  <h2 class="text-neutral-900 font-bold text-lg leading-tight">Deep Scan</h2>
                  <p class="text-neutral-500 text-xs">Security Scanner</p>
                </div>
              </div>
            </div>

            <!-- Navigation -->
            <nav class="flex-1 px-4 py-5 space-y-1 overflow-y-auto">
              <p class="text-[11px] font-semibold text-neutral-400 uppercase tracking-widest px-3 mb-3">Menu</p>
              <a
                @click="goToDashboard"
                href="#"
                :class="[
                  isActive('/dashboard')
                    ? 'bg-blue-50 text-blue-700 font-semibold shadow-sm'
                    : 'text-neutral-600 hover:bg-neutral-100',
                  'flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all duration-200 text-sm'
                ]"
              >
                <div :class="[isActive('/dashboard') ? 'bg-blue-100' : 'bg-neutral-100', 'h-8 w-8 rounded-lg flex items-center justify-center transition-colors']">
                  <Home :class="[isActive('/dashboard') ? 'text-blue-600' : 'text-neutral-500', 'h-4 w-4']" />
                </div>
                Dashboard
              </a>
              <a
                @click="goToScan"
                href="#"
                :class="[
                  isActive('/scan')
                    ? 'bg-blue-50 text-blue-700 font-semibold shadow-sm'
                    : 'text-neutral-600 hover:bg-neutral-100',
                  'flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all duration-200 text-sm'
                ]"
              >
                <div :class="[isActive('/scan') ? 'bg-blue-100' : 'bg-neutral-100', 'h-8 w-8 rounded-lg flex items-center justify-center transition-colors']">
                  <Scan :class="[isActive('/scan') ? 'text-blue-600' : 'text-neutral-500', 'h-4 w-4']" />
                </div>
                Scan
              </a>
              <a
                @click="goToHistory"
                href="#"
                :class="[
                  isActive('/history')
                    ? 'bg-blue-50 text-blue-700 font-semibold shadow-sm'
                    : 'text-neutral-600 hover:bg-neutral-100',
                  'flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all duration-200 text-sm'
                ]"
              >
                <div :class="[isActive('/history') ? 'bg-blue-100' : 'bg-neutral-100', 'h-8 w-8 rounded-lg flex items-center justify-center transition-colors']">
                  <History :class="[isActive('/history') ? 'text-blue-600' : 'text-neutral-500', 'h-4 w-4']" />
                </div>
                Riwayat
              </a>
            </nav>

            <!-- Profile & Logout -->
            <div class="px-4 pb-5">
              <Separator class="mb-4" />
              <div class="flex items-center gap-3 p-3 rounded-2xl bg-neutral-50 border border-neutral-100 mb-3">
                <div class="h-10 w-10 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center shadow-md">
                  <span class="text-white font-bold text-sm">{{ username.charAt(0).toUpperCase() }}</span>
                </div>
                <div class="flex-1 min-w-0">
                  <p class="font-semibold text-sm text-neutral-900 truncate">{{ username }}</p>
                  <p class="text-xs text-neutral-500">Deep-Scan User</p>
                </div>
              </div>
              <button
                @click="handleLogout"
                class="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-red-600 hover:bg-red-50 transition-all duration-200 text-sm font-medium"
              >
                <div class="h-8 w-8 rounded-lg bg-red-50 flex items-center justify-center">
                  <LogOut class="h-4 w-4 text-red-500" />
                </div>
                Logout
              </button>
            </div>
          </div>
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
      <div class="max-w-7xl mx-auto space-y-6">

        <div v-if="error" class="bg-red-50 border border-red-200 text-red-800 px-4 py-3 rounded-lg">
          {{ error }}
        </div>

        <div class="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          <Card class="border border-blue-200 bg-blue-50 hover:shadow-md transition-shadow">
            <CardHeader class="pb-3">
              <div class="flex items-center justify-between">
                <CardTitle class="text-sm font-medium text-blue-900">Total Pemindaian</CardTitle>
                <div class="h-8 w-8 rounded-lg bg-blue-200 flex items-center justify-center">
                  <Activity class="h-4 w-4 text-blue-700" />
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <Skeleton v-if="isLoading" class="h-10 w-20 bg-blue-200" />
              <div v-else class="text-3xl font-bold text-blue-900">{{ stats.total }}</div>
              <p class="text-xs text-blue-700 mt-2">Scan yang telah dilakukan</p>
            </CardContent>
          </Card>

          <Card class="border border-red-200 bg-red-50 hover:shadow-md transition-shadow">
            <CardHeader class="pb-3">
              <div class="flex items-center justify-between">
                <CardTitle class="text-sm font-medium text-red-900">Kerentanan Ditemukan</CardTitle>
                <div class="h-8 w-8 rounded-lg bg-red-200 flex items-center justify-center">
                  <AlertTriangle class="h-4 w-4 text-red-700" />
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <Skeleton v-if="isLoading" class="h-10 w-20 bg-red-200" />
              <div v-else class="text-3xl font-bold text-red-900">{{ stats.vulnerable }}</div>
              <p class="text-xs text-red-700 mt-2 flex items-center gap-1">
                <Clock class="h-3 w-3" />
                Perlu ditangani segera
              </p>
            </CardContent>
          </Card>

          <Card class="border border-green-200 bg-green-50 hover:shadow-md transition-shadow">
            <CardHeader class="pb-3">
              <div class="flex items-center justify-between">
                <CardTitle class="text-sm font-medium text-green-900">Website Aman</CardTitle>
                <div class="h-8 w-8 rounded-lg bg-green-200 flex items-center justify-center">
                  <Shield class="h-4 w-4 text-green-700" />
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <Skeleton v-if="isLoading" class="h-10 w-20 bg-green-200" />
              <div v-else class="text-3xl font-bold text-green-900">{{ stats.secure }}</div>
              <p class="text-xs text-green-700 mt-2">Tanpa kerentanan kritikal</p>
            </CardContent>
          </Card>
        </div>

        <div class="space-y-3">
          <h3 class="text-lg font-semibold text-neutral-800">Quick Actions</h3>
          
          <div class="grid gap-4 md:grid-cols-2">
            <Card class="border border-blue-200 hover:border-blue-300 transition-all cursor-pointer hover:shadow-md" @click="goToScan">
              <CardHeader class="pb-3">
                <div class="flex items-start gap-3">
                  <div class="h-12 w-12 rounded-xl bg-blue-200 flex items-center justify-center shrink-0">
                    <Scan class="h-6 w-6 text-blue-700" />
                  </div>
                  <div class="flex-1">
                    <CardTitle class="text-base mb-1 text-neutral-900">Scan Website</CardTitle>
                    <CardDescription class="text-sm">Lakukan pemindaian keamanan website secara otomatis</CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent class="pt-0">
                <Button class="w-full bg-blue-200 text-blue-900 hover:bg-blue-300">
                  Mulai Scan
                  <ArrowRight class="h-4 w-4 ml-2" />
                </Button>
              </CardContent>
            </Card>

            <Card class="border border-purple-200 hover:border-purple-300 transition-all cursor-pointer hover:shadow-md" @click="goToHistory">
              <CardHeader class="pb-3">
                <div class="flex items-start gap-3">
                  <div class="h-12 w-12 rounded-xl bg-purple-200 flex items-center justify-center shrink-0">
                    <History class="h-6 w-6 text-purple-700" />
                  </div>
                  <div class="flex-1">
                    <CardTitle class="text-base mb-1 text-neutral-900">Riwayat Pemindaian</CardTitle>
                    <CardDescription class="text-sm">Lihat riwayat pemindaian yang pernah dilakukan</CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent class="pt-0">
                <Button class="w-full bg-purple-200 text-purple-900 hover:bg-purple-300">
                  Lihat Riwayat
                  <ArrowRight class="h-4 w-4 ml-2" />
                </Button>
              </CardContent>
            </Card>
          </div>
        </div>

        <Card class="border border-neutral-200">
          <CardHeader>
            <div class="flex items-center justify-between">
              <div>
                <CardTitle class="text-base text-neutral-900">Aktivitas Terbaru</CardTitle>
                <CardDescription class="mt-1 text-sm">Pemindaian yang baru saja selesai</CardDescription>
              </div>
              <Button variant="ghost" size="sm" @click="goToHistory" class="text-blue-700 hover:text-blue-800 hover:bg-blue-50">
                Lihat Semua
                <ArrowRight class="h-4 w-4 ml-1" />
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <div v-if="isLoading" class="space-y-3">
              <div v-for="i in 3" :key="i" class="flex items-center gap-3 p-3">
                <Skeleton class="h-9 w-9 rounded-full" />
                <div class="flex-1 space-y-2">
                  <Skeleton class="h-4 w-32" />
                  <Skeleton class="h-3 w-48" />
                </div>
                <Skeleton class="h-6 w-16" />
              </div>
            </div>

            <div v-else-if="recentScans.length === 0" class="text-center py-8 text-neutral-500">
              <Activity class="h-12 w-12 mx-auto mb-3 text-neutral-300" />
              <p class="text-sm">Belum ada riwayat pemindaian</p>
              <Button @click="goToScan" variant="outline" size="sm" class="mt-4">
                Mulai Scan Pertama
              </Button>
            </div>

            <div v-else class="space-y-3">
              <div 
                v-for="scan in recentScans" 
                :key="scan.scan_id"
                @click="goToDetail(scan.scan_id)"
                :class="`flex items-center gap-3 p-3 rounded-lg border cursor-pointer hover:shadow-md transition-shadow bg-${getStatusColor(scan.vuln_count)}-50 border-${getStatusColor(scan.vuln_count)}-200`"
              >
                <div :class="`h-9 w-9 rounded-full flex items-center justify-center shrink-0 bg-${getStatusColor(scan.vuln_count)}-200`">
                  <component :is="getStatusIcon(scan.vuln_count)" :class="`h-4 w-4 text-${getStatusColor(scan.vuln_count)}-700`" />
                </div>
                <div class="flex-1 min-w-0">
                  <p class="font-medium text-sm text-neutral-900 truncate">{{ scan.target }}</p>
                  <p class="text-xs text-neutral-600">{{ scan.date }} - {{ scan.vuln_count }} kerentanan</p>
                </div>
                <Badge variant="secondary" :class="getStatusBadge(scan.vuln_count).class + ' shrink-0'">
                  {{ getStatusBadge(scan.vuln_count).text }}
                </Badge>
              </div>
            </div>
          </CardContent>
        </Card>

      </div>
    </main>

  </div>
</template>
