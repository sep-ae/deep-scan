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
  Scan, History, ArrowRight, Clock, Home, LogOut, Sun, Moon
} from 'lucide-vue-next'

import { useDarkMode } from '@/composables/useDarkMode'
const { isDark, toggleDark } = useDarkMode()


const router = useRouter()
const route = useRoute()
const username = ref('Pengguna')
const userEmail = ref('user@deepscan.local')

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
      userEmail.value = user.email || 'user@deepscan.local'
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
              <a
                @click="goToDashboard"
                href="#"
                :class="[
                  isActive('/dashboard')
                    ? 'bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-400 font-semibold shadow-sm'
                    : 'text-neutral-600 dark:text-slate-400 hover:bg-neutral-100 dark:hover:bg-slate-800',
                  'flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all duration-200 text-sm'
                ]"
              >
                <div :class="[isActive('/dashboard') ? 'bg-blue-100 dark:bg-blue-900/40' : 'bg-neutral-100 dark:bg-slate-800', 'h-8 w-8 rounded-lg flex items-center justify-center transition-colors']">
                  <Home :class="[isActive('/dashboard') ? 'text-blue-600 dark:text-blue-400' : 'text-neutral-500 dark:text-slate-400', 'h-4 w-4']" />
                </div>
                Dashboard
              </a>
              <a
                @click="goToScan"
                href="#"
                :class="[
                  isActive('/scan')
                    ? 'bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-400 font-semibold shadow-sm'
                    : 'text-neutral-600 dark:text-slate-400 hover:bg-neutral-100 dark:hover:bg-slate-800',
                  'flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all duration-200 text-sm'
                ]"
              >
                <div :class="[isActive('/scan') ? 'bg-blue-100 dark:bg-blue-900/40' : 'bg-neutral-100 dark:bg-slate-800', 'h-8 w-8 rounded-lg flex items-center justify-center transition-colors']">
                  <Scan :class="[isActive('/scan') ? 'text-blue-600 dark:text-blue-400' : 'text-neutral-500 dark:text-slate-400', 'h-4 w-4']" />
                </div>
                Scan
              </a>
              <a
                @click="goToHistory"
                href="#"
                :class="[
                  isActive('/history')
                    ? 'bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-400 font-semibold shadow-sm'
                    : 'text-neutral-600 dark:text-slate-400 hover:bg-neutral-100 dark:hover:bg-slate-800',
                  'flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all duration-200 text-sm'
                ]"
              >
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
              <button
                @click="handleLogout"
                class="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 transition-all duration-200 text-sm font-medium"
              >
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
      <div class="max-w-7xl mx-auto space-y-6">

        <div v-if="error" class="bg-red-50 border border-red-200 text-red-800 px-4 py-3 rounded-lg">
          {{ error }}
        </div>

        <div class="grid gap-4 md:grid-cols-3 lg:grid-cols-3">
          <Card class="border border-blue-200 dark:border-slate-700 bg-blue-50 dark:bg-slate-800/50 hover:shadow-md transition-shadow">
            <CardHeader class="pb-3">
              <CardTitle class="text-sm font-semibold text-blue-900 dark:text-white flex justify-between items-center">
                Total Pemindaian
                <div class="p-2 bg-blue-100 dark:bg-blue-900/40 rounded-lg">
                  <Activity class="h-4 w-4 text-blue-600 dark:text-blue-400" />
                </div>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div class="text-3xl font-bold text-blue-700 dark:text-white mb-1">
                <Skeleton v-if="isLoading" class="h-9 w-16" />
                <span v-else>{{ stats.total }}</span>
              </div>
              <p class="text-xs font-medium text-blue-600/80 dark:text-slate-400">Scan yang telah dilakukan</p>
            </CardContent>
          </Card>

          <Card class="border border-red-200 dark:border-slate-700 bg-red-50 dark:bg-slate-800/50 hover:shadow-md transition-shadow">
            <CardHeader class="pb-3">
              <CardTitle class="text-sm font-semibold text-red-900 dark:text-white flex justify-between items-center">
                Kerentanan Ditemukan
                <div class="p-2 bg-red-100 dark:bg-red-900/40 rounded-lg">
                  <AlertTriangle class="h-4 w-4 text-red-600 dark:text-red-400" />
                </div>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div class="text-3xl font-bold text-red-700 dark:text-white mb-1">
                <Skeleton v-if="isLoading" class="h-9 w-16" />
                <span v-else>{{ stats.vulnerable }}</span>
              </div>
              <p class="text-xs font-medium text-red-600/80 dark:text-slate-400">Perlu ditangani segera</p>
            </CardContent>
          </Card>

          <Card class="border border-green-200 dark:border-slate-700 bg-green-50 dark:bg-slate-800/50 hover:shadow-md transition-shadow">
            <CardHeader class="pb-3">
              <CardTitle class="text-sm font-semibold text-green-900 dark:text-white flex justify-between items-center">
                Website Aman
                <div class="p-2 bg-green-100 dark:bg-green-900/40 rounded-lg">
                  <Shield class="h-4 w-4 text-green-600 dark:text-green-400" />
                </div>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div class="text-3xl font-bold text-green-700 dark:text-white mb-1">
                <Skeleton v-if="isLoading" class="h-9 w-16" />
                <span v-else>{{ stats.secure }}</span>
              </div>
              <p class="text-xs font-medium text-green-600/80 dark:text-slate-400">Tanpa kerentanan kritikal</p>
            </CardContent>
          </Card>
        </div>

        <div class="space-y-3">
          <h3 class="text-lg font-semibold text-neutral-800 dark:text-white">Quick Actions</h3>
          
          <div class="grid gap-4 md:grid-cols-2">
            <Card class="border border-neutral-200 dark:border-slate-800 bg-white dark:bg-slate-900 hover:shadow-md transition-shadow">
              <CardContent class="p-6">
                <div class="flex items-start gap-4">
                  <div class="h-12 w-12 rounded-xl bg-blue-100 dark:bg-blue-900/30 flex items-center justify-center shrink-0">
                    <Scan class="h-6 w-6 text-blue-600 dark:text-blue-400" />
                  </div>
                  <div class="space-y-1">
                    <h3 class="font-semibold text-neutral-900 dark:text-white">Scan Website</h3>
                    <p class="text-sm text-neutral-500 dark:text-slate-400 leading-snug">Lakukan pemindaian keamanan website secara otomatis</p>
                  </div>
                </div>
                <Button @click="goToScan" class="w-full mt-6 bg-neutral-900 hover:bg-neutral-800 text-white dark:bg-blue-600 dark:hover:bg-blue-700">
                  Mulai Scan <ArrowRight class="ml-2 h-4 w-4" />
                </Button>
              </CardContent>
            </Card>

            <Card class="border border-neutral-200 dark:border-slate-800 bg-white dark:bg-slate-900 hover:shadow-md transition-shadow">
              <CardContent class="p-6">
                <div class="flex items-start gap-4">
                  <div class="h-12 w-12 rounded-xl bg-purple-100 dark:bg-purple-900/30 flex items-center justify-center shrink-0">
                    <History class="h-6 w-6 text-purple-600 dark:text-purple-400" />
                  </div>
                  <div class="space-y-1">
                    <h3 class="font-semibold text-neutral-900 dark:text-white">Riwayat Pemindaian</h3>
                    <p class="text-sm text-neutral-500 dark:text-slate-400 leading-snug">Lihat riwayat pemindaian yang pernah dilakukan</p>
                  </div>
                </div>
                <Button @click="goToHistory" variant="outline" class="w-full mt-6 border-neutral-200 dark:border-slate-700 dark:text-slate-200 dark:hover:bg-slate-800 hover:bg-neutral-100">
                  Lihat Riwayat <ArrowRight class="ml-2 h-4 w-4" />
                </Button>
              </CardContent>
            </Card>
          </div>
        </div>

        <Card class="border border-neutral-200 dark:border-slate-800 shadow-sm bg-white dark:bg-slate-900">
          <CardHeader class="border-b border-neutral-100 dark:border-slate-800 pb-4">
            <div class="flex items-center justify-between">
              <div>
                <CardTitle class="text-lg font-bold text-neutral-900 dark:text-white">Aktivitas Terbaru</CardTitle>
                <CardDescription class="dark:text-slate-400">Pemindaian yang baru saja selesai</CardDescription>
              </div>
              <Button @click="goToHistory" variant="ghost" size="sm" class="text-blue-600 hover:text-blue-700 hover:bg-blue-50 dark:text-blue-400 dark:hover:text-blue-300 dark:hover:bg-blue-900/20 font-medium">
                Lihat Semua <ArrowRight class="ml-1.5 h-4 w-4" />
              </Button>
            </div>
          </CardHeader>
          <CardContent class="p-0">
            <div v-if="isLoading" class="p-6 space-y-4">
              <Skeleton class="h-16 w-full rounded-xl" v-for="i in 3" :key="i" />
            </div>

            <div v-else-if="recentScans.length === 0" class="flex flex-col items-center justify-center py-12 text-center">
              <div class="h-12 w-12 rounded-full bg-neutral-100 dark:bg-slate-800 flex items-center justify-center mb-4">
                <Activity class="h-6 w-6 text-neutral-400 dark:text-slate-500" />
              </div>
              <h3 class="font-semibold text-neutral-900 dark:text-white mb-1">Belum ada riwayat pemindaian</h3>
              <p class="text-sm text-neutral-500 dark:text-slate-400 mb-4 max-w-[250px]">Lakukan pemindaian pertama Anda untuk melihat hasilnya di sini</p>
              <Button @click="goToScan" variant="outline" size="sm" class="dark:border-slate-700 dark:hover:bg-slate-800 dark:text-slate-200">
                Mulai Scan Pertama
              </Button>
            </div>

            <div v-else class="divide-y divide-neutral-100 dark:divide-slate-800">
              <div 
                v-for="scan in recentScans" 
                :key="scan.id"
                class="flex flex-col sm:flex-row sm:items-center justify-between p-4 sm:p-6 hover:bg-neutral-50/50 dark:hover:bg-slate-800/50 transition-colors group"
              >
                <div class="flex items-start gap-4 mb-4 sm:mb-0">
                  <div :class="[
                    'h-10 w-10 rounded-xl flex items-center justify-center shrink-0 mt-0.5',
                    getStatusConfig(scan.vulnerabilities_count).class
                  ]">
                    <component :is="getStatusIcon(scan.vulnerabilities_count)" class="h-5 w-5" />
                  </div>
                  <div>
                    <h4 class="font-semibold text-neutral-900 dark:text-white text-base mb-1 group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">{{ scan.target_url }}</h4>
                    <div class="flex items-center gap-3 text-xs text-neutral-500 dark:text-slate-400">
                      <span class="flex items-center gap-1.5">
                        <Clock class="h-3.5 w-3.5" />
                        {{ formatDate(scan.created_at) }}
                      </span>
                      <span class="w-1 h-1 rounded-full bg-neutral-300 dark:bg-slate-600"></span>
                      <span class="font-medium text-neutral-700 dark:text-slate-300">
                        {{ scan.vulnerabilities_count }} Kerentanan
                      </span>
                    </div>
                  </div>
                </div>
                
                <Button 
                  @click="goToDetail(scan.id)"
                  variant="secondary" 
                  size="sm" 
                  class="w-full sm:w-auto bg-white dark:bg-slate-800 border border-neutral-200 dark:border-slate-700 shadow-sm hover:bg-neutral-50 dark:hover:bg-slate-700 dark:text-white"
                >
                  Detail
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

      </div>
    </main>

  </div>
</template>
