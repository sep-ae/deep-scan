<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { toast } from 'vue-sonner'
import api from '@/services/api'

import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuItem } from '@/components/ui/dropdown-menu'
import { Sheet, SheetContent, SheetTrigger } from '@/components/ui/sheet'
import { Skeleton } from '@/components/ui/skeleton'
import { Separator } from '@/components/ui/separator'


import OverviewTab from '@/components/scan/OverviewTab.vue'
import ReconnaissanceTab from '@/components/scan/ReconnaissanceTab.vue'
import VulnerabilitiesTab from '@/components/scan/VulnerabilitiesTab.vue'
import RecommendationsTab from '@/components/scan/RecommendationsTab.vue'

import { 
  ArrowLeft, CircleUser, Menu, Package2, Home, Scan, History,
  AlertTriangle, AlertCircle, Info, CheckCircle2,
  Clock, ExternalLink, FileText, LogOut, Sun, Moon
} from 'lucide-vue-next'

import { useDarkMode } from '@/composables/useDarkMode'
const { isDark, toggleDark } = useDarkMode()


const router = useRouter()
const route = useRoute()
const username = ref('Pengguna')
const userEmail = ref('user@deepscan.local')

const scanId = route.params.id
const scanDetail = ref(null)
const isLoading = ref(true)
const activeTab = ref('overview')
const isMobileMenuOpen = ref(false)


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

const fetchScanDetail = async () => {
  try {
    isLoading.value = true
    
    const response = await api.get(`/scan/${scanId}`)
    scanDetail.value = response.data

  } catch (error) {
    const msg = error.response?.data?.msg || 'Gagal memuat detail scan'
    
    toast('Error', {
      description: msg
    })

    if (error.response?.status === 404) {
      router.push('/history')
    } else if (error.response?.status === 401) {
      localStorage.removeItem('token')
      localStorage.removeItem('user')
      router.push('/login')
    }
  } finally {
    isLoading.value = false
  }
}

const overallStatus = computed(() => {
  if (!scanDetail.value?.result) return { text: 'Unknown', color: 'neutral', icon: Info }
  
  const total = scanDetail.value.result.total_vulnerabilities
  const high = scanDetail.value.result.high_severity || 0
  
  if (total === 0) {
    return { text: 'Aman', color: 'green', icon: CheckCircle2 }
  } else if (high > 0) {
    return { text: 'Critical', color: 'red', icon: AlertTriangle }
  } else {
    return { text: 'Warning', color: 'yellow', icon: AlertCircle }
  }
})

const goToDashboard = () => { isMobileMenuOpen.value = false; router.push('/dashboard') }
const goToScan = () => { isMobileMenuOpen.value = false; router.push('/scan') }
const goToHistory = () => { isMobileMenuOpen.value = false; router.push('/history') }
const goBack = () => router.push('/history')


const handleLogout = () => {
  localStorage.removeItem('token')
  localStorage.removeItem('user')
  
  toast('Logout Berhasil', {
    description: 'Anda telah keluar dari sistem.'
  })
  
  router.push('/login')
}

const isActive = (path) => route.path === path

onMounted(() => {
  fetchScanDetail()
})
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
            <div class="px-6 py-5 bg-white border-b border-neutral-100 dark:bg-slate-900 dark:border-slate-800">
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
              <p class="text-[11px] font-semibold text-neutral-400 uppercase tracking-widest px-3 mb-3">Menu</p>
              <a @click="goToDashboard" href="#" :class="[isActive('/dashboard') ? 'bg-blue-50 text-blue-700 font-semibold shadow-sm' : 'text-neutral-600 hover:bg-neutral-100', 'flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all duration-200 text-sm']">
                <div :class="[isActive('/dashboard') ? 'bg-blue-100' : 'bg-neutral-100', 'h-8 w-8 rounded-lg flex items-center justify-center transition-colors']">
                  <Home :class="[isActive('/dashboard') ? 'text-blue-600' : 'text-neutral-500', 'h-4 w-4']" />
                </div>
                Dashboard
              </a>
              <a @click="goToScan" href="#" :class="[isActive('/scan') ? 'bg-blue-50 text-blue-700 font-semibold shadow-sm' : 'text-neutral-600 hover:bg-neutral-100', 'flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all duration-200 text-sm']">
                <div :class="[isActive('/scan') ? 'bg-blue-100' : 'bg-neutral-100', 'h-8 w-8 rounded-lg flex items-center justify-center transition-colors']">
                  <Scan :class="[isActive('/scan') ? 'text-blue-600' : 'text-neutral-500', 'h-4 w-4']" />
                </div>
                Scan
              </a>
              <a @click="goToHistory" href="#" :class="[isActive('/history') ? 'bg-blue-50 text-blue-700 font-semibold shadow-sm' : 'text-neutral-600 hover:bg-neutral-100', 'flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all duration-200 text-sm']">
                <div :class="[isActive('/history') ? 'bg-blue-100' : 'bg-neutral-100', 'h-8 w-8 rounded-lg flex items-center justify-center transition-colors']">
                  <History :class="[isActive('/history') ? 'text-blue-600' : 'text-neutral-500', 'h-4 w-4']" />
                </div>
                Riwayat
              </a>
            </nav>
            <div class="px-4 pb-5">
              <Separator class="mb-4" />
              <div class="flex items-center gap-3 p-3 rounded-2xl bg-neutral-50 dark:bg-slate-800/50 border border-neutral-100 dark:border-slate-700 mb-3">
                <div class="h-10 w-10 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center shadow-md">
                  <span class="text-white font-bold text-sm">{{ username.charAt(0).toUpperCase() }}</span>
                </div>
                <div class="flex-1 min-w-0">
                  <p class="font-semibold text-sm text-neutral-900 dark:text-white truncate">{{ username }}</p>
                  <p class="text-xs text-neutral-500 dark:text-slate-400 truncate">{{ userEmail }}</p>
                </div>
              </div>
              <button @click="handleLogout" class="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-red-600 hover:bg-red-50 transition-all duration-200 text-sm font-medium">
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

        <Button 
          variant="ghost" 
          size="sm" 
          @click="goBack"
          class="text-neutral-600 hover:text-neutral-900 dark:text-slate-400 dark:hover:text-white dark:hover:bg-slate-800"
        >
          <ArrowLeft class="h-4 w-4 mr-2" />
          Kembali ke Riwayat
        </Button>

        <div v-if="isLoading" class="space-y-6">
          <Skeleton class="h-32 w-full" />
          <Skeleton class="h-96 w-full" />
        </div>

        <div v-else-if="scanDetail" class="space-y-6">

          <Card class="border-none shadow-lg bg-white dark:bg-slate-900">
            <CardContent class="pt-6">
              
              <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
                <div class="flex-1">
                  <div class="flex items-center gap-2 mb-2">
                    <ExternalLink class="h-5 w-5 text-neutral-500 dark:text-slate-400" />
                    <h1 class="text-2xl font-bold text-neutral-900 dark:text-white break-all">
                      {{ scanDetail.target }}
                    </h1>
                  </div>
                  <div class="flex flex-wrap items-center gap-3 text-sm text-neutral-600 dark:text-slate-400">
                    <div class="flex items-center gap-1">
                      <Clock class="h-4 w-4" />
                      {{ scanDetail.start_time }}
                    </div>
                    <span>•</span>
                    <div>
                      Duration: {{ scanDetail.duration || 'N/A' }}
                    </div>
                  </div>
                </div>

                <div class="flex items-center gap-3">
                  <Badge 
                    variant="secondary" 
                    :class="`bg-${overallStatus.color}-200 text-${overallStatus.color}-800 border-${overallStatus.color}-300 text-lg px-4 py-2`"
                  >
                    <component :is="overallStatus.icon" class="h-5 w-5 mr-2" />
                    {{ overallStatus.text }}
                  </Badge>
                </div>
              </div>

              <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                
                <div class="bg-neutral-50 dark:bg-slate-800/50 rounded-lg p-4 border border-neutral-200 dark:border-slate-700">
                  <div class="text-sm text-neutral-600 dark:text-slate-400 mb-1">Total Kerentanan</div>
                  <div class="text-3xl font-bold text-neutral-900 dark:text-white">
                    {{ scanDetail.result?.total_vulnerabilities || 0 }}
                  </div>
                </div>

                <div class="bg-red-50 dark:bg-red-900/10 rounded-lg p-4 border border-red-200 dark:border-red-900/30">
                  <div class="text-sm text-red-600 dark:text-red-400 mb-1 flex items-center gap-1">
                    <AlertTriangle class="h-4 w-4" />
                    High
                  </div>
                  <div class="text-3xl font-bold text-red-700 dark:text-red-400">
                    {{ scanDetail.result?.high_severity || 0 }}
                  </div>
                </div>

                <div class="bg-yellow-50 dark:bg-yellow-900/10 rounded-lg p-4 border border-yellow-200 dark:border-yellow-900/30">
                  <div class="text-sm text-yellow-600 dark:text-yellow-400 mb-1 flex items-center gap-1">
                    <AlertCircle class="h-4 w-4" />
                    Medium
                  </div>
                  <div class="text-3xl font-bold text-yellow-700 dark:text-yellow-400">
                    {{ scanDetail.result?.medium_severity || 0 }}
                  </div>
                </div>

                <div class="bg-blue-50 dark:bg-blue-900/10 rounded-lg p-4 border border-blue-200 dark:border-blue-900/30">
                  <div class="text-sm text-blue-600 dark:text-blue-400 mb-1 flex items-center gap-1">
                    <Info class="h-4 w-4" />
                    Low
                  </div>
                  <div class="text-3xl font-bold text-blue-700 dark:text-blue-400">
                    {{ scanDetail.result?.low_severity || 0 }}
                  </div>
                </div>

              </div>

            </CardContent>
          </Card>

          <Alert v-if="scanDetail.result?.summary" class="bg-blue-50 border-blue-200 dark:bg-blue-900/10 dark:border-blue-900/30">
            <FileText class="h-4 w-4 text-blue-600 dark:text-blue-400" />
            <AlertTitle class="text-blue-900 dark:text-white">Ringkasan Hasil</AlertTitle>
            <AlertDescription class="text-blue-800 dark:text-blue-300">
              {{ scanDetail.result.summary }}
            </AlertDescription>
          </Alert>

          <Tabs v-model="activeTab" default-value="overview" class="w-full">
            <TabsList class="grid w-full grid-cols-2 md:grid-cols-4">
              <TabsTrigger value="overview" class="text-xs md:text-sm">Overview</TabsTrigger>
              <TabsTrigger value="reconnaissance" class="text-xs md:text-sm">
                Recon ({{ scanDetail.recon_data?.length || 0 }})
              </TabsTrigger>
              <TabsTrigger value="vulnerabilities" class="text-xs md:text-sm">
                Vuln ({{ scanDetail.vulnerabilities?.length || 0 }})
              </TabsTrigger>
              <TabsTrigger value="recommendations" class="text-xs md:text-sm">Rekomendasi</TabsTrigger>
            </TabsList>


            <TabsContent value="overview" class="mt-4">
              <OverviewTab 
                :vulnerabilities="scanDetail.vulnerabilities || []"
                :total-vulnerabilities="scanDetail.result?.total_vulnerabilities || 0"
              />
            </TabsContent>

            <TabsContent value="reconnaissance" class="mt-4">
              <ReconnaissanceTab :recon-data="scanDetail.recon_data || []" />
            </TabsContent>

            <TabsContent value="vulnerabilities" class="mt-4">
              <VulnerabilitiesTab :vulnerabilities="scanDetail.vulnerabilities || []" />
            </TabsContent>

            <TabsContent value="recommendations" class="mt-4">
              <RecommendationsTab :vulnerabilities="scanDetail.vulnerabilities || []" />
            </TabsContent>

          </Tabs>

        </div>

      </div>

    </main>

  </div>
</template>
