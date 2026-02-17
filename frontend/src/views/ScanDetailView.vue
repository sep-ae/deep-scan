<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { toast } from 'vue-sonner'
import api from '@/services/api'

import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuItem } from '@/components/ui/dropdown-menu'
import { Sheet, SheetContent, SheetTrigger } from '@/components/ui/sheet'
import { Skeleton } from '@/components/ui/skeleton'
import { Separator } from '@/components/ui/separator'

import { 
  ArrowLeft, CircleUser, Menu, Package2, Home, Scan, History,
  Shield, AlertTriangle, AlertCircle, Info, CheckCircle2,
  Clock, ExternalLink, FileText, TrendingUp, Search, 
  Server, Globe, Lock, Code
} from 'lucide-vue-next'

const router = useRouter()
const route = useRoute()
const scanId = route.params.id
const username = ref('Pengguna')

// Data state
const scanDetail = ref(null)
const isLoading = ref(true)
const activeTab = ref('overview')

// Get username dari localStorage
const storedUser = localStorage.getItem('user')
if (storedUser) {
  try {
    const user = JSON.parse(storedUser)
    username.value = user.username || 'Pengguna'
  } catch (e) {
    console.error('Error parsing user data:', e)
  }
}

// Fetch scan detail
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

// Computed - Vulnerabilities by severity
const vulnerabilitiesBySeverity = computed(() => {
  if (!scanDetail.value?.vulnerabilities) return { high: [], medium: [], low: [] }
  
  return {
    high: scanDetail.value.vulnerabilities.filter(v => v.severity === 'high'),
    medium: scanDetail.value.vulnerabilities.filter(v => v.severity === 'medium'),
    low: scanDetail.value.vulnerabilities.filter(v => v.severity === 'low')
  }
})

// Computed - Recon data by category
const reconDataByCategory = computed(() => {
  if (!scanDetail.value?.recon_data) return {}
  
  const grouped = {}
  scanDetail.value.recon_data.forEach(recon => {
    if (!grouped[recon.category]) {
      grouped[recon.category] = []
    }
    grouped[recon.category].push(recon)
  })
  
  return grouped
})

// Computed - Overall status
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

// Navigation functions
const goToDashboard = () => router.push('/dashboard')
const goToScan = () => router.push('/scan')
const goToHistory = () => router.push('/history')
const goBack = () => router.push('/history')

const handleLogout = () => {
  localStorage.removeItem('token')
  localStorage.removeItem('user')
  
  toast('Logout Berhasil', {
    description: 'Anda telah keluar dari sistem.'
  })
  
  router.push('/login')
}

// Check active menu
const isActive = (path) => route.path === path

// Helper - Severity badge
const getSeverityBadge = (severity) => {
  const badges = {
    high: { text: 'High', class: 'bg-red-200 text-red-800 border-red-300' },
    medium: { text: 'Medium', class: 'bg-yellow-200 text-yellow-800 border-yellow-300' },
    low: { text: 'Low', class: 'bg-blue-200 text-blue-800 border-blue-300' }
  }
  return badges[severity] || badges.low
}

// Helper - Severity icon
const getSeverityIcon = (severity) => {
  const icons = {
    high: AlertTriangle,
    medium: AlertCircle,
    low: Info
  }
  return icons[severity] || Info
}

// Helper - Category icon
const getCategoryIcon = (category) => {
  const icons = {
    'DNS': Globe,
    'Subdomain': Server,
    'Port': Lock,
    'Technology': Code,
    'Headers': Shield,
    'SSL': Lock
  }
  return icons[category] || Search
}

onMounted(() => {
  fetchScanDetail()
})
</script>

<template>
  <div class="flex min-h-screen w-full flex-col bg-neutral-50/50">

    <!-- NAVBAR (sama seperti sebelumnya) -->
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

      <!-- Mobile Menu -->
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

    <!-- MAIN CONTENT -->
    <main class="flex-1 py-8 px-4 md:px-8">
      
      <div class="max-w-6xl mx-auto space-y-6">

        <!-- Back Button -->
        <Button 
          variant="ghost" 
          size="sm" 
          @click="goBack"
          class="text-neutral-600 hover:text-neutral-900"
        >
          <ArrowLeft class="h-4 w-4 mr-2" />
          Kembali ke Riwayat
        </Button>

        <!-- Loading State -->
        <div v-if="isLoading" class="space-y-6">
          <Skeleton class="h-32 w-full" />
          <Skeleton class="h-96 w-full" />
        </div>

        <!-- Content -->
        <div v-else-if="scanDetail" class="space-y-6">

          <!-- Header Card -->
          <Card class="border-none shadow-lg">
            <CardContent class="pt-6">
              
              <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
                <div class="flex-1">
                  <div class="flex items-center gap-2 mb-2">
                    <ExternalLink class="h-5 w-5 text-neutral-500" />
                    <h1 class="text-2xl font-bold text-neutral-900 break-all">
                      {{ scanDetail.target }}
                    </h1>
                  </div>
                  <div class="flex flex-wrap items-center gap-3 text-sm text-neutral-600">
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

              <!-- Stats Grid -->
              <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                
                <div class="bg-neutral-50 rounded-lg p-4 border border-neutral-200">
                  <div class="text-sm text-neutral-600 mb-1">Total Kerentanan</div>
                  <div class="text-3xl font-bold text-neutral-900">
                    {{ scanDetail.result?.total_vulnerabilities || 0 }}
                  </div>
                </div>

                <div class="bg-red-50 rounded-lg p-4 border border-red-200">
                  <div class="text-sm text-red-600 mb-1 flex items-center gap-1">
                    <AlertTriangle class="h-4 w-4" />
                    High
                  </div>
                  <div class="text-3xl font-bold text-red-700">
                    {{ scanDetail.result?.high_severity || 0 }}
                  </div>
                </div>

                <div class="bg-yellow-50 rounded-lg p-4 border border-yellow-200">
                  <div class="text-sm text-yellow-600 mb-1 flex items-center gap-1">
                    <AlertCircle class="h-4 w-4" />
                    Medium
                  </div>
                  <div class="text-3xl font-bold text-yellow-700">
                    {{ scanDetail.result?.medium_severity || 0 }}
                  </div>
                </div>

                <div class="bg-blue-50 rounded-lg p-4 border border-blue-200">
                  <div class="text-sm text-blue-600 mb-1 flex items-center gap-1">
                    <Info class="h-4 w-4" />
                    Low
                  </div>
                  <div class="text-3xl font-bold text-blue-700">
                    {{ scanDetail.result?.low_severity || 0 }}
                  </div>
                </div>

              </div>

            </CardContent>
          </Card>

          <!-- Summary Alert -->
          <Alert v-if="scanDetail.result?.summary" class="bg-blue-50 border-blue-200">
            <FileText class="h-4 w-4 text-blue-600" />
            <AlertTitle class="text-blue-900">Ringkasan Hasil</AlertTitle>
            <AlertDescription class="text-blue-800">
              {{ scanDetail.result.summary }}
            </AlertDescription>
          </Alert>

          <!-- Tabs -->
          <Tabs v-model="activeTab" default-value="overview" class="w-full">
            <TabsList class="grid w-full grid-cols-4">
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="reconnaissance">
                Reconnaissance ({{ scanDetail.recon_data?.length || 0 }})
              </TabsTrigger>
              <TabsTrigger value="vulnerabilities">
                Vulnerabilities ({{ scanDetail.vulnerabilities?.length || 0 }})
              </TabsTrigger>
              <TabsTrigger value="recommendations">Rekomendasi</TabsTrigger>
            </TabsList>

            <!-- Overview Tab -->
            <TabsContent value="overview" class="space-y-4">
              
              <Card class="border-none shadow-lg">
                <CardHeader>
                  <CardTitle class="flex items-center gap-2">
                    <TrendingUp class="h-5 w-5" />
                    Breakdown by Severity
                  </CardTitle>
                </CardHeader>
                <CardContent class="space-y-4">
                  
                  <!-- High Severity -->
                  <div class="space-y-2">
                    <div class="flex items-center justify-between">
                      <div class="flex items-center gap-2 text-sm font-medium text-red-700">
                        <AlertTriangle class="h-4 w-4" />
                        High Severity
                      </div>
                      <span class="text-sm font-bold text-red-700">
                        {{ vulnerabilitiesBySeverity.high.length }}
                      </span>
                    </div>
                    <div class="h-2 bg-neutral-100 rounded-full overflow-hidden">
                      <div 
                        class="h-full bg-red-500"
                        :style="`width: ${(vulnerabilitiesBySeverity.high.length / (scanDetail.result?.total_vulnerabilities || 1)) * 100}%`"
                      ></div>
                    </div>
                  </div>

                  <!-- Medium Severity -->
                  <div class="space-y-2">
                    <div class="flex items-center justify-between">
                      <div class="flex items-center gap-2 text-sm font-medium text-yellow-700">
                        <AlertCircle class="h-4 w-4" />
                        Medium Severity
                      </div>
                      <span class="text-sm font-bold text-yellow-700">
                        {{ vulnerabilitiesBySeverity.medium.length }}
                      </span>
                    </div>
                    <div class="h-2 bg-neutral-100 rounded-full overflow-hidden">
                      <div 
                        class="h-full bg-yellow-500"
                        :style="`width: ${(vulnerabilitiesBySeverity.medium.length / (scanDetail.result?.total_vulnerabilities || 1)) * 100}%`"
                      ></div>
                    </div>
                  </div>

                  <!-- Low Severity -->
                  <div class="space-y-2">
                    <div class="flex items-center justify-between">
                      <div class="flex items-center gap-2 text-sm font-medium text-blue-700">
                        <Info class="h-4 w-4" />
                        Low Severity
                      </div>
                      <span class="text-sm font-bold text-blue-700">
                        {{ vulnerabilitiesBySeverity.low.length }}
                      </span>
                    </div>
                    <div class="h-2 bg-neutral-100 rounded-full overflow-hidden">
                      <div 
                        class="h-full bg-blue-500"
                        :style="`width: ${(vulnerabilitiesBySeverity.low.length / (scanDetail.result?.total_vulnerabilities || 1)) * 100}%`"
                      ></div>
                    </div>
                  </div>

                </CardContent>
              </Card>

            </TabsContent>

            <!-- Reconnaissance Tab (BARU!) -->
            <TabsContent value="reconnaissance" class="space-y-4">
              
              <Card v-if="!scanDetail.recon_data || scanDetail.recon_data.length === 0" class="border-none shadow-lg">
                <CardContent class="py-12 text-center">
                  <Search class="h-16 w-16 mx-auto mb-4 text-neutral-300" />
                  <h3 class="font-semibold text-lg text-neutral-900 mb-2">
                    Tidak Ada Data Reconnaissance
                  </h3>
                  <p class="text-sm text-neutral-600">
                    Belum ada informasi yang dikumpulkan saat fase reconnaissance.
                  </p>
                </CardContent>
              </Card>

              <div v-else class="space-y-4">
                <Card 
                  v-for="(items, category) in reconDataByCategory" 
                  :key="category"
                  class="border-none shadow-lg"
                >
                  <CardHeader>
                    <CardTitle class="flex items-center gap-2 text-lg">
                      <component :is="getCategoryIcon(category)" class="h-5 w-5 text-blue-600" />
                      {{ category }}
                    </CardTitle>
                    <CardDescription>{{ items.length }} item(s) ditemukan</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Item</TableHead>
                          <TableHead>Details</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        <TableRow v-for="item in items" :key="item.recon_id">
                          <TableCell class="font-medium">{{ item.item }}</TableCell>
                          <TableCell class="text-sm text-neutral-600">{{ item.details }}</TableCell>
                        </TableRow>
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>
              </div>

            </TabsContent>

            <!-- Vulnerabilities Tab -->
            <TabsContent value="vulnerabilities" class="space-y-4">
              
              <!-- Empty State -->
              <Card v-if="!scanDetail.vulnerabilities || scanDetail.vulnerabilities.length === 0" class="border-none shadow-lg">
                <CardContent class="py-12 text-center">
                  <CheckCircle2 class="h-16 w-16 mx-auto mb-4 text-green-500" />
                  <h3 class="font-semibold text-lg text-neutral-900 mb-2">
                    Tidak Ada Kerentanan Ditemukan
                  </h3>
                  <p class="text-sm text-neutral-600">
                    Website Anda aman dari kerentanan yang umum ditemukan.
                  </p>
                </CardContent>
              </Card>

              <!-- Vulnerabilities List -->
              <Accordion v-else type="single" collapsible class="space-y-3">
                <AccordionItem 
                  v-for="(vuln, index) in scanDetail.vulnerabilities" 
                  :key="vuln.vuln_id"
                  :value="`vuln-${index}`"
                  class="border-none"
                >
                  <Card class="border-none shadow-lg">
                    <AccordionTrigger class="px-6 py-4 hover:no-underline">
                      <div class="flex items-start gap-3 w-full">
                        <component 
                          :is="getSeverityIcon(vuln.severity)" 
                          class="h-5 w-5 mt-0.5 shrink-0"
                          :class="{
                            'text-red-600': vuln.severity === 'high',
                            'text-yellow-600': vuln.severity === 'medium',
                            'text-blue-600': vuln.severity === 'low'
                          }"
                        />
                        <div class="flex-1 text-left">
                          <div class="flex items-center gap-2 mb-1">
                            <h3 class="font-semibold text-neutral-900">{{ vuln.name }}</h3>
                            <Badge variant="secondary" :class="getSeverityBadge(vuln.severity).class">
                              {{ getSeverityBadge(vuln.severity).text }}
                            </Badge>
                          </div>
                          <p class="text-sm text-neutral-600">{{ vuln.affected_url }}</p>
                        </div>
                      </div>
                    </AccordionTrigger>
                    <AccordionContent class="px-6 pb-4">
                      <Separator class="mb-4" />
                      
                      <div class="space-y-4">
                        
                        <!-- Description -->
                        <div>
                          <h4 class="font-semibold text-sm text-neutral-900 mb-2">Deskripsi</h4>
                          <p class="text-sm text-neutral-700">{{ vuln.description }}</p>
                        </div>

                        <!-- Recommendation -->
                        <div v-if="vuln.recommendation">
                          <h4 class="font-semibold text-sm text-neutral-900 mb-2">Rekomendasi Perbaikan</h4>
                          <p class="text-sm text-neutral-700">{{ vuln.recommendation }}</p>
                        </div>

                        <!-- Technical Info -->
                        <div class="flex flex-wrap gap-4 text-sm">
                          <div v-if="vuln.cwe_id">
                            <span class="text-neutral-600">CWE ID:</span>
                            <span class="font-medium text-neutral-900 ml-1">{{ vuln.cwe_id }}</span>
                          </div>
                          <div v-if="vuln.owasp_category">
                            <span class="text-neutral-600">OWASP:</span>
                            <span class="font-medium text-neutral-900 ml-1">{{ vuln.owasp_category }}</span>
                          </div>
                        </div>

                      </div>
                    </AccordionContent>
                  </Card>
                </AccordionItem>
              </Accordion>

            </TabsContent>

            <!-- Recommendations Tab -->
            <TabsContent value="recommendations" class="space-y-4">
              
              <Card class="border-none shadow-lg">
                <CardHeader>
                  <CardTitle>Langkah-langkah Perbaikan</CardTitle>
                  <CardDescription>
                    Ikuti rekomendasi berikut untuk meningkatkan keamanan website Anda
                  </CardDescription>
                </CardHeader>
                <CardContent class="space-y-4">
                  
                  <div v-if="vulnerabilitiesBySeverity.high.length > 0">
                    <Alert class="bg-red-50 border-red-200 mb-4">
                      <AlertTriangle class="h-4 w-4 text-red-600" />
                      <AlertTitle class="text-red-900">Prioritas Tinggi</AlertTitle>
                      <AlertDescription class="text-red-800">
                        Perbaiki {{ vulnerabilitiesBySeverity.high.length }} kerentanan kritis segera untuk mencegah serangan berbahaya.
                      </AlertDescription>
                    </Alert>
                  </div>

                  <div class="space-y-3">
                    <div 
                      v-for="(vuln, index) in scanDetail.vulnerabilities" 
                      :key="index"
                      class="flex items-start gap-3 p-4 rounded-lg bg-neutral-50 border border-neutral-200"
                    >
                      <div class="h-6 w-6 rounded-full bg-blue-100 flex items-center justify-center shrink-0 text-sm font-medium text-blue-700">
                        {{ index + 1 }}
                      </div>
                      <div class="flex-1">
                        <h4 class="font-semibold text-neutral-900 mb-1">{{ vuln.name }}</h4>
                        <p class="text-sm text-neutral-700">{{ vuln.recommendation || 'Lihat dokumentasi untuk informasi lebih lanjut.' }}</p>
                      </div>
                    </div>
                  </div>

                </CardContent>
              </Card>

            </TabsContent>

          </Tabs>

        </div>

      </div>

    </main>

  </div>
</template>
