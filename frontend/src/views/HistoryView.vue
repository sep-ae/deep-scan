<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { toast } from 'vue-sonner'
import api from '@/services/api'

import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuItem } from '@/components/ui/dropdown-menu'
import { Sheet, SheetContent, SheetTrigger } from '@/components/ui/sheet'
import { Skeleton } from '@/components/ui/skeleton'

import { 
  History, Search, Filter, ChevronLeft, ChevronRight,
  CircleUser, Menu, Package2, Home, Scan as ScanIcon,
  Shield, AlertTriangle, Clock, ExternalLink, Download, FileText
} from 'lucide-vue-next'

const router = useRouter()
const route = useRoute()
const username = ref('Pengguna')

// Data state
const allScans = ref([])
const isLoading = ref(true)
const searchQuery = ref('')
const statusFilter = ref('all')
const currentPage = ref(1)
const itemsPerPage = 10
const downloadingId = ref(null)

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

// Fetch all scans
const fetchAllScans = async () => {
  try {
    isLoading.value = true
    
    const response = await api.get('/scan/history')
    allScans.value = response.data

  } catch (error) {
    const msg = error.response?.data?.msg || 'Gagal memuat riwayat scan'
    
    toast('Error', {
      description: msg
    })

    if (error.response?.status === 401) {
      localStorage.removeItem('token')
      localStorage.removeItem('user')
      router.push('/login')
    }
  } finally {
    isLoading.value = false
  }
}

// Download report
const downloadReport = async (scanId) => {
  try {
    downloadingId.value = scanId
    
    toast('Memproses...', {
      description: 'Sedang membuat laporan PDF...'
    })

    const response = await api.get(`/scan/${scanId}/report`, {
      responseType: 'blob'
    })

    // Create blob URL
    const blob = new Blob([response.data], { type: 'application/pdf' })
    const url = window.URL.createObjectURL(blob)
    
    // Create download link
    const link = document.createElement('a')
    link.href = url
    link.download = `DeepScan_Report_${scanId}_${new Date().getTime()}.pdf`
    document.body.appendChild(link)
    link.click()
    
    // Cleanup
    document.body.removeChild(link)
    window.URL.revokeObjectURL(url)

    toast('Download Berhasil', {
      description: 'Laporan PDF telah diunduh.'
    })

  } catch (error) {
    const msg = error.response?.data?.msg || 'Gagal mengunduh laporan'
    
    toast('Download Gagal', {
      description: msg
    })
  } finally {
    downloadingId.value = null
  }
}


// Filtered scans
const filteredScans = computed(() => {
  let result = allScans.value

  // Filter by search query
  if (searchQuery.value) {
    const query = searchQuery.value.toLowerCase()
    result = result.filter(scan => 
      scan.target.toLowerCase().includes(query)
    )
  }

  // Filter by status
  if (statusFilter.value !== 'all') {
    result = result.filter(scan => {
      if (statusFilter.value === 'vulnerable') {
        return scan.vuln_count > 0
      } else if (statusFilter.value === 'secure') {
        return scan.vuln_count === 0
      }
      return true
    })
  }

  return result
})

// Paginated scans
const paginatedScans = computed(() => {
  const start = (currentPage.value - 1) * itemsPerPage
  const end = start + itemsPerPage
  return filteredScans.value.slice(start, end)
})

// Total pages
const totalPages = computed(() => {
  return Math.ceil(filteredScans.value.length / itemsPerPage)
})

// Reset to page 1 when filter changes
const handleFilterChange = () => {
  currentPage.value = 1
}

// Pagination functions
const goToPage = (page) => {
  if (page >= 1 && page <= totalPages.value) {
    currentPage.value = page
  }
}

// Navigation functions
const goToDashboard = () => router.push('/dashboard')
const goToScan = () => router.push('/scan')
const goToHistory = () => router.push('/history')
const goToDetail = (scanId) => router.push(`/history/${scanId}`)

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

// Helper untuk badge status
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

const getScanStatusBadge = (status) => {
  const s = (status || '').toLowerCase()
  if (s === 'completed') {
    return { text: 'Selesai', class: 'bg-green-100 text-green-700 border-green-200' }
  } else if (s === 'cancelled') {
    return { text: 'Dibatalkan', class: 'bg-gray-100 text-gray-700 border-gray-200' }
  } else if (s === 'failed') {
    return { text: 'Gagal', class: 'bg-red-100 text-red-700 border-red-200' }
  } else if (s === 'running') {
    return { text: 'Berjalan', class: 'bg-blue-100 text-blue-700 border-blue-200' }
  }
  return { text: status || 'Pending', class: 'bg-neutral-100 text-neutral-700 border-neutral-200' }
}

onMounted(() => {
  fetchAllScans()
})
</script>

<template>
  <div class="flex min-h-screen w-full flex-col bg-neutral-50/50">

    <!-- NAVBAR - Sama dengan sebelumnya -->
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
              <ScanIcon class="h-5 w-5" />
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

        <!-- Header -->
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-3">
            <div class="h-12 w-12 rounded-xl bg-purple-100 flex items-center justify-center">
              <History class="h-6 w-6 text-purple-600" />
            </div>
            <div>
              <h1 class="text-2xl font-bold text-neutral-900">Riwayat Pemindaian</h1>
              <p class="text-sm text-neutral-600">Lihat semua hasil pemindaian yang pernah dilakukan</p>
            </div>
          </div>
        </div>

        <!-- Filters -->
        <Card class="border-none shadow-lg">
          <CardContent class="pt-6">
            <div class="flex flex-col md:flex-row gap-4">
              
              <!-- Search -->
              <div class="flex-1 relative">
                <Search class="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-neutral-400" />
                <Input
                  v-model="searchQuery"
                  @input="handleFilterChange"
                  type="text"
                  placeholder="Cari berdasarkan URL..."
                  class="pl-9 focus-visible:ring-blue-600"
                />
              </div>

              <!-- Status Filter -->
              <Select v-model="statusFilter" @update:modelValue="handleFilterChange">
                <SelectTrigger class="w-full md:w-48">
                  <Filter class="h-4 w-4 mr-2" />
                  <SelectValue placeholder="Semua Status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Semua Status</SelectItem>
                  <SelectItem value="vulnerable">Rentan</SelectItem>
                  <SelectItem value="secure">Aman</SelectItem>
                </SelectContent>
              </Select>

            </div>

            <!-- Result count -->
            <div class="mt-3 text-sm text-neutral-600">
              Menampilkan {{ paginatedScans.length }} dari {{ filteredScans.length }} hasil
            </div>
          </CardContent>
        </Card>

        <!-- Table -->
        <Card class="border-none shadow-lg">
          <CardContent class="p-0">
            
            <!-- Loading State -->
            <div v-if="isLoading" class="p-6 space-y-3">
              <Skeleton v-for="i in 5" :key="i" class="h-16 w-full" />
            </div>

            <!-- Empty State -->
            <div v-else-if="filteredScans.length === 0" class="text-center py-12">
              <History class="h-16 w-16 mx-auto mb-4 text-neutral-300" />
              <h3 class="font-semibold text-lg text-neutral-900 mb-2">
                {{ searchQuery || statusFilter !== 'all' ? 'Tidak ada hasil' : 'Belum ada riwayat' }}
              </h3>
              <p class="text-sm text-neutral-600 mb-4">
                {{ searchQuery || statusFilter !== 'all' ? 'Coba ubah filter pencarian' : 'Mulai scan pertama Anda' }}
              </p>
              <Button @click="goToScan" class="bg-blue-600 hover:bg-blue-700">
                Mulai Scan Baru
              </Button>
            </div>

            <!-- Table -->
            <Table v-else>
              <TableHeader>
                <TableRow class="bg-neutral-50">
                  <TableHead class="w-12 text-center">#</TableHead>
                  <TableHead>Target URL</TableHead>
                  <TableHead class="text-center">Status Scan</TableHead>
                  <TableHead class="text-center">Kondisi</TableHead>
                  <TableHead class="text-center">Kerentanan</TableHead>
                  <TableHead class="text-center">Tanggal</TableHead>
                  <TableHead class="text-center">Aksi</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                <TableRow 
                  v-for="(scan, index) in paginatedScans" 
                  :key="scan.scan_id"
                  class="hover:bg-neutral-50"
                >
                  <TableCell class="font-medium text-neutral-500 text-center">
                    {{ (currentPage - 1) * itemsPerPage + index + 1 }}
                  </TableCell>
                  <TableCell>
                    <div class="flex items-center gap-2">
                      <ExternalLink class="h-4 w-4 text-neutral-400 shrink-0" />
                      <span class="font-medium text-neutral-900 truncate max-w-md">
                        {{ scan.target }}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell class="text-center">
                    <Badge variant="outline" :class="getScanStatusBadge(scan.status).class">
                      {{ getScanStatusBadge(scan.status).text }}
                    </Badge>
                  </TableCell>
                  <TableCell class="text-center">
                    <Badge v-if="scan.status === 'completed'" variant="secondary" :class="getStatusBadge(scan.vuln_count).class">
                      {{ getStatusBadge(scan.vuln_count).text }}
                    </Badge>
                    <span v-else class="text-neutral-400 text-sm">-</span>
                  </TableCell>
                  <TableCell>
                    <div class="flex items-center justify-center gap-2">
                      <component 
                        :is="getStatusIcon(scan.vuln_count)" 
                        class="h-4 w-4"
                        :class="scan.vuln_count === 0 ? 'text-green-600' : 'text-red-600'"
                      />
                      <span class="font-semibold">{{ scan.vuln_count }}</span>
                      <span class="text-neutral-500 text-sm">kerentanan</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div class="flex items-center justify-center gap-2 text-sm text-neutral-600">
                      <Clock class="h-4 w-4" />
                      {{ scan.date }}
                    </div>
                  </TableCell>
                  <TableCell class="text-center">
                    <div class="flex items-center justify-center gap-2">
                      <Button 
                        variant="ghost" 
                        size="sm"
                        @click="goToDetail(scan.scan_id)"
                        class="text-blue-600 hover:text-blue-700 hover:bg-blue-50"
                      >
                        <FileText class="h-4 w-4 mr-1" />
                        Detail
                      </Button>
                        <Button 
                          variant="ghost" 
                          size="sm"
                          @click="downloadReport(scan.scan_id)"
                          :disabled="downloadingId === scan.scan_id"
                          class="text-green-600 hover:text-green-700 hover:bg-green-50"
                        >
                          <Download class="h-4 w-4 mr-1" />
                          {{ downloadingId === scan.scan_id ? 'Processing...' : 'Laporan' }}
                        </Button>
                    </div>
                  </TableCell>
                </TableRow>
              </TableBody>
            </Table>

          </CardContent>
        </Card>

        <!-- Pagination -->
        <Card v-if="!isLoading && filteredScans.length > itemsPerPage" class="border-none shadow-lg">
          <CardContent class="py-4">
            <div class="flex items-center justify-between">
              
              <div class="text-sm text-neutral-600">
                Halaman {{ currentPage }} dari {{ totalPages }}
              </div>

              <div class="flex items-center gap-2">
                <Button 
                  variant="outline" 
                  size="sm"
                  :disabled="currentPage === 1"
                  @click="goToPage(currentPage - 1)"
                >
                  <ChevronLeft class="h-4 w-4" />
                  Sebelumnya
                </Button>

                <div class="flex gap-1">
                  <Button
                    v-for="page in totalPages"
                    :key="page"
                    variant="outline"
                    size="sm"
                    :class="currentPage === page ? 'bg-blue-600 text-white border-blue-600' : ''"
                    @click="goToPage(page)"
                  >
                    {{ page }}
                  </Button>
                </div>

                <Button 
                  variant="outline" 
                  size="sm"
                  :disabled="currentPage === totalPages"
                  @click="goToPage(currentPage + 1)"
                >
                  Selanjutnya
                  <ChevronRight class="h-4 w-4" />
                </Button>
              </div>

            </div>
          </CardContent>
        </Card>

      </div>

    </main>

  </div>
</template>
