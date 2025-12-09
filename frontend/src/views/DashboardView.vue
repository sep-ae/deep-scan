<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'

import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '@/components/ui/card'
import { DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuItem } from '@/components/ui/dropdown-menu'
import { Sheet, SheetContent, SheetTrigger } from '@/components/ui/sheet'

import { 
  CircleUser, Menu, Package2, Search, 
  Activity, DollarSign, Users
} from 'lucide-vue-next'

const router = useRouter()
const username = ref('Pengguna')

onMounted(() => {
  const stored = localStorage.getItem('username')
  if (stored) username.value = stored
})

const handleLogout = () => {
  localStorage.removeItem('token')
  localStorage.removeItem('username')
  router.push('/login')
}
</script>

<template>
  <div class="flex min-h-screen w-full flex-col bg-neutral-50/50">

    <!-- NAVBAR -->
    <header class="sticky top-0 flex h-16 items-center gap-4 border-b bg-background px-4 md:px-6">
      
      <nav class="hidden flex-col gap-6 text-lg font-medium md:flex md:flex-row md:items-center md:gap-5 md:text-sm lg:gap-6">
        <a href="#" class="flex items-center gap-2 text-lg font-semibold md:text-base">
          <Package2 class="h-6 w-6" />
          <span class="sr-only">Deep Scan</span>
        </a>
        <a href="#" class="text-foreground transition-colors hover:text-foreground">Dashboard</a>
        <a href="#" class="text-muted-foreground transition-colors hover:text-foreground">History</a>
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
            <a href="#" class="hover:text-foreground">Dashboard</a>
            <a href="#" class="hover:text-foreground">History</a>
          </nav>
        </SheetContent>
      </Sheet>

      <div class="flex w-full items-center gap-4 md:ml-auto md:gap-2 lg:gap-4">
        <form class="ml-auto flex-1 sm:flex-initial">
          <div class="relative">
            <Search class="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input type="search" placeholder="Cari target..." class="pl-8 sm:w-[300px]" />
          </div>
        </form>

        <DropdownMenu>
          <DropdownMenuTrigger as-child>
            <Button variant="secondary" size="icon" class="rounded-full">
              <CircleUser class="h-5 w-5" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuLabel>Akun Saya</DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem @click="handleLogout" class="text-red-600 cursor-pointer">Logout</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>

    <!-- MAIN CONTENT -->
    <main class="flex flex-1 flex-col gap-4 p-4 md:gap-8 md:p-8">

      <!-- WELCOME BANNER -->
      <Card class="p-6">
        <h2 class="text-2xl font-bold">Selamat datang, {{ username }}!</h2>
        <p class="text-neutral-600 mt-1">
          Ini adalah dashboard untuk mengelola hasil pemindaian keamanan website Anda.
        </p>
      </Card>

      <!-- FEATURE SHORTCUTS -->
      <div class="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>Scan Website</CardTitle>
            <CardDescription>Lakukan pemindaian keamanan website secara otomatis.</CardDescription>
          </CardHeader>
          <CardContent>
            <Button class="w-full">Mulai Scan</Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Credentials</CardTitle>
            <CardDescription>Kelola kredensial yang digunakan untuk proses scan.</CardDescription>
          </CardHeader>
          <CardContent>
            <Button class="w-full">Kelola Credentials</Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Scan History</CardTitle>
            <CardDescription>Lihat riwayat pemindaian yang pernah dilakukan.</CardDescription>
          </CardHeader>
          <CardContent>
            <Button class="w-full">Lihat History</Button>
          </CardContent>
        </Card>
      </div>

      <!-- STATISTICS -->
      <div class="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader class="flex flex-row justify-between pb-2">
            <CardTitle class="text-sm">Total Scan</CardTitle>
            <Activity class="h-4 w-4" />
          </CardHeader>
          <CardContent>
            <div class="text-2xl font-bold">12</div>
            <p class="text-xs text-muted-foreground">Kali scan berjalan</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader class="flex flex-row justify-between pb-2">
            <CardTitle class="text-sm">Vulnerabilities</CardTitle>
            <DollarSign class="h-4 w-4" />
          </CardHeader>
          <CardContent>
            <div class="text-2xl font-bold text-red-600">3</div>
            <p class="text-xs text-muted-foreground">Bahaya ditemukan</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader class="flex flex-row justify-between pb-2">
            <CardTitle class="text-sm">Secure</CardTitle>
            <Users class="h-4 w-4" />
          </CardHeader>
          <CardContent>
            <div class="text-2xl font-bold text-green-600">9</div>
            <p class="text-xs text-muted-foreground">Website aman</p>
          </CardContent>
        </Card>
      </div>

    </main>
  </div>
</template>
