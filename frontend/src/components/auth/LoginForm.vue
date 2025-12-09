<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { toast } from 'vue-sonner'
import api from '@/services/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'

const router = useRouter()
const username = ref('')
const password = ref('')
const isLoading = ref(false)

const handleLogin = async () => {
  if (!username.value || !password.value) {
    toast('Validasi Gagal', {
      description: 'Username dan Password wajib diisi.'
    })
    return
  }

  try {
    isLoading.value = true

    const response = await api.post('/auth/login', {
      username: username.value,
      password: password.value
    })

    if (!response.data?.access_token) {
      toast('Login Gagal', {
        description: response.data?.msg || 'Login gagal.'
      })
      return
    }

    localStorage.setItem('token', response.data.access_token)

    toast('Login Berhasil', {
      description: 'Anda akan diarahkan ke dashboard.'
    })

    router.push('/dashboard')

  } catch (error) {
    const msg =
      error.response?.data?.msg ||
      'Login Gagal. Periksa kembali username dan password.'

    toast('Login Gagal', { description: msg })
  } finally {
    isLoading.value = false
  }
}
</script>

<template>
  <div class="min-h-screen flex flex-col items-center justify-center py-10">

    <div class="flex flex-col items-center mb-8">
      <h1 class="text-3xl font-bold text-neutral-800">Deep-Scan</h1>
      <p class="text-neutral-500 mt-1 text-sm">Keamanan Web Secara Cerdas & Otomatis</p>
    </div>

    <Card class="w-full max-w-md border-none shadow-lg rounded-2xl">
      <CardHeader class="space-y-1 text-center">
        <CardTitle class="text-xl font-bold">Selamat Datang</CardTitle>
        <CardDescription>Masuk untuk mulai mengelola sistem Anda</CardDescription>
      </CardHeader>

      <CardContent>
        <form @submit.prevent="handleLogin" class="space-y-4">
          <div class="space-y-2">
            <Label for="username">Username</Label>
            <Input
              id="username"
              type="text"
              placeholder="admin"
              v-model="username"
              :disabled="isLoading"
              required
              class="focus-visible:ring-blue-600"
            />
          </div>

          <div class="space-y-2">
            <Label for="password">Password</Label>
            <Input
              id="password"
              type="password"
              placeholder="Masukkan password Anda"
              v-model="password"
              :disabled="isLoading"
              required
              class="focus-visible:ring-blue-600"
            />
          </div>

          <Button
            type="submit"
            class="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold shadow-md"
            :disabled="isLoading"
          >
            <span v-if="isLoading">Memproses...</span>
            <span v-else>Masuk ke Dashboard</span>
          </Button>

          <p class="text-center text-sm text-neutral-500">
            Belum punya akun?
            <router-link to="/register" class="font-medium text-blue-600 hover:underline">
              Daftar sekarang
            </router-link>
          </p>
        </form>
      </CardContent>
    </Card>

    <p class="text-neutral-400 text-xs mt-6">© 2025 Deep-Scan, Tugas Akhir</p>
  </div>
</template>
