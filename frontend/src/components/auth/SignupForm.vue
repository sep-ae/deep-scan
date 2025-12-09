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
const confirmPassword = ref('')
const isLoading = ref(false)

const handleRegister = async () => {
  if (!username.value || !password.value || !confirmPassword.value) {
    toast('Validasi Gagal', {
      description: 'Semua kolom wajib diisi.'
    })
    return
  }

  if (password.value !== confirmPassword.value) {
    toast('Validasi Gagal', {
      description: 'Konfirmasi password tidak cocok.'
    })
    return
  }

  try {
    isLoading.value = true

    await api.post('/auth/register', {
      username: username.value,
      password: password.value
    })

    toast('Registrasi Berhasil', {
      description: 'Akun telah dibuat. Silakan login.'
    })

    router.push('/login')

  } catch (error) {
    const msg = error.response?.data?.msg || 'Gagal terhubung ke server.'
    toast('Registrasi Gagal', { description: msg })
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
        <CardTitle class="text-xl font-bold">Buat Akun Baru</CardTitle>
        <CardDescription>Daftar untuk mulai menggunakan Deep-Scan</CardDescription>
      </CardHeader>

      <CardContent>
        <form @submit.prevent="handleRegister" class="space-y-4">

          <div class="space-y-2">
            <Label for="username">Username</Label>
            <Input
              id="username"
              type="text"
              placeholder="username_anda"
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
              placeholder="Minimal 8 karakter"
              v-model="password"
              :disabled="isLoading"
              required
              class="focus-visible:ring-blue-600"
            />
          </div>

          <div class="space-y-2">
            <Label for="confirm-password">Konfirmasi Password</Label>
            <Input
              id="confirm-password"
              type="password"
              placeholder="Ulangi password"
              v-model="confirmPassword"
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
            <span v-else>Daftar Sekarang</span>
          </Button>

          <div class="text-center text-sm text-neutral-500">
            Sudah punya akun?
            <router-link to="/login" class="font-semibold text-blue-600 hover:underline">
              Masuk di sini
            </router-link>
          </div>

        </form>
      </CardContent>
    </Card>

    <p class="text-neutral-400 text-xs mt-6">© 2025 Deep-Scan, Tugas Akhir</p>
  </div>
</template>
