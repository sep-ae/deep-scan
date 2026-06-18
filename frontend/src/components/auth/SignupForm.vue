<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { toast } from 'vue-sonner'
import api from '@/services/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'

const router = useRouter()
const username = ref('')
const email = ref('') 
const password = ref('')
const confirmPassword = ref('')
const isLoading = ref(false)
const isGoogleLoading = ref(false)
const googleBtnRef = ref(null)

const handleRegister = async () => {
  if (!username.value || !email.value || !password.value || !confirmPassword.value) {
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
      email: email.value,
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

const handleGoogleCallback = async (response) => {
  try {
    isGoogleLoading.value = true

    const res = await api.post('/auth/google', {
      credential: response.credential
    })

    if (!res.data?.access_token) {
      toast('Login Google Gagal', {
        description: res.data?.msg || 'Login Google gagal.'
      })
      return
    }

    localStorage.setItem('token', res.data.access_token)

    if (res.data.user) {
      localStorage.setItem('user', JSON.stringify(res.data.user))
    }

    toast('Login Google Berhasil', {
      description: 'Akun berhasil dibuat. Anda akan diarahkan ke dashboard.'
    })

    router.push('/dashboard')

  } catch (error) {
    const msg =
      error.response?.data?.msg ||
      'Daftar dengan Google Gagal. Coba lagi nanti.'

    toast('Daftar Google Gagal', { description: msg })
  } finally {
    isGoogleLoading.value = false
  }
}

onMounted(() => {
  const clientId = import.meta.env.VITE_GOOGLE_CLIENT_ID
  if (!clientId) {
    console.error('[Google Login] VITE_GOOGLE_CLIENT_ID belum di-set di .env!')
    return
  }

  const initGoogle = () => {
    if (window.google?.accounts?.id) {
      window.google.accounts.id.initialize({
        client_id: clientId,
        callback: handleGoogleCallback,
        auto_select: false,
        cancel_on_tap_outside: true
      })

      if (googleBtnRef.value) {
        window.google.accounts.id.renderButton(googleBtnRef.value, {
          theme: 'outline',
          size: 'large',
          width: '100%',
          text: 'signup_with',
          shape: 'rectangular',
          logo_alignment: 'left'
        })
      }
    } else {
      setTimeout(initGoogle, 200)
    }
  }

  initGoogle()
})
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
              :disabled="isLoading || isGoogleLoading"
              required
              class="focus-visible:ring-blue-600"
            />
          </div>

          <div class="space-y-2">
            <Label for="email">Email</Label>
            <Input
              id="email"
              type="email"
              placeholder="nama@email.com"
              v-model="email"
              :disabled="isLoading || isGoogleLoading"
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
              :disabled="isLoading || isGoogleLoading"
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
              :disabled="isLoading || isGoogleLoading"
              required
              class="focus-visible:ring-blue-600"
            />
          </div>

          <Button
            type="submit"
            class="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold shadow-md"
            :disabled="isLoading || isGoogleLoading"
          >
            <span v-if="isLoading">Memproses...</span>
            <span v-else>Daftar Sekarang</span>
          </Button>

          <!-- Divider -->
          <div class="relative my-4">
            <div class="absolute inset-0 flex items-center">
              <span class="w-full border-t border-neutral-200"></span>
            </div>
            <div class="relative flex justify-center text-xs uppercase">
              <span class="bg-white px-2 text-neutral-500">atau</span>
            </div>
          </div>

          <!-- Google Sign-Up Button -->
          <div class="flex justify-center">
            <div ref="googleBtnRef" id="google-signup-btn"></div>
          </div>

          <p v-if="isGoogleLoading" class="text-center text-sm text-blue-600">
            Memproses daftar Google...
          </p>

          <div class="text-center text-sm text-neutral-500">
            Sudah punya akun?
            <router-link to="/login" class="font-semibold text-blue-600 hover:underline">
              Masuk di sini
            </router-link>
          </div>

        </form>
      </CardContent>
    </Card>

    <p class="text-neutral-400 text-xs mt-6">© 2026 Deep-Scan, Tugas Akhir</p>
  </div>
</template>