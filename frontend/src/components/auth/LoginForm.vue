<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { toast } from 'vue-sonner'
import api from '@/services/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useDarkMode } from '@/composables/useDarkMode'
import { Sun, Moon, Shield } from 'lucide-vue-next'

const { isDark, toggleDark } = useDarkMode()
const router = useRouter()
const identifier = ref('') 
const password = ref('')
const isLoading = ref(false)
const isGoogleLoading = ref(false)
const googleBtnRef = ref(null)

const handleLogin = async () => {
  if (!identifier.value || !password.value) {
    toast('Validasi Gagal', {
      description: 'Username/Email dan Password wajib diisi.'
    })
    return
  }

  try {
    isLoading.value = true

    const response = await api.post('/auth/login', {
      identifier: identifier.value,
      password: password.value
    })

    if (!response.data?.access_token) {
      toast('Login Gagal', {
        description: response.data?.msg || 'Login gagal.'
      })
      return
    }

    localStorage.setItem('token', response.data.access_token)
    
    if (response.data.user) {
      localStorage.setItem('user', JSON.stringify(response.data.user))
    }

    toast('Login Berhasil', {
      description: 'Anda akan diarahkan ke dashboard.'
    })

    router.push('/dashboard')

  } catch (error) {
    const msg =
      error.response?.data?.msg ||
      'Login Gagal. Periksa kembali username/email dan password.'

    toast('Login Gagal', { description: msg })
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
      description: 'Anda akan diarahkan ke dashboard.'
    })

    router.push('/dashboard')

  } catch (error) {
    const msg =
      error.response?.data?.msg ||
      'Login Google Gagal. Coba lagi nanti.'

    toast('Login Google Gagal', { description: msg })
  } finally {
    isGoogleLoading.value = false
  }
}

const renderGoogleBtn = () => {
  if (googleBtnRef.value && window.google?.accounts?.id) {
    window.google.accounts.id.renderButton(googleBtnRef.value, {
      theme: isDark.value ? 'filled_black' : 'outline',
      size: 'large',
      width: '100%',
      text: 'signin_with',
      shape: 'rectangular',
      logo_alignment: 'left'
    })
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
      renderGoogleBtn()
    } else {
      setTimeout(initGoogle, 200)
    }
  }

  initGoogle()
})
</script>

<template>
  <div class="min-h-screen flex items-center justify-center px-4 py-8 bg-gradient-to-br from-slate-50 via-white to-blue-50 dark:from-slate-950 dark:via-slate-900 dark:to-slate-950 transition-colors duration-300">

    <!-- Dark mode toggle -->
    <button
      @click="toggleDark"
      class="fixed top-4 right-4 z-50 p-2 rounded-full bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm border border-slate-200 dark:border-slate-700 shadow-sm hover:shadow-md transition-all duration-200"
      :title="isDark ? 'Switch to light mode' : 'Switch to dark mode'"
    >
      <Sun v-if="isDark" class="h-4 w-4 text-amber-500" />
      <Moon v-else class="h-4 w-4 text-slate-600" />
    </button>

    <div class="w-full max-w-sm">

      <!-- Logo -->
      <div class="flex items-center justify-center gap-2.5 mb-8">
        <div class="h-9 w-9 rounded-xl bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-blue-500/25">
          <Shield class="h-5 w-5 text-white" />
        </div>
        <span class="text-xl font-bold tracking-tight text-slate-900 dark:text-white">Deep-Scan</span>
      </div>

      <!-- Card -->
      <div class="bg-white dark:bg-slate-900 rounded-2xl shadow-xl shadow-slate-200/50 dark:shadow-black/20 border border-slate-100 dark:border-slate-800 p-6 sm:p-8 space-y-6">

        <div class="text-center space-y-1">
          <h1 class="text-xl font-bold text-slate-900 dark:text-white">Selamat Datang</h1>
          <p class="text-sm text-slate-500 dark:text-slate-400">Masuk ke dashboard keamanan Anda</p>
        </div>

        <form @submit.prevent="handleLogin" class="space-y-4">
          <div class="space-y-1.5">
            <Label for="identifier" class="text-xs font-medium text-slate-600 dark:text-slate-300">Username atau Email</Label>
            <Input
              id="identifier"
              type="text"
              placeholder="username atau email"
              v-model="identifier"
              :disabled="isLoading || isGoogleLoading"
              required
              class="h-10 bg-slate-50 dark:bg-slate-800 border-slate-200 dark:border-slate-700 focus-visible:ring-blue-500 dark:focus-visible:ring-blue-400 text-sm dark:text-white dark:placeholder-slate-500"
            />
          </div>

          <div class="space-y-1.5">
            <div class="flex items-center justify-between">
              <Label for="password" class="text-xs font-medium text-slate-600 dark:text-slate-300">Password</Label>
              <a href="#" class="text-xs text-blue-600 dark:text-blue-400 hover:underline">Lupa password?</a>
            </div>
            <Input
              id="password"
              type="password"
              placeholder="••••••••"
              v-model="password"
              :disabled="isLoading || isGoogleLoading"
              required
              class="h-10 bg-slate-50 dark:bg-slate-800 border-slate-200 dark:border-slate-700 focus-visible:ring-blue-500 dark:focus-visible:ring-blue-400 text-sm dark:text-white dark:placeholder-slate-500"
            />
          </div>

          <Button
            type="submit"
            class="w-full h-10 bg-blue-600 hover:bg-blue-700 dark:bg-blue-500 dark:hover:bg-blue-600 text-white font-medium text-sm rounded-lg shadow-sm transition-all duration-200"
            :disabled="isLoading || isGoogleLoading"
          >
            <span v-if="isLoading">Memproses...</span>
            <span v-else>Masuk</span>
          </Button>
        </form>

        <!-- Divider -->
        <div class="relative">
          <div class="absolute inset-0 flex items-center">
            <div class="w-full border-t border-slate-200 dark:border-slate-700"></div>
          </div>
          <div class="relative flex justify-center">
            <span class="bg-white dark:bg-slate-900 px-3 text-xs text-slate-400 dark:text-slate-500 uppercase">atau</span>
          </div>
        </div>

        <!-- Google Sign-In -->
        <div class="flex justify-center">
          <div ref="googleBtnRef" id="google-signin-btn"></div>
        </div>

        <p v-if="isGoogleLoading" class="text-center text-xs text-blue-600 dark:text-blue-400">
          Memproses login Google...
        </p>

        <p class="text-center text-sm text-slate-500 dark:text-slate-400">
          Belum punya akun?
          <router-link to="/register" class="font-semibold text-blue-600 dark:text-blue-400 hover:underline">
            Daftar
          </router-link>
        </p>
      </div>

      <p class="text-center text-xs text-slate-400 dark:text-slate-600 mt-6">© 2026 Deep-Scan · Tugas Akhir</p>
    </div>
  </div>
</template>