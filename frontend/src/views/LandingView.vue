<script setup>
import { Button } from '@/components/ui/button' // Panggil tombol Shadcn
</script>

<template>
  <div class="min-h-screen bg-neutral-950 text-white flex flex-col items-center justify-center p-4">
    
    <div class="text-center max-w-2xl space-y-6">
      <h1 class="text-5xl md:text-7xl font-bold tracking-tight bg-gradient-to-r from-green-400 to-blue-500 bg-clip-text text-transparent">
        DEEP-SCAN
      </h1>
      
      <p class="text-neutral-400 text-lg md:text-xl">
        Platform Deteksi Kerentanan Web (Vulnerability Scanner) berbasis Python & AI. 
        Aman, Cepat, dan Akurat.
      </p>

      <div class="flex gap-4 justify-center mt-8">
        <router-link to="/login">
          <Button class="bg-green-600 hover:bg-green-700 text-white px-8 py-6 text-lg">
            Login Sekarang
          </Button>
        </router-link>

        <router-link to="/register">
          <Button variant="outline" class="border-neutral-700 text-neutral-300 hover:bg-neutral-900 px-8 py-6 text-lg">
            Daftar Akun
          </Button>
        </router-link>
      </div>
    </div>

    <footer class="absolute bottom-4 text-neutral-600 text-sm">
      &copy; 2025 Deep-Scan Project. Built with Flask & Vue.
    </footer>
  </div>
</template>