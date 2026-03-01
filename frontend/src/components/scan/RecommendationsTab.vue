<script setup>
import { computed } from 'vue'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card'
import { Alert, AlertTitle, AlertDescription } from '@/components/ui/alert'
import { CheckCircle2, AlertTriangle } from 'lucide-vue-next'

const props = defineProps({
  vulnerabilities: {
    type: Array,
    required: true
  }
})

const highSeverityCount = computed(() => {
  return props.vulnerabilities.filter(v => v.severity.toLowerCase() === 'high').length
})
</script>

<template>
  <Card class="border-none shadow-lg">
    <CardHeader>
      <CardTitle>Langkah-langkah Perbaikan</CardTitle>
      <CardDescription>
        Ikuti rekomendasi berikut untuk meningkatkan keamanan website Anda
      </CardDescription>
    </CardHeader>
    <CardContent class="space-y-4">
      
      <div v-if="highSeverityCount > 0">
        <Alert class="bg-red-50 border-red-200 mb-4">
          <AlertTriangle class="h-4 w-4 text-red-600" />
          <AlertTitle class="text-red-900">Prioritas Tinggi</AlertTitle>
          <AlertDescription class="text-red-800">
            Perbaiki {{ highSeverityCount }} kerentanan kritis segera untuk mencegah serangan berbahaya.
          </AlertDescription>
        </Alert>
      </div>

      <div v-if="vulnerabilities && vulnerabilities.length > 0" class="space-y-3">
        <div 
          v-for="(vuln, index) in vulnerabilities" 
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

      <div v-else class="text-center py-8">
        <CheckCircle2 class="h-12 w-12 mx-auto mb-3 text-green-500" />
        <p class="text-sm text-neutral-600">Tidak ada rekomendasi perbaikan yang diperlukan.</p>
      </div>

    </CardContent>
  </Card>
</template>
