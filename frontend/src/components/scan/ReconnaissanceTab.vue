<script setup>
import { computed, ref } from 'vue'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  Search, Server, Globe, Lock, Code, Shield, Network,
  ChevronDown, ChevronUp, ExternalLink, Wifi
} from 'lucide-vue-next'

const props = defineProps({
  reconData: {
    type: Array,
    required: true
  }
})

const expandedCategories = ref({})

const toggleCategory = (key) => {
  expandedCategories.value[key] = !expandedCategories.value[key]
}

const RECON_CATEGORIES = ['DNS', 'Subdomain', 'Port', 'Technology', 'HTTP Headers', 'CORS', 'Auth Protection']

const HIDDEN_CATEGORIES = [
  'XSS', 'SQL Injection', 'Command Injection', 'File Upload',
  'Open Redirect', 'Directory Listing',
  'XSS:Summary', 'SQL Injection:Summary', 'Command Injection:Summary',
  'File Upload:Summary', 'Open Redirect:Summary', 'Directory Listing:Summary',
]

const parseDetails = (details) => {
  if (!details) return null
  if (typeof details === 'object') return details
  try {
    return JSON.parse(details)
  } catch {
    try {
      const jsonStr = details
        .replace(/'/g, '"')
        .replace(/\bNone\b/g, 'null')
        .replace(/\bTrue\b/g, 'true')
        .replace(/\bFalse\b/g, 'false')
      return JSON.parse(jsonStr)
    } catch {
      return details
    }
  }
}

const reconDataByCategory = computed(() => {
  const grouped = {}

  RECON_CATEGORIES.forEach(cat => {
    grouped[cat] = []
  })

  props.reconData.forEach(recon => {
    const category = recon.category || 'Other'

    if (HIDDEN_CATEGORIES.includes(category)) return

    if (!grouped[category]) grouped[category] = []
    grouped[category].push({ ...recon, parsedDetails: parseDetails(recon.details) })
  })

  return Object.fromEntries(
    Object.entries(grouped).filter(([, items]) => items.length > 0)
  )
})

const subdomainsByCategory = computed(() => {
  const subdomains = reconDataByCategory.value['Subdomain'] || []
  const grouped = {}
  subdomains.forEach(item => {
    const category = item.parsedDetails?.category || 'Unknown'
    if (!grouped[category]) grouped[category] = []
    grouped[category].push(item)
  })
  return grouped
})

const getCategoryIcon = (category) => {
  const icons = {
    'DNS': Globe, 'Subdomain': Server, 'Port': Lock,
    'Technology': Code, 'HTTP Headers': Shield, 'CORS': Network,
    'Auth Protection': Wifi
  }
  return icons[category] || Search
}

const formatDNSValue = (item) => {
  const data = item.parsedDetails
  if (!data) return item.details || '-'

  if (typeof data === 'string') return data

  if (data.total_queries !== undefined) return null

  if (Array.isArray(data)) {
    if (data.length === 0) return null
    return data.map(entry => {
      if (typeof entry === 'string') return entry
      if (entry.mail_server) return `${entry.mail_server} (Priority: ${entry.priority})`
      if (entry.mname) return `${entry.mname} — Serial: ${entry.serial}`
      if (entry.hostname) return entry.hostname
      if (entry.name) return `${entry.name}: ${entry.data || ''}`
      return JSON.stringify(entry)
    })
  }

  if (data.mname) {
    return [`${data.mname} — Serial: ${data.serial}, Refresh: ${data.refresh}s, Expire: ${data.expire}s`]
  }

  if (data.attempted !== undefined) return null
  if (data.vulnerable !== undefined && !data.vulnerable) return null

  if (typeof data === 'object') {
    const entries = Object.entries(data).filter(([, v]) => {
      if (v === null || v === undefined) return false
      if (Array.isArray(v) && v.length === 0) return false
      if (typeof v === 'boolean' && !v) return false
      return true
    })
    if (entries.length === 0) return null
    return entries.map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`)
  }

  return [String(data)]
}

const getDNSMetadata = (items) => {
  for (const item of items) {
    const data = item.parsedDetails
    if (data && typeof data === 'object' && data.total_queries !== undefined) {
      return {
        'Domain': data.domain,
        'Total Queries': data.total_queries,
        'Total Time': `${data.total_time}s`,
        'Timestamp': new Date(data.timestamp * 1000).toLocaleString('id-ID')
      }
    }
  }
  return null
}

const getDNSRecords = (items) => {
  return items.filter(item => {
    const data = item.parsedDetails
    if (!data || typeof data !== 'object') return true
    if (data.total_queries !== undefined) return false
    if (data.attempted !== undefined) return false
    if (data.vulnerable !== undefined && !data.vulnerable && !data.records?.length) return false
    if (Array.isArray(data) && data.length === 0) return false
    return true
  })
}

const renderHeaderItem = (data) => {
  if (!data || typeof data !== 'object') return { present: false, description: String(data), value: null }
  return { present: data.present, description: data.description, value: data.value || null }
}

const renderCORS = (data) => {
  if (!data || typeof data !== 'object') return String(data)
  return Object.entries(data)
    .map(([k, v]) => `${k}: ${v ?? 'null'}`)
    .join('  |  ')
}
</script>

<template>
  <Card v-if="!reconData || reconData.length === 0" class="border-none shadow-lg">
    <CardContent class="py-12 text-center">
      <Search class="h-16 w-16 mx-auto mb-4 text-neutral-300" />
      <h3 class="font-semibold text-lg text-neutral-900 mb-2">Tidak Ada Data Reconnaissance</h3>
      <p class="text-sm text-neutral-600">Belum ada informasi yang dikumpulkan saat fase reconnaissance.</p>
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
          <component :is="getCategoryIcon(category)" class="h-5 w-5 text-neutral-700" />
          {{ category }}
        </CardTitle>
        <CardDescription>{{ items.length }} item(s) ditemukan</CardDescription>
      </CardHeader>

      <CardContent>

        <!-- DNS -->
        <div v-if="category === 'DNS'" class="space-y-3">
          <div
            v-for="item in getDNSRecords(items)"
            :key="item.recon_id"
            class="p-3 rounded-lg border border-neutral-200 bg-white"
          >
            <div class="font-semibold text-sm text-neutral-900 mb-1">{{ item.item }}</div>
            <template v-if="formatDNSValue(item)">
              <template v-if="Array.isArray(formatDNSValue(item))">
                <div
                  v-for="(val, idx) in formatDNSValue(item)"
                  :key="idx"
                  class="text-sm text-neutral-600"
                >
                  {{ val }}
                </div>
              </template>
              <div v-else class="text-sm text-neutral-600">
                {{ formatDNSValue(item) }}
              </div>
            </template>
          </div>

          <div
            v-if="getDNSMetadata(items)"
            class="p-3 rounded-lg border border-neutral-100 bg-neutral-50"
          >
            <div class="font-semibold text-xs text-neutral-400 uppercase tracking-wide mb-2">Scan Metadata</div>
            <div class="grid grid-cols-2 gap-x-6 gap-y-1 text-xs">
              <template v-for="(val, key) in getDNSMetadata(items)" :key="key">
                <span class="font-medium text-neutral-600">{{ key }}</span>
                <span class="text-neutral-800">{{ val }}</span>
              </template>
            </div>
          </div>
        </div>

        <!-- Port -->
        <div v-else-if="category === 'Port'" class="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div
            v-for="item in items"
            :key="item.recon_id"
            class="p-3 rounded-lg border border-neutral-200 bg-white"
          >
            <div class="flex items-start justify-between gap-3">
              <div class="flex-1">
                <div class="font-semibold text-sm text-neutral-900 mb-1">Port {{ item.item }}</div>
                <div v-if="item.parsedDetails && typeof item.parsedDetails === 'object'" class="space-y-1 text-xs text-neutral-600">
                  <div>Service: {{ item.parsedDetails.service }}</div>
                  <div v-if="item.parsedDetails.banner">Banner: {{ item.parsedDetails.banner }}</div>
                </div>
              </div>
              <Badge variant="outline" class="text-xs bg-green-50 text-green-700 border-green-200">Open</Badge>
            </div>
          </div>
        </div>

        <!-- Technology -->
        <div v-else-if="category === 'Technology'" class="space-y-3">
          <div
            v-for="item in items"
            :key="item.recon_id"
            class="p-3 rounded-lg border border-neutral-200 bg-white"
          >
            <div class="font-semibold text-sm text-neutral-900 capitalize mb-2">
              {{ item.item.replace(/_/g, ' ') }}
            </div>
            <div class="flex flex-wrap gap-2">
              <template v-if="Array.isArray(item.parsedDetails)">
                <Badge v-for="(tech, idx) in item.parsedDetails" :key="idx" variant="secondary">
                  {{ tech }}
                </Badge>
              </template>
              <template v-else>
                <Badge variant="secondary">{{ item.parsedDetails || item.details }}</Badge>
              </template>
            </div>
          </div>
        </div>

        <!-- Subdomain -->
        <div v-else-if="category === 'Subdomain'" class="space-y-4">
          <div
            v-for="(subItems, subCategory) in subdomainsByCategory"
            :key="subCategory"
            class="border border-neutral-200 rounded-lg overflow-hidden bg-white"
          >
            <div
              class="flex items-center justify-between p-3 bg-neutral-50 cursor-pointer hover:bg-neutral-100 transition-colors"
              @click="toggleCategory(subCategory)"
            >
              <div class="flex items-center gap-3">
                <Server class="h-4 w-4 text-neutral-700" />
                <div>
                  <h4 class="font-semibold text-sm text-neutral-900">{{ subCategory }}</h4>
                  <p class="text-xs text-neutral-600">{{ subItems.length }} subdomain(s)</p>
                </div>
              </div>
              <component :is="expandedCategories[subCategory] ? ChevronUp : ChevronDown" class="h-4 w-4 text-neutral-600" />
            </div>

            <div v-if="expandedCategories[subCategory]" class="max-h-96 overflow-y-auto">
              <div
                v-for="(item, idx) in subItems"
                :key="item.recon_id"
                :class="['grid grid-cols-3 gap-4 p-3 border-b border-neutral-100', idx % 2 === 0 ? 'bg-neutral-50' : 'bg-white']"
              >
                <div class="text-sm font-medium text-neutral-900 truncate">
                  {{ item.parsedDetails?.subdomain || item.item }}
                </div>
                <div class="text-xs text-neutral-600">
                  <template v-if="item.parsedDetails?.all_ips">
                    <div v-for="(ip, ipIdx) in item.parsedDetails.all_ips.slice(0, 2)" :key="ipIdx">{{ ip }}</div>
                    <div v-if="item.parsedDetails.all_ips.length > 2" class="text-neutral-400">
                      +{{ item.parsedDetails.all_ips.length - 2 }} more
                    </div>
                  </template>
                  <template v-else-if="item.parsedDetails?.ip">{{ item.parsedDetails.ip }}</template>
                  <template v-else><span class="text-neutral-400">N/A</span></template>
                </div>
                <div class="flex items-center justify-end">
                  <Badge variant="outline" class="text-xs">{{ item.parsedDetails?.category || 'Unknown' }}</Badge>
                </div>
              </div>
            </div>

            <div v-if="!expandedCategories[subCategory]" class="p-2 bg-neutral-50 text-center">
              <Button variant="ghost" size="sm" @click="toggleCategory(subCategory)" class="text-sm text-neutral-700">
                Show {{ subItems.length }} subdomains
                <ChevronDown class="h-4 w-4 ml-1" />
              </Button>
            </div>
          </div>
        </div>

        <!-- HTTP Headers -->
        <div v-else-if="category === 'HTTP Headers'" class="space-y-3">
          <div
            v-for="item in items"
            :key="item.recon_id"
            class="p-3 rounded-lg border border-neutral-200 bg-white"
          >
            <div class="flex items-center justify-between mb-1">
              <div class="font-semibold text-sm text-neutral-900">{{ item.item }}</div>
              <Badge
                :class="renderHeaderItem(item.parsedDetails).present
                  ? 'bg-green-100 text-green-700 border-green-200'
                  : 'bg-red-100 text-red-700 border-red-200'"
                variant="outline"
                class="text-xs"
              >
                {{ renderHeaderItem(item.parsedDetails).present ? '✓ Present' : '✗ Missing' }}
              </Badge>
            </div>
            <div class="text-xs text-neutral-500">{{ renderHeaderItem(item.parsedDetails).description }}</div>
            <div v-if="renderHeaderItem(item.parsedDetails).value" class="text-xs font-mono bg-neutral-50 rounded px-2 py-1 mt-1 text-neutral-700 break-all">
              {{ renderHeaderItem(item.parsedDetails).value }}
            </div>
          </div>
        </div>

        <!-- CORS -->
        <div v-else-if="category === 'CORS'" class="space-y-3">
          <div
            v-for="item in items"
            :key="item.recon_id"
            class="p-3 rounded-lg border border-neutral-200 bg-white"
          >
            <div class="font-semibold text-sm text-neutral-900 mb-2">{{ item.item }}</div>
            <div class="text-xs font-mono bg-neutral-50 rounded p-2 text-neutral-700 break-all">
              {{ renderCORS(item.parsedDetails) }}
            </div>
            <div
              v-if="item.parsedDetails?.['Access-Control-Allow-Origin'] === '*'"
              class="mt-2 text-xs text-amber-600 flex items-center gap-1"
            >
              ⚠️ Wildcard origin (*) — semua domain diizinkan akses
            </div>
          </div>
        </div>

        <!-- Auth Protection -->
        <div v-else-if="category === 'Auth Protection'" class="space-y-3">
          <div
            v-for="item in items"
            :key="item.recon_id"
            class="p-3 rounded-lg border border-neutral-200 bg-white"
          >
            <div class="flex items-center gap-2 mb-1">
              <Shield class="h-4 w-4 text-neutral-600" />
              <div class="font-semibold text-sm text-neutral-900">{{ item.item }}</div>
            </div>
            <div class="text-sm text-neutral-600">{{ item.details }}</div>
          </div>
        </div>

        <!-- Fallback -->
        <div v-else class="space-y-3">
          <div
            v-for="item in items"
            :key="item.recon_id"
            class="p-3 rounded-lg border border-neutral-200 bg-white"
          >
            <div class="font-semibold text-sm text-neutral-900 mb-1">{{ item.item }}</div>
            <div class="text-sm text-neutral-600">{{ item.details }}</div>
          </div>
        </div>

      </CardContent>
    </Card>
  </div>
</template>