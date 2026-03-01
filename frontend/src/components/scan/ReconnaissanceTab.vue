<script setup>
import { computed, ref } from 'vue'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Search, Server, Globe, Lock, Code, Shield, Network, ChevronDown, ChevronUp } from 'lucide-vue-next'

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

const parseDetails = (details) => {
  if (!details) return null
  
  try {
    return JSON.parse(details.replace(/'/g, '"').replace(/None/g, 'null'))
  } catch {
    return details
  }
}

const reconDataByCategory = computed(() => {
  const grouped = {
    'DNS': [],
    'Port': [],
    'Technology': [],
    'Subdomain': []
  }
  
  props.reconData.forEach(recon => {
    const category = recon.category || 'Other'
    if (!grouped[category]) {
      grouped[category] = []
    }
    
    const parsedData = {
      ...recon,
      parsedDetails: parseDetails(recon.details)
    }
    
    grouped[category].push(parsedData)
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
    if (!grouped[category]) {
      grouped[category] = []
    }
    grouped[category].push(item)
  })
  
  return grouped
})

const getCategoryIcon = (category) => {
  const icons = {
    'DNS': Globe,
    'Subdomain': Server,
    'Port': Lock,
    'Technology': Code,
    'Headers': Shield,
    'SSL': Network
  }
  return icons[category] || Search
}

const renderDNSData = (data) => {
  if (!data || typeof data === 'string') return data
  
  if (Array.isArray(data)) {
    return data.join(', ')
  }
  
  if (data.mname) {
    return `${data.mname} (Serial: ${data.serial})`
  }
  
  if (data.priority !== undefined) {
    return `${data.mail_server} (Priority: ${data.priority})`
  }
  
  return JSON.stringify(data)
}
</script>

<template>
  <Card v-if="!reconData || reconData.length === 0" class="border-none shadow-lg">
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
          <component :is="getCategoryIcon(category)" class="h-5 w-5 text-neutral-700" />
          {{ category }}
        </CardTitle>
        <CardDescription>{{ items.length }} item(s) ditemukan</CardDescription>
      </CardHeader>
      <CardContent>
        
        <div v-if="category === 'DNS'" class="space-y-3">
          <div 
            v-for="item in items" 
            :key="item.recon_id"
            class="p-3 rounded-lg border border-neutral-200 bg-white"
          >
            <div class="font-semibold text-sm text-neutral-900 mb-1">{{ item.item }}</div>
            <div class="text-sm text-neutral-600">
              {{ renderDNSData(item.parsedDetails) }}
            </div>
          </div>
        </div>

        <div v-else-if="category === 'Port'" class="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div 
            v-for="item in items" 
            :key="item.recon_id"
            class="p-3 rounded-lg border border-neutral-200 bg-white"
          >
            <div class="flex items-start justify-between gap-3">
              <div class="flex-1">
                <div class="font-semibold text-sm text-neutral-900 mb-1">
                  Port {{ item.item }}
                </div>
                <div v-if="item.parsedDetails && typeof item.parsedDetails === 'object'" class="space-y-1 text-xs text-neutral-600">
                  <div>Service: {{ item.parsedDetails.service }}</div>
                  <div v-if="item.parsedDetails.banner">Banner: {{ item.parsedDetails.banner }}</div>
                </div>
              </div>
              <Badge variant="outline" class="text-xs">Open</Badge>
            </div>
          </div>
        </div>

        <div v-else-if="category === 'Technology'" class="space-y-3">
          <div 
            v-for="item in items" 
            :key="item.recon_id"
            class="p-3 rounded-lg border border-neutral-200 bg-white"
          >
            <div class="font-semibold text-sm text-neutral-900 mb-2">{{ item.item }}</div>
            <div class="flex flex-wrap gap-2">
              <template v-if="Array.isArray(item.parsedDetails)">
                <Badge 
                  v-for="(tech, idx) in item.parsedDetails" 
                  :key="idx" 
                  variant="secondary"
                >
                  {{ tech }}
                </Badge>
              </template>
              <template v-else>
                <span class="text-sm text-neutral-600">{{ item.parsedDetails || item.details }}</span>
              </template>
            </div>
          </div>
        </div>

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
              <component 
                :is="expandedCategories[subCategory] ? ChevronUp : ChevronDown" 
                class="h-4 w-4 text-neutral-600"
              />
            </div>
            
            <div 
              v-if="expandedCategories[subCategory]" 
              class="max-h-96 overflow-y-auto"
            >
              <div 
                v-for="(item, idx) in subItems" 
                :key="item.recon_id"
                :class="[
                  'grid grid-cols-3 gap-4 p-3 border-b border-neutral-100',
                  idx % 2 === 0 ? 'bg-neutral-50' : 'bg-white'
                ]"
              >
                <div class="text-sm font-medium text-neutral-900 truncate">
                  {{ item.parsedDetails?.subdomain || item.item }}
                </div>
                
                <div class="text-xs text-neutral-600">
                  <div v-if="item.parsedDetails?.all_ips">
                    <div v-for="(ip, ipIdx) in item.parsedDetails.all_ips.slice(0, 2)" :key="ipIdx">
                      {{ ip }}
                    </div>
                    <div v-if="item.parsedDetails.all_ips.length > 2" class="text-neutral-400">
                      +{{ item.parsedDetails.all_ips.length - 2 }} more
                    </div>
                  </div>
                  <div v-else-if="item.parsedDetails?.ip">
                    {{ item.parsedDetails.ip }}
                  </div>
                  <div v-else class="text-neutral-400">N/A</div>
                </div>
                
                <div class="flex items-center justify-end">
                  <Badge variant="outline" class="text-xs">
                    {{ item.parsedDetails?.category || 'Unknown' }}
                  </Badge>
                </div>
              </div>
            </div>
            
            <div 
              v-if="!expandedCategories[subCategory]" 
              class="p-2 bg-neutral-50 text-center"
            >
              <Button 
                variant="ghost" 
                size="sm" 
                @click="toggleCategory(subCategory)"
                class="text-sm text-neutral-700"
              >
                Show {{ subItems.length }} subdomains
                <ChevronDown class="h-4 w-4 ml-1" />
              </Button>
            </div>
          </div>
        </div>

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
