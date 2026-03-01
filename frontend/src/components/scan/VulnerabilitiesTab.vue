<script setup>
import { computed } from 'vue'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion'
import { Separator } from '@/components/ui/separator'
import { CheckCircle2, AlertTriangle, AlertCircle, Info, Shield } from 'lucide-vue-next'

const props = defineProps({
  vulnerabilities: {
    type: Array,
    required: true
  }
})

const parseVulnerabilityDetails = (description) => {
  if (!description) return { cleanDescription: '', vector: null, score: null, affected: null }

  const affectedMatch = description.match(/Affected:\s*([^\s]+)/)
  const vectorMatch   = description.match(/Vector:\s*(CVSS:[^\s]+)/)
  const scoreMatch    = description.match(/Score:\s*([\d.]+)/)

  let cleanDescription = description
    .replace(/Affected:\s*[^\s]+/g, '')
    .replace(/Vector:\s*CVSS:[^\s]+/g, '')
    .replace(/Score:\s*[\d.]+/g, '')
    .trim()

  return {
    cleanDescription,
    affected: affectedMatch ? affectedMatch[1] : null,
    vector:   vectorMatch   ? vectorMatch[1]   : null,
    score:    scoreMatch    ? scoreMatch[1]     : null
  }
}

const processedVulnerabilities = computed(() => {
  return props.vulnerabilities.map(vuln => ({
    ...vuln,
    parsed: parseVulnerabilityDetails(vuln.description)
  }))
})

const normalizeSeverity = (severity) => {
  const s = severity?.toLowerCase()
  if (s === 'critical' || s === 'high') return 'high'
  if (s === 'medium') return 'medium'
  if (s === 'low') return 'low'
  return 'low'
}

const SEVERITY_CONFIG = {
  high: {
    badge:  { text: 'High', class: 'bg-red-200 text-red-800 border-red-300' },
    icon:   AlertTriangle,
    color:  'text-red-600'
  },
  medium: {
    badge:  { text: 'Medium', class: 'bg-yellow-200 text-yellow-800 border-yellow-300' },
    icon:   AlertCircle,
    color:  'text-yellow-600'
  },
  low: {
    badge:  { text: 'Low', class: 'bg-blue-200 text-blue-800 border-blue-300' },
    icon:   Info,
    color:  'text-blue-600'
  }
}

const getSeverityBadge  = (severity) => SEVERITY_CONFIG[normalizeSeverity(severity)].badge
const getSeverityIcon   = (severity) => SEVERITY_CONFIG[normalizeSeverity(severity)].icon
const getSeverityColor  = (severity) => SEVERITY_CONFIG[normalizeSeverity(severity)].color
</script>

<template>
  <Card v-if="!vulnerabilities || vulnerabilities.length === 0" class="border-none shadow-lg">
    <CardContent class="py-12 text-center">
      <CheckCircle2 class="h-16 w-16 mx-auto mb-4 text-green-500" />
      <h3 class="font-semibold text-lg text-neutral-900 mb-2">
        Tidak Ada Kerentanan Ditemukan
      </h3>
      <p class="text-sm text-neutral-600">
        Website Anda aman dari kerentanan yang umum ditemukan.
      </p>
    </CardContent>
  </Card>

  <Accordion v-else type="single" collapsible class="space-y-3">
    <AccordionItem
      v-for="(vuln, index) in processedVulnerabilities"
      :key="vuln.vuln_id"
      :value="`vuln-${index}`"
      class="border-none"
    >
      <Card class="border-none shadow-lg">
        <AccordionTrigger class="px-6 py-4 hover:no-underline">
          <div class="flex items-start gap-3 w-full">
            <component
              :is="getSeverityIcon(vuln.severity)"
              class="h-5 w-5 mt-0.5 shrink-0"
              :class="getSeverityColor(vuln.severity)"
            />
            <div class="flex-1 text-left">
              <div class="flex items-center gap-2 mb-2">
                <h3 class="font-semibold text-base text-neutral-900">{{ vuln.name }}</h3>
                <Badge variant="secondary" :class="getSeverityBadge(vuln.severity).class">
                  {{ getSeverityBadge(vuln.severity).text }}
                </Badge>
              </div>
              <p class="text-xs text-neutral-500">{{ vuln.category }}</p>
            </div>
          </div>
        </AccordionTrigger>

        <AccordionContent class="px-6 pb-4">
          <Separator class="mb-4" />

          <div class="space-y-4">

            <div
              v-if="vuln.parsed.vector || vuln.parsed.score || vuln.parsed.affected"
              class="flex flex-wrap gap-3 p-3 bg-neutral-50 rounded-lg border border-neutral-200"
            >
              <div v-if="vuln.parsed.affected" class="flex items-center gap-2">
                <Shield class="h-4 w-4 text-neutral-600" />
                <div>
                  <span class="text-xs text-neutral-500">Affected Port/Service</span>
                  <p class="text-sm font-semibold text-neutral-900">{{ vuln.parsed.affected }}</p>
                </div>
              </div>

              <Separator
                v-if="vuln.parsed.affected && (vuln.parsed.vector || vuln.parsed.score)"
                orientation="vertical"
                class="h-10"
              />

              <div v-if="vuln.parsed.vector" class="flex items-center gap-2">
                <div>
                  <span class="text-xs text-neutral-500">CVSS Vector</span>
                  <p class="text-xs font-mono text-neutral-900 bg-white px-2 py-1 rounded border border-neutral-200 mt-1">
                    {{ vuln.parsed.vector }}
                  </p>
                </div>
              </div>

              <Separator
                v-if="vuln.parsed.vector && vuln.parsed.score"
                orientation="vertical"
                class="h-10"
              />

              <div v-if="vuln.parsed.score" class="flex items-center gap-2">
                <div>
                  <span class="text-xs text-neutral-500">Risk Score</span>
                  <p class="text-sm font-bold" :class="{
                    'text-red-700':    parseFloat(vuln.parsed.score) >= 7,
                    'text-yellow-700': parseFloat(vuln.parsed.score) >= 4 && parseFloat(vuln.parsed.score) < 7,
                    'text-blue-700':   parseFloat(vuln.parsed.score) < 4
                  }">
                    {{ vuln.parsed.score }} / 10
                  </p>
                </div>
              </div>
            </div>

            <div>
              <h4 class="font-semibold text-sm text-neutral-900 mb-2 flex items-center gap-2">
                <Info class="h-4 w-4 text-neutral-600" />
                Deskripsi
              </h4>
              <p class="text-sm text-neutral-700 leading-relaxed">
                {{ vuln.parsed.cleanDescription || vuln.description }}
              </p>
            </div>

            <div v-if="vuln.recommendation">
              <h4 class="font-semibold text-sm text-neutral-900 mb-2 flex items-center gap-2">
                <CheckCircle2 class="h-4 w-4 text-green-600" />
                Rekomendasi Perbaikan
              </h4>
              <div class="text-sm text-neutral-700 leading-relaxed bg-green-50 p-3 rounded-lg border border-green-200">
                {{ vuln.recommendation }}
              </div>
            </div>

          </div>
        </AccordionContent>
      </Card>
    </AccordionItem>
  </Accordion>
</template>
