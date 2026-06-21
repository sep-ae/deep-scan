<script setup>
import { computed } from 'vue'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { AlertTriangle, AlertCircle, Info, TrendingUp } from 'lucide-vue-next'

const props = defineProps({
  vulnerabilities: {
    type: Array,
    required: true
  },
  totalVulnerabilities: {
    type: Number,
    required: true
  }
})

const vulnerabilitiesBySeverity = computed(() => {
  return {
    high:   props.vulnerabilities.filter(v => ['high', 'critical'].includes(v.severity.toLowerCase())),
    medium: props.vulnerabilities.filter(v => v.severity.toLowerCase() === 'medium'),
    low:    props.vulnerabilities.filter(v => v.severity.toLowerCase() === 'low')
  }
})

const getProgressPercentage = (count) => {
  if (props.totalVulnerabilities === 0) return 0
  return Math.round((count / props.totalVulnerabilities) * 100)
}

const severityLevels = computed(() => [
  {
    key: 'high',
    label: 'High Severity',
    count: vulnerabilitiesBySeverity.value.high.length,
    textClass: 'text-red-700 dark:text-red-400',
    barClass: 'bg-red-500',
    icon: AlertTriangle
  },
  {
    key: 'medium',
    label: 'Medium Severity',
    count: vulnerabilitiesBySeverity.value.medium.length,
    textClass: 'text-yellow-700 dark:text-yellow-400',
    barClass: 'bg-yellow-500',
    icon: AlertCircle
  },
  {
    key: 'low',
    label: 'Low Severity',
    count: vulnerabilitiesBySeverity.value.low.length,
    textClass: 'text-blue-700 dark:text-blue-400',
    barClass: 'bg-blue-500',
    icon: Info
  }
])
</script>

<template>
  <Card class="border-none shadow-lg">
    <CardHeader>
      <CardTitle class="flex items-center gap-2">
        <TrendingUp class="h-5 w-5" />
        Breakdown by Severity
      </CardTitle>
    </CardHeader>
    <CardContent class="space-y-4">

      <div
        v-for="level in severityLevels"
        :key="level.key"
        class="space-y-2"
      >
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-2 text-sm font-medium" :class="level.textClass">
            <component :is="level.icon" class="h-4 w-4" />
            {{ level.label }}
          </div>
          <span class="text-sm font-bold" :class="level.textClass">
            {{ level.count }}
          </span>
        </div>
        <div class="h-2 bg-neutral-100 dark:bg-slate-800 rounded-full overflow-hidden">
          <div
            class="h-full transition-all"
            :class="level.barClass"
            :style="`width: ${getProgressPercentage(level.count)}%`"
          ></div>
        </div>
      </div>

    </CardContent>
  </Card>
</template>
