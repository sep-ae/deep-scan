import { createRouter, createWebHistory } from 'vue-router'
import { jwtDecode } from 'jwt-decode'

import LandingView from '@/views/LandingView.vue'
import LoginView from '@/views/LoginView.vue'
import RegisterView from '@/views/RegisterView.vue'
import DashboardView from '@/views/DashboardView.vue'
import ScanView from '@/views/ScanView.vue'
import HistoryView from '@/views/HistoryView.vue'
import ScanDetailView from '@/views/ScanDetailView.vue'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      name: 'landing',
      component: LandingView
    },
    {
      path: '/login',
      name: 'login',
      component: LoginView
    },
    {
      path: '/register',
      name: 'register',
      component: RegisterView
    },
    {
      path: '/dashboard',
      name: 'dashboard',
      component: DashboardView,
      meta: { requiresAuth: true }
    },
    {
      path: '/scan',
      name: 'scan',
      component: ScanView,
      meta: { requiresAuth: true }
    },
    {
      path: '/history',
      name: 'history',
      component: HistoryView,
      meta: { requiresAuth: true }
    },
    {
      path: '/history/:id',
      name: 'scan-detail',
      component: ScanDetailView,
      meta: { requiresAuth: true }
    },
    {
      path: '/:pathMatch(.*)*',
      name: 'not-found',
      redirect: '/'
    }
  ]
})

function isTokenValid(token) {
  try {
    const decoded = jwtDecode(token)
    const now = Date.now() / 1000
    return decoded.exp && decoded.exp > now
  } catch {
    return false
  }
}

function clearAuth() {
  localStorage.removeItem('token')
  localStorage.removeItem('user')
}

router.beforeEach((to, from, next) => {
  const token = localStorage.getItem('token')

  if (to.meta.requiresAuth) {
    if (!token) {
      return next('/login')
    }

    if (!isTokenValid(token)) {
      clearAuth()
      return next('/login')
    }
  }

  if ((to.path === '/login' || to.path === '/register') && token) {
    if (isTokenValid(token)) {
      return next('/dashboard')
    }
    clearAuth()
  }

  next()
})

export default router
