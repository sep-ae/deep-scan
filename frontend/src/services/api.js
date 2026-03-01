import axios from 'axios'

const BASE_URL = import.meta.env.VITE_API_BASE_URL

if (!BASE_URL) {
  console.error('[API] VITE_API_BASE_URL belum di-set di .env!')
}

const api = axios.create({
  baseURL: BASE_URL,
  headers: {
    'Content-Type': 'application/json'
  },
  timeout: 30000
})

api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => Promise.reject(error)
)

api.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error.response?.status
    const requestUrl = error.config?.url
    const token = localStorage.getItem('token')

    if (status === 401 && token && requestUrl !== '/auth/login') {
      localStorage.removeItem('token')
      localStorage.removeItem('user')
      window.location.href = '/login'
      return Promise.reject(error)
    }

    if (status === 429) {
      return Promise.reject({
        ...error,
        userMessage: 'Terlalu banyak permintaan. Coba lagi nanti.'
      })
    }

    if (status === 403) {
      return Promise.reject({
        ...error,
        userMessage: 'Akses ditolak.'
      })
    }

    if (status >= 500) {
      return Promise.reject({
        ...error,
        userMessage: 'Terjadi kesalahan server. Coba lagi nanti.'
      })
    }

    if (!error.response) {
      return Promise.reject({
        ...error,
        userMessage: 'Tidak dapat terhubung ke server. Cek koneksi internet kamu.'
      })
    }

    return Promise.reject(error)
  }
)

export default api
