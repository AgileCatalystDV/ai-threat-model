import axios from 'axios'

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Threat Models API
export const threatModelsApi = {
  list: () => apiClient.get('/api/v1/threat-models/'),
  get: (id: string) => apiClient.get(`/api/v1/threat-models/${id}`),
  create: (data: any) => apiClient.post('/api/v1/threat-models/', data),
  update: (id: string, data: any) => apiClient.put(`/api/v1/threat-models/${id}`, data),
  delete: (id: string) => apiClient.delete(`/api/v1/threat-models/${id}`),
  analyze: (id: string) => apiClient.post(`/api/v1/threat-models/${id}/analyze`),
}

// Vision API
export const visionApi = {
  analyze: (file: File, systemType?: string, framework?: string) => {
    const formData = new FormData()
    formData.append('file', file)
    if (systemType) formData.append('system_type', systemType)
    if (framework) formData.append('framework', framework)
    return apiClient.post('/api/v1/vision/analyze', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    })
  },
  analyzeBase64: (imageData: string, systemType?: string, framework?: string) => {
    return apiClient.post('/api/v1/vision/analyze-base64', {
      image_data: imageData,
      system_type: systemType,
      framework: framework,
    })
  },
  convertToModel: (visionResponse: any, overrides?: any) => {
    return apiClient.post('/api/v1/vision/convert-to-model', {
      ...visionResponse,
      ...overrides,
    })
  },
}

// Patterns API
export const patternsApi = {
  list: (framework?: string) => {
    const params = framework ? { framework } : {}
    return apiClient.get('/api/v1/patterns/', { params })
  },
  get: (id: string) => apiClient.get(`/api/v1/patterns/${id}`),
}
