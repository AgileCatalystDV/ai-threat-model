import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { threatModelsApi } from '../api/client'

interface ThreatModel {
  id: string
  name: string
  system_type: string
  framework: string
  component_count: number
  data_flow_count: number
  threat_count: number
}

export default function ThreatModelList() {
  const [models, setModels] = useState<ThreatModel[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    loadModels()
  }, [])

  const loadModels = async () => {
    try {
      setLoading(true)
      const response = await threatModelsApi.list()
      setModels(response.data)
    } catch (err: any) {
      setError(err.message || 'Failed to load threat models')
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="text-gray-500">Loading threat models...</div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
        Error: {error}
      </div>
    )
  }

  return (
    <div className="px-4 py-6">
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-2xl font-bold text-gray-900">Threat Models</h2>
        <Link
          to="/editor"
          className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md text-sm font-medium"
        >
          Create New
        </Link>
      </div>

      {models.length === 0 ? (
        <div className="text-center py-12">
          <p className="text-gray-500 mb-4">No threat models found.</p>
          <Link
            to="/editor"
            className="text-blue-600 hover:text-blue-700 font-medium"
          >
            Create your first threat model
          </Link>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {models.map((model) => (
            <Link
              key={model.id}
              to={`/editor/${model.id}`}
              className="bg-white rounded-lg shadow p-6 hover:shadow-lg transition-shadow"
            >
              <h3 className="text-lg font-semibold text-gray-900 mb-2">{model.name}</h3>
              <div className="text-sm text-gray-500 space-y-1">
                <div>Type: {model.system_type}</div>
                <div>Framework: {model.framework}</div>
                <div className="pt-2 border-t">
                  {model.component_count} components • {model.data_flow_count} flows •{' '}
                  {model.threat_count} threats
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  )
}
