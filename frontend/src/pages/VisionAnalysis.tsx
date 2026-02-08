import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { visionApi } from '../api/client'

export default function VisionAnalysis() {
  const [file, setFile] = useState<File | null>(null)
  const [preview, setPreview] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<any>(null)
  const [error, setError] = useState<string | null>(null)
  const [systemType, setSystemType] = useState('')
  const [framework, setFramework] = useState('')
  const navigate = useNavigate()

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0]
    if (selectedFile) {
      setFile(selectedFile)
      const reader = new FileReader()
      reader.onloadend = () => {
        setPreview(reader.result as string)
      }
      reader.readAsDataURL(selectedFile)
    }
  }

  const handleAnalyze = async () => {
    if (!file) {
      setError('Please select an image file')
      return
    }

    try {
      setLoading(true)
      setError(null)
      const response = await visionApi.analyze(
        file,
        systemType || undefined,
        framework || undefined
      )
      setResult(response.data)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Failed to analyze image')
    } finally {
      setLoading(false)
    }
  }

  const handleCreateModel = async () => {
    if (!result) return

    try {
      setLoading(true)
      const response = await visionApi.convertToModel(result, {
        system_name: result.suggested_system_name,
        system_type: systemType || result.suggested_system_type,
        framework: framework || result.suggested_framework,
      })
      
      // Navigate to editor with the new model
      navigate(`/editor?model=${encodeURIComponent(JSON.stringify(response.data))}`)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Failed to create threat model')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="px-4 py-6 max-w-4xl mx-auto">
      <h2 className="text-2xl font-bold text-gray-900 mb-6">Analyze Diagram</h2>

      <div className="bg-white rounded-lg shadow p-6 space-y-6">
        {/* File Upload */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Upload Diagram Image
          </label>
          <input
            type="file"
            accept="image/*"
            onChange={handleFileChange}
            className="block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100"
          />
          {preview && (
            <div className="mt-4">
              <img
                src={preview}
                alt="Preview"
                className="max-w-full h-auto rounded border"
              />
            </div>
          )}
        </div>

        {/* Options */}
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              System Type (optional)
            </label>
            <input
              type="text"
              value={systemType}
              onChange={(e) => setSystemType(e.target.value)}
              placeholder="e.g., llm-app, agentic-system"
              className="w-full px-3 py-2 border border-gray-300 rounded-md"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Framework (optional)
            </label>
            <input
              type="text"
              value={framework}
              onChange={(e) => setFramework(e.target.value)}
              placeholder="e.g., owasp-llm-top10-2025"
              className="w-full px-3 py-2 border border-gray-300 rounded-md"
            />
          </div>
        </div>

        {/* Analyze Button */}
        <button
          onClick={handleAnalyze}
          disabled={!file || loading}
          className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white px-4 py-2 rounded-md font-medium"
        >
          {loading ? 'Analyzing...' : 'Analyze Image'}
        </button>

        {/* Error */}
        {error && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
            {error}
          </div>
        )}

        {/* Results */}
        {result && (
          <div className="border-t pt-6 space-y-4">
            <h3 className="text-lg font-semibold">Analysis Results</h3>
            
            <div className="bg-gray-50 p-4 rounded">
              <div className="text-sm text-gray-600 mb-2">
                <strong>Suggested System:</strong> {result.suggested_system_name}
              </div>
              <div className="text-sm text-gray-600 mb-2">
                <strong>Type:</strong> {result.suggested_system_type || 'Not detected'}
              </div>
              <div className="text-sm text-gray-600 mb-2">
                <strong>Framework:</strong> {result.suggested_framework || 'Not detected'}
              </div>
              <div className="text-sm text-gray-600">
                <strong>Confidence:</strong> {(result.confidence * 100).toFixed(1)}%
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <strong className="text-gray-700">Components Found:</strong>
                <div className="mt-2 space-y-1">
                  {result.components?.map((comp: any, i: number) => (
                    <div key={i} className="text-gray-600">
                      • {comp.name} ({comp.type})
                    </div>
                  ))}
                </div>
              </div>
              <div>
                <strong className="text-gray-700">Data Flows Found:</strong>
                <div className="mt-2 space-y-1">
                  {result.data_flows?.map((flow: any, i: number) => (
                    <div key={i} className="text-gray-600">
                      • {flow.from_component} → {flow.to_component}
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {result.raw_analysis && (
              <div className="bg-blue-50 p-4 rounded text-sm text-gray-700">
                <strong>Analysis:</strong> {result.raw_analysis}
              </div>
            )}

            <button
              onClick={handleCreateModel}
              disabled={loading}
              className="w-full bg-green-600 hover:bg-green-700 disabled:bg-gray-400 text-white px-4 py-2 rounded-md font-medium"
            >
              {loading ? 'Creating...' : 'Create Threat Model'}
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
