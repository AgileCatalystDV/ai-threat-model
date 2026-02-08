import { useState, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import ReactFlow, { Node, Edge, Background, Controls, MiniMap } from 'reactflow'
import 'reactflow/dist/style.css'
import { threatModelsApi } from '../api/client'

export default function ThreatModelEditor() {
  const [searchParams] = useSearchParams()
  const [nodes, setNodes] = useState<Node[]>([])
  const [edges, setEdges] = useState<Edge[]>([])
  const [threatModel, setThreatModel] = useState<any>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    const modelParam = searchParams.get('model')
    if (modelParam) {
      try {
        const model = JSON.parse(decodeURIComponent(modelParam))
        setThreatModel(model)
        loadModelToFlow(model)
      } catch (err) {
        console.error('Failed to parse model:', err)
      }
    }
  }, [searchParams])

  const loadModelToFlow = (model: any) => {
    if (!model?.system) return

    // Create nodes from components
    const newNodes: Node[] = model.system.components.map((comp: any, index: number) => ({
      id: comp.id,
      type: 'default',
      position: { x: (index % 4) * 200, y: Math.floor(index / 4) * 150 },
      data: { label: `${comp.name}\n(${comp.type})` },
    }))

    // Create edges from data flows
    const newEdges: Edge[] = model.system.data_flows.map((flow: any) => ({
      id: `${flow.from_component}-${flow.to_component}`,
      source: flow.from_component,
      target: flow.to_component,
      label: flow.data_type || '',
      animated: !flow.encrypted,
      style: { stroke: flow.encrypted ? '#10b981' : '#ef4444' },
    }))

    setNodes(newNodes)
    setEdges(newEdges)
  }

  const handleAnalyze = async () => {
    if (!threatModel?.system?.name) {
      alert('Please create or load a threat model first')
      return
    }

    try {
      setLoading(true)
      // For now, we'll use a mock ID - in production, save first
      const response = await threatModelsApi.analyze('temp-id')
      setThreatModel(response.data)
      alert('Analysis complete! Check threats.')
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to analyze')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="h-screen flex flex-col">
      <div className="bg-white border-b px-4 py-3 flex justify-between items-center">
        <h2 className="text-xl font-bold text-gray-900">
          {threatModel?.system?.name || 'New Threat Model'}
        </h2>
        <div className="space-x-2">
          <button
            onClick={handleAnalyze}
            disabled={loading}
            className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white px-4 py-2 rounded-md text-sm font-medium"
          >
            {loading ? 'Analyzing...' : 'Analyze Threats'}
          </button>
        </div>
      </div>

      <div className="flex-1">
        {nodes.length === 0 ? (
          <div className="flex items-center justify-center h-full text-gray-500">
            <div className="text-center">
              <p className="mb-4">No components to display</p>
              <p className="text-sm">
                Upload an image or create components manually
              </p>
            </div>
          </div>
        ) : (
          <ReactFlow nodes={nodes} edges={edges} fitView>
            <Background />
            <Controls />
            <MiniMap />
          </ReactFlow>
        )}
      </div>

      {/* Sidebar for threats */}
      {threatModel?.threats && threatModel.threats.length > 0 && (
        <div className="bg-white border-t h-64 overflow-y-auto p-4">
          <h3 className="font-semibold mb-2">Detected Threats</h3>
          <div className="space-y-2">
            {threatModel.threats.map((threat: any, i: number) => (
              <div key={i} className="bg-red-50 border border-red-200 rounded p-2 text-sm">
                <div className="font-medium text-red-900">{threat.category}: {threat.title}</div>
                <div className="text-red-700 text-xs mt-1">{threat.description}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
