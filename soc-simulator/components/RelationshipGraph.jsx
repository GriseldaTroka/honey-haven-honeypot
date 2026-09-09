import { useMemo, useState } from 'react'

const TYPE_COLUMNS = ['Session', 'AttackJourney', 'IOC', 'Campaign', 'DetectionAlert']

function RelationshipGraph({ graph = { nodes: [], edges: [] }, loading = false, error = '' }) {
  const [selectedNodeId, setSelectedNodeId] = useState('')

  const prepared = useMemo(() => {
    const grouped = new Map(TYPE_COLUMNS.map((type) => [type, []]))
    const extras = []
    for (const node of graph.nodes || []) {
      if (grouped.has(node.type)) {
        grouped.get(node.type).push(node)
      } else {
        extras.push(node)
      }
    }
    const columns = TYPE_COLUMNS.filter((type) => grouped.get(type)?.length).map((type) => ({ type, nodes: grouped.get(type) }))
    if (extras.length) {
      columns.push({ type: 'Other', nodes: extras })
    }

    const positions = new Map()
    columns.forEach((column, columnIndex) => {
      const step = 1 / Math.max(column.nodes.length + 1, 2)
      column.nodes.forEach((node, nodeIndex) => {
        positions.set(node.id, {
          x: ((columnIndex + 1) / (columns.length + 1)) * 100,
          y: (nodeIndex + 1) * step * 100,
        })
      })
    })

    return { columns, positions }
  }, [graph.nodes])

  const selectedNode = (graph.nodes || []).find((node) => node.id === selectedNodeId) || null

  if (loading) {
    return <div className="panel-empty">Loading relationship graph...</div>
  }

  if (error) {
    return <div className="panel-empty">{error}</div>
  }

  if (!(graph.nodes || []).length) {
    return <div className="panel-empty">No graph data available for this session.</div>
  }

  return (
    <div className="graph-panel">
      <div className="graph-legend">
        {prepared.columns.map((column) => (
          <span key={column.type} className="graph-legend-item">{column.type}</span>
        ))}
      </div>
      <div className="graph-canvas">
        <svg className="graph-edges" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
          {(graph.edges || []).map((edge, index) => {
            const source = prepared.positions.get(edge.source)
            const target = prepared.positions.get(edge.target)
            if (!source || !target) return null
            const isSelected = !selectedNodeId || selectedNodeId === edge.source || selectedNodeId === edge.target
            return (
              <line
                key={`${edge.source}-${edge.target}-${index}`}
                x1={source.x}
                y1={source.y}
                x2={target.x}
                y2={target.y}
                className={`graph-edge ${isSelected ? 'active' : 'muted'}`}
              />
            )
          })}
        </svg>

        {(graph.nodes || []).map((node) => {
          const position = prepared.positions.get(node.id)
          if (!position) return null
          const isSelected = selectedNodeId === node.id
          return (
            <button
              key={node.id}
              type="button"
              className={`graph-node ${isSelected ? 'selected' : ''}`}
              style={{ left: `${position.x}%`, top: `${position.y}%` }}
              onClick={() => setSelectedNodeId(isSelected ? '' : node.id)}
            >
              <span className="graph-node-type">{node.type}</span>
              <strong>{node.label}</strong>
            </button>
          )
        })}
      </div>

      <div className="graph-detail">
        {selectedNode ? (
          <>
            <h4>{selectedNode.label}</h4>
            <p>{selectedNode.type}</p>
            <dl>
              {Object.entries(selectedNode)
                .filter(([key]) => !['id', 'type', 'label'].includes(key))
                .slice(0, 6)
                .map(([key, value]) => (
                  <div key={key}>
                    <dt>{key}</dt>
                    <dd>{typeof value === 'object' ? JSON.stringify(value) : String(value)}</dd>
                  </div>
                ))}
            </dl>
          </>
        ) : (
          <p>Select a node to inspect graph metadata.</p>
        )}
      </div>
    </div>
  )
}

export default RelationshipGraph
