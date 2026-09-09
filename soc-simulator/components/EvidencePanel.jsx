function EvidencePanel({ items = [] }) {
  if (!items.length) {
    return <div className="panel-empty">No provenance items available.</div>
  }

  return (
    <div className="table-wrap">
      <table className="soc-table">
        <thead>
          <tr>
            <th>Source Model</th>
            <th>Source Object</th>
            <th>Timestamp</th>
            <th>Evidence Summary</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item, index) => (
            <tr key={`${item.source_model}-${item.source_object_id}-${index}`}>
              <td>{item.source_model || '-'}</td>
              <td className="code-cell">{item.source_object_id ?? '-'}</td>
              <td>{item.timestamp ? new Date(item.timestamp).toLocaleString() : '-'}</td>
              <td>{item.evidence_summary || item.summary || '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default EvidencePanel
