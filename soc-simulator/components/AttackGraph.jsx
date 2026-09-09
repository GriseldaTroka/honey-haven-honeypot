function AttackGraph({ alertsBySeverity = [] }) {
  const total = alertsBySeverity.reduce((acc, item) => acc + (item.total || 0), 0)

  if (!alertsBySeverity.length) {
    return <div className="panel-empty">No severity distribution available.</div>
  }

  return (
    <div className="severity-chart">
      {alertsBySeverity.map((item) => {
        const width = total ? Math.max(8, Math.round((item.total / total) * 100)) : 8
        const level = String(item.severity || '').toLowerCase()
        return (
          <div key={item.severity} className="severity-row">
            <span className="severity-label">{item.severity}</span>
            <div className="severity-bar-wrap">
              <div className={`severity-bar ${level}`} style={{ width: `${width}%` }} />
            </div>
            <span className="severity-count">{item.total}</span>
          </div>
        )
      })}
    </div>
  )
}

export default AttackGraph
