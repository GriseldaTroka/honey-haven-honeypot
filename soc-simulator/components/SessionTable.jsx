function SessionTable({ rows = [], sortKey = 'current_risk_score', sortDirection = 'desc', onSort, onRowClick }) {
  const sortLabel = (key, label) => (
    <button type="button" className="table-sort-button" onClick={() => onSort?.(key)}>
      {label}
      {sortKey === key ? <span>{sortDirection === 'asc' ? ' ▲' : ' ▼'}</span> : null}
    </button>
  )

  if (!rows.length) {
    return <div className="panel-empty">No attacker sessions match the current filters.</div>
  }

  return (
    <div className="table-wrap">
      <table className="soc-table clickable">
        <thead>
          <tr>
            <th>{sortLabel('session_id', 'Session ID')}</th>
            <th>{sortLabel('current_risk_score', 'Current Risk Score')}</th>
            <th>{sortLabel('current_attack_phase', 'Current Attack Phase')}</th>
            <th>{sortLabel('campaign_id', 'Campaign ID')}</th>
            <th>{sortLabel('start_time', 'Start Time')}</th>
            <th>{sortLabel('alert_count', 'Detection Alerts')}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.session_id} onClick={() => onRowClick?.(row)}>
              <td className="code-cell">{row.session_id}</td>
              <td><span className={`severity-pill ${row.current_risk_score >= 80 ? 'critical' : row.current_risk_score >= 65 ? 'high' : row.current_risk_score >= 35 ? 'medium' : 'low'}`}>{row.current_risk_score}</span></td>
              <td>{row.current_attack_phase || row.current_phase || '-'}</td>
              <td>{row.campaign_id || '-'}</td>
              <td>{row.start_time ? new Date(row.start_time).toLocaleString() : '-'}</td>
              <td>{row.alert_count ?? 0}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default SessionTable
