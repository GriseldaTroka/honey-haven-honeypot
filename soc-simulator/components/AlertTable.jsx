function AlertTable({ alerts = [], onRowClick }) {
  if (!alerts.length) {
    return <div className="panel-empty">No detections available.</div>
  }

  return (
    <div className="table-wrap">
      <table className="soc-table">
        <thead>
          <tr>
            <th>Rule</th>
            <th>Severity</th>
            <th>Status</th>
            <th>Session</th>
            <th>Campaign</th>
            <th>Evidence Source</th>
            <th>Created</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => {
            const severity = String(alert.severity || '').toLowerCase()
            return (
              <tr key={alert.id} onClick={() => onRowClick?.(alert)}>
                <td>{alert.rule_name}</td>
                <td>
                  <span className={`severity-pill ${severity}`}>{alert.severity}</span>
                </td>
                <td>{alert.status}</td>
                <td className="code-cell">{alert.session_id || '-'}</td>
                <td>{alert.campaign_id || '-'}</td>
                <td className="code-cell">
                  {alert.evidence_source_model ? `${alert.evidence_source_model}:${alert.evidence_source_object_id ?? '-'}` : '-'}
                </td>
                <td>{alert.created_at ? new Date(alert.created_at).toLocaleString() : '-'}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

export default AlertTable
