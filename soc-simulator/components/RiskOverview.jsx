function RiskOverview({ title, items = [], emptyLabel = 'No risk data available.' }) {
  return (
    <div className="risk-overview">
      <div className="section-header compact">
        <div>
          <h4>{title}</h4>
        </div>
      </div>
      {!items.length ? (
        <div className="panel-empty">{emptyLabel}</div>
      ) : (
        <div className="risk-overview-list">
          {items.map((item) => {
            const score = item.highest_risk_score !== undefined ? item.highest_risk_score : item.average_risk_score !== undefined ? item.average_risk_score : null
            // build a useful secondary description from available campaign fields
            let secondary = item.summary || item.description || item.label || ''
            if (!secondary) {
              if (item.dominant_attack_phases && item.dominant_attack_phases.length) {
                secondary = String(item.dominant_attack_phases.slice(0, 3).join(', '))
              } else if (item.total_journeys != null || item.total_sessions != null) {
                const j = item.total_journeys != null ? `${item.total_journeys} journeys` : null
                const s = item.total_sessions != null ? `${item.total_sessions} sessions` : null
                secondary = [j, s].filter(Boolean).join(' • ') || ''
              }
            }
            if (!secondary) secondary = 'Campaign intelligence available'

            return (
              <article key={String(item?.campaign_id || item?.value || item?.id)} className="risk-overview-item">
                <div>
                  <strong>{item.campaign_id || item.value || item.id || '-'}</strong>
                  <p>{secondary}</p>
                </div>
                <div className="risk-overview-metrics">
                  {score !== null && score !== undefined ? <span>Risk {Number(score).toFixed(1)}</span> : null}
                  {item.count !== undefined ? <span>{item.count} hits</span> : null}
                  {item.country ? <span>{item.country}</span> : null}
                </div>
              </article>
            )
          })}
        </div>
      )}
    </div>
  )
}

export default RiskOverview
