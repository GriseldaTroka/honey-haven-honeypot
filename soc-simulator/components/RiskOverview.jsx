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
          {items.map((item) => (
            <article key={String(item?.campaign_id || item?.value || item?.id)} className="risk-overview-item">
              <div>
                <strong>{item.campaign_id || item.value || item.id || '-'}</strong>
                <p>{item.summary || item.description || item.label || item.country || '-'}</p>
              </div>
              <div className="risk-overview-metrics">
                {item.highest_risk_score !== undefined ? <span>Risk {Number(item.highest_risk_score).toFixed(1)}</span> : null}
                {item.count !== undefined ? <span>{item.count} hits</span> : null}
                {item.country ? <span>{item.country}</span> : null}
              </div>
            </article>
          ))}
        </div>
      )}
    </div>
  )
}

export default RiskOverview
