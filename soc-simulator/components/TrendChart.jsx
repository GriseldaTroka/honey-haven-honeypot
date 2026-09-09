function TrendChart({ title, items = [], labelKey = 'label', valueKey = 'value', tone = 'info' }) {
  const total = items.reduce((sum, item) => sum + Number(item?.[valueKey] || 0), 0)

  return (
    <div className="trend-chart">
      <div className="section-header compact">
        <div>
          <h4>{title}</h4>
        </div>
      </div>
      {!items.length ? (
        <div className="panel-empty">No trend data available.</div>
      ) : (
        <div className="trend-bars">
          {items.map((item) => {
            const value = Number(item?.[valueKey] || 0)
            const width = total ? Math.max(8, Math.round((value / total) * 100)) : 8
            return (
              <div key={String(item?.[labelKey] || item?.label || item?.campaign_id || value)} className="trend-row">
                <div className="trend-row-label">
                  <strong>{String(item?.[labelKey] || item?.label || item?.campaign_id || '-')}</strong>
                  <span>{value}</span>
                </div>
                <div className="severity-bar-wrap">
                  <div className={`severity-bar ${tone}`} style={{ width: `${width}%` }} />
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

export default TrendChart
