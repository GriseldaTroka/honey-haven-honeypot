function DashboardStats({ items = [] }) {
  if (!items.length) {
    return null
  }

  return (
    <div className="dashboard-stats-grid">
      {items.map((item) => (
        <article key={item.label} className={`summary-card ${item.tone || ''}`}>
          <p className="summary-label">{item.label}</p>
          <p className="summary-value">{item.value}</p>
          {item.helper ? <p className="muted-line">{item.helper}</p> : null}
        </article>
      ))}
    </div>
  )
}

export default DashboardStats
