function StatCard({ title, value, tone = 'neutral', subtitle }) {
  return (
    <article className={`stat-card ${tone}`}>
      <p className="stat-title">{title}</p>
      <p className="stat-value">{value}</p>
      {subtitle ? <p className="stat-subtitle">{subtitle}</p> : null}
    </article>
  )
}

export default StatCard
