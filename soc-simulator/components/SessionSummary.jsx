function SessionSummary({ session, journey }) {
  const items = [
    ['Session ID', session?.session_id || journey?.session_id || '-'],
    ['Campaign ID', session?.campaign_id || journey?.campaign_id || '-'],
    ['Current Risk Score', session?.current_risk_score ?? journey?.risk_score ?? '-'],
    ['Confidence', session?.confidence ?? journey?.confidence_score ?? '-'],
    ['Current Attack Phase', session?.current_attack_phase || journey?.intent_label || session?.current_phase || '-'],
    ['First Seen', session?.start_time || journey?.first_seen || '-'],
    ['Last Seen', session?.last_seen || session?.updated_at || journey?.last_seen || '-'],
    ['Duration', session?.duration_seconds != null ? `${Math.round(session.duration_seconds / 60)} min` : journey?.seconds_spent != null ? `${journey.seconds_spent} sec` : '-'],
  ]

  return (
    <div className="summary-grid">
      {items.map(([label, value]) => (
        <article className="summary-card" key={label}>
          <p className="summary-label">{label}</p>
          <p className="summary-value">{value}</p>
        </article>
      ))}
    </div>
  )
}

export default SessionSummary
