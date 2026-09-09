function AlertCard({ alert, onSelect, onQuickAction }) {
  const level = String(alert.severity || '').toLowerCase()

  return (
    <article className={`alert-card severity-${level}`}>
      <div className="alert-card-head">
        <div>
          <strong>{alert.rule_name}</strong>
          <p>{alert.description}</p>
        </div>
        <span className={`severity-pill ${level}`}>{alert.severity}</span>
      </div>
      <div className="alert-card-meta">
        <span>{alert.status}</span>
        <span>{alert.session_id || '-'}</span>
        <span>{alert.campaign_id || '-'}</span>
      </div>
      <div className="alert-card-footer">
        <span>{alert.evidence_source_model ? `${alert.evidence_source_model}:${alert.evidence_source_object_id ?? '-'}` : '-'}</span>
        <div className="alert-card-actions">
          <button
            type="button"
            className="soc-button secondary"
            onClick={(event) => {
              event.stopPropagation()
              onQuickAction?.('requeue', alert.id)
            }}
          >
            Requeue
          </button>
          <button
            type="button"
            className="soc-button"
            onClick={(event) => {
              event.stopPropagation()
              onQuickAction?.('reviewed', alert.id)
            }}
          >
            Mark Reviewed
          </button>
          <button type="button" className="soc-button secondary" onClick={() => onSelect?.(alert)}>Triage</button>
        </div>
      </div>
    </article>
  )
}

export default AlertCard
