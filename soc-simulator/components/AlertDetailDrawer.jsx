function AlertDetailDrawer({ alert, detail, onClose, onStatusChange, onQuickAction }) {
  if (!alert) {
    return null
  }

  const activeDetail = detail || {}
  const timeline = activeDetail.timeline || []
  // Prefer authoritative evidence from `detail` payload when present.
  // Show a clean "No evidence available" state when nothing meaningful is present
  // and avoid rendering internal verification/debug tokens as evidence.
  function isDebugEvidence(text) {
    if (!text) return false
    const t = String(text).trim().toLowerCase()
    if (!t) return false
    if (t === '-' || t === 'verify detail get' || t.includes('verify detail')) return true
    return false
  }

  let evidenceSummary = '-'
  if (activeDetail.alert && Array.isArray(activeDetail.alert.evidence) && activeDetail.alert.evidence.length) {
    // Prefer structured evidence items returned by the detail API
    evidenceSummary = activeDetail.alert.evidence.map((e) => e.summary || e.message || '').filter(Boolean).join('; ') || '-'
  } else if (activeDetail.alert && activeDetail.alert.evidence_summary && !isDebugEvidence(activeDetail.alert.evidence_summary)) {
    evidenceSummary = activeDetail.alert.evidence_summary
  } else if (alert.evidence_summary && !isDebugEvidence(alert.evidence_summary)) {
    evidenceSummary = alert.evidence_summary
  } else if (alert.description && !isDebugEvidence(alert.description)) {
    evidenceSummary = alert.description
  } else {
    evidenceSummary = 'No evidence available'
  }

  const evidenceSource = (activeDetail.alert && activeDetail.alert.evidence_source_model) ? `${activeDetail.alert.evidence_source_model}:${activeDetail.alert.evidence_source_object_id ?? '-'}` : (alert.evidence_source_model ? `${alert.evidence_source_model}:${alert.evidence_source_object_id ?? '-'}` : '-')

  return (
    <aside className="alert-drawer">
      <div className="alert-drawer-header">
        <div>
          <p className="summary-label">Triage Detail</p>
          <h3>{alert.rule_name}</h3>
        </div>
        <button type="button" className="soc-button secondary" onClick={onClose}>Close</button>
      </div>

      <div className="summary-grid drawer-grid">
        <article className="summary-card"><p className="summary-label">Severity</p><p className="summary-value">{alert.severity}</p></article>
        <article className="summary-card"><p className="summary-label">Status</p><p className="summary-value">{alert.status}</p></article>
        <article className="summary-card"><p className="summary-label">Session</p><p className="summary-value code-cell">{alert.session_id || '-'}</p></article>
        <article className="summary-card"><p className="summary-label">Campaign</p><p className="summary-value code-cell">{alert.campaign_id || '-'}</p></article>
      </div>

      <div className="drawer-actions">
        <button type="button" className="soc-button secondary" onClick={() => onQuickAction?.('requeue', alert.id)}>
          Requeue
        </button>
        <button type="button" className="soc-button" onClick={() => onQuickAction?.('reviewed', alert.id)}>
          Mark Reviewed
        </button>
        {['OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'].map((status) => (
          <button key={status} type="button" className="soc-button secondary" onClick={() => onStatusChange?.(status)}>
            {status.replaceAll('_', ' ')}
          </button>
        ))}
      </div>

      <section className="drawer-section">
        <h4>Evidence</h4>
        <p>{evidenceSummary}</p>
        <p className="muted-line">{evidenceSource}</p>
      </section>

      <section className="drawer-section">
        <h4>Timeline</h4>
        {!timeline.length ? (
          <div className="panel-empty">No timeline entries available.</div>
        ) : (
          <div className="drawer-timeline">
            {timeline.map((item, index) => (
              <article key={`${item.timestamp}-${index}`} className="drawer-timeline-item">
                <strong>{item.event_type || item.kind || 'event'}</strong>
                <p>{item.summary || item.detail || '-'}</p>
                <span>{item.timestamp ? new Date(item.timestamp).toLocaleString() : '-'}</span>
              </article>
            ))}
          </div>
        )}
      </section>
    </aside>
  )
}

export default AlertDetailDrawer
