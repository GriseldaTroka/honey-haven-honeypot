function CampaignCard({ campaign, sessionSummary }) {
  if (!campaign && !sessionSummary) {
    return <div className="panel-empty">No campaign data available for this session.</div>
  }

  const summary = campaign?.summary || campaign || {}
  const relatedSessions = campaign?.sessions || []
  // Smallest-change mapping: support both campaign.sessions (array) and flat summary.total_sessions
  const relatedSessionsCount = Array.isArray(relatedSessions) && relatedSessions.length ? relatedSessions.length : (summary.total_sessions ?? '-')
  const sharedIocs = campaign?.ioc_statistics?.top_ioc_types || summary.dominant_ioc_types || []
  const sharedTools = summary.dominant_tools || []
  const sharedPhases = summary.dominant_attack_phases || []

  return (
    <div className="campaign-card-grid">
      <article className="summary-card wide">
        <p className="summary-label">Campaign ID</p>
        <p className="summary-value code-cell">{summary.campaign_id || sessionSummary?.campaign_id || '-'}</p>
      </article>
      <article className="summary-card">
        <p className="summary-label">Related Sessions</p>
        <p className="summary-value">{relatedSessionsCount}</p>
      </article>
      <article className="summary-card">
        <p className="summary-label">Shared IOCs</p>
        <p className="summary-value">{sharedIocs.length ? sharedIocs.join(', ') : '-'}</p>
      </article>
      <article className="summary-card">
        <p className="summary-label">Shared Tools</p>
        <p className="summary-value">{sharedTools.length ? sharedTools.join(', ') : '-'}</p>
      </article>
      <article className="summary-card">
        <p className="summary-label">Shared Attack Phases</p>
        <p className="summary-value">{sharedPhases.length ? sharedPhases.join(', ') : '-'}</p>
      </article>
    </div>
  )
}

export default CampaignCard
