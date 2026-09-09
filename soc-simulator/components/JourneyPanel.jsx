function stageFromText(value) {
  const text = String(value || '').toLowerCase()
  if (text.includes('recon') || text.includes('scan') || text.includes('probe')) return 'Recon'
  if (text.includes('credential') || text.includes('login') || text.includes('auth')) return 'Credential Abuse'
  if (text.includes('sql')) return 'SQL Injection'
  if (text.includes('upload') || text.includes('file')) return 'Upload'
  if (text.includes('privilege') || text.includes('escalation') || text.includes('lateral')) return 'Privilege Escalation'
  return ''
}

function JourneyPanel({ journey }) {
  if (!journey) {
    return <div className="panel-empty">No attack journey available for this session.</div>
  }

  const phases = journey.phases || journey.attack_phases || []
  const stageSet = new Set(phases.map((phase) => stageFromText(typeof phase === 'string' ? phase : phase?.phase || phase?.name || phase?.label)).filter(Boolean))
  const stageOrder = ['Recon', 'Credential Abuse', 'SQL Injection', 'Upload', 'Privilege Escalation']
  const dominantTools = journey.tools_used || []
  const dominantTechniques = phases.map((phase) => (typeof phase === 'string' ? phase : phase?.phase || phase?.name || phase?.label)).filter(Boolean)
  const duration = journey.seconds_spent != null ? `${journey.seconds_spent} sec` : journey.duration_seconds != null ? `${journey.duration_seconds} sec` : '-'

  return (
    <div className="journey-panel">
      <div className="journey-flow">
        {stageOrder.map((stage, index) => (
          <div key={stage} className={`journey-stage ${stageSet.has(stage) ? 'active' : ''}`}>
            <div className="journey-stage-label">{stage}</div>
            {index < stageOrder.length - 1 ? <div className="journey-stage-arrow">↓</div> : null}
          </div>
        ))}
      </div>

      <div className="journey-meta-grid">
        <article><span>Dominant Tools</span><strong>{dominantTools.length ? dominantTools.join(', ') : '-'}</strong></article>
        <article><span>Dominant Techniques</span><strong>{dominantTechniques.length ? dominantTechniques.join(', ') : '-'}</strong></article>
        <article><span>Journey Duration</span><strong>{duration}</strong></article>
      </div>
    </div>
  )
}

export default JourneyPanel
