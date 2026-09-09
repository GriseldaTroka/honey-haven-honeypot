import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import TimelinePanel from '../components/TimelinePanel'
import { getAlertDetail } from '../services/api'

function AlertDetail() {
  const { alertId } = useParams()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [detail, setDetail] = useState(null)

  useEffect(() => {
    let cancelled = false

    async function load() {
      setLoading(true)
      setError('')
      try {
        const response = await getAlertDetail(alertId)
        if (!cancelled) {
          setDetail(response)
        }
      } catch (loadError) {
        if (!cancelled) {
          setError(loadError.message || 'Failed to load alert detail')
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }

    load()
    return () => {
      cancelled = true
    }
  }, [alertId])

  if (loading) {
    return <section className="panel loading">Loading alert detail...</section>
  }

  if (error) {
    return <section className="panel error"><h3>Alert detail unavailable</h3><p>{error}</p></section>
  }

  const alert = detail?.alert || {}
  const timeline = detail?.timeline || []

  return (
    <section className="investigation-section">
      <div className="section-header">
        <div>
          <h3>{alert.rule_name || 'Alert Detail'}</h3>
          <p>Alert {alert.id} with persisted provenance and response context.</p>
        </div>
        <Link className="soc-link" to={`/soc/sessions/${alert.session_id || ''}`}>Back to session</Link>
      </div>

      <div className="summary-grid">
        <article className="summary-card"><p className="summary-label">Severity</p><p className="summary-value">{alert.severity || '-'}</p></article>
        <article className="summary-card"><p className="summary-label">Status</p><p className="summary-value">{alert.status || '-'}</p></article>
        <article className="summary-card"><p className="summary-label">Session</p><p className="summary-value code-cell">{alert.session_id || '-'}</p></article>
        <article className="summary-card"><p className="summary-label">Campaign</p><p className="summary-value code-cell">{detail?.campaign_id || '-'}</p></article>
        <article className="summary-card"><p className="summary-label">Evidence Source</p><p className="summary-value code-cell">{alert.evidence_source_model ? `${alert.evidence_source_model}:${alert.evidence_source_object_id ?? '-'}` : '-'}</p></article>
      </div>

      <div className="panel-grid two-col">
        <article className="panel">
          <h3>Description</h3>
          <p>{alert.description || '-'}</p>
          <p className="muted-line">Evidence summary: {alert.evidence_summary || '-'}</p>
        </article>
        <article className="panel">
          <h3>Related Journey</h3>
          <p className="muted-line">{detail?.journey?.session_id || alert.session_id || '-'}</p>
          <p className="muted-line">{detail?.journey?.intent_label || '-'}</p>
        </article>
      </div>

      <article className="panel">
        <h3>Alert Timeline</h3>
        <TimelinePanel events={timeline} />
      </article>
    </section>
  )
}

export default AlertDetail
