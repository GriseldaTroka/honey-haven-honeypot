import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { getIocDetail, getIocEvidence, getIocRelationships } from '../services/api'

function IOCDetail() {
  const { iocId } = useParams()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [detail, setDetail] = useState(null)
  const [relationships, setRelationships] = useState(null)
  const [evidence, setEvidence] = useState(null)

  useEffect(() => {
    let cancelled = false

    async function load() {
      setLoading(true)
      setError('')
      try {
        const [detailRes, relationshipsRes, evidenceRes] = await Promise.all([
          getIocDetail(iocId),
          getIocRelationships(iocId),
          getIocEvidence(iocId),
        ])
        if (!cancelled) {
          setDetail(detailRes)
          setRelationships(relationshipsRes)
          setEvidence(evidenceRes)
        }
      } catch (loadError) {
        if (!cancelled) {
          setError(loadError.message || 'Failed to load IOC detail')
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
  }, [iocId])

  if (loading) {
    return <section className="panel loading">Loading IOC detail...</section>
  }

  if (error) {
    return <section className="panel error"><h3>IOC detail unavailable</h3><p>{error}</p></section>
  }

  const ioc = detail || {}

  return (
    <section className="investigation-section">
      <div className="section-header">
        <div>
          <h3>{ioc.ioc_value || 'IOC Detail'}</h3>
          <p>Provenance and relationship context for the persisted IOC.</p>
        </div>
        <Link className="soc-link" to={`/soc/sessions/${ioc.session_id || ''}`}>Back to session</Link>
      </div>

      <div className="summary-grid">
        <article className="summary-card"><p className="summary-label">IOC Type</p><p className="summary-value">{ioc.ioc_type || '-'}</p></article>
        <article className="summary-card"><p className="summary-label">Confidence</p><p className="summary-value">{ioc.confidence_score ?? '-'}</p></article>
        <article className="summary-card"><p className="summary-label">Session</p><p className="summary-value code-cell">{ioc.session_id || '-'}</p></article>
        <article className="summary-card"><p className="summary-label">Campaign</p><p className="summary-value code-cell">{ioc.campaign_id || '-'}</p></article>
      </div>

      <div className="panel-grid two-col">
        <article className="panel">
          <h3>Provenance</h3>
          <p className="muted-line">{ioc.provenance?.source_model || ioc.source_model || '-'}</p>
          <p className="muted-line">{ioc.provenance?.source_object_id ?? ioc.source_object_id ?? '-'}</p>
          <p>{ioc.provenance?.evidence_summary || ioc.evidence_summary || '-'}</p>
        </article>
        <article className="panel">
          <h3>Relationships</h3>
          <p className="muted-line">Shared sessions: {relationships?.shared_sessions ?? '-'}</p>
          <p className="muted-line">Shared journeys: {relationships?.shared_journeys ?? '-'}</p>
          <p className="muted-line">Shared campaigns: {relationships?.shared_campaigns ?? '-'}</p>
        </article>
      </div>

      <article className="panel">
        <h3>Evidence Bundle</h3>
        <div className="table-wrap">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Source Model</th>
                <th>Source Object</th>
                <th>Timestamp</th>
                <th>Evidence Summary</th>
              </tr>
            </thead>
            <tbody>
              {(evidence?.evidence_objects || []).map((item, index) => (
                <tr key={`${item.source_model}-${item.source_object_id}-${index}`}>
                  <td>{item.source_model || '-'}</td>
                  <td className="code-cell">{item.source_object_id ?? '-'}</td>
                  <td>{item.timestamp ? new Date(item.timestamp).toLocaleString() : '-'}</td>
                  <td>{item.evidence_summary || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </article>
    </section>
  )
}

export default IOCDetail
