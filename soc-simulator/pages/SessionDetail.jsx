import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import AlertTable from '../components/AlertTable'
import CampaignCard from '../components/CampaignCard'
import EvidencePanel from '../components/EvidencePanel'
import ExportMenu from '../components/ExportMenu'
import JourneyPanel from '../components/JourneyPanel'
import IOCTable from '../components/IOCTable'
import RelationshipGraph from '../components/RelationshipGraph'
import SessionSummary from '../components/SessionSummary'
import TimelinePanel from '../components/TimelinePanel'
import { getAlerts, getCampaignDetail, getInvestigationGraph, getSessionIocs, getSessionJourney, getTimeline, getAttackerState } from '../services/api'

const SECTION_LINKS = [
  ['overview', 'Overview'],
  ['timeline', 'Timeline'],
  ['journey', 'Journey'],
  ['iocs', 'IOCs'],
  ['alerts', 'Alerts'],
  ['evidence', 'Evidence'],
  ['campaign', 'Campaign'],
  ['relationships', 'Relationships'],
]

function SessionDetail() {
  const { sessionId } = useParams()
  const navigate = useNavigate()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [sessionRecord, setSessionRecord] = useState(null)
  const [journey, setJourney] = useState(null)
  const [timeline, setTimeline] = useState([])
  const [iocs, setIocs] = useState([])
  const [alerts, setAlerts] = useState([])
  const [campaign, setCampaign] = useState(null)
  const [graph, setGraph] = useState({ nodes: [], edges: [] })

  useEffect(() => {
    let cancelled = false

    async function load() {
      setLoading(true)
      setError('')
      try {
        const [stateRes, journeyRes, timelineRes, iocRes, alertRes, graphRes] = await Promise.allSettled([
          getAttackerState(sessionId),
          getSessionJourney(sessionId),
          getTimeline(300, sessionId),
          getSessionIocs(sessionId),
          getAlerts(sessionId),
          getInvestigationGraph(250, sessionId),
        ])

        const sessionState = stateRes.status === 'fulfilled' ? stateRes.value || null : null
        const journeyData = journeyRes.status === 'fulfilled' ? journeyRes.value : null
        const timelineData = timelineRes.status === 'fulfilled' ? timelineRes.value?.events || [] : []
        const iocData = iocRes.status === 'fulfilled' ? iocRes.value?.iocs || [] : []
        const alertData = alertRes.status === 'fulfilled' ? alertRes.value?.alerts || [] : []
        const graphData = graphRes.status === 'fulfilled' ? graphRes.value || { nodes: [], edges: [] } : { nodes: [], edges: [] }

        let campaignData = null
        if (journeyData?.campaign_id) {
          try {
            campaignData = await getCampaignDetail(journeyData.campaign_id)
          } catch {
            campaignData = null
          }
        }

        if (!cancelled) {
          const mappedSession = sessionState
            ? {
                session_id: sessionState.session_id,
                campaign_id: sessionState.campaign_id,
                current_risk_score: sessionState.risk_score != null ? Math.round(Number(sessionState.risk_score) * 100) / 100 : null,
                confidence: sessionState.confidence_score || sessionState.intent_score || null,
                current_attack_phase: sessionState.current_phase || null,
                start_time: sessionState.start_time || null,
                updated_at: sessionState.updated_at || sessionState.last_observed_at || null,
                duration_seconds: sessionState.duration_seconds || null,
                }
                : null
          
              setSessionRecord(mappedSession)
          setJourney(journeyData)
          setTimeline(timelineData)
          setIocs(iocData)
          setAlerts(alertData)
          setGraph(graphData)
          setCampaign(campaignData)

          if ([stateRes, journeyRes, timelineRes, iocRes, alertRes, graphRes].some((result) => result.status === 'rejected')) {
            setError('Some feeds are unavailable. Showing the data that loaded successfully.')
          }
        }
      } catch (loadError) {
        if (!cancelled) {
          setError(loadError.message || 'Failed to load session detail')
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
  }, [sessionId])

  const evidenceItems = useMemo(() => {
    const iocEvidence = iocs.map((ioc) => ({
      source_model: ioc.source_model,
      source_object_id: ioc.source_object_id,
      timestamp: ioc.first_seen,
      evidence_summary: ioc.evidence_summary,
    }))
    const alertEvidence = alerts.map((alert) => ({
      source_model: alert.evidence_source_model,
      source_object_id: alert.evidence_source_object_id,
      timestamp: alert.created_at,
      evidence_summary: alert.evidence_summary || alert.description,
    }))
    return [...iocEvidence, ...alertEvidence].filter((item) => item.source_model || item.source_object_id || item.evidence_summary)
  }, [alerts, iocs])

  const relatedCampaignSessions = campaign?.sessions || []
  const exportPayloads = [
    { label: 'Export session JSON', filename: `${sessionId}.json`, data: { session: sessionRecord, journey, timeline, iocs, alerts, campaign }, format: 'json' },
    { label: 'Export evidence CSV', filename: `${sessionId}-evidence.csv`, data: evidenceItems, format: 'csv' },
  ]

  if (loading) {
    return <section className="panel loading">Loading session investigation...</section>
  }

  return (
    <section className="investigation-layout">
      <aside className="investigation-nav panel">
        {SECTION_LINKS.map(([anchor, label]) => (
          <a key={anchor} href={`#${anchor}`} className="investigation-nav-link">{label}</a>
        ))}
      </aside>

      <main className="investigation-workspace">
        {error ? <article className="panel warning-banner"><h3>Partial feed warning</h3><p>{error}</p></article> : null}

        <article className="panel investigation-section" id="overview">
          <div className="section-header">
            <div>
              <h3>Session Summary</h3>
              <p>Primary analyst investigation context for {sessionId}.</p>
            </div>
            <div className="section-toolbar">
              <ExportMenu title="Export session" exports={exportPayloads} />
              <Link className="soc-link" to="/soc/sessions">Back to session inventory</Link>
            </div>
          </div>
          <SessionSummary session={sessionRecord} journey={journey?.journey || journey} />
        </article>

        <article className="panel investigation-section" id="timeline">
          <div className="section-header"><div><h3>Attack Timeline</h3><p>Chronological event replay for this session.</p></div></div>
          <TimelinePanel events={timeline} />
        </article>

        <article className="panel investigation-section" id="journey">
          <div className="section-header"><div><h3>Attack Journey</h3><p>Journey reconstruction from the backend intelligence layer.</p></div></div>
          <JourneyPanel journey={journey?.journey ? journey.journey : journey} />
        </article>

        <article className="panel investigation-section" id="iocs">
          <div className="section-header"><div><h3>IOC Panel</h3><p>Session IOC provenance and persistence details.</p></div></div>
          <IOCTable iocs={iocs} onRowClick={(ioc) => navigate(`/soc/ioc/${ioc.id}`)} />
        </article>

        <article className="panel investigation-section" id="alerts">
          <div className="section-header"><div><h3>Detection Alerts</h3><p>Alerts correlated to this session.</p></div></div>
          <AlertTable alerts={alerts} onRowClick={(alert) => navigate(`/soc/alerts/${alert.id}`)} />
        </article>

        <article className="panel investigation-section" id="evidence">
          <div className="section-header"><div><h3>Evidence Viewer</h3><p>Persisted object provenance surfaced directly from existing records.</p></div></div>
          <EvidencePanel items={evidenceItems} />
        </article>

        <article className="panel investigation-section" id="campaign">
          <div className="section-header"><div><h3>Campaign Information</h3><p>Campaign context shared across related sessions.</p></div></div>
          <CampaignCard campaign={campaign} sessionSummary={sessionRecord} />
          <div className="related-session-strip">
            {relatedCampaignSessions.map((relatedSession) => (
              <Link key={relatedSession} className="related-session-chip" to={`/soc/sessions/${relatedSession}`}>
                {relatedSession}
              </Link>
            ))}
          </div>
        </article>

        <article className="panel investigation-section" id="relationships">
          <div className="section-header"><div><h3>Relationship Graph</h3><p>Session, journey, IOC, campaign, and alert connectivity.</p></div></div>
          <RelationshipGraph graph={graph} />
        </article>
      </main>
    </section>
  )
}

export default SessionDetail
