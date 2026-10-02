import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'

function severityForEvent(event) {
  const kind = String(event.kind || event.event_type || '').toLowerCase()
  if (kind.includes('alert') || kind.includes('detection') || kind.includes('sql') || kind.includes('upload')) {
    return 'critical'
  }
  if (kind.includes('login') || kind.includes('journey') || kind.includes('request')) {
    return 'high'
  }
  if (kind.includes('telemetry') || kind.includes('support')) {
    return 'medium'
  }
  return 'low'
}

function summarizeEvents(events) {
  const total = events.length
  const alerts = events.filter((event) => {
    const kind = String(event.kind || event.event_type || '').toLowerCase()
    return kind.includes('alert') || kind.includes('detection')
  }).length
  const sessions = new Set(events.map((event) => event.session_id).filter(Boolean)).size
  const pages = events.filter((event) => {
    const kind = String(event.kind || event.event_type || '').toLowerCase()
    return kind.includes('page') || kind.includes('request') || kind.includes('visit')
  }).length
  const logins = events.filter((event) => {
    const kind = String(event.kind || event.event_type || '').toLowerCase()
    return kind.includes('login') || kind.includes('auth')
  }).length
  const telemetry = events.filter((event) => {
    const kind = String(event.kind || event.event_type || '').toLowerCase()
    return kind.includes('telemetry') || kind.includes('fingerprint') || kind.includes('system')
  }).length
  const journeys = events.filter((event) => {
    const kind = String(event.kind || event.event_type || '').toLowerCase()
    return kind.includes('journey') || kind.includes('phase') || kind.includes('escalation')
  }).length

  return { total, alerts, sessions, pages, logins, telemetry, journeys }
}

function TimelinePanel({ events = [], loading = false, error = '' }) {
  const [expanded, setExpanded] = useState(null)
  const [ipFilter, setIpFilter] = useState('')
  const [sessionFilter, setSessionFilter] = useState('')
  const [attackFilter, setAttackFilter] = useState('all')
  const [speed, setSpeed] = useState(1)
  const [isPlaying, setIsPlaying] = useState(false)
  const [focusedIndex, setFocusedIndex] = useState(0)

  const sortedEvents = useMemo(
    () => [...events].sort((left, right) => String(left.timestamp || '').localeCompare(String(right.timestamp || ''))),
    [events],
  )

  const typeOptions = useMemo(
    () => ['all', ...new Set(sortedEvents.map((event) => String(event.kind || event.event_type || '').trim()).filter(Boolean))],
    [sortedEvents],
  )

  const filteredEvents = useMemo(() => {
    const ipMatch = ipFilter.trim().toLowerCase()
    const sessionMatch = sessionFilter.trim().toLowerCase()
    const attackMatch = attackFilter.toLowerCase()

    return sortedEvents.filter((event) => {
      const haystack = [
        event.ip,
        event.ip_address,
        event.source,
        event.summary,
        event.detail,
        event.kind,
        event.event_type,
        event.session_id,
        event.campaign_id,
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase()

      if (ipMatch && !haystack.includes(ipMatch)) {
        return false
      }
      if (sessionMatch && !(event.session_id || '').toLowerCase().includes(sessionMatch)) {
        return false
      }
      if (attackMatch !== 'all') {
        const normalizedKind = String(event.kind || event.event_type || '').toLowerCase()
        if (!normalizedKind.includes(attackMatch.toLowerCase())) {
          return false
        }
      }
      return true
    })
  }, [attackFilter, ipFilter, sessionFilter, sortedEvents])

  const summary = useMemo(() => summarizeEvents(filteredEvents), [filteredEvents])
  const activeEvent = filteredEvents[focusedIndex] || null

  useEffect(() => {
    if (!filteredEvents.length) {
      setFocusedIndex(0)
      setIsPlaying(false)
      return
    }

    setFocusedIndex((current) => Math.min(current, filteredEvents.length - 1))
  }, [filteredEvents])

  useEffect(() => {
    if (!isPlaying || !filteredEvents.length) {
      return undefined
    }

    const intervalMs = Math.max(250, 1250 / speed)
    const timer = setInterval(() => {
      setFocusedIndex((current) => {
        if (current >= filteredEvents.length - 1) {
          setIsPlaying(false)
          return current
        }
        return current + 1
      })
    }, intervalMs)

    return () => clearInterval(timer)
  }, [filteredEvents.length, isPlaying, speed])

  if (loading) {
    return <div className="panel-empty">Loading timeline...</div>
  }

  if (error) {
    return <div className="panel-empty">{error}</div>
  }

  if (!sortedEvents.length) {
    return <div className="panel-empty">No timeline events found for this session.</div>
  }

  return (
    <div className="timeline-panel">
      <div className="timeline-summary-grid">
        <div className="summary-card">
          <span className="summary-label">Events</span>
          <p className="summary-value">{summary.total}</p>
        </div>
        <div className="summary-card">
          <span className="summary-label">Alerts</span>
          <p className="summary-value">{summary.alerts}</p>
        </div>
        <div className="summary-card">
          <span className="summary-label">Sessions</span>
          <p className="summary-value">{summary.sessions}</p>
        </div>
        <div className="summary-card">
          <span className="summary-label">Focus</span>
          <p className="summary-value">{activeEvent ? activeEvent.event_type || activeEvent.kind || 'event' : 'none'}</p>
        </div>
      </div>

      <div className="timeline-filter-bar">
        <input className="soc-input" value={ipFilter} onChange={(event) => setIpFilter(event.target.value)} placeholder="Filter by IP or source" />
        <input className="soc-input" value={sessionFilter} onChange={(event) => setSessionFilter(event.target.value)} placeholder="Filter by session" />
        <select className="soc-input" value={attackFilter} onChange={(event) => setAttackFilter(event.target.value)}>
          {typeOptions.map((value) => (
            <option key={value} value={value}>{value === 'all' ? 'All attack types' : value}</option>
          ))}
        </select>
      </div>

      <div className="timeline-replay-controls">
        <button type="button" className="soc-button secondary" onClick={() => setIsPlaying(true)}>Play</button>
        <button type="button" className="soc-button secondary" onClick={() => setIsPlaying(false)}>Pause</button>
        <label className="timeline-speed-label" htmlFor="timeline-speed">Speed</label>
        <select id="timeline-speed" className="soc-input timeline-speed-select" value={speed} onChange={(event) => setSpeed(Number(event.target.value))}>
          <option value={1}>1x</option>
          <option value={2}>2x</option>
          <option value={4}>4x</option>
        </select>
      </div>

      {activeEvent ? (
        <div className="timeline-focus-card">
          <div className="timeline-focus-header">
            <strong>{activeEvent.event_type || activeEvent.kind || 'event'}</strong>
            <span className={`severity-pill ${activeEvent.severity || severityForEvent(activeEvent)}`}>
              {(activeEvent.severity || severityForEvent(activeEvent)).toUpperCase()}
            </span>
          </div>
          <p>{activeEvent.summary || activeEvent.detail || 'No evidence summary available.'}</p>
          <div className="timeline-focus-meta">
            <span>{activeEvent.timestamp ? new Date(activeEvent.timestamp).toLocaleString() : 'Unknown time'}</span>
            <span>{activeEvent.source || 'unknown source'}</span>
          </div>
          {activeEvent.session_id && activeEvent.session_id_is_canonical ? (
            <Link className="soc-link" to={`/soc/sessions/${activeEvent.session_id}`}>
              Open session {activeEvent.session_id}
            </Link>
          ) : null}
        </div>
      ) : null}

      <div className="timeline-list investigation-timeline">
        {filteredEvents.map((event, index) => {
          const eventId = `${event.timestamp}-${event.kind}-${index}`
          const isOpen = expanded === eventId
          const severity = event.severity || severityForEvent(event)
          return (
            <article className={`timeline-event ${isOpen ? 'open' : ''}`} key={eventId}>
              <button type="button" className="timeline-event-trigger" onClick={() => {
                setExpanded(isOpen ? null : eventId)
                setFocusedIndex(index)
              }}>
                <div className={`timeline-badge ${severity}`} />
                <div className="timeline-event-header">
                  <div className="timeline-event-title-row">
                    <span className="timeline-event-title">{event.event_type || event.kind || 'event'}</span>
                    <span className={`severity-pill ${severity}`}>{severity.toUpperCase()}</span>
                  </div>
                  <div className="timeline-event-meta">
                    <span>{event.timestamp ? new Date(event.timestamp).toLocaleString() : 'Unknown time'}</span>
                    <span>{event.source || 'unknown source'}</span>
                  </div>
                  <p className="timeline-detail">{event.summary || event.detail || 'No evidence summary available.'}</p>
                </div>
              </button>
              {isOpen ? (
                <div className="timeline-event-body">
                  <div><span>Session</span><strong>{event.session_id || '-'}</strong></div>
                  <div><span>Campaign</span><strong>{event.campaign_id || '-'}</strong></div>
                  <div><span>Kind</span><strong>{event.kind || '-'}</strong></div>
                  <div><span>Source</span><strong>{event.source || '-'}</strong></div>
                </div>
              ) : null}
            </article>
          )
        })}
      </div>

      {!filteredEvents.length ? <div className="panel-empty">No timeline events match the active filters.</div> : null}
    </div>
  )
}

export default TimelinePanel
