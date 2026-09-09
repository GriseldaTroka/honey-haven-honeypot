import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import SessionTable from '../components/SessionTable'
import { getSessions } from '../services/api'

const SORT_FIELDS = {
  session_id: 'session_id',
  current_risk_score: 'current_risk_score',
  current_attack_phase: 'current_attack_phase',
  campaign_id: 'campaign_id',
  start_time: 'start_time',
  alert_count: 'alert_count',
}

function Sessions() {
  const navigate = useNavigate()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [sessions, setSessions] = useState([])
  const [query, setQuery] = useState('')
  const [campaignFilter, setCampaignFilter] = useState('all')
  const [phaseFilter, setPhaseFilter] = useState('all')
  const [riskFilter, setRiskFilter] = useState('all')
  const [dateFilter, setDateFilter] = useState('')
  const [sortKey, setSortKey] = useState('current_risk_score')
  const [sortDirection, setSortDirection] = useState('desc')

  useEffect(() => {
    let cancelled = false

    async function load() {
      setLoading(true)
      setError('')
      try {
        const response = await getSessions(1000)
        if (!cancelled) {
          setSessions(response?.sessions || [])
        }
      } catch (loadError) {
        if (!cancelled) {
          setError(loadError.message || 'Failed to load sessions')
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
  }, [])

  const campaigns = useMemo(() => ['all', ...new Set(sessions.map((session) => session.campaign_id).filter(Boolean))], [sessions])
  const phases = useMemo(() => ['all', ...new Set(sessions.map((session) => session.current_attack_phase).filter(Boolean))], [sessions])

  const filteredSessions = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase()
    const threshold = riskFilter === 'all' ? null : Number(riskFilter)

    const rows = sessions.filter((session) => {
      const matchesQuery = !normalizedQuery || [session.session_id, session.campaign_id, session.current_attack_phase].some((value) => String(value || '').toLowerCase().includes(normalizedQuery))
      const matchesCampaign = campaignFilter === 'all' || session.campaign_id === campaignFilter
      const matchesPhase = phaseFilter === 'all' || session.current_attack_phase === phaseFilter
      const matchesRisk = threshold == null ? true : session.current_risk_score >= threshold
      const matchesDate = !dateFilter || String(session.start_time || '').slice(0, 10) === dateFilter
      return matchesQuery && matchesCampaign && matchesPhase && matchesRisk && matchesDate
    })

    rows.sort((left, right) => {
      const key = SORT_FIELDS[sortKey] || sortKey
      const leftValue = left[key]
      const rightValue = right[key]
      const leftComparable = typeof leftValue === 'number' ? leftValue : String(leftValue || '')
      const rightComparable = typeof rightValue === 'number' ? rightValue : String(rightValue || '')
      if (leftComparable === rightComparable) {
        return 0
      }
      const comparison = leftComparable > rightComparable ? 1 : -1
      return sortDirection === 'asc' ? comparison : -comparison
    })

    return rows
  }, [campaignFilter, dateFilter, phaseFilter, query, riskFilter, sessions, sortDirection, sortKey])

  function handleSort(nextKey) {
    setSortDirection((currentDirection) => (sortKey === nextKey ? (currentDirection === 'asc' ? 'desc' : 'asc') : 'desc'))
    setSortKey(nextKey)
  }

  if (loading) {
    return <section className="panel loading">Loading sessions...</section>
  }

  if (error) {
    return <section className="panel error"><h3>Session inventory unavailable</h3><p>{error}</p></section>
  }

  return (
    <section className="panel investigation-section">
      <div className="section-header">
        <div>
          <h3>Session Inventory</h3>
          <p>Search, sort, and filter the attacker sessions collected by the honeypot.</p>
        </div>
        <div className="section-toolbar">
          <input className="soc-input" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search session, campaign, or phase" />
          <select className="soc-input" value={campaignFilter} onChange={(event) => setCampaignFilter(event.target.value)}>
            {campaigns.map((campaign) => <option key={campaign} value={campaign}>{campaign === 'all' ? 'All campaigns' : campaign}</option>)}
          </select>
          <select className="soc-input" value={phaseFilter} onChange={(event) => setPhaseFilter(event.target.value)}>
            {phases.map((phase) => <option key={phase} value={phase}>{phase === 'all' ? 'All phases' : phase}</option>)}
          </select>
          <select className="soc-input" value={riskFilter} onChange={(event) => setRiskFilter(event.target.value)}>
            <option value="all">All risk levels</option>
            <option value="35">Risk 35+</option>
            <option value="65">Risk 65+</option>
            <option value="80">Risk 80+</option>
          </select>
          <input className="soc-input" type="date" value={dateFilter} onChange={(event) => setDateFilter(event.target.value)} />
        </div>
      </div>

      <SessionTable
        rows={filteredSessions}
        sortKey={sortKey}
        sortDirection={sortDirection}
        onSort={handleSort}
        onRowClick={(session) => navigate(`/soc/sessions/${session.session_id}`)}
      />
    </section>
  )
}

export default Sessions
