import { useEffect, useState } from 'react'
import ExportMenu from '../components/ExportMenu'
import DashboardStats from '../components/DashboardStats'
import RecentActivity from '../components/RecentActivity'
import RiskOverview from '../components/RiskOverview'
import TrendChart from '../components/TrendChart'
import { getOverview } from '../services/api'

function Dashboard() {
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [overview, setOverview] = useState(null)

  useEffect(() => {
    let cancelled = false

    async function load() {
      setLoading(true)
      setError('')
      try {
        // Do not pass an AbortController.signal here so the shared GET dedupe
        // in `services/api.js` can coalesce duplicate requests (e.g. StrictMode remounts).
        const response = await getOverview(20)
        if (!cancelled) {
          setOverview(response)
        }
      } catch {
        if (!cancelled) {
          setError('Failed to load dashboard overview')
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
      // keep cancelled flag to avoid state updates after unmount
    }
  }, [])

  if (loading) {
    return <section className="panel loading">Loading SOC intelligence...</section>
  }

  const summary = overview?.summary || {}
  const detection = overview?.detection || {}
  const attackFlow = overview?.attack_flow || {}
  const campaignIntelligence = overview?.campaign_intelligence || {}
  const exportPayloads = [
    { label: 'Export overview JSON', filename: 'soc-overview.json', data: overview, format: 'json' },
    { label: 'Export recent sessions CSV', filename: 'recent-sessions.csv', data: overview?.recent_sessions || [], format: 'csv' },
    { label: 'Export recent notes JSON', filename: 'recent-notes.json', data: overview?.recent_notes || [], format: 'json' },
  ]

  return (
    <section className="dashboard-page">
      {error ? (
        <article className="panel warning-banner">
          <h3>Partial Feed Warning</h3>
          <p>{error}</p>
        </article>
      ) : null}

      <div className="dashboard-toolbar">
        <ExportMenu title="Export dashboard" exports={exportPayloads} />
      </div>

      <DashboardStats
        items={[
          { label: 'Sessions', value: summary.session_count || 0, tone: 'info', helper: 'Tracked attacker sessions' },
          { label: 'Journeys', value: summary.journey_count || 0, tone: 'high', helper: 'Reconstructed attack journeys' },
          { label: 'Open Alerts', value: detection.active_alerts || 0, tone: 'critical', helper: 'Alerts requiring triage' },
          { label: 'Campaigns', value: summary.campaign_count || 0, tone: 'warning', helper: 'Correlated campaign clusters' },
        ]}
      />

      <div className="panel-grid two-col">
        <article className="panel">
          <TrendChart title="Risk Over Time" items={attackFlow.risk_over_time || []} labelKey="bucket" valueKey="average_risk" tone="info" />
        </article>

        <article className="panel">
          <RiskOverview title="Highest Risk Campaigns" items={campaignIntelligence.highest_risk_campaigns || []} />
        </article>
      </div>

      <div className="panel-grid two-col">
        <article className="panel">
          <TrendChart
            title="Transition Counts"
            items={(attackFlow.transition_counts || []).map((item) => ({ ...item, label: `${item.from_phase || 'unknown'} → ${item.to_phase || 'unknown'}`, value: item.count }))}
            labelKey="label"
            valueKey="value"
            tone="warning"
          />
        </article>

        <article className="panel">
          <RecentActivity title="Recent Notes" items={overview?.recent_notes || []} emptyLabel="No analyst notes yet." />
        </article>
      </div>

      <div className="panel-grid two-col">
        <article className="panel">
          <RecentActivity title="Recent Bookmarks" items={overview?.recent_bookmarks || []} emptyLabel="No bookmarks yet." />
        </article>

        <article className="panel">
          <RiskOverview title="Recent Campaigns" items={overview?.recent_campaigns || []} emptyLabel="No campaign data available." />
        </article>
      </div>
    </section>
  )
}

export default Dashboard
