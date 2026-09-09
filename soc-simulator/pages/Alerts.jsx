import { useEffect, useMemo, useState } from 'react'
import AlertCard from '../components/AlertCard'
import AlertDetailDrawer from '../components/AlertDetailDrawer'
import AlertFilters from '../components/AlertFilters'
import ExportMenu from '../components/ExportMenu'
import { getAlertDetail, getCampaigns, getFilteredAlerts, updateAlertStatus } from '../services/api'

function summarizeAlertReviewCounts(items = []) {
  return items.reduce((totals, alert) => {
    const status = String(alert.status || '').toUpperCase()
    if (status === 'OPEN') {
      totals.pending += 1
    } else if (status === 'INVESTIGATING') {
      totals.sent += 1
    } else if (status === 'RESOLVED' || status === 'FALSE_POSITIVE') {
      totals.reviewed += 1
    }
    return totals
  }, { pending: 0, sent: 0, reviewed: 0 })
}

function Alerts() {
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [campaignError, setCampaignError] = useState('')
  const [alerts, setAlerts] = useState([])
  const [campaigns, setCampaigns] = useState([])
  const [selectedAlert, setSelectedAlert] = useState(null)
  const [selectedDetail, setSelectedDetail] = useState(null)
  const [filters, setFilters] = useState({ search: '', severity: '', status: '', campaign: '', date_from: '', date_to: '' })

  useEffect(() => {
    let cancelled = false
    const currentFilters = { ...filters }

    async function load() {
      setLoading(true)
      setError('')
      try {
        const alertResponse = await getFilteredAlerts(currentFilters)
        if (cancelled) {
          return
        }
        setAlerts(alertResponse?.alerts || [])
      } catch (loadError) {
        if (!cancelled) {
          setError(loadError.message || 'Failed to load alerts')
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
  }, [filters])

  useEffect(() => {
    let cancelled = false

    async function loadCampaigns() {
      try {
        const campaignResponse = await getCampaigns(100)
        if (!cancelled) {
          const campaignIds = (campaignResponse?.campaigns || []).map((item) => item.campaign_id).filter(Boolean)
          setCampaigns(Array.from(new Set(campaignIds)))
          setCampaignError('')
        }
      } catch (loadError) {
        if (!cancelled) {
          setCampaigns([])
          setCampaignError(loadError.message || 'Failed to load campaign filters')
        }
      }
    }

    loadCampaigns()
    return () => {
      cancelled = true
    }
  }, [])

  const alertReviewCounts = useMemo(() => summarizeAlertReviewCounts(alerts), [alerts])

  const exportPayloads = useMemo(() => ([
    { label: 'Export alerts JSON', filename: 'alerts.json', data: alerts, format: 'json' },
    { label: 'Export alerts CSV', filename: 'alerts.csv', data: alerts, format: 'csv' },
  ]), [alerts])

  async function openAlert(alert) {
    setSelectedAlert(alert)
    setSelectedDetail(null)
    try {
      const response = await getAlertDetail(alert.id)
      setSelectedDetail(response)
    } catch {
      setSelectedDetail(null)
    }
  }

  async function updateAlertInState(alertId, nextStatus) {
    try {
      const response = await updateAlertStatus(alertId, nextStatus)
      setSelectedAlert((current) => (current ? { ...current, status: nextStatus } : current))
      // If we have a detailed payload open, refresh it from the server response
      setSelectedDetail((current) => (current ? (response?.alert ? { ...current, alert: response.alert } : current) : current))
      setAlerts((current) => current.map((alert) => (alert.id === alertId ? { ...alert, status: nextStatus } : alert)))
      return true
    } catch (updateError) {
      setError(updateError.message || 'Failed to update alert status')
      return false
    }
  }

  async function handleStatusChange(status) {
    if (!selectedAlert) {
      return
    }
    await updateAlertInState(selectedAlert.id, status)
  }

  async function handleQuickAction(action, alertId) {
    const nextStatus = action === 'requeue' ? 'OPEN' : 'RESOLVED'
    await updateAlertInState(alertId, nextStatus)
  }

  if (loading) {
    return <section className="panel loading">Loading detections...</section>
  }

  if (error) {
    return <section className="panel error"><h3>Alerts unavailable</h3><p>{error}</p></section>
  }

  return (
    <section className="investigation-section">
      <div className="section-header">
        <div>
          <h3>Alert Review Console</h3>
          <p>Review, requeue, and mark honeypot alerts as handled.</p>
        </div>
        <div style={{ display: 'flex', gap: '0.65rem', flexWrap: 'wrap', alignItems: 'center' }}>
          <span style={{ padding: '0.35rem 0.7rem', borderRadius: '999px', background: '#fff3cd', color: '#6b4f00', fontWeight: 600 }}>Pending {alertReviewCounts.pending}</span>
          <span style={{ padding: '0.35rem 0.7rem', borderRadius: '999px', background: '#d1e7dd', color: '#0f5132', fontWeight: 600 }}>Sent {alertReviewCounts.sent}</span>
          <span style={{ padding: '0.35rem 0.7rem', borderRadius: '999px', background: '#e2e3e5', color: '#41464b', fontWeight: 600 }}>Reviewed {alertReviewCounts.reviewed}</span>
          <ExportMenu title="Export alerts" exports={exportPayloads} />
        </div>
      </div>

      <article className="panel">
        <AlertFilters value={filters} campaigns={campaigns} onChange={setFilters} />
        {campaignError ? <p className="muted-line">Campaign filters unavailable: {campaignError}</p> : null}
      </article>

      <div className="alert-grid">
        {alerts.map((alert) => (
          <AlertCard key={alert.id} alert={alert} onSelect={openAlert} onQuickAction={handleQuickAction} />
        ))}
      </div>

      {selectedAlert ? (
        <AlertDetailDrawer
          alert={selectedAlert}
          detail={selectedDetail}
          onClose={() => setSelectedAlert(null)}
          onStatusChange={handleStatusChange}
          onQuickAction={handleQuickAction}
        />
      ) : null}
    </section>
  )
}

export default Alerts
