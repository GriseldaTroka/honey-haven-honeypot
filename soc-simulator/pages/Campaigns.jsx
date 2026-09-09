import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import ExportMenu from '../components/ExportMenu'
import RiskOverview from '../components/RiskOverview'
import { getCampaigns } from '../services/api'

function Campaigns() {
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [campaigns, setCampaigns] = useState([])

  const overviewItems = useMemo(() => campaigns.map((campaign) => ({
    ...campaign,
    summary: `${campaign.total_journeys || 0} journeys · ${campaign.total_sessions || 0} sessions`,
    description: `${campaign.ioc_count || 0} IOCs (${campaign.unique_ioc_count || 0} unique) · avg risk ${Number(campaign.average_risk_score || 0).toFixed(1)}`,
    highest_risk_score: campaign.average_risk_score,
    count: campaign.total_sessions,
  })), [campaigns])

  useEffect(() => {
    let cancelled = false

    async function load() {
      setLoading(true)
      setError('')
      try {
        const response = await getCampaigns(100)
        if (!cancelled) {
          setCampaigns(response?.campaigns || [])
        }
      } catch (loadError) {
        if (!cancelled) {
          setError(loadError.message || 'Failed to load campaigns')
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

  const exportPayloads = useMemo(() => ([
    { label: 'Export campaigns JSON', filename: 'campaigns.json', data: campaigns, format: 'json' },
    { label: 'Export campaigns CSV', filename: 'campaigns.csv', data: campaigns, format: 'csv' },
  ]), [campaigns])

  if (loading) {
    return <section className="panel loading">Loading campaigns...</section>
  }

  if (error) {
    return <section className="panel error"><h3>Campaign inventory unavailable</h3><p>{error}</p></section>
  }

  return (
    <section className="investigation-section">
      <div className="section-header">
        <div>
          <h3>Campaign Inventory</h3>
          <p>Correlated campaign clusters built from existing session intelligence.</p>
        </div>
        <ExportMenu title="Export campaigns" exports={exportPayloads} />
      </div>

      <div className="panel-grid two-col">
        <article className="panel">
          <RiskOverview title="Campaign Summary" items={overviewItems} emptyLabel="No campaigns found." />
        </article>
        <article className="panel">
          <h3>Campaign Links</h3>
          <div className="related-session-strip">
            {campaigns.map((campaign) => (
              <Link key={campaign.campaign_id} className="related-session-chip" to={`/soc/campaigns/${campaign.campaign_id}`}>
                {campaign.campaign_id}
              </Link>
            ))}
          </div>
        </article>
      </div>
    </section>
  )
}

export default Campaigns
