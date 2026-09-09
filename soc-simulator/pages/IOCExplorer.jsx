import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import IOCTable from '../components/IOCTable'
import { getIocIndex } from '../services/api'

function IOCExplorer() {
  const navigate = useNavigate()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [iocs, setIocs] = useState([])
  const [query, setQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')

  useEffect(() => {
    let cancelled = false

    async function load() {
      setLoading(true)
      setError('')
      try {
        const response = await getIocIndex(500)
        if (!cancelled) {
          setIocs(response?.iocs || [])
        }
      } catch (loadError) {
        if (!cancelled) {
          setError(loadError.message || 'Failed to load IOC inventory')
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

  const iocTypes = useMemo(() => ['all', ...new Set(iocs.map((ioc) => ioc.ioc_type).filter(Boolean))], [iocs])

  const filteredIocs = useMemo(() => {
    const normalized = query.trim().toLowerCase()
    return iocs.filter((ioc) => {
      const matchesText = !normalized || [ioc.ioc_value, ioc.session_id, ioc.ioc_type].some((value) => String(value || '').toLowerCase().includes(normalized))
      const matchesType = typeFilter === 'all' || ioc.ioc_type === typeFilter
      return matchesText && matchesType
    })
  }, [iocs, query, typeFilter])

  if (loading) {
    return <section className="panel loading">Loading IOC inventory...</section>
  }

  if (error) {
    return <section className="panel error"><h3>IOC inventory unavailable</h3><p>{error}</p></section>
  }

  return (
    <section className="panel investigation-section">
      <div className="section-header">
        <div>
          <h3>IOC Explorer</h3>
          <p>Browse persisted IOC intelligence and drill into detail, relationships, and evidence.</p>
        </div>
        <div className="section-toolbar">
          <input
            className="soc-input"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search IOC value, type, or session"
          />
          <select className="soc-input" value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)}>
            {iocTypes.map((value) => <option key={value} value={value}>{value === 'all' ? 'All IOC types' : value}</option>)}
          </select>
        </div>
      </div>

      <IOCTable iocs={filteredIocs} onRowClick={(ioc) => navigate(`/soc/ioc/${ioc.id}`)} />
    </section>
  )
}

export default IOCExplorer
