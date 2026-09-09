import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { getSearchResults } from '../services/api'

function buildTarget(item) {
  if (item.session_id) {
    return `/soc/sessions/${item.session_id}`
  }
  if (item.campaign_id) {
    return `/soc/campaigns/${item.campaign_id}`
  }
  if (item.id && item.rule_name) {
    return `/soc/alerts/${item.id}`
  }
  if (item.id && item.ioc_type) {
    return `/soc/ioc/${item.id}`
  }
  if (item.id && item.title) {
    return item.session_id ? `/soc/sessions/${item.session_id}` : '/soc'
  }
  return '/soc'
}

function SearchBar() {
  const navigate = useNavigate()
  const [query, setQuery] = useState('')
  const [results, setResults] = useState(null)
  const [open, setOpen] = useState(false)
  const [loading, setLoading] = useState(false)

  const flatResults = useMemo(() => {
    if (!results) {
      return []
    }
    return [
      ...(results.sessions || []).map((item) => ({ ...item, kind: 'Session', label: item.session_id })),
      ...(results.campaigns || []).map((item) => ({ ...item, kind: 'Campaign', label: item.campaign_id })),
      ...(results.iocs || []).map((item) => ({ ...item, kind: 'IOC', label: `${item.ioc_type}:${item.ioc_value}` })),
      ...(results.alerts || []).map((item) => ({ ...item, kind: 'Alert', label: item.rule_name })),
      ...(results.notes || []).map((item) => ({ ...item, kind: 'Note', label: item.title })),
    ]
  }, [results])

  useEffect(() => {
    let cancelled = false
    const value = query.trim()
    if (value.length < 2) {
      setResults(null)
      setLoading(false)
      return undefined
    }

    setLoading(true)
    const timer = setTimeout(async () => {
      try {
        const response = await getSearchResults(value)
        if (!cancelled) {
          setResults(response)
          setOpen(true)
        }
      } catch {
        if (!cancelled) {
          setResults(null)
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }, 250)

    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [query])

  function handleSelect(item) {
    navigate(buildTarget(item))
    setOpen(false)
    setQuery('')
  }

  return (
    <div className="search-bar-shell">
      <input
        className="soc-input search-input"
        value={query}
        onChange={(event) => {
          setQuery(event.target.value)
          setOpen(true)
        }}
        onFocus={() => setOpen(Boolean(flatResults.length))}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
        placeholder="Search sessions, campaigns, IOCs, alerts, notes"
      />
      {open && (loading || flatResults.length) ? (
        <div className="search-results-panel">
          {loading ? <div className="panel-empty">Searching intelligence...</div> : null}
          {!loading && !flatResults.length ? <div className="panel-empty">No results matched.</div> : null}
          {!loading && flatResults.map((item, index) => (
            <button key={`${item.kind}-${item.id || item.label || index}`} type="button" className="search-result-row" onMouseDown={() => handleSelect(item)}>
              <span className="search-result-kind">{item.kind}</span>
              <strong>{item.label}</strong>
              <span>{item.session_id || item.campaign_id || item.status || item.note || ''}</span>
            </button>
          ))}
        </div>
      ) : null}
    </div>
  )
}

export default SearchBar
