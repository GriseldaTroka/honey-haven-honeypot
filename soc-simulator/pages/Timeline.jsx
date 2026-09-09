import { useEffect, useState } from 'react'
import TimelinePanel from '../components/TimelinePanel'
import { getTimeline } from '../services/api'

function Timeline() {
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [events, setEvents] = useState([])

  useEffect(() => {
    let cancelled = false
    const controller = new AbortController()

    // Diagnostic helper: record timeline request timings for temporary debugging.
    function diag(name, info) {
      try {
        if (typeof window !== 'undefined') {
          window.__timelineDiagnostics = window.__timelineDiagnostics || []
          window.__timelineDiagnostics.push({ name, timestamp: Date.now(), info })
        }
      } catch (e) {
        // ignore
      }
      // also log to console for quick visibility
      // eslint-disable-next-line no-console
      console.log('[timeline-diag]', name, info)
    }

    async function loadTimeline() {
      setLoading(true)
      setError('')

      try {
        const t0 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now()
        diag('start-request', { path: '/research/timeline/json/?limit=250', t0 })
        let response
        try {
          response = await getTimeline(250, '', { signal: controller.signal })
          const t1 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now()
          diag('request-resolved', { elapsed_ms: Math.round(t1 - t0) })
        } catch (err) {
          const tErr = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now()
          diag('request-rejected', { elapsed_ms: Math.round(tErr - t0), name: err?.name, message: err?.message })
          throw err
        }

        if (!cancelled) {
          setEvents(response?.events || [])
        }
      } catch (loadError) {
        if (!cancelled) {
          setError(loadError.message || 'Failed to load timeline events')
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }

    loadTimeline()
    return () => {
      cancelled = true
      try {
        controller.abort()
      } catch (e) {
        // ignore
      }
    }
  }, [])

  return (
    <section className="panel investigation-section">
      <div className="section-header">
        <div>
          <h3>Timeline</h3>
          <p>Correlated event stream across all sessions and campaigns.</p>
        </div>
      </div>
      <TimelinePanel events={loading ? [] : events} loading={loading} error={error} />
    </section>
  )
}

export default Timeline
