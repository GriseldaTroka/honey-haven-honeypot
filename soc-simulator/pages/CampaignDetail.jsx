import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import AlertTable from '../components/AlertTable'
import CampaignCard from '../components/CampaignCard'
import ExportMenu from '../components/ExportMenu'
import RecentActivity from '../components/RecentActivity'
import TimelinePanel from '../components/TimelinePanel'
import { createBookmark, createNote, getBookmarks, getCampaignDetail, getCampaignJourneys, getFilteredAlerts, getNotes, getTimeline } from '../services/api'

function CampaignDetail() {
  const { campaignId } = useParams()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [campaign, setCampaign] = useState(null)
  const [journeys, setJourneys] = useState([])
  const [alerts, setAlerts] = useState([])
  const [journeysError, setJourneysError] = useState('')
  const [alertsError, setAlertsError] = useState('')
  const [notes, setNotes] = useState([])
  const [notesLoading, setNotesLoading] = useState(true)
  const [notesError, setNotesError] = useState('')
  const [bookmarks, setBookmarks] = useState([])
  const [bookmarksError, setBookmarksError] = useState('')
  const [timeline, setTimeline] = useState([])
  const [timelineLoading, setTimelineLoading] = useState(true)
  const [noteForm, setNoteForm] = useState({ title: '', body: '' })

  useEffect(() => {
    let cancelled = false

    async function load() {
      setLoading(true)
      setError('')
      setJourneysError('')
      setAlertsError('')
      setBookmarksError('')
      try {
        // Required request: campaign detail must succeed or we show fatal error
        const campaignResponse = await getCampaignDetail(campaignId)
        if (!cancelled) {
          setCampaign(campaignResponse)
        }

        // Auxiliary requests: fetch in parallel but treat failures as non-fatal
        const auxPromises = [
          getCampaignJourneys(campaignId).then((r) => ({ type: 'journeys', r })).catch((e) => ({ type: 'journeys', e })),
          getFilteredAlerts({ campaign: campaignId }).then((r) => ({ type: 'alerts', r })).catch((e) => ({ type: 'alerts', e })),
          getBookmarks({ campaign_id: campaignId }).then((r) => ({ type: 'bookmarks', r })).catch((e) => ({ type: 'bookmarks', e })),
        ]

        const auxResults = await Promise.all(auxPromises)

        if (!cancelled) {
          for (const res of auxResults) {
            if (res.type === 'journeys') {
              if (res.r) {
                setJourneys(res.r?.journeys || [])
              } else {
                setJourneys([])
                setJourneysError(res.e?.message || 'Failed to load journeys')
              }
            }
            if (res.type === 'alerts') {
              if (res.r) {
                setAlerts(res.r?.alerts || [])
              } else {
                setAlerts([])
                setAlertsError(res.e?.message || 'Failed to load alerts')
              }
            }
            if (res.type === 'bookmarks') {
              if (res.r) {
                setBookmarks(res.r?.bookmarks || [])
              } else {
                setBookmarks([])
                setBookmarksError(res.e?.message || 'Failed to load bookmarks')
              }
            }
          }
        }
      } catch (loadError) {
        if (!cancelled) {
          setError(loadError.message || 'Failed to load campaign detail')
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
  }, [campaignId])

  useEffect(() => {
    let cancelled = false

    async function loadNotes() {
      setNotesLoading(true)
      setNotesError('')
      try {
        const notesResponse = await getNotes({ campaign_id: campaignId })
        if (!cancelled) {
          setNotes(notesResponse?.notes || [])
        }
      } catch (notesLoadError) {
        if (!cancelled) {
          setNotes([])
          setNotesError(notesLoadError.message || 'Failed to load analyst notes')
        }
      } finally {
        if (!cancelled) {
          setNotesLoading(false)
        }
      }
    }

    if (!loading && !error) {
      loadNotes()
    }

    return () => {
      cancelled = true
    }
  }, [campaignId, error, loading])

  useEffect(() => {
    let cancelled = false

    async function loadTimeline() {
      setTimelineLoading(true)
      try {
        const timelineResponse = await getTimeline(120)
        if (!cancelled) {
          const journeySessionIds = new Set(journeys.map((journey) => journey.session_id))
          setTimeline((timelineResponse?.events || []).filter((event) => journeySessionIds.has(event.session_id) || event.campaign_id === campaignId))
        }
      } catch {
        if (!cancelled) {
          setTimeline([])
        }
      } finally {
        if (!cancelled) {
          setTimelineLoading(false)
        }
      }
    }

    if (!loading && !error) {
      loadTimeline()
    }

    return () => {
      cancelled = true
    }
  }, [campaignId, error, journeys, loading])

  const exportPayloads = useMemo(() => ([
    { label: 'Export campaign JSON', filename: `campaign-${campaignId}.json`, data: { campaign, journeys, alerts, notes, bookmarks }, format: 'json' },
    { label: 'Export journeys CSV', filename: `campaign-${campaignId}-journeys.csv`, data: journeys, format: 'csv' },
  ]), [alerts, bookmarks, campaign, campaignId, journeys, notes])

  async function handleAddNote(event) {
    event.preventDefault()
    try {
      const response = await createNote({ campaign_id: campaignId, title: noteForm.title, body: noteForm.body })
      setNotesError('')
      setNotes((current) => [response.note, ...current])
      setNoteForm({ title: '', body: '' })
    } catch (noteError) {
      setError(noteError.message || 'Failed to save note')
    }
  }

  async function handleBookmarkSession(sessionId) {
    try {
      const response = await createBookmark({ campaign_id: campaignId, session_id: sessionId, label: `Bookmark ${sessionId}` })
      setBookmarks((current) => [response.bookmark, ...current])
    } catch (bookmarkError) {
      setError(bookmarkError.message || 'Failed to save bookmark')
    }
  }

  if (loading) {
    return <section className="panel loading">Loading campaign detail...</section>
  }

  if (error) {
    return <section className="panel error"><h3>Campaign detail unavailable</h3><p>{error}</p></section>
  }

  return (
    <section className="investigation-section">
      <div className="section-header">
        <div>
          <h3>Campaign {campaignId}</h3>
          <p>Cross-session campaign workspace with analyst notes and bookmarks.</p>
        </div>
        <ExportMenu title="Export campaign" exports={exportPayloads} />
      </div>

      <article className="panel">
        <CampaignCard campaign={campaign} />
      </article>

      <div className="panel-grid two-col">
        <article className="panel">
          <h3>Journeys</h3>
          <div className="related-session-strip">
            {journeys.map((journey) => (
              <Link key={journey.session_id} className="related-session-chip" to={`/soc/sessions/${journey.session_id}`}>
                {journey.session_id}
              </Link>
            ))}
          </div>
          <TimelinePanel events={timelineLoading ? [] : timeline} />
        </article>

        <article className="panel">
          <h3>Alerts</h3>
          <AlertTable alerts={alerts} />
        </article>
      </div>

      <div className="panel-grid two-col">
        <article className="panel">
          <h3>Analyst Note</h3>
          <form className="campaign-note-form" onSubmit={handleAddNote}>
            <input className="soc-input" value={noteForm.title} onChange={(event) => setNoteForm((current) => ({ ...current, title: event.target.value }))} placeholder="Note title" />
            <textarea className="soc-input" rows={5} value={noteForm.body} onChange={(event) => setNoteForm((current) => ({ ...current, body: event.target.value }))} placeholder="Write a short investigation note" />
            <button className="soc-button" type="submit">Save note</button>
          </form>
          {notesError ? <p className="panel-message">{notesError}</p> : null}
          <RecentActivity title="Recent Notes" items={notesLoading ? [] : notes} emptyLabel={notesLoading ? 'Loading notes...' : 'No analyst notes for this campaign.'} />
        </article>

        <article className="panel">
          <h3>Bookmarks</h3>
          <div className="bookmark-actions">
            {journeys.map((journey) => (
              <button key={journey.session_id} type="button" className="soc-button secondary" onClick={() => handleBookmarkSession(journey.session_id)}>
                Bookmark {journey.session_id}
              </button>
            ))}
          </div>
          <RecentActivity title="Saved Bookmarks" items={bookmarks} emptyLabel="No bookmarks saved for this campaign." />
        </article>
      </div>
    </section>
  )
}

export default CampaignDetail
