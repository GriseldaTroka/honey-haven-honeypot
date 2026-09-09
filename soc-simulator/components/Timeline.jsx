function Timeline({ events = [] }) {
  if (!events.length) {
    return <div className="panel-empty">No timeline events available.</div>
  }

  return (
    <div className="timeline-list">
      {events.map((event, index) => (
        <div key={`${event.timestamp}-${event.kind}-${index}`} className="timeline-item">
          <div className="timeline-dot" />
          <div>
            <p className="timeline-title">{event.label || event.event_type || event.kind}</p>
            <p className="timeline-detail">{event.detail || event.summary || 'No detail'}</p>
            <p className="timeline-meta">
              {event.timestamp ? new Date(event.timestamp).toLocaleString() : 'Unknown time'}
              {event.session_id ? ` • ${event.session_id}` : ''}
            </p>
          </div>
        </div>
      ))}
    </div>
  )
}

export default Timeline
