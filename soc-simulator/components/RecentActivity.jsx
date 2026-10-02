function RecentActivity({ title, items = [], emptyLabel = 'No recent activity.' }) {
  return (
    <div className="recent-activity">
      <div className="section-header compact">
        <div>
          <h4>{title}</h4>
        </div>
      </div>
      {!items.length ? (
        <div className="panel-empty">{emptyLabel}</div>
      ) : (
        <div className="recent-activity-list">
          {items.map((item) => {
            const title = item.title || item.label || item.session_id || item.campaign_id || 'Item'
            const bodyText = item.body || item.note || item.summary || item.description || item.campaign_id || item.session_id || 'Bookmark created'
            return (
              <article key={String(item.id || item.title || item.label)} className="activity-card">
                <div className="activity-card-head">
                  <strong>{title}</strong>
                  {item.pinned ? <span className="severity-pill info">Pinned</span> : null}
                </div>
                <p>{bodyText}</p>
                <div className="activity-card-meta">
                  {item.session_id ? <span>{item.session_id}</span> : null}
                  {item.campaign_id ? <span>{item.campaign_id}</span> : null}
                  {item.updated_at ? <span>{new Date(item.updated_at).toLocaleString()}</span> : null}
                  {item.created_at ? <span>{new Date(item.created_at).toLocaleString()}</span> : null}
                </div>
              </article>
            )
          })}
        </div>
      )}
    </div>
  )
}

export default RecentActivity
