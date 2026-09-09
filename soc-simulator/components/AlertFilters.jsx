function AlertFilters({ value, campaigns = [], onChange }) {
  return (
    <div className="alert-filter-bar">
      <input
        className="soc-input"
        value={value.search}
        onChange={(event) => onChange?.({ ...value, search: event.target.value })}
        placeholder="Search rules, sessions, campaigns, evidence"
      />
      <select className="soc-input" value={value.severity} onChange={(event) => onChange?.({ ...value, severity: event.target.value })}>
        <option value="">All severities</option>
        <option value="LOW">Low</option>
        <option value="MEDIUM">Medium</option>
        <option value="HIGH">High</option>
        <option value="CRITICAL">Critical</option>
      </select>
      <select className="soc-input" value={value.status} onChange={(event) => onChange?.({ ...value, status: event.target.value })}>
        <option value="">All statuses</option>
        <option value="OPEN">Open</option>
        <option value="INVESTIGATING">Investigating</option>
        <option value="RESOLVED">Resolved</option>
        <option value="FALSE_POSITIVE">False Positive</option>
      </select>
      <select className="soc-input" value={value.campaign} onChange={(event) => onChange?.({ ...value, campaign: event.target.value })}>
        <option value="">All campaigns</option>
        {campaigns.map((campaign) => <option key={campaign} value={campaign}>{campaign}</option>)}
      </select>
      <input className="soc-input" type="date" value={value.date_from} onChange={(event) => onChange?.({ ...value, date_from: event.target.value })} />
      <input className="soc-input" type="date" value={value.date_to} onChange={(event) => onChange?.({ ...value, date_to: event.target.value })} />
    </div>
  )
}

export default AlertFilters
