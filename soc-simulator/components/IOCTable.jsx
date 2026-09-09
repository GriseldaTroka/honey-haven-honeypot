import { useMemo } from 'react'

function IOCTable({ iocs = [], onRowClick }) {
  const groupedIocs = useMemo(() => {
    const groups = new Map()

    for (const ioc of iocs) {
      const key = `${ioc.ioc_type || ''}::${ioc.ioc_value || ''}`
      const current = groups.get(key)
      if (!current) {
        groups.set(key, {
          ...ioc,
          occurrence_count: 1,
          session_ids: new Set(ioc.session_id ? [ioc.session_id] : []),
        })
        continue
      }

      current.occurrence_count += 1
      if (ioc.session_id) {
        current.session_ids.add(ioc.session_id)
      }
      if (!current.last_seen || (ioc.last_seen && new Date(ioc.last_seen) > new Date(current.last_seen))) {
        current.last_seen = ioc.last_seen
      }
    }

    return Array.from(groups.values()).map((ioc) => ({
      ...ioc,
      session_count: ioc.session_ids?.size || (ioc.session_id ? 1 : 0),
    }))
  }, [iocs])

  if (!groupedIocs.length) {
    return <div className="panel-empty">No IOCs observed yet.</div>
  }

  return (
    <div className="table-wrap">
      <table className="soc-table">
        <thead>
          <tr>
            <th>IOC Type</th>
            <th>IOC Value</th>
            <th>Occurrences</th>
            <th>Sessions</th>
            <th>Last Seen</th>
          </tr>
        </thead>
        <tbody>
          {groupedIocs.map((ioc) => (
            <tr key={`${ioc.ioc_type}-${ioc.ioc_value}`} onClick={() => onRowClick?.(ioc)}>
              <td>{ioc.ioc_type}</td>
              <td className="code-cell">{ioc.ioc_value}</td>
              <td>{ioc.occurrence_count ?? '-'}</td>
              <td>{ioc.session_count ?? '-'}</td>
              <td>{ioc.last_seen ? new Date(ioc.last_seen).toLocaleString() : '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default IOCTable
