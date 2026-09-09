import { useMemo, useState } from 'react'

function toCsv(rows = []) {
  if (!rows.length) {
    return ''
  }
  const headers = Array.from(new Set(rows.flatMap((row) => Object.keys(row || {}))))
  const escapeValue = (value) => {
    const text = value === null || value === undefined ? '' : typeof value === 'object' ? JSON.stringify(value) : String(value)
    return `"${text.replaceAll('"', '""')}"`
  }
  return [headers.join(','), ...rows.map((row) => headers.map((header) => escapeValue(row?.[header])).join(','))].join('\n')
}

function downloadFile(filename, content, type) {
  const blob = new Blob([content], { type })
  const link = document.createElement('a')
  link.href = URL.createObjectURL(blob)
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(link.href)
}

function ExportMenu({ title = 'Export', exports = [] }) {
  const [open, setOpen] = useState(false)

  const items = useMemo(() => exports.filter((item) => item && item.data), [exports])

  function handleExport(item) {
    const data = item.data
    const payload = item.format === 'csv' ? toCsv(Array.isArray(data) ? data : [data]) : JSON.stringify(data, null, 2)
    downloadFile(item.filename, payload, item.format === 'csv' ? 'text/csv;charset=utf-8' : 'application/json;charset=utf-8')
    setOpen(false)
  }

  if (!items.length) {
    return null
  }

  return (
    <div className="export-menu">
      <button type="button" className="soc-button secondary" onClick={() => setOpen((current) => !current)}>{title}</button>
      {open ? (
        <div className="export-menu-panel">
          {items.map((item) => (
            <button key={item.filename} type="button" className="export-menu-item" onClick={() => handleExport(item)}>
              {item.label}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  )
}

export default ExportMenu
