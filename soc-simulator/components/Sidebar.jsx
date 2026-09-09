import { NavLink } from 'react-router-dom'

const NAV_ITEMS = [
  { to: '/soc', label: 'SOC Dashboard' },
  { to: '/soc/sessions', label: 'Sessions' },
  { to: '/soc/campaigns', label: 'Campaigns' },
  { to: '/soc/timeline', label: 'Timeline' },
  { to: '/soc/ioc-explorer', label: 'IOC Explorer' },
  { to: '/soc/alerts', label: 'Alerts' },
]

function Sidebar({ open, onClose }) {
  return (
    <aside className={`soc-sidebar ${open ? 'open' : ''}`}>
      <div className="soc-sidebar-header">
        <div className="soc-logo-dot" />
        <div>
          <h1>Honey SOC</h1>
          <p>Analyst Simulator</p>
        </div>
      </div>

      <nav className="soc-nav" aria-label="SOC navigation">
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              isActive ? 'soc-nav-link active' : 'soc-nav-link'
            }
            onClick={onClose}
          >
            {item.label}
          </NavLink>
        ))}
      </nav>
    </aside>
  )
}

export default Sidebar
