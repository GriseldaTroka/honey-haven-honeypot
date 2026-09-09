import SearchBar from './SearchBar'

function Navbar({ onMenuClick }) {
  const now = new Date()

  return (
    <header className="soc-navbar">
      <button className="soc-menu-button" onClick={onMenuClick} aria-label="Open navigation">
        <span />
        <span />
        <span />
      </button>

      <div>
        <h2>SOC Analyst Dashboard</h2>
        <p>{now.toUTCString()}</p>
      </div>

      <SearchBar />

      <div className="soc-status-pill">
        <span className="soc-status-dot" />
        Staff Session
      </div>
    </header>
  )
}

export default Navbar
