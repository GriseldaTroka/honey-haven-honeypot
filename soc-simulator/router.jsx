import { useEffect, useState } from 'react'
import { getStaffStatus } from './services/api'
import {
  Navigate,
  Outlet,
  RouterProvider,
  createBrowserRouter,
} from 'react-router-dom'
import Navbar from './components/Navbar'
import Sidebar from './components/Sidebar'
import CampaignDetail from './pages/CampaignDetail'
import Campaigns from './pages/Campaigns'
import Dashboard from './pages/Dashboard'
import Alerts from './pages/Alerts'
import IOCDetail from './pages/IOCDetail'
import IOCExplorer from './pages/IOCExplorer'
import AlertDetail from './pages/AlertDetail'
import SessionDetail from './pages/SessionDetail'
import Sessions from './pages/Sessions'
import Timeline from './pages/Timeline'
function RequireStaff({ children }) {
  const [state, setState] = useState({ loading: true, authenticated: false, staff: false })

  useEffect(() => {
    let cancelled = false
    async function validate() {
      // Retry a few times to allow session cookie propagation or transient backend work
      const maxAttempts = 3
      const backoffMs = 400
      for (let attempt = 1; attempt <= maxAttempts && !cancelled; attempt += 1) {
        try {
          const status = await getStaffStatus()
          if (!cancelled) {
            setState({ loading: false, authenticated: Boolean(status?.authenticated), staff: Boolean(status?.staff) })
          }
          return
        } catch (err) {
          if (attempt === maxAttempts) {
            if (!cancelled) setState({ loading: false, authenticated: false, staff: false })
            return
          }
          // small delay before retry
          await new Promise((r) => setTimeout(r, backoffMs))
        }
      }
    }

    validate()
    return () => {
      cancelled = true
    }
  }, [])
  const backendHost = window.location.hostname
  const backendProtocol = window.location.protocol
  const loginBaseUrl = import.meta.env.VITE_AUTH_BASE_URL || `${backendProtocol}//${backendHost}:8000`
  const loginUrl = `${loginBaseUrl}/login/?next=${encodeURIComponent(`${window.location.origin}/soc`)}`

  useEffect(() => {
    if (!state.loading && (!state.authenticated || !state.staff)) {
      window.location.assign(loginUrl)
    }
  }, [loginUrl, state.authenticated, state.loading, state.staff])

  if (state.loading) {
    return <div className="auth-state">Validating staff session...</div>
  }

  if (!state.authenticated || !state.staff) {
    return (
      <div className="auth-state">
        <h2>SOC Access Required</h2>
        <p>This simulator is restricted to authenticated staff/admin users.</p>
        <a className="auth-link" href={loginUrl}>
          Log in to Django staff account
        </a>
      </div>
    )
  }

  return children
}

function SocLayout() {
  const [sidebarOpen, setSidebarOpen] = useState(false)

  return (
    <div className="soc-shell">
      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />
      <main className="soc-main">
        <Navbar onMenuClick={() => setSidebarOpen((open) => !open)} />
        <div className="soc-content">
          <Outlet />
        </div>
      </main>
    </div>
  )
}

const router = createBrowserRouter([
  {
    path: '/',
    element: <Navigate to="/soc" replace />,
  },
  {
    path: '/soc',
    element: (
      <RequireStaff>
        <SocLayout />
      </RequireStaff>
    ),
    children: [
      { index: true, element: <Dashboard /> },
      { path: 'sessions', element: <Sessions /> },
      { path: 'sessions/:sessionId', element: <SessionDetail /> },
      { path: 'campaigns', element: <Campaigns /> },
      { path: 'campaigns/:campaignId', element: <CampaignDetail /> },
      { path: 'timeline', element: <Timeline /> },
      { path: 'ioc-explorer', element: <IOCExplorer /> },
      { path: 'ioc/:iocId', element: <IOCDetail /> },
      { path: 'alerts', element: <Alerts /> },
      { path: 'alerts/:alertId', element: <AlertDetail /> },
      { path: '*', element: <Navigate to="/" replace /> },
    ],
  },
])

export default function AppRouter() {
  return <RouterProvider router={router} />
}
