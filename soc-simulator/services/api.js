const API_BASE = import.meta.env.VITE_API_BASE_PATH || ''
const REQUEST_TIMEOUT_MS = Number(import.meta.env.VITE_API_TIMEOUT_MS || 30000)
// Read cookie by name (browser only)
function getCookie(name) {
  if (typeof document === 'undefined' || !document.cookie) return null
  const matches = document.cookie.split(';').map((c) => c.trim()).filter(Boolean)
  for (const part of matches) {
    const [k, ...rest] = part.split('=')
    if (k === name) return decodeURIComponent(rest.join('='))
  }
  return null
}
const IN_FLIGHT_GET_REQUESTS = new Map()

function createAbortError() {
  return new DOMException('Aborted', 'AbortError')
}

// Note: overview requests are not deduped via an in-memory shared controller to avoid
// shared AbortController cancellation edge-cases. getOverview() calls `request()`
// directly with an endpoint-specific timeout.

async function request(path, options = {}) {
  const method = String(options.method || 'GET').toUpperCase()
  const useRequestDeduping = method === 'GET' && !options.signal
  const requestKey = useRequestDeduping ? `${method}:${API_BASE}${path}` : ''

  if (useRequestDeduping && IN_FLIGHT_GET_REQUESTS.has(requestKey)) {
    return IN_FLIGHT_GET_REQUESTS.get(requestKey)
  }

  const controller = new AbortController()
  const externalSignal = options.signal
  const timeoutMs = Number(options.timeout ?? REQUEST_TIMEOUT_MS)
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs)
  // Debug: log that a timeout has been scheduled for this request
  try {
    // prefer console.debug but fall back to console.log if not available
    (console.debug || console.log)(`[api] scheduled timeout ${timeoutMs}ms for ${method} ${API_BASE}${path}`)
  } catch (e) {}
  let externalAbortHandler = null

  if (externalSignal) {
    if (externalSignal.aborted) {
      controller.abort()
    } else {
      externalAbortHandler = () => controller.abort()
      externalSignal.addEventListener('abort', externalAbortHandler, { once: true })
    }
  }

  const requestPromise = (async () => {
    let response
    try {
      // Ensure CSRF cookie is present for state-changing requests.
      const needCsrf = method !== 'GET' && method !== 'HEAD'
      if (needCsrf) {
        let csrfToken = getCookie('csrftoken')
        if (!csrfToken) {
          // Fetch login page (or any backend page) to let Django set the CSRF cookie
          try {
            await fetch(`${API_BASE}/login/`, { credentials: 'include' })
          } catch (e) {
            // ignore
          }
          csrfToken = getCookie('csrftoken')
        }
      }

      const headersObj = {
        ...(options.headers || {}),
      }
      // Only set Content-Type for requests that may have a body
      if (method !== 'GET' && method !== 'HEAD') {
        headersObj['Content-Type'] = 'application/json'
      }
      if (method !== 'GET' && method !== 'HEAD') {
        const token = getCookie('csrftoken')
        if (token) headersObj['X-CSRFToken'] = token
      }

      const fetchOptions = { ...options }
      // ensure we do not accidentally pass our internal timeout or external signal through to fetch
      delete fetchOptions.signal
      delete fetchOptions.timeout

      // Debug: log fetch start
      try { (console.debug || console.log)(`[api] fetch start ${method} ${API_BASE}${path}`, { timeoutMs, dedupe: useRequestDeduping }) } catch (e) {}
      const fetchStart = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now()
      response = await fetch(`${API_BASE}${path}`, {
        credentials: 'include',
        headers: headersObj,
        ...fetchOptions,
        signal: controller.signal,
      })
      const fetchEnd = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now()
      try { (console.debug || console.log)(`[api] fetch resolved ${method} ${API_BASE}${path}`, { status: response.status, duration_ms: Math.round(fetchEnd - fetchStart) }) } catch (e) {}
    } catch (error) {
      // Debug: log AbortError and other errors
      try { (console.debug || console.log)(`[api] fetch error for ${method} ${API_BASE}${path}`, { name: error?.name, message: error?.message }) } catch (e) {}
      if (error?.name === 'AbortError') {
        throw new Error(`Request timeout for ${path}`)
      }
      throw error
    } finally {
      // Debug: clear timeout
      try { (console.debug || console.log)(`[api] clearing timeout for ${method} ${API_BASE}${path}`) } catch (e) {}
      clearTimeout(timeoutId)
      if (externalSignal && externalAbortHandler) {
        externalSignal.removeEventListener('abort', externalAbortHandler)
      }
    }

    if (response.status === 302) {
      throw new Error('Not authorized for SOC data.')
    }

    if (!response.ok) {
      let message = `Request failed (${response.status})`
      try {
        const body = await response.json()
        if (body?.message) {
          message = body.message
        }
      } catch {
        // keep default error message
      }
      throw new Error(message)
    }

    return response.json()
  })()

  if (useRequestDeduping) {
    IN_FLIGHT_GET_REQUESTS.set(requestKey, requestPromise)
    requestPromise.finally(() => {
      IN_FLIGHT_GET_REQUESTS.delete(requestKey)
    })
  }

  return requestPromise
}

export function getStaffStatus() {
  return request('/api/internal/staff-status/')
}

export function getDetectionDashboard(limit = 20) {
  return request(`/api/dashboard/detection/?limit=${limit}`)
}

export function getCampaigns(limit = 200) {
  return request(`/api/campaigns/?limit=${limit}`)
}

export function getSessions(limit = 250) {
  return request(`/api/sessions/?limit=${limit}`)
}

export function getIocIndex(limit = 500) {
  return request(`/api/iocs/?limit=${limit}`)
}

export function getTimeline(limit = 60, sessionId = '', options = {}) {
  const sessionQuery = sessionId ? `&session=${encodeURIComponent(sessionId)}` : ''
  return request(`/research/timeline/json/?limit=${limit}${sessionQuery}`, options)
}

export function getAlerts(sessionId = '') {
  const sessionQuery = sessionId ? `?session_id=${encodeURIComponent(sessionId)}` : ''
  return request(`/api/alerts/${sessionQuery}`)
}

export function getFilteredAlerts(params = {}) {
  const query = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && String(value).trim() !== '') {
      // Map UI filter keys to API params: status -> status, severity -> severity, campaign -> campaign
      const apiKey = key === 'campaign' ? 'campaign' : key
      query.set(apiKey, value)
    }
  }
  const suffix = query.toString() ? `?${query.toString()}` : ''
  return request(`/api/alerts/${suffix}`)
}

export function getAlertDetail(alertId) {
  return request(`/api/alerts/${alertId}/`)
}

export function updateAlertStatus(alertId, status) {
  return request(`/api/alerts/${alertId}/`, {
    method: 'PATCH',
    body: JSON.stringify({ status }),
  })
}

export function getSessionJourney(sessionId) {
  return request(`/api/session/${sessionId}/`)
}

export function getAttackerState(sessionId) {
  return request(`/api/state/attacker/${encodeURIComponent(sessionId)}/`)
}

export function getSessionIocs(sessionId) {
  return request(`/api/session/${sessionId}/iocs/`)
}

export function getCampaignDetail(campaignId) {
  return request(`/api/campaigns/${campaignId}/`)
}

export function getCampaignJourneys(campaignId) {
  return request(`/api/campaigns/${campaignId}/journeys/`)
}

export function getIocDetail(iocId) {
  return request(`/api/iocs/${iocId}/`)
}

export function getIocRelationships(iocId) {
  return request(`/api/iocs/${iocId}/relationships/`)
}

export function getIocEvidence(iocId) {
  return request(`/api/iocs/${iocId}/evidence/`)
}

export function getInvestigationGraph(limit = 250, sessionId = '') {
  const sessionQuery = sessionId ? `&session_id=${encodeURIComponent(sessionId)}` : ''
  return request(`/api/investigation/graph/?limit=${limit}${sessionQuery}`)
}

export async function getOverview(limit = 20) {
  const response = await fetch(`/api/dashboard/overview/?limit=${limit}`, {
    credentials: 'include',
  })

  if (!response.ok) {
    throw new Error(`Request failed (${response.status})`)
  }

  return response.json()
}

export function getSearchResults(query) {
  return request(`/api/search/?q=${encodeURIComponent(query)}`)
}

export function getNotes(params = {}) {
  const query = new URLSearchParams(params).toString()
  return request(`/api/notes/${query ? `?${query}` : ''}`)
}

export function createNote(payload) {
  return request('/api/notes/', { method: 'POST', body: JSON.stringify(payload) })
}

export function updateNote(noteId, payload) {
  return request(`/api/notes/${noteId}/`, { method: 'PATCH', body: JSON.stringify(payload) })
}

export function deleteNote(noteId) {
  return request(`/api/notes/${noteId}/`, { method: 'DELETE' })
}

export function getBookmarks(params = {}) {
  const query = new URLSearchParams(params).toString()
  return request(`/api/bookmarks/${query ? `?${query}` : ''}`)
}

export function createBookmark(payload) {
  return request('/api/bookmarks/', { method: 'POST', body: JSON.stringify(payload) })
}

export function deleteBookmark(bookmarkId) {
  return request(`/api/bookmarks/${bookmarkId}/`, { method: 'DELETE' })
}
