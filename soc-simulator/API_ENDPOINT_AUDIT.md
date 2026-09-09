# SOC Simulator API Endpoint Audit

## Scope and Rule Confirmation
- Honeypot-facing website routes remain unchanged.
- SOC Simulator is a separate analyst UI (React) that consumes existing Django APIs.
- No backend intelligence logic was moved to frontend.

## Authentication and Access Control
- `GET /api/internal/staff-status/`
  - Purpose: Verify authenticated + staff role.
  - Used by: Route guard (`RequireStaff`).

## Phase 1 Endpoints Consumed by Dashboard
- `GET /api/dashboard/detection/?limit=<n>`
  - Source: `detection_dashboard_view`
  - Data used: `active_alerts`, `alerts_by_severity`, `highest_risk_campaigns`, `recent_detections`.

- `GET /api/campaigns/?limit=<n>`
  - Source: `campaign_list_view`
  - Data used: active campaign count and campaign summary context.

- `GET /api/iocs/?limit=<n>`
  - Source: `ioc_index_view`
  - Data used: IOC count and IOC snapshot table.

- `GET /research/timeline/json/?limit=<n>`
  - Source: `attacker_timeline_json`
  - Data used: recent attack activity timeline.

## Endpoints Prepared in API Service for Next Phases
- `GET /api/alerts/`
- `GET /api/alerts/<alert_id>/`
- `PATCH /api/alerts/<alert_id>/`
- `GET /api/session/<session_id>/`
- `GET /api/session/<session_id>/iocs/`
- `GET /api/campaigns/<campaign_id>/`
- `GET /api/campaigns/<campaign_id>/journeys/`
- `GET /api/iocs/<ioc_id>/`
- `GET /api/iocs/<ioc_id>/relationships/`
- `GET /api/iocs/<ioc_id>/evidence/`
- `GET /api/investigation/graph/?limit=<n>`

## Staff Access Behavior Verified in Django Views
- SOC investigation/detection endpoints are decorated with staff-only checks (`@user_passes_test(lambda user: user.is_staff)`).
- Timeline JSON endpoint for investigations is also staff-only.
- Frontend guard aligns with this behavior by checking `staff-status` before rendering SOC routes.
