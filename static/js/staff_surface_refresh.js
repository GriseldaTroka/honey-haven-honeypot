(function () {
    const surface = document.querySelector('[data-staff-refresh-page="true"]');
    if (!surface) {
        return;
    }

    const body = document.body;
    const apiEndpoint = surface.dataset.apiEndpoint;
    const statusEndpoint = body?.dataset?.staffStatusEndpoint || '/api/internal/staff-status/';
    const output = document.getElementById('staff-protected-json');
    const meta = document.getElementById('staff-refresh-meta');
    const statusPill = document.getElementById('staff-status-pill');
    const metricAlerts = document.getElementById('staff-metric-alerts');
    const metricTelemetry = document.getElementById('staff-metric-telemetry');
    const metricUploads = document.getElementById('staff-metric-uploads');
    const metricPayments = document.getElementById('staff-metric-payments');
    const alertList = document.getElementById('staff-alert-list');
    const telemetryList = document.getElementById('staff-telemetry-list');
    const uploadList = document.getElementById('staff-upload-list');
    const paymentList = document.getElementById('staff-payment-list');
    const ticketList = document.getElementById('staff-ticket-list');
    const reportMetricConfidence = document.getElementById('report-metric-confidence');
    const reportMetricPhases = document.getElementById('report-metric-phases');
    const reportMetricIocs = document.getElementById('report-metric-iocs');
    const reportMetricClusters = document.getElementById('report-metric-clusters');
    const reportClassification = document.getElementById('report-classification');
    const reportActorBehavior = document.getElementById('report-actor-behavior');
    const reportTooling = document.getElementById('report-tooling');
    const reportInfrastructure = document.getElementById('report-infrastructure');
    const reportTimelineList = document.getElementById('report-timeline-list');
    const reportIocList = document.getElementById('report-ioc-list');
    const reportClusterList = document.getElementById('report-cluster-list');
    const reportPathList = document.getElementById('report-path-list');
    const reportPhaseList = document.getElementById('report-phase-list');
    const reportEnvironmentList = document.getElementById('report-environment-list');
    const apiDocsVersion = document.getElementById('api-docs-version');
    const apiDocsRoutes = document.getElementById('api-docs-routes');
    const apiDocsMethods = document.getElementById('api-docs-methods');
    const apiDocsScope = document.getElementById('api-docs-scope');
    const apiDocsTitle = document.getElementById('api-docs-title');
    const apiDocsOpenapi = document.getElementById('api-docs-openapi');
    const apiDocsMeta = document.getElementById('api-docs-meta');
    const apiDocsPathList = document.getElementById('api-docs-path-list');
    const apiDocsOperationList = document.getElementById('api-docs-operation-list');
    const apiDocsEnvironmentList = document.getElementById('api-docs-environment-list');

    if (!apiEndpoint || !output) {
        return;
    }

    let lastStatus = null;
    let pollTimer = null;

    function statusLabel(status) {
        if (!status.authenticated) {
            return 'Anonymous';
        }
        return status.staff ? 'Staff' : 'Authenticated';
    }

    function applyStatusBadge(status) {
        if (!statusPill) {
            return;
        }

        statusPill.textContent = statusLabel(status);
        statusPill.className = status.staff
            ? 'badge text-bg-success'
            : status.authenticated
                ? 'badge text-bg-warning'
                : 'badge text-bg-secondary';
    }

    async function fetchStatus(eventName) {
        const query = eventName ? `?event=${encodeURIComponent(eventName)}` : '';
        const response = await fetch(`${statusEndpoint}${query}`, {
            method: 'GET',
            credentials: 'same-origin',
            headers: {
                'Accept': 'application/json',
            },
        });

        if (!response.ok) {
            throw new Error(`staff-status ${response.status}`);
        }

        const status = await response.json();
        applyStatusBadge(status);
        return status;
    }

    async function refreshSurfaceData(reason) {
        if (meta) {
            meta.textContent = `Refreshing data (${reason})...`;
        }

        const response = await fetch(apiEndpoint, {
            method: 'GET',
            credentials: 'same-origin',
            headers: {
                'Accept': 'application/json',
            },
        });

        let payload;
        try {
            payload = await response.json();
        } catch (error) {
            payload = { error: 'Invalid JSON response', status: response.status };
        }

        renderPayload(payload);
        if (meta) {
            meta.textContent = `Last refresh: ${new Date().toLocaleTimeString()} (${reason}, HTTP ${response.status})`;
        }
    }

    function countItems(value) {
        return Array.isArray(value) ? value.length : 0;
    }

    function escapeText(value) {
        return String(value ?? '')
            .replaceAll('&', '&amp;')
            .replaceAll('<', '&lt;')
            .replaceAll('>', '&gt;')
            .replaceAll('"', '&quot;')
            .replaceAll("'", '&#39;');
    }

    function renderList(container, items, emptyText, itemRenderer) {
        if (!container) {
            return;
        }

        container.innerHTML = '';

        if (!items.length) {
            const empty = document.createElement('div');
            empty.className = 'list-group-item border-0 px-0 text-muted';
            empty.textContent = emptyText;
            container.appendChild(empty);
            return;
        }

        items.forEach((item) => {
            const element = document.createElement('div');
            element.className = 'list-group-item border-0 px-0';
            element.innerHTML = itemRenderer(item);
            container.appendChild(element);
        });
    }

    function renderPayload(payload) {
        if (output) {
            output.textContent = JSON.stringify(payload, null, 2);
        }

        if (payload && (payload.classification || payload.threat_actor_profile || payload.campaign_timeline || payload.iocs || payload.autonomous_deception_paths)) {
            renderResearchReport(payload);
            return;
        }

        if (payload && (payload.openapi || payload.paths || payload.info)) {
            renderApiDocs(payload);
            return;
        }

        if (payload && (payload.summary || payload.meta)) {
            renderResearchSummary(payload);
            return;
        }

        const alerts = Array.isArray(payload.alerts) ? payload.alerts : [];
        const telemetry = Array.isArray(payload.telemetry) ? payload.telemetry : [];
        const uploads = Array.isArray(payload.uploads) ? payload.uploads : [];
        const payments = Array.isArray(payload.payments) ? payload.payments : [];
        const tickets = Array.isArray(payload.tickets) ? payload.tickets : [];

        if (metricAlerts) metricAlerts.textContent = String(countItems(alerts));
        if (metricTelemetry) metricTelemetry.textContent = String(countItems(telemetry));
        if (metricUploads) metricUploads.textContent = String(countItems(uploads));
        if (metricPayments) metricPayments.textContent = String(countItems(payments));

        renderList(alertList, alerts, 'No alerts recorded yet.', (item) => `
            <div class="d-flex justify-content-between gap-3">
                <div>
                    <div class="fw-semibold">${escapeText(item.alert_type || 'Alert')}</div>
                    <div class="text-muted small">${escapeText(item.detail || '')}</div>
                </div>
                <div class="text-muted small text-end">${escapeText(item.timestamp || '')}</div>
            </div>
        `);

        renderList(telemetryList, telemetry, 'No telemetry events yet.', (item) => `
            <div class="d-flex justify-content-between gap-3">
                <div>
                    <div class="fw-semibold">${escapeText(item.event_type || 'Telemetry')}</div>
                    <div class="text-muted small">${escapeText(item.path || '')}</div>
                </div>
                <div class="text-muted small text-end">${escapeText(item.timestamp || '')}</div>
            </div>
        `);

        renderList(uploadList, uploads, 'No quarantined uploads yet.', (item) => `
            <div class="d-flex justify-content-between gap-3">
                <div>
                    <div class="fw-semibold">${escapeText(item.filename || 'Upload')}</div>
                    <div class="text-muted small">${escapeText(item.verdict || '')} | entropy ${escapeText(item.entropy ?? '')}</div>
                </div>
                <div class="text-muted small text-end">${escapeText(item.timestamp || '')}</div>
            </div>
        `);

        renderList(paymentList, payments, 'No payment records yet.', (item) => `
            <div class="d-flex justify-content-between gap-3">
                <div>
                    <div class="fw-semibold">${escapeText(item.payment_id || 'Payment')}</div>
                    <div class="text-muted small">${escapeText(item.amount ?? '')} ${escapeText(item.currency || '')} | ${escapeText(item.status || '')}</div>
                </div>
                <div class="text-muted small text-end">${escapeText(item.timestamp || '')}</div>
            </div>
        `);

        renderList(ticketList, tickets, 'No support tickets yet.', (item) => `
            <div class="d-flex justify-content-between gap-3">
                <div>
                    <div class="fw-semibold">${escapeText(item.ticket_id || 'Ticket')}</div>
                    <div class="text-muted small">${escapeText(item.priority || '')} | ${escapeText(item.status || '')}</div>
                </div>
                <div class="text-muted small text-end">${escapeText(item.timestamp || '')}</div>
            </div>
        `);
    }

    function renderResearchReport(payload) {
        const iocs = payload.iocs || {};
        const phases = Array.isArray(payload.campaign_timeline) ? payload.campaign_timeline : [];
        const clusters = Array.isArray(payload.clusters) ? payload.clusters : [];
        const paths = Array.isArray(payload.autonomous_deception_paths) ? payload.autonomous_deception_paths : [];
        const environment = payload.dynamic_environment || {};
        const tooling = Array.isArray(payload.threat_actor_profile?.tooling) ? payload.threat_actor_profile.tooling : [];
        const infrastructure = Array.isArray(payload.threat_actor_profile?.infrastructure) ? payload.threat_actor_profile.infrastructure : [];

        if (reportMetricConfidence) reportMetricConfidence.textContent = String(payload.confidence ?? '0.00');
        if (reportMetricPhases) reportMetricPhases.textContent = String(phases.length);
        if (reportMetricIocs) reportMetricIocs.textContent = String((iocs.ips?.length || 0) + (iocs.urls?.length || 0) + (iocs.emails?.length || 0) + (iocs.hashes?.length || 0));
        if (reportMetricClusters) reportMetricClusters.textContent = String(clusters.length);
        if (reportClassification) reportClassification.textContent = payload.classification || 'Unknown';
        if (reportActorBehavior) reportActorBehavior.textContent = payload.threat_actor_profile?.behavior || 'Unknown';
        if (reportTooling) reportTooling.textContent = tooling.length ? tooling.join(', ') : 'None';
        if (reportInfrastructure) reportInfrastructure.textContent = infrastructure.length ? infrastructure.join(', ') : 'None';

        renderList(reportTimelineList, phases, 'No campaign timeline yet.', (item) => `
            <div class="d-flex justify-content-between gap-3">
                <div>
                    <div class="fw-semibold">${escapeText(item.stage || 'Stage')}</div>
                    <div class="text-muted small">${escapeText(item.note || '')}</div>
                </div>
            </div>
        `);

        const iocItems = [
            ...(iocs.ips || []).map((value) => ({ label: 'IP', value })),
            ...(iocs.urls || []).map((value) => ({ label: 'URL', value })),
            ...(iocs.emails || []).map((value) => ({ label: 'Email', value })),
            ...(iocs.hashes || []).map((value) => ({ label: 'Hash', value })),
        ];
        renderList(reportIocList, iocItems, 'No indicators extracted yet.', (item) => `
            <div class="d-flex justify-content-between gap-3">
                <div>
                    <div class="fw-semibold">${escapeText(item.label)}</div>
                    <div class="text-muted small">${escapeText(item.value)}</div>
                </div>
            </div>
        `);

        renderList(reportClusterList, clusters, 'No clusters yet.', (item) => `
            <div class="d-flex justify-content-between gap-3">
                <div>
                    <div class="fw-semibold">${escapeText(item.cluster_id || 'Cluster')}</div>
                    <div class="text-muted small">Count ${escapeText(item.count ?? '')}</div>
                </div>
            </div>
        `);

        renderList(reportPathList, paths.map((value) => ({ value })), 'No deception paths yet.', (item) => `
            <div class="d-flex justify-content-between gap-3">
                <div>
                    <div class="fw-semibold">Decoy Path</div>
                    <div class="text-muted small">${escapeText(item.value)}</div>
                </div>
            </div>
        `);

        const phaseEntries = Array.isArray(payload.campaign_timeline) ? payload.campaign_timeline : [];
        renderList(reportPhaseList, phaseEntries, 'No phase entries yet.', (item) => `
            <div class="d-flex justify-content-between gap-3">
                <div>
                    <div class="fw-semibold">${escapeText(item.stage || 'Phase')}</div>
                    <div class="text-muted small">${escapeText(item.note || '')}</div>
                </div>
            </div>
        `);

        const environmentEntries = Object.entries(environment).map(([key, value]) => ({ key, value }));
        renderList(reportEnvironmentList, environmentEntries, 'No environment metadata yet.', (item) => `
            <div class="d-flex justify-content-between gap-3">
                <div>
                    <div class="fw-semibold">${escapeText(item.key)}</div>
                    <div class="text-muted small">${escapeText(item.value)}</div>
                </div>
            </div>
        `);
    }

    function renderResearchSummary(payload) {
        if (reportMetricConfidence) reportMetricConfidence.textContent = 'n/a';
        if (reportMetricPhases) reportMetricPhases.textContent = '0';
        if (reportMetricIocs) reportMetricIocs.textContent = '0';
        if (reportMetricClusters) reportMetricClusters.textContent = '0';
        if (reportClassification) reportClassification.textContent = payload.summary || 'Research summary unavailable';
        if (reportActorBehavior) reportActorBehavior.textContent = payload.meta?.cluster || 'No actor profile available';
        if (reportTooling) reportTooling.textContent = payload.meta?.backend || 'No tooling details available';
        if (reportInfrastructure) reportInfrastructure.textContent = payload.meta?.organization || 'No infrastructure details available';

        renderList(reportTimelineList, [], 'No campaign timeline yet.', () => '');
        renderList(reportIocList, [], 'No indicators extracted yet.', () => '');
        renderList(reportClusterList, [], 'No clusters yet.', () => '');
        renderList(reportPathList, [], 'No deception paths yet.', () => '');
        renderList(reportPhaseList, [], 'No phase entries yet.', () => '');

        const environmentEntries = Object.entries(payload.meta || {}).map(([key, value]) => ({ key, value }));
        renderList(reportEnvironmentList, environmentEntries, 'No environment metadata yet.', (item) => `
            <div class="d-flex justify-content-between gap-3">
                <div>
                    <div class="fw-semibold">${escapeText(item.key)}</div>
                    <div class="text-muted small">${escapeText(item.value)}</div>
                </div>
            </div>
        `);
    }

    function renderApiDocs(payload) {
        const info = payload.info || {};
        const paths = payload.paths || {};
        const metaData = payload.meta || {};
        const pathEntries = Object.entries(paths).map(([path, operations]) => ({ path, operations }));
        const operationEntries = [];

        pathEntries.forEach((entry) => {
            Object.entries(entry.operations || {}).forEach(([method, details]) => {
                operationEntries.push({ path: entry.path, method, summary: details?.summary || '' });
            });
        });

        if (apiDocsVersion) apiDocsVersion.textContent = String(info.version || 'n/a');
        if (apiDocsRoutes) apiDocsRoutes.textContent = String(pathEntries.length);
        if (apiDocsMethods) apiDocsMethods.textContent = String(operationEntries.length);
        if (apiDocsScope) apiDocsScope.textContent = info.title && /public/i.test(info.title) ? 'Public' : 'Internal';
        if (apiDocsTitle) apiDocsTitle.textContent = info.title || 'API Docs';
        if (apiDocsOpenapi) apiDocsOpenapi.textContent = payload.openapi || 'n/a';
        if (apiDocsMeta) apiDocsMeta.textContent = Object.keys(metaData).length ? JSON.stringify(metaData) : 'No metadata';

        renderList(apiDocsPathList, pathEntries, 'No API paths available.', (item) => `
            <div>
                <div class="fw-semibold">${escapeText(item.path)}</div>
                <div class="text-muted small">${escapeText(Object.keys(item.operations || {}).join(', ') || 'No methods')}</div>
            </div>
        `);

        renderList(apiDocsOperationList, operationEntries, 'No operations available.', (item) => `
            <div>
                <div class="fw-semibold text-uppercase">${escapeText(item.method)}</div>
                <div class="text-muted small">${escapeText(item.path)}</div>
                <div class="text-muted small">${escapeText(item.summary || '')}</div>
            </div>
        `);

        renderList(apiDocsEnvironmentList, Object.entries(metaData).map(([key, value]) => ({ key, value })), 'No metadata available.', (item) => `
            <div class="d-flex justify-content-between gap-3">
                <div>
                    <div class="fw-semibold">${escapeText(item.key)}</div>
                    <div class="text-muted small">${escapeText(item.value)}</div>
                </div>
            </div>
        `);
    }

    async function pollStatus() {
        try {
            const currentStatus = await fetchStatus('poll');
            const changedToStaff = Boolean(lastStatus && !lastStatus.staff && currentStatus.staff);

            if (changedToStaff) {
                await fetchStatus('stale_tab_refresh');
                await refreshSurfaceData('staff-transition');
            }

            lastStatus = currentStatus;
        } catch (error) {
            if (meta) {
                meta.textContent = `Status check failed: ${error.message}`;
            }
        }
    }

    async function initialize() {
        try {
            lastStatus = await fetchStatus('page_load');
            await refreshSurfaceData('initial-load');
        } catch (error) {
            if (meta) {
                meta.textContent = `Initial load failed: ${error.message}`;
            }
            if (output) {
                output.textContent = JSON.stringify({ error: error.message }, null, 2);
            }
        }

        pollTimer = window.setInterval(pollStatus, 4000);
    }

    window.addEventListener('beforeunload', () => {
        if (pollTimer) {
            window.clearInterval(pollTimer);
            pollTimer = null;
        }
    });

    initialize();
})();