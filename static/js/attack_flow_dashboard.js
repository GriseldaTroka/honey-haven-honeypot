(function () {
    const sankeyContainer = document.getElementById('flow-sankey');
    if (!sankeyContainer) {
        return;
    }

    const analyticsEndpoint = document.body?.dataset?.attackFlowEndpoint || '/api/analytics/attack-flow/';
    const rawJson = document.getElementById('flow-raw-json');
    const metricSessions = document.getElementById('flow-metric-sessions');
    const metricTransitions = document.getElementById('flow-metric-transitions');
    const metricPaths = document.getElementById('flow-metric-paths');
    const metricUpdated = document.getElementById('flow-metric-updated');
    const pathList = document.getElementById('flow-path-list');
    const depthList = document.getElementById('flow-depth-list');
    const transitionCanvas = document.getElementById('transitionChart');
    const riskCanvas = document.getElementById('riskChart');

    let transitionChart = null;
    let riskChart = null;

    function escapeText(value) {
        return String(value ?? '')
            .replaceAll('&', '&amp;')
            .replaceAll('<', '&lt;')
            .replaceAll('>', '&gt;')
            .replaceAll('"', '&quot;')
            .replaceAll("'", '&#39;');
    }

    function renderList(container, items, emptyText, renderItem) {
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
            element.innerHTML = renderItem(item);
            container.appendChild(element);
        });
    }

    function renderMetrics(payload) {
        if (metricSessions) metricSessions.textContent = String(payload.session_count ?? 0);
        if (metricTransitions) metricTransitions.textContent = String((payload.transition_counts || []).length);
        if (metricPaths) metricPaths.textContent = String((payload.most_common_attack_paths || []).length);
        if (metricUpdated) metricUpdated.textContent = payload.generated_at ? new Date(payload.generated_at).toLocaleString() : 'n/a';
    }

    function renderTransitionChart(payload) {
        const items = payload.transition_counts || [];
        const labels = items.map((item) => `${item.from_phase || 'unknown'} → ${item.to_phase || 'unknown'}`);
        const values = items.map((item) => item.count || 0);

        if (!transitionCanvas || !labels.length) {
            return;
        }

        if (transitionChart) {
            transitionChart.destroy();
        }

        transitionChart = new Chart(transitionCanvas, {
            type: 'bar',
            data: {
                labels,
                datasets: [{
                    label: 'Transition Count',
                    data: values,
                    borderWidth: 0,
                    backgroundColor: '#a86816',
                    borderRadius: 8,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                },
                scales: {
                    x: { ticks: { color: '#5c5145' }, grid: { display: false } },
                    y: { beginAtZero: true, ticks: { color: '#5c5145' }, grid: { color: 'rgba(92, 81, 69, 0.1)' } },
                },
            },
        });
    }

    function renderRiskChart(payload) {
        const items = payload.risk_over_time || [];
        const labels = items.map((item) => item.bucket ? new Date(item.bucket).toLocaleString() : 'n/a');
        const riskValues = items.map((item) => Number(item.average_risk || 0));
        const confidenceValues = items.map((item) => Number(item.average_confidence || 0));

        if (!riskCanvas || !labels.length) {
            return;
        }

        if (riskChart) {
            riskChart.destroy();
        }

        riskChart = new Chart(riskCanvas, {
            type: 'line',
            data: {
                labels,
                datasets: [
                    {
                        label: 'Average Risk',
                        data: riskValues,
                        borderColor: '#8b2f14',
                        backgroundColor: 'rgba(139, 47, 20, 0.1)',
                        fill: true,
                        tension: 0.3,
                        pointRadius: 2,
                    },
                    {
                        label: 'Average Confidence',
                        data: confidenceValues,
                        borderColor: '#3b6b4b',
                        backgroundColor: 'rgba(59, 107, 75, 0.08)',
                        fill: false,
                        tension: 0.3,
                        pointRadius: 2,
                    },
                ],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom' },
                },
                scales: {
                    x: { ticks: { color: '#5c5145' }, grid: { display: false } },
                    y: { beginAtZero: true, ticks: { color: '#5c5145' }, grid: { color: 'rgba(92, 81, 69, 0.1)' } },
                },
            },
        });
    }

    function renderSankey(payload) {
        const sankey = payload.sankey || { nodes: [], links: [] };
        const nodes = sankey.nodes || [];
        const links = sankey.links || [];
        sankeyContainer.innerHTML = '';

        if (!nodes.length || !links.length) {
            sankeyContainer.innerHTML = '<div class="text-muted">No flow data available yet.</div>';
            return;
        }

        const width = Math.max(1000, sankeyContainer.clientWidth || 1000);
        const spacingY = 56;
        const nodeWidth = 160;
        const nodeHeight = 28;
        const marginX = 24;
        const marginY = 24;
        const height = Math.max(420, nodes.length * spacingY + marginY * 2);
        const usableWidth = Math.max(width - marginX * 2 - nodeWidth, 320);
        const stepX = nodes.length > 1 ? usableWidth / (nodes.length - 1) : 0;

        const positions = new Map();
        nodes.forEach((node, index) => {
            positions.set(node, {
                x: marginX + index * stepX,
                y: marginY + index * spacingY * 0.35,
            });
        });

        const svgNS = 'http://www.w3.org/2000/svg';
        const svg = document.createElementNS(svgNS, 'svg');
        svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
        svg.setAttribute('class', 'w-100');
        svg.style.minHeight = `${height}px`;

        const defs = document.createElementNS(svgNS, 'defs');
        const gradient = document.createElementNS(svgNS, 'linearGradient');
        gradient.setAttribute('id', 'flowGradient');
        gradient.setAttribute('x1', '0%');
        gradient.setAttribute('x2', '100%');
        gradient.setAttribute('y1', '0%');
        gradient.setAttribute('y2', '0%');
        const stop1 = document.createElementNS(svgNS, 'stop');
        stop1.setAttribute('offset', '0%');
        stop1.setAttribute('stop-color', '#c28b2c');
        const stop2 = document.createElementNS(svgNS, 'stop');
        stop2.setAttribute('offset', '100%');
        stop2.setAttribute('stop-color', '#7f2a18');
        gradient.appendChild(stop1);
        gradient.appendChild(stop2);
        defs.appendChild(gradient);
        svg.appendChild(defs);

        const maxLinkValue = Math.max(...links.map((link) => Number(link.value || 0)), 1);
        links.forEach((link, index) => {
            const source = positions.get(link.source);
            const target = positions.get(link.target);
            if (!source || !target) {
                return;
            }

            const thickness = Math.max(2, (Number(link.value || 0) / maxLinkValue) * 18);
            const path = document.createElementNS(svgNS, 'path');
            const startX = source.x + nodeWidth;
            const startY = source.y + nodeHeight / 2;
            const endX = target.x;
            const endY = target.y + nodeHeight / 2;
            const curve = Math.max(80, Math.abs(endX - startX) * 0.45);
            path.setAttribute('d', `M ${startX} ${startY} C ${startX + curve} ${startY}, ${endX - curve} ${endY}, ${endX} ${endY}`);
            path.setAttribute('fill', 'none');
            path.setAttribute('stroke', 'url(#flowGradient)');
            path.setAttribute('stroke-width', String(thickness));
            path.setAttribute('stroke-linecap', 'round');
            path.setAttribute('opacity', '0.28');
            svg.appendChild(path);

            const label = document.createElementNS(svgNS, 'text');
            label.setAttribute('x', String((startX + endX) / 2));
            label.setAttribute('y', String(((startY + endY) / 2) - 6 - index * 0.5));
            label.setAttribute('text-anchor', 'middle');
            label.setAttribute('fill', '#6d6050');
            label.setAttribute('font-size', '10');
            label.textContent = `${link.value}`;
            svg.appendChild(label);
        });

        nodes.forEach((node) => {
            const position = positions.get(node);
            if (!position) {
                return;
            }

            const group = document.createElementNS(svgNS, 'g');
            const rect = document.createElementNS(svgNS, 'rect');
            rect.setAttribute('x', String(position.x));
            rect.setAttribute('y', String(position.y));
            rect.setAttribute('rx', '12');
            rect.setAttribute('ry', '12');
            rect.setAttribute('width', String(nodeWidth));
            rect.setAttribute('height', String(nodeHeight));
            rect.setAttribute('fill', '#fff7e6');
            rect.setAttribute('stroke', '#d7b67d');
            rect.setAttribute('stroke-width', '1.25');
            group.appendChild(rect);

            const text = document.createElementNS(svgNS, 'text');
            text.setAttribute('x', String(position.x + nodeWidth / 2));
            text.setAttribute('y', String(position.y + 18));
            text.setAttribute('text-anchor', 'middle');
            text.setAttribute('fill', '#2d3138');
            text.setAttribute('font-size', '11');
            text.setAttribute('font-weight', '600');
            text.textContent = node;
            group.appendChild(text);
            svg.appendChild(group);
        });

        sankeyContainer.appendChild(svg);
    }

    function renderSummaryLists(payload) {
        renderList(pathList, payload.most_common_attack_paths || [], 'No path data yet.', (item) => `
            <div class="d-flex justify-content-between gap-3">
                <div>
                    <div class="fw-semibold">${escapeText(item.path || '')}</div>
                    <div class="text-muted small">Average events: ${escapeText(item.avg_events ?? '')}</div>
                </div>
                <div class="text-muted small">${escapeText(item.count ?? '')}</div>
            </div>
        `);

        renderList(depthList, payload.session_depth_distribution || [], 'No depth data yet.', (item) => `
            <div class="d-flex justify-content-between gap-3">
                <div>
                    <div class="fw-semibold">${escapeText(item.bucket || '')}</div>
                </div>
                <div class="text-muted small">${escapeText(item.count ?? '')}</div>
            </div>
        `);
    }

    async function loadDashboard() {
        const response = await fetch(analyticsEndpoint, {
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json' },
        });
        const payload = await response.json();
        if (rawJson) {
            rawJson.textContent = JSON.stringify(payload, null, 2);
        }
        renderMetrics(payload);
        renderTransitionChart(payload);
        renderRiskChart(payload);
        renderSankey(payload);
        renderSummaryLists(payload);
    }

    loadDashboard().catch((error) => {
        if (rawJson) {
            rawJson.textContent = JSON.stringify({ error: error.message }, null, 2);
        }
        sankeyContainer.innerHTML = '<div class="text-danger">Failed to load attack flow analytics.</div>';
    });
})();
