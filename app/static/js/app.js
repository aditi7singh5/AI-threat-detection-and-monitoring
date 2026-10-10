// State management
let alertsData = [];
let logsData = [];
let mitreData = [];
let currentFilter = 'ALL';
let activeModalAlertId = null;
let threatChart = null;

// Initialize Lucide icons & chart on page load
document.addEventListener('DOMContentLoaded', () => {
    lucide.createIcons();
    initChart();
    fetchInitialData();
    connectSSE();
});

// Initial API fetch
async function fetchInitialData() {
    try {
        const [statsRes, alertsRes, logsRes, mitreRes] = await Promise.all([
            fetch('/api/dashboard/stats').then(r => r.json()),
            fetch('/api/alerts').then(r => r.json()),
            fetch('/api/logs?limit=25').then(r => r.json()),
            fetch('/api/dashboard/mitre-coverage').then(r => r.json())
        ]);

        updateMetricsUI(statsRes);
        alertsData = alertsRes;
        logsData = logsRes;
        mitreData = mitreRes;

        renderAlertsFeed();
        renderLogsTable();
        renderMitreGrid();
        updateChart();
    } catch (err) {
        console.error("Failed to load initial dataset:", err);
    }
}

// Real-Time SSE Listener
function connectSSE() {
    const evtSource = new EventSource('/api/stream');

    evtSource.onmessage = function (event) {
        try {
            const data = JSON.parse(event.data);
            if (data.metrics) updateMetricsUI(data.metrics);
            if (data.latest_alerts) {
                alertsData = data.latest_alerts;
                renderAlertsFeed();
                updateChart();
            }
            if (data.latest_log) {
                // Prepend new log if unique
                if (!logsData.some(l => l.id === data.latest_log.id)) {
                    logsData.unshift(data.latest_log);
                    if (logsData.length > 25) logsData.pop();
                    renderLogsTable();
                }
            }
        } catch (e) {
            console.error("Error processing SSE message:", e);
        }
    };
}

// Update Top KPI Cards
function updateMetricsUI(m) {
    document.getElementById('metric-total-logs').innerText = m.total_logs_processed.toLocaleString();
    document.getElementById('metric-active-threats').innerText = m.active_threats_count;
    document.getElementById('metric-critical-badge').innerText = `${m.critical_alerts_count} Critical`;
    document.getElementById('metric-anomaly-index').innerText = m.average_anomaly_index.toFixed(1);
    document.getElementById('metric-assets').innerText = m.monitored_assets;
    document.getElementById('metric-mitigated').innerText = m.mitigated_count;

    const healthBadge = document.getElementById('ai-health-badge');
    if (m.ai_gateway_health === 'UNDER_ATTACK') {
        healthBadge.className = "px-3 py-1.5 rounded-lg bg-rose-950/80 border border-rose-800 text-rose-400 text-xs font-medium flex items-center space-x-1.5 animate-pulse";
        healthBadge.innerHTML = `<i data-lucide="alert-octagon" class="w-4 h-4"></i><span>AI Gateway: UNDER ATTACK</span>`;
    } else if (m.ai_gateway_health === 'WARNING') {
        healthBadge.className = "px-3 py-1.5 rounded-lg bg-amber-950/80 border border-amber-800 text-amber-400 text-xs font-medium flex items-center space-x-1.5";
        healthBadge.innerHTML = `<i data-lucide="alert-triangle" class="w-4 h-4"></i><span>AI Gateway: WARNING</span>`;
    } else {
        healthBadge.className = "px-3 py-1.5 rounded-lg bg-emerald-950/60 border border-emerald-800/60 text-emerald-400 text-xs font-medium flex items-center space-x-1.5";
        healthBadge.innerHTML = `<i data-lucide="cpu" class="w-4 h-4"></i><span>AI Gateway: HEALTHY</span>`;
    }
    lucide.createIcons();
}

// Render Alerts List
function renderAlertsFeed() {
    const container = document.getElementById('alerts-container');
    let filtered = alertsData;
    if (currentFilter !== 'ALL') {
        filtered = alertsData.filter(a => a.severity === currentFilter);
    }

    if (filtered.length === 0) {
        container.innerHTML = `<div class="p-6 rounded-xl bg-slate-950/60 border border-slate-800/80 text-center text-slate-500 text-xs">No active ${currentFilter} threat alerts in system.</div>`;
        return;
    }

    container.innerHTML = filtered.map(a => {
        const isCritical = a.severity === 'CRITICAL';
        const isHigh = a.severity === 'HIGH';
        const badgeStyle = isCritical 
            ? 'bg-rose-950/80 text-rose-400 border-rose-800/80' 
            : isHigh ? 'bg-amber-950/80 text-amber-400 border-amber-800/80' : 'bg-blue-950/80 text-blue-400 border-blue-800/80';
        
        const isMitigated = a.status === 'MITIGATED';
        const statusBadge = isMitigated 
            ? '<span class="px-2 py-0.5 text-[10px] rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-mono">MITIGATED</span>'
            : `<span class="px-2 py-0.5 text-[10px] font-bold rounded border font-mono ${badgeStyle}">${a.severity}</span>`;

        return `
            <div onclick="investigateAlert('${a.id}')" class="p-3.5 rounded-xl bg-slate-950/80 hover:bg-slate-900 border border-slate-800/80 hover:border-slate-700 cursor-pointer transition flex flex-col justify-between space-y-2 group">
                <div class="flex items-start justify-between">
                    <div class="space-y-1">
                        <div class="flex items-center space-x-2">
                            ${statusBadge}
                            <span class="font-bold text-slate-200 text-xs group-hover:text-cyan-300 transition">${escapeHtml(a.title)}</span>
                        </div>
                        <p class="text-[11px] text-slate-400 line-clamp-2">${escapeHtml(a.description)}</p>
                    </div>
                    <span class="text-[10px] font-mono text-indigo-300 bg-indigo-950/60 px-2 py-1 rounded border border-indigo-900/60">
                        ${a.anomaly_score}/100 Risk
                    </span>
                </div>
                <div class="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-slate-900 font-mono">
                    <span>Target: ${escapeHtml(a.identity)}</span>
                    <span class="text-slate-400">${escapeHtml(a.geo_location)}</span>
                </div>
            </div>
        `;
    }).join('');
}

function filterAlerts(sev) {
    currentFilter = sev;
    renderAlertsFeed();
}

// Render Telemetry Table
function renderLogsTable() {
    const tbody = document.getElementById('logs-table-body');
    if (logsData.length === 0) return;

    tbody.innerHTML = logsData.map(l => {
        const timeStr = new Date(l.timestamp).toLocaleTimeString();
        const provBadge = l.provider === 'AI_GATEWAY' 
            ? '<span class="text-rose-400 font-bold">AI_GATEWAY</span>'
            : l.provider === 'AWS' ? '<span class="text-amber-400">AWS</span>' : '<span class="text-cyan-400">K8S</span>';
        
        const scoreColor = l.anomaly_score > 75 ? 'text-rose-400 font-bold' : l.anomaly_score > 50 ? 'text-amber-400' : 'text-slate-400';

        return `
            <tr class="hover:bg-slate-900/60 transition">
                <td class="p-3 text-slate-400">${timeStr}</td>
                <td class="p-3">${provBadge}</td>
                <td class="p-3 text-slate-300 max-w-[180px] truncate" title="${escapeHtml(l.identity)}">${escapeHtml(l.identity)}</td>
                <td class="p-3 font-semibold text-slate-200">${escapeHtml(l.action)}</td>
                <td class="p-3 text-slate-400">${escapeHtml(l.geo_location)} (${escapeHtml(l.ip_address)})</td>
                <td class="p-3 text-right ${scoreColor}">${l.anomaly_score}</td>
            </tr>
        `;
    }).join('');
}

// Render MITRE Matrix Cards
function renderMitreGrid() {
    const grid = document.getElementById('mitre-grid');
    if (!mitreData.length) return;

    grid.innerHTML = mitreData.map(m => {
        const isThreat = m.status === 'THREAT_DETECTED';
        const badgeColor = isThreat ? 'bg-amber-950/80 text-amber-400 border-amber-800' : 'bg-emerald-950/80 text-emerald-400 border-emerald-800';

        return `
            <div class="p-2.5 rounded-xl bg-slate-950/60 border border-slate-800/80 flex items-center justify-between">
                <div>
                    <span class="text-[10px] font-mono text-slate-400 block">${m.id}</span>
                    <span class="text-xs font-semibold text-slate-200">${m.name}</span>
                </div>
                <span class="px-2 py-0.5 text-[10px] font-mono rounded border ${badgeColor}">
                    ${m.count} Detected
                </span>
            </div>
        `;
    }).join('');
}

// Initialize Threat Donut Chart
function initChart() {
    const ctx = document.getElementById('threat-chart').getContext('2d');
    threatChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['IAM Escalation', 'AI Prompt Injection', 'Data Exfiltration', 'Container Escape', 'Anomalous Access'],
            datasets: [{
                data: [35, 28, 18, 12, 7],
                backgroundColor: ['#f59e0b', '#f43f5e', '#6366f1', '#06b6d4', '#10b981'],
                borderWidth: 2,
                borderColor: '#0f172a'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: { color: '#94a3b8', font: { size: 11, family: 'Inter' }, padding: 12 }
                }
            },
            cutout: '70%'
        }
    });
}

// Update Chart dataset counts
function updateChart() {
    if (!threatChart || !alertsData.length) return;
    const catCounts = {
        'IAM Escalation': 0,
        'AI Prompt Injection': 0,
        'Data Exfiltration': 0,
        'Container Escape / K8s Privilege': 0,
        'Anomalous Geo / Access Pattern': 0
    };

    alertsData.forEach(a => {
        if (catCounts[a.category] !== undefined) catCounts[a.category]++;
    });

    threatChart.data.datasets[0].data = Object.values(catCounts);
    threatChart.update();
}

// Investigate Alert Modal
async function investigateAlert(alertId) {
    activeModalAlertId = alertId;
    try {
        const alert = await fetch(`/api/alerts/${alertId}`).then(r => r.json());
        
        document.getElementById('modal-title').innerText = alert.title;
        document.getElementById('modal-subtitle').innerText = `ID: ${alert.id} | Provider: ${alert.provider} | Identity: ${alert.identity}`;
        
        const sevBadge = document.getElementById('modal-severity-badge');
        sevBadge.innerText = alert.severity;
        sevBadge.className = alert.severity === 'CRITICAL' 
            ? "px-2.5 py-1 text-xs font-bold rounded bg-rose-950 text-rose-400 border border-rose-800"
            : "px-2.5 py-1 text-xs font-bold rounded bg-amber-950 text-amber-400 border border-amber-800";

        const ai = alert.ai_analysis || {};
        document.getElementById('modal-ai-summary').innerText = ai.summary || alert.description;
        document.getElementById('modal-confidence').innerText = `Confidence: ${ai.confidence_score || '98.5%'}`;
        document.getElementById('modal-root-cause').innerText = ai.root_cause || 'Credentials Compromise';
        document.getElementById('modal-impact').innerText = ai.impact_assessment || 'Unauthorized Access';
        
        document.getElementById('modal-mitre-tactic').innerText = alert.mitre_tactic;
        document.getElementById('modal-mitre-technique').innerText = alert.mitre_technique;

        const playbookDiv = document.getElementById('modal-playbook');
        const commands = alert.mitigation_playbook || ai.mitigation_playbook || ["echo 'No automated script available'"];
        playbookDiv.innerHTML = commands.map(cmd => `<div class="p-1.5 bg-slate-900 rounded border border-slate-800 font-mono text-[11px] select-all">$ ${escapeHtml(cmd)}</div>`).join('');

        const mitigateBtn = document.getElementById('modal-mitigate-btn');
        if (alert.status === 'MITIGATED') {
            mitigateBtn.disabled = true;
            mitigateBtn.className = "px-5 py-2.5 rounded-lg bg-slate-800 text-slate-500 text-xs font-bold cursor-not-allowed flex items-center space-x-2";
            mitigateBtn.innerHTML = `<i data-lucide="check-circle-2" class="w-4 h-4"></i><span>Already Mitigated</span>`;
        } else {
            mitigateBtn.disabled = false;
            mitigateBtn.className = "px-5 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold shadow-lg shadow-emerald-600/30 flex items-center space-x-2 transition";
            mitigateBtn.innerHTML = `<i data-lucide="play" class="w-4 h-4"></i><span>Execute 1-Click Mitigation</span>`;
        }

        document.getElementById('investigate-modal').classList.remove('hidden');
        lucide.createIcons();
    } catch (e) {
        console.error("Failed to load alert modal details:", e);
    }
}

function closeModal() {
    document.getElementById('investigate-modal').classList.add('hidden');
}

// 1-Click Mitigation Action
async function executeMitigation() {
    if (!activeModalAlertId) return;
    try {
        const res = await fetch(`/api/alerts/${activeModalAlertId}/mitigate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action_type: 'automated_playbook_execution' })
        }).then(r => r.json());

        alert(`Remediation Executed Successfully!\nStatus: ${res.message}`);
        closeModal();
        fetchInitialData();
    } catch (e) {
        alert("Failed to execute mitigation action");
    }
}

async function dismissAlertModal() {
    if (!activeModalAlertId) return;
    try {
        await fetch(`/api/alerts/${activeModalAlertId}/dismiss`, { method: 'POST' });
        closeModal();
        fetchInitialData();
    } catch (e) {
        console.error("Error dismissing alert", e);
    }
}

// Attack Injection Trigger
async function injectAttack(scenario) {
    try {
        const res = await fetch('/api/simulation/inject-attack', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scenario: scenario })
        }).then(r => r.json());

        fetchInitialData();
    } catch (e) {
        console.error("Failed to inject attack scenario:", e);
    }
}

function openAttackModal() {
    injectAttack('prompt_injection');
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
