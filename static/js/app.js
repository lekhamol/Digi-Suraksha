// Digi Suraksha - Dashboard Controller
let threatsChart = null;

document.addEventListener('DOMContentLoaded', () => {
  loadDashboardData();
  loadHistory();
  loadAwarenessTips();
});

// Tab Switcher Logic
function switchTab(tabId) {
  document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
  document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.classList.remove('text-cyan-400', 'bg-slate-800/80');
    btn.classList.add('text-slate-300');
  });

  const activeTab = document.getElementById(`tab-${tabId}`);
  if (activeTab) activeTab.classList.remove('hidden');

  const activeBtn = document.getElementById(`nav-${tabId}`);
  if (activeBtn) {
    activeBtn.classList.add('text-cyan-400', 'bg-slate-800/80');
    activeBtn.classList.remove('text-slate-300');
  }

  if (tabId === 'dashboard') loadDashboardData();
  if (tabId === 'history') loadHistory();
}

// Load Dashboard Data (Stats, Chart, Alerts)
async function loadDashboardData() {
  try {
    const [statsRes, alertsRes] = await Promise.all([
      fetch('/api/stats'),
      fetch('/api/alerts')
    ]);

    const stats = await statsRes.json();
    const alerts = await alertsRes.json();

    document.getElementById('stat-total-scans').innerText = stats.total_scans || 0;
    document.getElementById('stat-threats-blocked').innerText = stats.total_threats || 0;
    document.getElementById('stat-active-alerts').innerText = stats.active_alerts || 0;

    renderChart(stats);
    renderAlerts(alerts);
  } catch (err) {
    console.error("Failed to load dashboard data:", err);
  }
}

// Render Chart.js
function renderChart(stats) {
  const ctx = document.getElementById('threatsChart').getContext('2d');
  
  const scanTypes = Object.keys(stats.scans_by_type || {});
  const scanCounts = Object.values(stats.scans_by_type || {});

  if (threatsChart) {
    threatsChart.destroy();
  }

  threatsChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: scanTypes.length ? scanTypes : ['URL', 'MESSAGE', 'PASSWORD'],
      datasets: [{
        label: 'Scans & Threat Count',
        data: scanCounts.length ? scanCounts : [12, 8, 5],
        backgroundColor: [
          'rgba(6, 182, 212, 0.7)',
          'rgba(244, 63, 94, 0.7)',
          'rgba(245, 158, 11, 0.7)'
        ],
        borderColor: [
          '#06b6d4',
          '#f43f5e',
          '#f59e0b'
        ],
        borderWidth: 1.5,
        borderRadius: 8
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        y: {
          beginAtZero: true,
          ticks: { color: '#9ca3af' },
          grid: { color: '#1f2937' }
        },
        x: {
          ticks: { color: '#9ca3af' },
          grid: { display: false }
        }
      }
    }
  });
}

// Render Security Alerts
function renderAlerts(alerts) {
  const container = document.getElementById('alerts-container');
  const badge = document.getElementById('alerts-badge');

  const activeAlerts = alerts.filter(a => !a.is_resolved);
  badge.innerText = `${activeAlerts.length} Active`;

  if (!alerts || alerts.length === 0) {
    container.innerHTML = `<div class="text-center py-6 text-slate-500 text-xs">No pending security alerts. System is safe!</div>`;
    return;
  }

  container.innerHTML = alerts.map(alert => `
    <div class="p-3 rounded-xl border ${alert.is_resolved ? 'bg-slate-950/40 border-slate-800/60 opacity-60' : 'bg-rose-950/20 border-rose-900/40'} flex items-start justify-between gap-2">
      <div>
        <div class="flex items-center space-x-2">
          <span class="px-2 py-0.5 rounded text-[10px] font-bold ${alert.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-400 border border-rose-800' : 'bg-amber-950 text-amber-400 border border-amber-800'}">${alert.severity}</span>
          <span class="text-xs font-bold text-white">${alert.title}</span>
        </div>
        <p class="text-xs text-slate-300 mt-1">${alert.description}</p>
        <span class="text-[10px] text-slate-500">${alert.timestamp || ''}</span>
      </div>
      ${!alert.is_resolved ? `
        <button onclick="resolveAlert(${alert.id})" class="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-xs text-emerald-400 border border-emerald-900/50 rounded whitespace-nowrap">
          Resolve
        </button>
      ` : `<span class="text-[10px] text-emerald-400"><i class="fa-solid fa-check"></i> Resolved</span>`}
    </div>
  `).join('');
}

async function resolveAlert(alertId) {
  try {
    await fetch(`/api/alerts/${alertId}/resolve`, { method: 'POST' });
    loadDashboardData();
  } catch (err) {
    console.error("Error resolving alert:", err);
  }
}

// Quick Scan Handler
function runQuickUrlScan() {
  const val = document.getElementById('quick-url-input').value;
  if (!val) return;
  switchTab('url-scanner');
  document.getElementById('url-scanner-input').value = val;
  runUrlScan();
}

function setUrlSample(sample) {
  document.getElementById('url-scanner-input').value = sample;
}

// URL Scanner Action
async function runUrlScan() {
  const url = document.getElementById('url-scanner-input').value.trim();
  if (!url) return alert("Please enter a URL to scan.");

  const panel = document.getElementById('url-result-panel');
  panel.classList.remove('hidden');

  try {
    const res = await fetch('/api/scan/url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await res.json();

    document.getElementById('url-result-target').innerText = data.url;
    document.getElementById('url-result-score-num').innerText = data.risk_score;
    document.getElementById('url-result-entropy').innerText = data.entropy || 'N/A';
    document.getElementById('url-result-recommendation').innerText = data.recommendation;

    const banner = document.getElementById('url-result-banner');
    const badge = document.getElementById('url-result-level-badge');
    const iconBox = document.getElementById('url-result-icon-box');

    if (data.risk_level === 'CRITICAL' || data.risk_level === 'HIGH') {
      banner.className = "rounded-xl p-4 bg-rose-950/40 border border-rose-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4";
      badge.className = "px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-rose-950 text-rose-400 border border-rose-800 alert-pulse";
      badge.innerText = `${data.risk_level} THREAT`;
      iconBox.className = "w-12 h-12 rounded-xl flex items-center justify-center text-2xl bg-rose-950 text-rose-400 border border-rose-800";
      iconBox.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i>`;
    } else if (data.risk_level === 'MEDIUM') {
      banner.className = "rounded-xl p-4 bg-amber-950/40 border border-amber-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4";
      badge.className = "px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-amber-950 text-amber-400 border border-amber-800";
      badge.innerText = "MEDIUM RISK";
      iconBox.className = "w-12 h-12 rounded-xl flex items-center justify-center text-2xl bg-amber-950 text-amber-400 border border-amber-800";
      iconBox.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i>`;
    } else {
      banner.className = "rounded-xl p-4 bg-emerald-950/40 border border-emerald-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4";
      badge.className = "px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-emerald-950 text-emerald-400 border border-emerald-800";
      badge.innerText = "SAFE DOMAIN";
      iconBox.className = "w-12 h-12 rounded-xl flex items-center justify-center text-2xl bg-emerald-950 text-emerald-400 border border-emerald-800";
      iconBox.innerHTML = `<i class="fa-solid fa-shield-check"></i>`;
    }

    document.getElementById('url-result-indicators').innerHTML = data.indicators.map(i => `<li class="flex items-center space-x-2"><i class="fa-solid fa-check-circle text-rose-400 text-xs"></i><span>${i}</span></li>`).join('');
    document.getElementById('url-result-reasons').innerHTML = data.reasons.map(r => `<li class="flex items-start space-x-2"><i class="fa-solid fa-circle-info text-cyan-400 text-xs mt-1"></i><span>${r}</span></li>`).join('');

    loadDashboardData();
  } catch (err) {
    console.error("URL scan failed:", err);
  }
}

// SMS Scanner Handlers
function setMsgSample(sample) {
  document.getElementById('msg-input').value = sample;
}

async function runMsgScan() {
  const message = document.getElementById('msg-input').value.trim();
  if (!message) return alert("Please enter message text to scan.");

  const panel = document.getElementById('msg-result-panel');
  panel.classList.remove('hidden');

  try {
    const res = await fetch('/api/scan/message', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message })
    });
    const data = await res.json();

    document.getElementById('msg-result-confidence').innerText = `${data.ai_confidence}%`;
    document.getElementById('msg-result-recommendation').innerText = data.recommendation;

    const banner = document.getElementById('msg-result-banner');
    const badge = document.getElementById('msg-result-badge');

    if (data.risk_level === 'CRITICAL' || data.risk_level === 'HIGH') {
      banner.className = "rounded-xl p-4 bg-rose-950/40 border border-rose-800 flex items-center justify-between";
      badge.className = "px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-rose-950 text-rose-400 border border-rose-800 alert-pulse";
      badge.innerText = `${data.risk_level} SCAM RISK (${data.risk_score}%)`;
    } else if (data.risk_level === 'MEDIUM') {
      banner.className = "rounded-xl p-4 bg-amber-950/40 border border-amber-800 flex items-center justify-between";
      badge.className = "px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-amber-950 text-amber-400 border border-amber-800";
      badge.innerText = `SUSPICIOUS (${data.risk_score}%)`;
    } else {
      banner.className = "rounded-xl p-4 bg-emerald-950/40 border border-emerald-800 flex items-center justify-between";
      badge.className = "px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-emerald-950 text-emerald-400 border border-emerald-800";
      badge.innerText = "SAFE TEXT";
    }

    document.getElementById('msg-result-indicators').innerHTML = data.indicators.map(i => `<li class="flex items-center space-x-2"><i class="fa-solid fa-flag text-rose-400 text-xs"></i><span>${i}</span></li>`).join('');
    document.getElementById('msg-result-reasons').innerHTML = data.reasons.map(r => `<li class="flex items-start space-x-2"><i class="fa-solid fa-angle-right text-cyan-400 text-xs mt-1"></i><span>${r}</span></li>`).join('');

    const embeddedBox = document.getElementById('msg-embedded-url-box');
    const embeddedContent = document.getElementById('msg-embedded-url-content');
    if (data.url_analysis && data.url_analysis.length > 0) {
      embeddedBox.classList.remove('hidden');
      embeddedContent.innerHTML = data.url_analysis.map(u => `
        <div class="p-2 rounded bg-slate-900 border border-slate-800">
          <div class="font-bold text-white">${u.url}</div>
          <div class="text-rose-400">Risk Level: ${u.risk_level} (${u.risk_score}%)</div>
          <div>${u.recommendation}</div>
        </div>
      `).join('');
    } else {
      embeddedBox.classList.add('hidden');
    }

    loadDashboardData();
  } catch (err) {
    console.error("SMS scan failed:", err);
  }
}

// Password Checker Handlers
function togglePasswordVisibility() {
  const pwdInput = document.getElementById('pwd-input');
  const icon = document.getElementById('pwd-toggle-icon');
  if (pwdInput.type === 'password') {
    pwdInput.type = 'text';
    icon.className = 'fa-solid fa-eye-slash';
  } else {
    pwdInput.type = 'password';
    icon.className = 'fa-solid fa-eye';
  }
}

async function runPwdCheck() {
  const password = document.getElementById('pwd-input').value;
  if (!password) return alert("Please enter a password.");

  const panel = document.getElementById('pwd-result-panel');
  panel.classList.remove('hidden');

  try {
    const res = await fetch('/api/scan/password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password })
    });
    const data = await res.json();

    document.getElementById('pwd-res-score').innerText = `${data.strength_score}/100`;
    document.getElementById('pwd-res-entropy').innerText = `${data.entropy_bits} bits`;
    document.getElementById('pwd-res-status').innerText = data.status;
    document.getElementById('pwd-res-advice').innerText = data.recommendation;

    const checklist = [
      { label: '8+ Characters', pass: data.length >= 8 },
      { label: '12+ Characters', pass: data.length >= 12 },
      { label: 'Uppercase & Lowercase', pass: data.has_uppercase && data.has_lowercase },
      { label: 'Numbers & Symbols', pass: data.has_digits && data.has_symbols }
    ];

    document.getElementById('pwd-checklist').innerHTML = checklist.map(c => `
      <div class="p-2.5 rounded-lg border ${c.pass ? 'bg-emerald-950/30 border-emerald-800/60 text-emerald-400' : 'bg-rose-950/30 border-rose-800/60 text-rose-400'} flex items-center justify-between">
        <span>${c.label}</span>
        <i class="fa-solid ${c.pass ? 'fa-check' : 'fa-xmark'}"></i>
      </div>
    `).join('');

    loadDashboardData();
  } catch (err) {
    console.error("Password check failed:", err);
  }
}

// Load Threat History Table
async function loadHistory() {
  try {
    const res = await fetch('/api/history');
    const logs = await res.json();
    const tbody = document.getElementById('history-table-body');

    if (!logs || logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" class="text-center py-6 text-slate-500">No scan history recorded yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = logs.map(log => {
      let badgeClass = 'bg-emerald-950 text-emerald-400 border-emerald-800';
      if (log.risk_level === 'CRITICAL' || log.risk_level === 'HIGH') {
        badgeClass = 'bg-rose-950 text-rose-400 border-rose-800';
      } else if (log.risk_level === 'MEDIUM' || log.risk_level === 'MODERATE') {
        badgeClass = 'bg-amber-950 text-amber-400 border-amber-800';
      }

      return `
        <tr class="hover:bg-slate-900/50">
          <td class="px-4 py-3"><span class="font-bold text-xs text-cyan-400">${log.scan_type}</span></td>
          <td class="px-4 py-3 max-w-xs truncate text-xs text-white" title="${log.target_input}">${log.target_input}</td>
          <td class="px-4 py-3 font-semibold text-xs text-slate-200">${log.risk_score}%</td>
          <td class="px-4 py-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold border ${badgeClass}">${log.risk_level}</span></td>
          <td class="px-4 py-3 text-xs text-slate-400">${log.timestamp ? log.timestamp.split('T')[0] : ''}</td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    console.error("Failed to load audit history:", err);
  }
}

// Load Awareness Tips
async function loadAwarenessTips() {
  try {
    const res = await fetch('/api/tips');
    const tips = await res.json();
    const container = document.getElementById('awareness-cards-container');

    container.innerHTML = tips.map(tip => `
      <div class="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 flex flex-col justify-between">
        <div>
          <div class="flex items-center space-x-3 mb-3">
            <div class="w-10 h-10 rounded-xl bg-cyan-950 border border-cyan-800/60 flex items-center justify-center text-cyan-400 text-lg">
              <i class="fa-solid fa-${tip.icon || 'shield-halved'}"></i>
            </div>
            <div>
              <span class="text-xs font-semibold text-cyan-400 uppercase tracking-wider">${tip.category}</span>
              <h3 class="text-lg font-bold text-white">${tip.title}</h3>
            </div>
          </div>
          <p class="text-sm text-slate-300 mb-4 leading-relaxed">${tip.summary}</p>
        </div>
        <div class="bg-slate-950 border border-slate-800 rounded-xl p-4">
          <span class="text-xs font-bold text-emerald-400 block mb-1"><i class="fa-solid fa-shield-check mr-1"></i> Key Prevention Rule</span>
          <p class="text-xs text-slate-300">${tip.prevention_steps}</p>
        </div>
      </div>
    `).join('');
  } catch (err) {
    console.error("Failed to load awareness tips:", err);
  }
}

// Export Security Report Download
function exportReport() {
  window.open('/api/export/report', '_blank');
}
