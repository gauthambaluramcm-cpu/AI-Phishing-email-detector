// ── Tab Switching ─────────────────────────────────────────────────────────
function switchTab(tab) {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

    document.getElementById(`tab-${tab}`).classList.add('active');
    event.target.classList.add('active');

    // Clear opposite input
    if (tab === 'paste') clearFile();
    else document.getElementById('email_text').value = '';
}

// ── File Handling ─────────────────────────────────────────────────────────
function handleFileSelect(input) {
    if (input.files && input.files[0]) {
        const fileName = input.files[0].name;
        document.getElementById('file-name').textContent = fileName;
        document.getElementById('file-selected').classList.remove('hidden');
        document.getElementById('uploadZone').classList.add('hidden');
    }
}

function clearFile() {
    document.getElementById('eml_file').value = '';
    document.getElementById('file-selected').classList.add('hidden');
    document.getElementById('uploadZone').classList.remove('hidden');
    document.getElementById('file-name').textContent = '';
}

// ── Drag & Drop ───────────────────────────────────────────────────────────
const uploadZone = document.getElementById('uploadZone');
if (uploadZone) {
    uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadZone.style.borderColor = 'var(--green)';
    });

    uploadZone.addEventListener('dragleave', () => {
        uploadZone.style.borderColor = '';
    });

    uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadZone.style.borderColor = '';
        const file = e.dataTransfer.files[0];
        if (file && file.name.endsWith('.eml')) {
            const input = document.getElementById('eml_file');
            const dt = new DataTransfer();
            dt.items.add(file);
            input.files = dt.files;
            handleFileSelect(input);
        } else {
            alert('Please drop a valid .eml file.');
        }
    });
}

// ── Loading Animation ─────────────────────────────────────────────────────
const loadingMessages = [
    'Initializing AI analysis...',
    'Scanning email patterns...',
    'Detecting manipulation tactics...',
    'Extracting URLs...',
    'Checking threat databases...',
    'Generating risk report...'
];

let msgInterval = null;

function startLoadingAnimation() {
    let i = 0;
    const msgEl = document.getElementById('loading-msg');
    const steps = ['ls1', 'ls2', 'ls3'];
    let stepIdx = 0;

    msgInterval = setInterval(() => {
        if (msgEl) {
            msgEl.textContent = loadingMessages[i % loadingMessages.length];
            i++;
        }
        // Progressively activate loading steps
        if (stepIdx < steps.length) {
            document.getElementById(steps[stepIdx])?.classList.add('active');
            stepIdx++;
        }
    }, 1800);
}

function stopLoadingAnimation() {
    if (msgInterval) clearInterval(msgInterval);
}

// ── Main Scan Function ────────────────────────────────────────────────────
async function startScan() {
    const emailText = document.getElementById('email_text')?.value?.trim();
    const emlFile = document.getElementById('eml_file')?.files[0];

    if (!emailText && !emlFile) {
        alert('Please paste an email or upload a .eml file.');
        return;
    }

    // Show loading, hide results
    document.getElementById('loading').classList.remove('hidden');
    document.getElementById('results').classList.add('hidden');
    document.getElementById('results').innerHTML = '';
    document.getElementById('scanBtn').disabled = true;

    // Reset loading steps
    ['ls1', 'ls2', 'ls3'].forEach(id => {
        document.getElementById(id)?.classList.remove('active');
    });

    startLoadingAnimation();

    try {
        const formData = new FormData();
        if (emlFile) formData.append('eml_file', emlFile);
        else formData.append('email_text', emailText);

        const response = await fetch('/api/scan', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        stopLoadingAnimation();
        document.getElementById('loading').classList.add('hidden');
        document.getElementById('scanBtn').disabled = false;

        if (data.error) {
            showError(data.error);
            return;
        }

        renderResults(data.analysis, data.url_results, data.is_logged_in);

    } catch (err) {
        stopLoadingAnimation();
        document.getElementById('loading').classList.add('hidden');
        document.getElementById('scanBtn').disabled = false;
        showError('Something went wrong. Please try again.');
        console.error(err);
    }
}

// ── Render Results ────────────────────────────────────────────────────────
function renderResults(analysis, urlResults, isLoggedIn) {
    const container = document.getElementById('results');
    container.classList.remove('hidden');

    const risk = analysis.risk_level || 'UNKNOWN';
    const score = analysis.risk_score || 0;
    const summary = analysis.summary || '';
    const redFlags = analysis.red_flags || [];
    const action = analysis.action_guide || {};
    const urls = urlResults || [];
    const eduTip = analysis.education_tip || '';
    const legit = analysis.legitimate_elements || [];

    const riskIcon = risk === 'HIGH' ? '🔴' : risk === 'MEDIUM' ? '🟡' : '🟢';
    const riskMsg = risk === 'HIGH'
        ? 'This is a Phishing Email'
        : risk === 'MEDIUM'
            ? 'Suspicious — Proceed with Caution'
            : 'This Email Appears Safe';

    let html = `
    <!-- Risk Banner -->
    <div class="risk-banner ${risk}">
      <div class="risk-icon">${riskIcon}</div>
      <div>
        <div class="risk-label">Threat Assessment</div>
        <div class="risk-level-text">${riskMsg}</div>
      </div>
      <div class="risk-score-wrap">
        <svg class="score-circular-chart" viewBox="0 0 36 36">
            <path class="score-circle-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
            <path class="score-circle" id="result-score-circle" stroke-dasharray="0, 100" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
        </svg>
        <div class="risk-score-num">${score}</div>
      </div>
    </div>

    <!-- Summary -->
    <div class="result-card">
      <div class="result-card-title">📋 AI Summary</div>
      <div class="summary-text">${summary}</div>
    </div>
  `;

    // Red Flags
    if (redFlags.length > 0) {
        html += `<div class="result-card">
      <div class="result-card-title">🚩 Red Flags Detected (${redFlags.length})</div>`;
        redFlags.forEach(flag => {
            html += `
        <div class="red-flag-item ${flag.severity}">
          <span class="flag-severity ${flag.severity}">${flag.severity}</span>
          <div>
            <div class="flag-category">${flag.category}</div>
            <div class="flag-detail">${flag.detail}</div>
          </div>
        </div>`;
        });
        html += `</div>`;
    } else {
        html += `<div class="result-card">
      <div class="result-card-title">🚩 Red Flags</div>
      <div class="summary-text" style="color:var(--green)">✅ No red flags detected.</div>
    </div>`;
    }

    // URL Results
    if (urls.length > 0) {
        html += `<div class="result-card">
      <div class="result-card-title">🔗 URL Scan Results (${urls.length})</div>`;
        urls.forEach(u => {
            html += `
        <div class="url-item">
          <span class="url-verdict ${u.verdict}">${u.verdict}</span>
          <span class="url-text">${u.url}</span>
          ${u.verdict === 'MALICIOUS'
                    ? `<span style="font-size:0.75rem;color:var(--red);margin-left:auto;">
                ⚠️ ${u.malicious} engines flagged</span>`
                    : ''}
        </div>`;
        });
        html += `</div>`;
    }

    // Action Guide
    if (action.primary_action) {
        html += `<div class="result-card">
      <div class="result-card-title">✅ Action Guide</div>
      <div class="action-primary">👉 ${action.primary_action}</div>
      <ul class="action-steps">`;
        (action.steps || []).forEach((step, i) => {
            html += `<li>
        <span class="step-bullet">0${i + 1}.</span>
        <span>${step}</span>
      </li>`;
        });
        html += `</ul></div>`;
    }

    // Legitimate elements warning
    if (legit.length > 0) {
        html += `<div class="result-card">
      <div class="result-card-title">⚠️ Why This Looks Convincing</div>
      <ul class="action-steps">`;
        legit.forEach(el => {
            html += `<li>
        <span class="step-bullet">→</span>
        <span>${el}</span>
      </li>`;
        });
        html += `</ul></div>`;
    }

    // Education tip
    if (eduTip) {
        html += `<div class="result-card">
      <div class="result-card-title">💡 Security Tip</div>
      <div class="edu-tip">💡 ${eduTip}</div>
    </div>`;
    }
    
    // Action Buttons
    html += `<div style="display: flex; gap: 1rem; margin-top: 1rem;">`;
    
    // Scan again
    html += `<button class="btn-scan-again" style="flex: 1;" onclick="resetScan()">
    🔄 Scan Another Email
  </button>`;
  
    // Export Report (Premium feature)
    if (isLoggedIn) {
        // Store analysis data globally for the export function
        window.currentAnalysisData = { analysis, urlResults };
        html += `<button class="btn-scan-again" style="flex: 1; background: var(--blue); color: white;" onclick="exportReport()">
        📥 Export Report (Premium)
      </button>`;
    } else {
        html += `<a href="/login" class="btn-scan-again" style="flex: 1; text-align: center; background: rgba(255,255,255,0.05); text-decoration: none; display: flex; align-items: center; justify-content: center;">
        🔒 Login to Export
      </a>`;
    }
    
    html += `</div>`;

    container.innerHTML = html;
    container.scrollIntoView({ behavior: 'smooth', block: 'start' });
    
    // Animate circle
    setTimeout(() => {
        const circle = document.getElementById('result-score-circle');
        if (circle) circle.setAttribute('stroke-dasharray', `${score}, 100`);
    }, 100);
}

// ── Error Display ─────────────────────────────────────────────────────────
function showError(message) {
    const container = document.getElementById('results');
    container.classList.remove('hidden');
    container.innerHTML = `
    <div class="result-card" style="border-color:var(--red);">
      <div class="result-card-title" style="color:var(--red);">❌ Error</div>
      <div class="summary-text">${message}</div>
    </div>
    <button class="btn-scan-again" onclick="resetScan()">🔄 Try Again</button>
  `;
}

// ── Export Report ─────────────────────────────────────────────────────────
function exportReport() {
    const data = window.currentAnalysisData;
    if (!data) return;
    
    const { analysis, urlResults } = data;
    
    let report = `=== PHISHGUARD AI REPORT ===\n\n`;
    report += `Threat Level: ${analysis.risk_level}\n`;
    report += `Risk Score: ${analysis.risk_score}/100\n\n`;
    
    report += `[SUMMARY]\n${analysis.summary}\n\n`;
    
    report += `[RED FLAGS]\n`;
    if (analysis.red_flags && analysis.red_flags.length > 0) {
        analysis.red_flags.forEach(f => {
            report += `- [${f.severity}] ${f.category}: ${f.detail}\n`;
        });
    } else {
        report += `None detected.\n`;
    }
    
    report += `\n[ACTION GUIDE]\n👉 ${analysis.action_guide?.primary_action || 'Proceed with caution'}\n`;
    (analysis.action_guide?.steps || []).forEach(s => report += `- ${s}\n`);
    
    // Download logic
    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `PhishGuard_Report_${new Date().getTime()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
}

// ── Reset ─────────────────────────────────────────────────────────────────
function resetScan() {
    document.getElementById('results').classList.add('hidden');
    document.getElementById('results').innerHTML = '';
    document.getElementById('email_text').value = '';
    clearFile();
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ── Initialization & Quick Scan ───────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    if (typeof AOS !== 'undefined') {
        AOS.init({
            once: true,
            offset: 50,
            duration: 600
        });
    }

    // Check if we arrived from a Quick Scan on the home page
    const quickScanText = localStorage.getItem('quickScanText');
    if (quickScanText && window.location.pathname === '/analyze') {
        const emailInput = document.getElementById('email_text');
        if (emailInput) {
            emailInput.value = quickScanText;
            localStorage.removeItem('quickScanText');
            
            // Auto start scan after a brief moment to let animations finish
            setTimeout(() => {
                if(typeof startScan === 'function') startScan();
            }, 600);
        }
    }
});

function submitQuickScan() {
    const input = document.getElementById('quick-scan-input');
    if (input && input.value.trim().length > 0) {
        localStorage.setItem('quickScanText', input.value.trim());
        window.location.href = '/analyze';
    }
}