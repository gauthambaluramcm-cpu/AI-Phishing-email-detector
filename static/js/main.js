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

        renderResults(data.analysis, data.url_results);

    } catch (err) {
        stopLoadingAnimation();
        document.getElementById('loading').classList.add('hidden');
        document.getElementById('scanBtn').disabled = false;
        showError('Something went wrong. Please try again.');
        console.error(err);
    }
}

// ── Render Results ────────────────────────────────────────────────────────
function renderResults(analysis, urlResults) {
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
        <div class="risk-score-num">${score}</div>
        <div class="risk-score-label">/ 100 Risk Score</div>
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

    // Scan again
    html += `<button class="btn-scan-again" onclick="resetScan()">
    🔄 Scan Another Email
  </button>`;

    container.innerHTML = html;
    container.scrollIntoView({ behavior: 'smooth', block: 'start' });
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

// ── Reset ─────────────────────────────────────────────────────────────────
function resetScan() {
    document.getElementById('results').classList.add('hidden');
    document.getElementById('results').innerHTML = '';
    document.getElementById('email_text').value = '';
    clearFile();
    window.scrollTo({ top: 0, behavior: 'smooth' });
}