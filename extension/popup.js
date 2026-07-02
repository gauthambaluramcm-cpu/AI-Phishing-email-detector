document.addEventListener('DOMContentLoaded', async () => {
    // --- Elements ---
    const mainContent = document.getElementById('main-content');
    const analyzeBtn = document.getElementById('analyze-btn');
    const loadingDiv = document.getElementById('loading');
    const resultSection = document.getElementById('result-section');
    const errorSection = document.getElementById('error-section');
    const errorMessage = document.getElementById('error-message');
    const retryBtn = document.getElementById('retry-btn');
    const actionSection = document.getElementById('action-section');
    
    // Settings Elements
    const settingsBtn = document.getElementById('settings-btn');
    const settingsPanel = document.getElementById('settings-panel');
    const closeSettingsBtn = document.getElementById('close-settings-btn');
    const autoScanToggle = document.getElementById('auto-scan-toggle');

    // Result Elements
    const riskBadge = document.getElementById('risk-badge');
    const riskLabel = document.getElementById('risk-label');
    const riskScore = document.getElementById('risk-score');
    const scoreCircle = document.getElementById('score-circle');
    const summaryText = document.getElementById('summary-text');
    
    const primaryAction = document.getElementById('primary-action');
    const actionStepsList = document.getElementById('action-steps-list');
    const redFlagsContainer = document.getElementById('red-flags-container');
    const redFlagsList = document.getElementById('red-flags-list');
    const educationText = document.getElementById('education-text');

    // Your Render API URL
    const API_URL = 'https://ai-phishing-email-detector-0962.onrender.com/api/scan';

    // --- Settings & State ---
    
    // Load Auto-Scan preference
    chrome.storage.local.get(['autoScan'], (result) => {
        if (result.autoScan) {
            autoScanToggle.checked = true;
            startAnalysis(); // Automatically start!
        }
    });

    // Save Auto-Scan preference
    autoScanToggle.addEventListener('change', (e) => {
        chrome.storage.local.set({ autoScan: e.target.checked });
    });

    // Toggle Settings Panel
    settingsBtn.addEventListener('click', () => {
        settingsPanel.classList.toggle('hidden');
        mainContent.classList.toggle('hidden');
    });

    closeSettingsBtn.addEventListener('click', () => {
        settingsPanel.classList.add('hidden');
        mainContent.classList.remove('hidden');
    });

    // --- Accordion Logic ---
    const accordionHeaders = document.querySelectorAll('.accordion-header');
    accordionHeaders.forEach(header => {
        header.addEventListener('click', () => {
            const item = header.parentElement;
            // Toggle current
            item.classList.toggle('active');
            
            // Optional: Close others
            // accordionHeaders.forEach(other => {
            //     if(other !== header) other.parentElement.classList.remove('active');
            // });
        });
    });

    // --- Action Handlers ---
    analyzeBtn.addEventListener('click', startAnalysis);
    retryBtn.addEventListener('click', () => {
        errorSection.classList.add('hidden');
        actionSection.classList.remove('hidden');
    });

    async function startAnalysis() {
        actionSection.classList.add('hidden');
        errorSection.classList.add('hidden');
        resultSection.classList.add('hidden');
        loadingDiv.classList.remove('hidden');
        
        try {
            let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            
            let results = await chrome.scripting.executeScript({
                target: { tabId: tab.id },
                func: getPageText,
            });

            const pageText = results[0].result;

            if (!pageText || pageText.length < 20) {
                throw new Error("Could not find enough text on this page to analyze.");
            }

            const formData = new FormData();
            formData.append('email_text', pageText);

            const response = await fetch(API_URL, {
                method: 'POST',
                body: formData
            });

            const text = await response.text();
            let data;
            try {
                data = JSON.parse(text);
            } catch (e) {
                if (text.includes("<html")) {
                    throw new Error("Server is waking up from sleep. Please try again in 45 seconds.");
                }
                throw new Error("Invalid response from server.");
            }

            if (!response.ok) {
                throw new Error(data.error || "Failed to analyze content");
            }

            displayResults(data.analysis);

        } catch (error) {
            loadingDiv.classList.add('hidden');
            errorSection.classList.remove('hidden');
            errorMessage.textContent = error.message;
        }
    }

    function displayResults(analysis) {
        loadingDiv.classList.add('hidden');
        resultSection.classList.remove('hidden');
        actionSection.classList.remove('hidden'); // Show button to re-scan
        analyzeBtn.textContent = "Re-analyze Page";
        
        // Reset classes
        riskBadge.className = 'risk-badge';
        
        // --- Core Risk Details ---
        const riskLevel = (analysis.risk_level || "UNKNOWN").toUpperCase();
        riskLabel.textContent = riskLevel;
        
        // Animate score circle
        const score = analysis.risk_score || 0;
        riskScore.textContent = score;
        setTimeout(() => {
            scoreCircle.setAttribute('stroke-dasharray', `${score}, 100`);
        }, 100);

        if (riskLevel === 'SAFE') {
            riskBadge.classList.add('risk-safe');
        } else if (riskLevel === 'SUSPICIOUS') {
            riskBadge.classList.add('risk-suspicious');
        } else {
            riskBadge.classList.add('risk-phishing');
        }

        // --- Summary ---
        summaryText.textContent = analysis.summary || "No summary provided.";

        // --- Action Guide ---
        if (analysis.action_guide) {
            primaryAction.textContent = analysis.action_guide.primary_action || "Take Precaution";
            actionStepsList.innerHTML = '';
            if (analysis.action_guide.steps && analysis.action_guide.steps.length > 0) {
                analysis.action_guide.steps.forEach(step => {
                    const li = document.createElement('li');
                    li.textContent = step;
                    actionStepsList.appendChild(li);
                });
            } else {
                actionStepsList.innerHTML = '<li>No specific steps provided.</li>';
            }
        }

        // --- Red Flags ---
        if (analysis.red_flags && analysis.red_flags.length > 0) {
            redFlagsContainer.classList.remove('hidden');
            redFlagsList.innerHTML = '';
            analysis.red_flags.forEach(flag => {
                // If the backend sends objects {category, detail}, format them nicely
                const detailStr = typeof flag === 'string' ? flag : `${flag.category}: ${flag.detail}`;
                const li = document.createElement('li');
                li.textContent = detailStr;
                redFlagsList.appendChild(li);
            });
            // Auto-open red flags if it's phishing
            if(riskLevel === 'PHISHING') {
                redFlagsContainer.classList.add('active');
            }
        } else {
            redFlagsContainer.classList.add('hidden');
        }

        // --- Education Tip ---
        if (analysis.education_tip) {
            educationText.textContent = analysis.education_tip;
        } else {
            educationText.textContent = "Always verify the sender's email address.";
        }
    }
});

function getPageText() {
    return document.body.innerText;
}
