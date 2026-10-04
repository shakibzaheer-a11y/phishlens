let currentReport = null;

// Tab Switching
document.querySelectorAll(".nav-item").forEach(button => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));

    button.classList.add("active");
    const targetTab = button.getAttribute("data-tab");
    const pane = document.getElementById(targetTab);
    if (pane) pane.classList.add("active");
  });
});

// Dropzone & File Upload
const dropzone = document.getElementById("dropzone");
const fileInput = document.getElementById("file-input");

dropzone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropzone.classList.add("dragover");
});

dropzone.addEventListener("dragleave", () => {
  dropzone.classList.remove("dragover");
});

dropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropzone.classList.remove("dragover");
  if (e.dataTransfer.files.length > 0) {
    uploadEmailFile(e.dataTransfer.files[0]);
  }
});

fileInput.addEventListener("change", (e) => {
  if (e.target.files.length > 0) {
    uploadEmailFile(e.target.files[0]);
  }
});

function showLoader(show) {
  document.getElementById("loader").style.display = show ? "flex" : "none";
  if (show) {
    document.getElementById("results-container").style.display = "none";
  }
}

// Load Pre-built Sample
async function loadSample(sampleName) {
  showLoader(true);
  try {
    const res = await fetch(`/api/sample-analyze?name=${encodeURIComponent(sampleName)}`);
    const data = await res.json();
    renderAnalysis(data);
  } catch (err) {
    alert("Error analyzing sample: " + err.message);
  } finally {
    showLoader(false);
  }
}

// Upload Custom EML File
async function uploadEmailFile(file) {
  showLoader(true);
  try {
    const formData = new FormData();
    formData.append("email_file", file);

    const res = await fetch("/api/analyze", {
      method: "POST",
      body: formData
    });
    const data = await res.json();
    renderAnalysis(data);
  } catch (err) {
    alert("Upload analysis failed: " + err.message);
  } finally {
    showLoader(false);
  }
}

// Render Results into Dashboard
function renderAnalysis(data) {
  currentReport = data;
  document.getElementById("results-container").style.display = "block";

  const meta = data.metadata || {};
  const sender = data.sender_analysis || {};
  const auth = data.authentication || {};
  const scoring = data.scoring || {};
  const intel = data.threat_intel || {};
  const urls = data.urls || [];
  const atts = data.attachments || [];
  const rules = scoring.triggered_rules || [];

  // Top Metrics
  const verdictEl = document.getElementById("metric-verdict");
  verdictEl.textContent = scoring.verdict || "UNKNOWN";
  verdictEl.className = "verdict-badge " + getVerdictClass(scoring.verdict);

  document.getElementById("metric-score").textContent = scoring.risk_score || 0;
  document.getElementById("metric-time").textContent = data.execution_time_seconds || "0.45";

  // Auth Statuses
  renderAuthBadge("metric-spf", auth.spf?.verdict);
  renderAuthBadge("metric-dkim", auth.dkim?.verdict);
  renderAuthBadge("metric-dmarc", auth.dmarc?.verdict);

  // Counts
  document.getElementById("metric-urls-count").textContent = urls.length;
  document.getElementById("metric-atts-count").textContent = atts.length;
  document.getElementById("metric-hops-count").textContent = data.received_chain?.total_hops || 0;
  document.getElementById("metric-intel-count").textContent = intel.total_malicious_indicators || 0;

  // Recommendation
  document.getElementById("rec-text").textContent = scoring.recommendation || "No action required.";

  // Render Rules
  document.getElementById("triggered-count").textContent = rules.length;
  const tbodyRules = document.getElementById("tbody-rules");
  tbodyRules.innerHTML = "";
  if (rules.length === 0) {
    tbodyRules.innerHTML = "<tr><td colspan='4' style='text-align: center; color: var(--success); font-weight: 600;'>Clean email! No malicious forensic indicators triggered.</td></tr>";
  } else {
    rules.forEach(r => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><span class="code-pill">${r.rule_id}</span></td>
        <td><span class="sev-pill sev-${r.severity.toLowerCase()}">${r.severity}</span></td>
        <td><strong>${escapeHtml(r.name)}</strong></td>
        <td>${escapeHtml(r.detail || r.description)}</td>
      `;
      tbodyRules.appendChild(tr);
    });
  }

  // Render Sender Forensics
  const tbodySender = document.getElementById("tbody-sender");
  tbodySender.innerHTML = `
    <tr><td style="width: 25%"><strong>Subject</strong></td><td>${escapeHtml(meta.subject || "")}</td></tr>
    <tr><td><strong>Envelope Sender</strong></td><td>${escapeHtml(sender.from_raw || "")}</td></tr>
    <tr><td><strong>Sender Domain</strong></td><td><span class="code-pill">${escapeHtml(sender.from_domain || "")}</span></td></tr>
    <tr><td><strong>Display Name Spoof</strong></td><td>${sender.display_name_spoof ? `<span style="color: var(--danger); font-weight: 700;">⚠️ ${escapeHtml(sender.spoof_indicator)}</span>` : '<span style="color: var(--success);">Clean</span>'}</td></tr>
    <tr><td><strong>Reply-To Mismatch</strong></td><td>${sender.reply_to_mismatch ? `<span style="color: var(--danger); font-weight: 700;">⚠️ Replies route to external mailbox: ${escapeHtml(sender.reply_to_addr)}</span>` : '<span style="color: var(--success);">Aligned with From</span>'}</td></tr>
    <tr><td><strong>Originating IP</strong></td><td><span class="code-pill">${sender.originating_ip || "Not detected in hops"}</span></td></tr>
    <tr><td><strong>Domain Age (RDAP)</strong></td><td>${escapeHtml(intel.sender_domain_age?.details || "Not queried")}</td></tr>
  `;

  // Render Relay Hops
  const tbodyHops = document.getElementById("tbody-hops");
  tbodyHops.innerHTML = "";
  const hops = data.received_chain?.hops || [];
  if (hops.length === 0) {
    tbodyHops.innerHTML = "<tr><td colspan='4' style='color: var(--text-muted);'>No Received headers present.</td></tr>";
  } else {
    hops.forEach(h => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>#${h.hop_number}</strong></td>
        <td><span class="code-pill">${h.ip || "Unknown"}</span></td>
        <td>${escapeHtml(h.from_mta || "—")}</td>
        <td>${escapeHtml(h.by_mta || "—")}</td>
      `;
      tbodyHops.appendChild(tr);
    });
  }

  // Render URLs
  const tbodyUrls = document.getElementById("tbody-urls");
  tbodyUrls.innerHTML = "";
  if (urls.length === 0) {
    tbodyUrls.innerHTML = "<tr><td colspan='4' style='color: var(--text-muted);'>No URLs found in email body.</td></tr>";
  } else {
    urls.forEach(u => {
      const tr = document.createElement("tr");
      let flags = "";
      if (u.text_mismatch) {
        flags += `<div style="color: var(--danger); font-weight: 700;">⚠️ Phishing Mismatch: ${escapeHtml(u.mismatch_detail)}</div>`;
      }
      (u.indicators || []).forEach(ind => {
        if (!u.text_mismatch || ind !== u.mismatch_detail) {
          flags += `<div>• ${escapeHtml(ind)}</div>`;
        }
      });
      if (!flags) flags = "<span style='color: var(--success);'>Clean structure</span>";

      tr.innerHTML = `
        <td><span class="code-pill">${escapeHtml(u.defanged_url || u.url)}</span></td>
        <td style="color: var(--text-muted); font-size: 0.8rem;">${escapeHtml(u.display_text || "[Hidden / Image]")}</td>
        <td>${escapeHtml(u.domain || "")} (<strong>.${escapeHtml(u.tld || "")}</strong>)</td>
        <td>${flags}</td>
      `;
      tbodyUrls.appendChild(tr);
    });
  }

  // Render Attachments
  const tbodyAtts = document.getElementById("tbody-attachments");
  tbodyAtts.innerHTML = "";
  if (atts.length === 0) {
    tbodyAtts.innerHTML = "<tr><td colspan='5' style='color: var(--text-muted);'>No attachments found.</td></tr>";
  } else {
    atts.forEach(a => {
      const tr = document.createElement("tr");
      let inds = (a.indicators || []).map(i => `<div style="color: var(--danger); font-weight: 600;">• ${escapeHtml(i)}</div>`).join("");
      if (!inds) inds = "<span style='color: var(--success);'>Standard file extension</span>";

      tr.innerHTML = `
        <td><strong>${escapeHtml(a.filename)}</strong></td>
        <td><span class="code-pill">${escapeHtml(a.declared_type)}</span></td>
        <td>${a.size_kb} KB</td>
        <td><span class="code-pill">${a.sha256}</span></td>
        <td>${inds}</td>
      `;
      tbodyAtts.appendChild(tr);
    });
  }

  // Render Threat Intel
  const tbodyIntel = document.getElementById("tbody-intel");
  tbodyIntel.innerHTML = "";

  if (intel.sender_ip_intel) {
    appendIntelRow(tbodyIntel, "AbuseIPDB (Originating IP)", intel.sender_ip_intel.indicator, intel.sender_ip_intel.is_malicious, intel.sender_ip_intel.details);
  }
  if (intel.sender_domain_age) {
    appendIntelRow(tbodyIntel, "RDAP / WHOIS (Domain Age)", intel.sender_domain_age.indicator, intel.sender_domain_age.is_malicious, intel.sender_domain_age.details);
  }
  (intel.url_intel || []).forEach(u => {
    appendIntelRow(tbodyIntel, "VirusTotal / URLhaus (URL)", u.url.substring(0, 45) + "...", u.is_malicious, u.summary_details);
  });
  (intel.attachment_intel || []).forEach(a => {
    appendIntelRow(tbodyIntel, "VirusTotal (File Hash)", a.filename, a.intel?.is_malicious, a.intel?.details);
  });
}

function appendIntelRow(tbody, service, ioc, isMal, details) {
  const tr = document.createElement("tr");
  const statBadge = isMal
    ? "<span class='sev-pill sev-critical'>MALICIOUS HIT</span>"
    : "<span class='sev-pill sev-low'>CLEAN</span>";
  tr.innerHTML = `
    <td><strong>${service}</strong></td>
    <td><span class="code-pill">${escapeHtml(ioc)}</span></td>
    <td>${statBadge}</td>
    <td>${escapeHtml(details)}</td>
  `;
  tbody.appendChild(tr);
}

function renderAuthBadge(elementId, verdict) {
  const el = document.getElementById(elementId);
  const v = (verdict || "none").toLowerCase();
  el.textContent = v.toUpperCase();
  if (v === "pass") {
    el.className = "auth-status status-pass";
  } else if (["fail", "softfail", "reject", "quarantine"].includes(v)) {
    el.className = "auth-status status-fail";
  } else {
    el.className = "auth-status status-warn";
  }
}

function getVerdictClass(verdict) {
  switch ((verdict || "").toUpperCase()) {
    case "MALICIOUS": return "verdict-malicious";
    case "HIGH RISK": return "verdict-high";
    case "SUSPICIOUS": return "verdict-suspicious";
    default: return "verdict-benign";
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Machine Learning Evaluation Suite
async function runMLEvaluation() {
  const container = document.getElementById("ml-eval-container");
  container.innerHTML = `<div class="loader-banner"><div class="spinner"></div> Running benchmark across labeled phishing and legitimate corpora...</div>`;

  try {
    const res = await fetch("/api/evaluate");
    const data = await res.json();
    const m = data.metrics || {};
    const cm = data.confusion_matrix || {};

    container.innerHTML = `
      <div class="metrics-grid" style="margin-top: 1rem;">
        <div class="metric-card">
          <div class="card-label">Detection Accuracy</div>
          <div class="score-display">${(m.accuracy * 100).toFixed(1)}%</div>
          <div class="speed-pill">Total Samples: ${m.total_evaluated}</div>
        </div>
        <div class="metric-card">
          <div class="card-label">Precision & Recall</div>
          <div class="score-display" style="font-size: 1.6rem;">P: ${(m.precision * 100).toFixed(1)}% | R: ${(m.recall * 100).toFixed(1)}%</div>
          <div class="speed-pill">F1-Score: ${(m.f1_score * 100).toFixed(1)}%</div>
        </div>
        <div class="metric-card">
          <div class="card-label">False Positive Rate</div>
          <div class="score-display" style="color: var(--success);">${(m.false_positive_rate * 100).toFixed(1)}%</div>
          <div class="speed-pill">Avg Inference: ${m.avg_seconds_per_email}s / email</div>
        </div>
      </div>

      <div class="section-title" style="margin-top: 1.5rem;">Confusion Matrix</div>
      <div class="table-wrapper">
        <table class="data-table">
          <thead>
            <tr>
              <th>Ground Truth \\ Predicted</th>
              <th>Predicted Phishing</th>
              <th>Predicted Benign</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>Actual Phishing</strong></td>
              <td style="color: var(--danger); font-weight: 800;">${cm.predicted_phish?.actual_phish || 0} (True Positives)</td>
              <td style="color: var(--warning);">${cm.predicted_benign?.actual_phish || 0} (False Negatives)</td>
            </tr>
            <tr>
              <td><strong>Actual Benign</strong></td>
              <td style="color: var(--warning);">${cm.predicted_phish?.actual_benign || 0} (False Positives)</td>
              <td style="color: var(--success); font-weight: 800;">${cm.predicted_benign?.actual_benign || 0} (True Negatives)</td>
            </tr>
          </tbody>
        </table>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<div style="color: var(--danger);">Evaluation failed: ${err.message}</div>`;
  }
}

// Exports
function exportJSONReport() {
  if (!currentReport) {
    alert("Please analyze an email first.");
    return;
  }
  const blob = new Blob([JSON.stringify(currentReport, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `phishlens_report_${Date.now()}.json`;
  a.click();
}

function exportHTMLReport() {
  if (!currentReport) {
    alert("Please analyze an email first.");
    return;
  }
  // Construct printable HTML file client-side
  const htmlContent = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>PhishLens Forensic Report</title>
      <style>
        body { font-family: sans-serif; padding: 2rem; background: #0f172a; color: #f8fafc; line-height: 1.5; }
        .box { background: #1e293b; padding: 1.5rem; border-radius: 8px; margin-bottom: 1.5rem; border: 1px solid #334155; }
        h1, h2 { color: #38bdf8; }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
        th, td { padding: 0.5rem; border: 1px solid #334155; text-align: left; }
        th { background: #0b1120; }
        .pill { font-family: monospace; background: #000; padding: 2px 6px; border-radius: 4px; color: #38bdf8; }
      </style>
    </head>
    <body>
      <h1>🛡️ PhishLens Forensic Report</h1>
      <div class="box">
        <h2>Verdict: ${currentReport.scoring?.verdict} (Risk Score: ${currentReport.scoring?.risk_score}/100)</h2>
        <p><strong>Recommendation:</strong> ${currentReport.scoring?.recommendation}</p>
        <p><strong>Target File:</strong> ${currentReport.metadata?.source_filename}</p>
        <p><strong>Subject:</strong> ${currentReport.metadata?.subject}</p>
        <p><strong>Sender:</strong> ${currentReport.sender_analysis?.from_raw}</p>
      </div>
      <div class="box">
        <h2>Triggered Indicators</h2>
        <table>
          <tr><th>ID</th><th>Severity</th><th>Indicator</th><th>Detail</th></tr>
          ${(currentReport.scoring?.triggered_rules || []).map(r => `<tr><td>${r.rule_id}</td><td>${r.severity}</td><td>${r.name}</td><td>${r.detail}</td></tr>`).join("")}
        </table>
      </div>
    </body>
    </html>
  `;
  const blob = new Blob([htmlContent], { type: "text/html" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `phishlens_forensic_${Date.now()}.html`;
  a.click();
}

// Auto-load first sample upon dashboard startup for immediate demo
window.addEventListener("DOMContentLoaded", () => {
  loadSample("m365_credential_harvest.eml");
});
