const form = document.getElementById("audit-form");
const button = document.getElementById("scan-btn");
const errorBox = document.getElementById("error");
const results = document.getElementById("results");
let lastReport = null;

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorBox.hidden = true;
  results.hidden = true;
  button.disabled = true;
  button.textContent = "Auditing...";
  try {
    const response = await fetch("/api/audit", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({url: document.getElementById("url").value})
    });
    const payload = await response.json();
    if (!response.ok || !payload.ok) throw new Error(payload.error || "Audit failed.");
    lastReport = payload.result;
    renderReport(lastReport);
  } catch (error) {
    errorBox.textContent = error.message || "Could not complete the audit.";
    errorBox.hidden = false;
  } finally {
    button.disabled = false;
    button.innerHTML = 'Run audit <span>↗</span>';
  }
});

function renderReport(report) {
  document.getElementById("score").textContent = report.score;
  document.getElementById("meter-fill").style.width = report.score + "%";
  document.getElementById("meter-fill").style.background =
    report.score >= 80 ? "var(--cyan)" : report.score >= 55 ? "var(--yellow)" : "var(--red)";
  document.getElementById("score-caption").textContent =
    report.score >= 80 ? "Good baseline; review all findings" :
    report.score >= 55 ? "Some configuration improvements needed" : "Several issues need review";
  document.getElementById("http-status").textContent = report.status_code;
  document.getElementById("high-count").textContent = report.counts.high;
  document.getElementById("pass-count").textContent = report.counts.pass;
  document.getElementById("target-host").textContent = report.host;
  document.getElementById("note").textContent = report.note;

  const body = document.getElementById("findings-body");
  body.replaceChildren();
  for (const finding of report.findings) {
    const tr = document.createElement("tr");
    for (const value of [
      finding.name, finding.severity, finding.status, finding.recommendation
    ]) {
      const td = document.createElement("td");
      if (value === finding.severity) {
        const badge = document.createElement("span");
        badge.className = "pill sev-" + finding.severity;
        badge.textContent = finding.severity.toUpperCase();
        td.appendChild(badge);
      } else {
        td.textContent = value;
      }
      tr.appendChild(td);
    }
    body.appendChild(tr);
  }
  results.hidden = false;
  results.scrollIntoView({behavior: "smooth", block: "start"});
}

document.getElementById("download-btn").addEventListener("click", () => {
  if (!lastReport) return;
  const blob = new Blob([JSON.stringify(lastReport, null, 2)], {type: "application/json"});
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "cybershield-audit-report.json";
  link.click();
  URL.revokeObjectURL(url);
});
