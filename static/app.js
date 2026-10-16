const form = document.querySelector("#scan-form");
const targetInput = document.querySelector("#target");
const authorizedInput = document.querySelector("#authorized");
const scanButton = document.querySelector("#scan-button");
const formMessage = document.querySelector("#form-message");
const scanList = document.querySelector("#scan-list");
const runCount = document.querySelector("#run-count");
const nmapStatus = document.querySelector("#nmap-status");

let nmapAvailable = true;
const severityOrder = { high: 0, medium: 1, low: 2, info: 3 };

function addText(parent, tag, text, className) {
  const element = document.createElement(tag);
  element.textContent = text;
  if (className) element.className = className;
  parent.append(element);
  return element;
}

function renderScans(scans) {
  scanList.replaceChildren();
  runCount.textContent = `${scans.length} SCAN${scans.length === 1 ? "" : "S"}`;
  if (!scans.length) {
    addText(scanList, "p", "No assessments yet. Choose an authorized private target to begin.", "empty-state");
    return;
  }

  for (const scan of scans) {
    const row = document.createElement("article");
    row.className = "scan-row";
    const identity = document.createElement("div");
    identity.className = "scan-identity";
    addText(identity, "strong", scan.target);
    addText(identity, "span", new Date(scan.created_at).toLocaleString());
    row.append(identity);

    const metrics = document.createElement("div");
    metrics.className = "scan-metrics";
    addText(metrics, "span", `${scan.host_count} hosts`);
    addText(metrics, "span", `${scan.device_count} probable devices`);
    addText(metrics, "span", `${scan.finding_count} observations`);
    row.append(metrics);

    const state = addText(row, "span", scan.status, `state state-${scan.status}`);
    state.setAttribute("aria-label", `Scan ${scan.status}`);
    if (scan.message) addText(row, "p", scan.message, "scan-message");

    if (scan.status === "completed" || scan.status === "failed") {
      const actions = document.createElement("div");
      actions.className = "scan-actions";
      const detailLink = document.createElement("a");
      detailLink.href = `/reports/${encodeURIComponent(scan.id)}`;
      detailLink.textContent = "View report ↗";
      actions.append(detailLink);
      const detailButton = document.createElement("button");
      detailButton.type = "button";
      detailButton.textContent = "Details";
      detailButton.addEventListener("click", () => showDetails(scan.id, row));
      actions.append(detailButton);
      row.append(actions);
    }
    scanList.append(row);
  }
}

async function loadScans() {
  try {
    const response = await fetch("/api/scans");
    if (!response.ok) throw new Error("Could not load assessments.");
    const scans = await response.json();
    renderScans(scans);
    if (scans.some((scan) => scan.status === "queued" || scan.status === "running")) {
      window.setTimeout(loadScans, 2500);
    }
  } catch (error) {
    formMessage.textContent = error.message;
  }
}

async function showDetails(scanId, row) {
  const existing = row.querySelector(".scan-detail");
  if (existing) {
    existing.remove();
    return;
  }
  const response = await fetch(`/api/scans/${encodeURIComponent(scanId)}`);
  const scan = await response.json();
  const detail = document.createElement("div");
  detail.className = "scan-detail";
  const findings = [...scan.findings].sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  if (!findings.length) addText(detail, "p", "No service observations recorded.");
  for (const finding of findings) {
    const item = document.createElement("div");
    item.className = "detail-finding";
    addText(item, "span", finding.severity, `severity severity-${finding.severity}`);
    addText(item, "strong", `${finding.device_ip} · ${finding.title}`);
    addText(item, "p", finding.details);
    addText(item, "p", `Evidence: ${finding.evidence}`);
    addText(item, "p", `Recommendation: ${finding.recommendation}`);
    detail.append(item);
  }
  row.append(detail);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  formMessage.textContent = "";

  if (!nmapAvailable) {
    formMessage.textContent = "Nmap is not installed or not on PATH, so scans cannot run in this environment.";
    return;
  }

  scanButton.disabled = true;
  scanButton.querySelector("span").textContent = "Queueing…";
  try {
    const response = await fetch("/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: targetInput.value.trim(), authorized: authorizedInput.checked }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail?.[0]?.msg || result.detail || "Could not start scan.");
    formMessage.textContent = `Assessment queued for ${result.target}.`;
    await loadScans();
  } catch (error) {
    formMessage.textContent = error.message;
  } finally {
    scanButton.disabled = false;
    scanButton.querySelector("span").textContent = "Start scan";
  }
});

fetch("/health")
  .then((response) => response.json())
  .then((health) => {
    nmapAvailable = Boolean(health.nmap_available);
    nmapStatus.textContent = nmapAvailable ? "Scanner ready" : "Nmap not installed";
    nmapStatus.parentElement.classList.toggle("unavailable", !nmapAvailable);
    scanButton.disabled = !nmapAvailable;
    if (!nmapAvailable) {
      scanButton.querySelector("span").textContent = "Scanner unavailable";
      formMessage.textContent = "This environment cannot run scans until Nmap is installed.";
    }
  })
  .catch(() => {
    nmapAvailable = false;
    nmapStatus.textContent = "Scanner status unavailable";
    scanButton.disabled = true;
    scanButton.querySelector("span").textContent = "Scanner unavailable";
  });

loadScans();