/**
 * VORTEX-SDN AI Root-Cause Analysis (RCA) Controller
 * Fetches and renders root-cause diagnostics, correlated telemetry evidence,
 * event chain timelines, and enterprise relationship graph.
 */

const RootCause = {
  data: null,
  pollInterval: null,

  async init() {
    await this.fetchAnalysis();
    if (!this.pollInterval) {
      this.pollInterval = setInterval(() => {
        if (App.currentView === "root-cause" || App.currentView === "dashboard") {
          this.fetchAnalysis();
        }
      }, 5000);
    }
  },

  async fetchAnalysis() {
    try {
      const res = await API.get("/api/root-cause/analysis");
      this.data = res;
      this.render();
      this.updateDashboardWidget(res);
    } catch (err) {
      console.warn("[Root Cause] Failed to fetch RCA data:", err);
    }
  },

  async reanalyze() {
    try {
      Utils.showToast("Correlating live telemetry and security signals...", "info");
      const res = await API.post("/api/root-cause/reanalyze", {});
      this.data = res.analysis || res;
      this.render();
      this.updateDashboardWidget(this.data);
      Utils.showToast("Root-cause analysis updated.", "success");
    } catch (err) {
      Utils.showToast(`Re-analysis error: ${err.message}`, "danger");
    }
  },

  render() {
    if (!this.data) return;
    const d = this.data;

    // 1. Status Badge
    const statusEl = document.getElementById("rca-status-badge");
    if (statusEl) {
      const s = (d.status || "STABLE").toLowerCase();
      statusEl.className = `rca-status-badge ${s}`;
      statusEl.innerHTML = `<span class="rca-pulse-dot"></span> <span>${d.status || "STABLE"}</span>`;
    }

    // 2. Incident & Root Cause
    const incEl = document.getElementById("rca-incident-title");
    if (incEl) incEl.textContent = d.incident || "Normal Baseline Operation";

    const rcEl = document.getElementById("rca-root-cause-text");
    if (rcEl) rcEl.textContent = d.root_cause || "No anomalies detected.";

    // 3. Confidence Meter
    const confValEl = document.getElementById("rca-confidence-val");
    if (confValEl) confValEl.textContent = `${d.confidence || 97.4}%`;

    const confBarEl = document.getElementById("rca-confidence-bar");
    if (confBarEl) confBarEl.style.width = `${Math.min(100, Math.max(10, d.confidence || 97.4))}%`;

    // 4. Evidence List
    const evListEl = document.getElementById("rca-evidence-list");
    if (evListEl) {
      if (d.evidence && d.evidence.length > 0) {
        evListEl.innerHTML = d.evidence.map(ev => `
          <div class="rca-evidence-item">
            <span class="rca-evidence-bullet">●</span>
            <span>${ev}</span>
          </div>
        `).join("");
      } else {
        evListEl.innerHTML = `<div class="rca-evidence-item"><span>No anomalous evidence detected.</span></div>`;
      }
    }

    // 5. Impact List
    const impListEl = document.getElementById("rca-impact-list");
    if (impListEl) {
      if (d.impact && d.impact.length > 0) {
        impListEl.innerHTML = d.impact.map(imp => `
          <div class="rca-impact-item">
            <svg class="icon icon-sm" viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>
            <span>${imp}</span>
          </div>
        `).join("");
      } else {
        impListEl.innerHTML = `<div class="rca-impact-item" style="color:#94a3b8; border-color:rgba(255,255,255,0.1);"><span>0 degraded services.</span></div>`;
      }
    }

    // 6. Mitigation & Recovery
    const mitEl = document.getElementById("rca-mitigation-text");
    if (mitEl) mitEl.textContent = d.mitigation || "None required";

    const recEl = document.getElementById("rca-recovery-text");
    if (recEl) recEl.textContent = d.recovery || "Network healthy";

    // 7. Timeline Chain
    const tlEl = document.getElementById("rca-timeline-steps");
    if (tlEl && d.timeline) {
      tlEl.innerHTML = d.timeline.map((step, idx) => `
        <div class="rca-timeline-step">
          <span class="rca-step-time">${step.time}</span>
          <div class="rca-step-dot"></div>
          <span class="rca-step-text">${step.event}</span>
        </div>
        ${idx < d.timeline.length - 1 ? `<div class="rca-step-arrow">→</div>` : ''}
      `).join("");
    }

    // 8. Visual Relationship Graph
    const graphEl = document.getElementById("rca-graph-container");
    if (graphEl && d.graph && d.graph.nodes) {
      graphEl.innerHTML = d.graph.nodes.map((node, idx) => `
        <div class="rca-node ${node.status || 'normal'}">
          <span class="rca-node-stage">${node.stage}</span>
          <span class="rca-node-label">${node.label}</span>
        </div>
        ${idx < d.graph.nodes.length - 1 ? `
          <div class="rca-graph-arrow">
            <svg class="icon icon-sm" viewBox="0 0 24 24"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
          </div>
        ` : ''}
      `).join("");
    }
  },

  updateDashboardWidget(d) {
    const titleEl = document.getElementById("dash-rca-title");
    const descEl = document.getElementById("dash-rca-desc");
    const badgeEl = document.getElementById("dash-rca-badge");

    if (!titleEl) return;
    if (d.status === "ANALYZING" || (d.affected_flows_count && d.affected_flows_count > 0)) {
      titleEl.textContent = "1 Active Root Cause Detected";
      if (descEl) descEl.textContent = d.incident || "Security/QoS Anomaly";
      if (badgeEl) {
        badgeEl.textContent = d.status || "ANALYZING";
        badgeEl.className = "badge badge-critical";
      }
    } else {
      titleEl.textContent = "Network Stable — 0 Active Root Causes";
      if (descEl) descEl.textContent = "All OpenFlow nodes conforming to normal baseline.";
      if (badgeEl) {
        badgeEl.textContent = "STABLE";
        badgeEl.className = "badge badge-live";
      }
    }
  }
};
