/**
 * VORTEX-SDN Intelligent Incident Management & Root Cause Analysis Controller
 * Manages incident lifecycle (DETECTED, INVESTIGATING, MITIGATING, RECOVERING, RESOLVED, CLOSED),
 * automated Root Cause Analysis (RCA), impact inspection, visual timelines, and KPI cards.
 */

const Incidents = {
  currentStatusFilter: "ALL",
  currentTimeFilter: "24h",
  currentSort: "newest",
  searchDebounceTimer: null,
  activeIncidentId: null,

  async init() {
    this.setupListeners();
    await this.fetchSummary();
    await this.fetchIncidents();
  },

  setupListeners() {
    // ESC key listener to close detail modal
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        const modal = document.getElementById("incident-detail-modal");
        if (modal && modal.classList.contains("active")) {
          this.closeDetailModal();
        }
      }
    });
  },

  async fetchSummary() {
    try {
      const summary = await API.get("/api/incidents/summary");
      this.renderSummaryKPIs(summary);
    } catch (err) {
      console.warn("[Incidents] Error fetching summary KPIs:", err);
    }
  },

  renderSummaryKPIs(summary) {
    const elActive = document.getElementById("inc-kpi-active");
    const elCrit = document.getElementById("inc-kpi-critical");
    const elHigh = document.getElementById("inc-kpi-high");
    const elMed = document.getElementById("inc-kpi-medium");
    const elResolved = document.getElementById("inc-kpi-resolved");
    const elMttr = document.getElementById("inc-kpi-mttr");

    if (elActive) elActive.textContent = summary.active_incidents ?? 0;
    if (elCrit) elCrit.textContent = summary.critical_count ?? 0;
    if (elHigh) elHigh.textContent = summary.high_count ?? 0;
    if (elMed) elMed.textContent = summary.medium_count ?? 0;
    if (elResolved) elResolved.textContent = summary.resolved_today ?? 0;
    if (elMttr) elMttr.textContent = summary.mttr ?? "0m";
  },

  setStatusFilter(status) {
    this.currentStatusFilter = status;
    
    // Update active tab styling
    const tabs = document.querySelectorAll("#inc-status-tabs .inc-tab-btn");
    tabs.forEach(t => {
      if (t.dataset.status === status) {
        t.classList.add("active");
      } else {
        t.classList.remove("active");
      }
    });

    this.fetchIncidents();
  },

  onFilterChange() {
    clearTimeout(this.searchDebounceTimer);
    this.searchDebounceTimer = setTimeout(() => {
      const timeSelect = document.getElementById("inc-time-select");
      const sortSelect = document.getElementById("inc-sort-select");

      if (timeSelect) this.currentTimeFilter = timeSelect.value;
      if (sortSelect) this.currentSort = sortSelect.value;

      this.fetchIncidents();
    }, 200);
  },

  async fetchIncidents() {
    const tbody = document.getElementById("incidents-table-tbody");
    const searchInput = document.getElementById("inc-search-input");
    const query = searchInput ? searchInput.value.trim() : "";

    try {
      const data = await API.get("/api/incidents", {
        status: this.currentStatusFilter,
        time_filter: this.currentTimeFilter,
        sort_by: this.currentSort,
        search: query || undefined,
        limit: 100
      });

      this.renderTable(data.incidents || []);
      this.fetchSummary();
    } catch (err) {
      console.warn("[Incidents] Error fetching incident list:", err);
      if (tbody) {
        tbody.innerHTML = `
          <tr>
            <td colspan="9" style="text-align: center; color: #ef4444; padding: 24px;">
              Failed to load incidents.
              <button class="btn btn-secondary btn-sm" style="margin-left: 10px;" onclick="Incidents.fetchIncidents()">Retry</button>
            </td>
          </tr>
        `;
      }
    }
  },

  renderTable(incidents) {
    const tbody = document.getElementById("incidents-table-tbody");
    if (!tbody) return;

    if (!incidents || incidents.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="9" style="text-align: center; color: #64748b; padding: 32px;">
            <div style="font-weight: 600; color: #10b981; font-size: 14px; margin-bottom: 4px;">✓ NO ACTIVE INCIDENTS</div>
            <div style="font-size: 12px; color: #94a3b8;">Network operations are currently normal and adhering to all security and QoS SLAs.</div>
          </td>
        </tr>
      `;
      return;
    }

    let html = "";
    incidents.forEach(inc => {
      const statusBadge = this.getStatusBadge(inc.status);
      const sevBadge = this.getSeverityBadge(inc.severity);

      // Primary Quick Action button based on state
      let actionBtn = "";
      const stUpper = (inc.status || "DETECTED").upper ? inc.status.toUpperCase() : String(inc.status).toUpperCase();

      if (stUpper === "DETECTED" || stUpper === "OPEN") {
        actionBtn = `<button class="btn btn-secondary btn-sm" onclick="event.stopPropagation(); Incidents.acknowledge('${inc.id}')">Ack</button>`;
      } else if (stUpper === "ACKNOWLEDGED") {
        actionBtn = `<button class="btn btn-secondary btn-sm" onclick="event.stopPropagation(); Incidents.investigate('${inc.id}')">Investigate</button>`;
      } else if (stUpper === "INVESTIGATING") {
        actionBtn = `<button class="btn btn-danger btn-sm" onclick="event.stopPropagation(); Incidents.mitigate('${inc.id}')">Mitigate</button>`;
      } else if (stUpper === "MITIGATING" || stUpper === "RECOVERING") {
        actionBtn = `<button class="btn btn-primary btn-sm" onclick="event.stopPropagation(); Incidents.resolve('${inc.id}')">Resolve</button>`;
      } else {
        actionBtn = `<button class="btn btn-secondary btn-sm" onclick="event.stopPropagation(); Incidents.closeIncident('${inc.id}')">Close</button>`;
      }

      html += `
        <tr class="incident-row" onclick="Incidents.openDetailModal('${inc.id}')">
          <td class="mono" style="color: var(--accent-cyan); font-weight: 700;">${inc.id}</td>
          <td>
            <div style="font-weight: 600; color: #ffffff; font-size: 12.5px;">${Utils.escapeHtml(inc.title || 'Security Incident')}</div>
            <div style="font-size: 11px; color: #94a3b8;">${Utils.escapeHtml(inc.category || 'SECURITY')} • Risk ${inc.risk_score || 80}/100</div>
          </td>
          <td>${sevBadge}</td>
          <td class="mono">${Utils.escapeHtml(inc.source_ip)}</td>
          <td><span class="mono" style="background:rgba(255,255,255,0.06); padding:2px 6px; border-radius:4px; font-size:11px;">${Utils.escapeHtml(inc.affected_device || 'S1')}</span></td>
          <td>${statusBadge}</td>
          <td class="mono" style="font-size: 11.5px;">${Utils.formatRelativeTime(inc.timestamp)}</td>
          <td class="mono" style="font-size: 11.5px;">${Utils.formatRelativeTime(inc.updated_at || inc.timestamp)}</td>
          <td style="text-align: right; white-space: nowrap;">
            ${actionBtn}
            <button class="btn btn-secondary btn-sm" style="margin-left: 4px;" onclick="event.stopPropagation(); Incidents.openDetailModal('${inc.id}')">Details</button>
          </td>
        </tr>
      `;
    });

    tbody.innerHTML = html;
  },

  getStatusBadge(status) {
    const st = (status || "DETECTED").toUpperCase();
    if (st === "DETECTED" || st === "OPEN") {
      return `<span class="badge badge-critical">DETECTED</span>`;
    } else if (st === "ACKNOWLEDGED") {
      return `<span class="badge badge-stale">ACKNOWLEDGED</span>`;
    } else if (st === "INVESTIGATING") {
      return `<span class="badge badge-demo">INVESTIGATING</span>`;
    } else if (st === "MITIGATING") {
      return `<span class="badge" style="background:rgba(245,158,11,0.2); color:#fbbf24; border:1px solid rgba(245,158,11,0.4);">MITIGATING</span>`;
    } else if (st === "RECOVERING") {
      return `<span class="badge" style="background:rgba(56,189,248,0.2); color:#38bdf8; border:1px solid rgba(56,189,248,0.4);">RECOVERING</span>`;
    } else if (st === "RESOLVED") {
      return `<span class="badge badge-live">RESOLVED</span>`;
    } else if (st === "CLOSED") {
      return `<span class="badge badge-info">CLOSED</span>`;
    }
    return `<span class="badge badge-info">${st}</span>`;
  },

  getSeverityBadge(severity) {
    const sev = (severity || "MEDIUM").toUpperCase();
    if (sev === "CRITICAL") return `<span class="badge badge-critical">CRITICAL</span>`;
    if (sev === "HIGH") return `<span class="badge badge-stale">HIGH</span>`;
    if (sev === "MEDIUM") return `<span class="badge" style="background:rgba(56,189,248,0.15); color:#38bdf8; border:1px solid rgba(56,189,248,0.3);">MEDIUM</span>`;
    return `<span class="badge badge-info">LOW</span>`;
  },

  async openDetailModal(incidentId) {
    this.activeIncidentId = incidentId;
    const modal = document.getElementById("incident-detail-modal");
    const body = document.getElementById("modal-inc-body");
    const footer = document.getElementById("modal-inc-footer");
    if (!modal || !body) return;

    // Show loading skeleton
    body.innerHTML = `<div style="text-align:center; padding:40px; color:#94a3b8;">Loading correlated incident analysis...</div>`;
    modal.classList.add("active");

    try {
      const res = await API.get(`/api/incidents/${incidentId}`);
      const inc = res.incident;
      if (!inc) throw new Error("Incident record not found");

      // Update header
      const elId = document.getElementById("modal-inc-id");
      const elTitle = document.getElementById("modal-inc-title-tag");
      const elSev = document.getElementById("modal-inc-sev-badge");
      const elStatus = document.getElementById("modal-inc-status-badge");

      if (elId) elId.textContent = inc.id;
      if (elTitle) elTitle.textContent = inc.title || "Network Incident";
      if (elSev) elSev.innerHTML = this.getSeverityBadge(inc.severity);
      if (elStatus) elStatus.innerHTML = this.getStatusBadge(inc.status);

      // Parse RCA & Impact
      const rca = inc.root_cause || {};
      const impact = inc.impact || {};
      const timeline = inc.timeline || [];
      const recPct = inc.recovery_pct || (inc.status === "RESOLVED" || inc.status === "CLOSED" ? 100 : 0);

      const rcaLevel = rca.level || "CONFIRMED";
      const rcaLevelBadge = rcaLevel === "CONFIRMED" 
        ? `<span class="rca-level-badge confirmed">CONFIRMED</span>` 
        : (rcaLevel === "LIKELY" ? `<span class="rca-level-badge likely">LIKELY</span>` : `<span class="rca-level-badge possible">POSSIBLE</span>`);

      // Contributing Factors list
      let factorsHtml = "";
      if (rca.contributing_factors && rca.contributing_factors.length > 0) {
        factorsHtml = `<ul class="inc-factors-list">` + rca.contributing_factors.map(f => `<li>${Utils.escapeHtml(f)}</li>`).join("") + `</ul>`;
      }

      // Visual Timeline
      let timelineHtml = "";
      if (timeline && timeline.length > 0) {
        timelineHtml = timeline.map(t => {
          const tsStr = t.timestamp ? Utils.formatTimestamp(t.timestamp) : "--";
          return `
            <div class="timeline-step">
              <div class="timeline-step-dot"></div>
              <div class="timeline-step-content">
                <div class="timeline-step-header">
                  <span class="timeline-step-time mono">${tsStr}</span>
                  <span class="timeline-step-status">${this.getStatusBadge(t.status || 'DETECTED')}</span>
                </div>
                <div class="timeline-step-event">${Utils.escapeHtml(t.event || '')}</div>
              </div>
            </div>
          `;
        }).join("");
      } else {
        timelineHtml = `<div style="font-size:12px; color:#64748b;">No timeline entries recorded yet.</div>`;
      }

      body.innerHTML = `
        <!-- Top Metrics Row -->
        <div class="inc-detail-grid">
          <div class="inc-prop-card">
            <div class="inc-prop-label">Source Host</div>
            <div class="inc-prop-val mono" style="color:var(--accent-cyan);">${Utils.escapeHtml(inc.source_ip)}</div>
          </div>
          <div class="inc-prop-card">
            <div class="inc-prop-label">Target Destination</div>
            <div class="inc-prop-val mono">${Utils.escapeHtml(inc.destination_ip)}</div>
          </div>
          <div class="inc-prop-card">
            <div class="inc-prop-label">Affected Device</div>
            <div class="inc-prop-val mono">${Utils.escapeHtml(inc.affected_device || 'S1')}</div>
          </div>
          <div class="inc-prop-card">
            <div class="inc-prop-label">AI Confidence</div>
            <div class="inc-prop-val" style="color:#10b981;">${((inc.ai_confidence || 0.9) * 100).toFixed(1)}%</div>
          </div>
        </div>

        <!-- Root Cause Analysis Card -->
        <div class="inc-section-card rca-card">
          <div class="inc-section-header">
            <div style="display:flex; align-items:center; gap:8px;">
              <svg class="icon icon-sm" viewBox="0 0 24 24" style="color:#00f2fe;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
              <strong>Automated Root Cause Analysis (RCA)</strong>
            </div>
            ${rcaLevelBadge}
          </div>
          <p class="rca-summary-text">${Utils.escapeHtml(rca.summary || inc.description || 'Anomalous traffic conditions detected.')}</p>
          <div style="font-size:11.5px; font-weight:600; color:#cbd5e1; margin-top:8px;">Contributing Factors:</div>
          ${factorsHtml}
        </div>

        <!-- Impact & Health Analysis -->
        <div class="inc-detail-grid" style="margin-top:12px;">
          <!-- Impact Card -->
          <div class="inc-section-card">
            <div class="inc-section-title">Multidimensional Impact</div>
            <div class="impact-metric-row">
              <span class="impact-metric-label">Security Posture Impact:</span>
              <span class="impact-metric-val" style="color:#ef4444; font-weight:600;">${impact.security_impact || inc.severity}</span>
            </div>
            <div class="impact-metric-row">
              <span class="impact-metric-label">QoS Performance Impact:</span>
              <span class="impact-metric-val" style="color:#38bdf8;">${impact.qos_impact || 'MEDIUM'}</span>
            </div>
            <div class="impact-metric-row">
              <span class="impact-metric-label">Latency Transit Delta:</span>
              <span class="impact-metric-val mono">${impact.latency_impact || '+14.2 ms'}</span>
            </div>
            <div class="impact-metric-row">
              <span class="impact-metric-label">Packet Loss Impact:</span>
              <span class="impact-metric-val mono">${impact.packet_loss_impact || '+0.4%'}</span>
            </div>
          </div>

          <!-- Recovery Progress Card -->
          <div class="inc-section-card">
            <div class="inc-section-title">Recovery & Mitigation State</div>
            <div style="margin-bottom:10px;">
              <div style="display:flex; justify-content:space-between; font-size:11.5px; margin-bottom:4px;">
                <span style="color:#94a3b8;">Recovery Progress:</span>
                <span style="font-weight:700; color:#38bdf8;">${recPct.toFixed(0)}%</span>
              </div>
              <div class="inc-progress-bar-bg">
                <div class="inc-progress-bar-fill" style="width: ${recPct}%;"></div>
              </div>
            </div>
            <div class="impact-metric-row">
              <span class="impact-metric-label">Action Applied:</span>
              <span class="impact-metric-val mono" style="color:#00f2fe;">${Utils.escapeHtml(inc.action_taken || 'AUTO_MITIGATE')}</span>
            </div>
            <div class="impact-metric-row">
              <span class="impact-metric-label">Assigned Operator:</span>
              <span class="impact-metric-val">${Utils.escapeHtml(inc.assigned_to || 'Unassigned')}</span>
            </div>
          </div>
        </div>

        <!-- Timeline Section -->
        <div class="inc-section-card" style="margin-top:12px;">
          <div class="inc-section-title">Chronological Incident Timeline</div>
          <div class="inc-timeline-container">
            ${timelineHtml}
          </div>
        </div>

        <!-- Advisory Recommendations -->
        <div class="inc-section-card" style="margin-top:12px; background:rgba(0,242,254,0.04); border-color:rgba(0,242,254,0.2);">
          <div class="inc-section-title" style="color:#00f2fe;">NOC Operator Recommendations</div>
          <ul class="inc-factors-list">
            <li>Verify OpenFlow drop / meter flow modification rules on switch <code>${Utils.escapeHtml(inc.affected_device || 'S1')}</code>.</li>
            <li>Inspect host <code>${Utils.escapeHtml(inc.source_ip)}</code> in Network Topology to ensure physical/virtual interface quarantine.</li>
            <li>Confirm DSCP priority bandwidth allocations (EF/AF) have normalized across the fabric.</li>
          </ul>
        </div>
      `;

      // Render Footer Actions
      if (footer) {
        const st = (inc.status || "DETECTED").toUpperCase();
        let btns = `<button class="btn btn-secondary" onclick="Incidents.closeDetailModal()">Close</button>`;

        if (st === "DETECTED" || st === "OPEN") {
          btns += `<button class="btn btn-secondary" onclick="Incidents.acknowledge('${inc.id}')">Acknowledge</button>`;
        }
        if (st === "DETECTED" || st === "ACKNOWLEDGED") {
          btns += `<button class="btn btn-secondary" onclick="Incidents.investigate('${inc.id}')">Investigate</button>`;
        }
        if (st !== "MITIGATING" && st !== "RESOLVED" && st !== "CLOSED") {
          btns += `<button class="btn btn-danger" onclick="Incidents.mitigate('${inc.id}')">Dispatch Mitigation</button>`;
        }
        if (st !== "RESOLVED" && st !== "CLOSED") {
          btns += `<button class="btn btn-primary" onclick="Incidents.resolve('${inc.id}')">Mark Resolved</button>`;
        }
        if (st !== "CLOSED") {
          btns += `<button class="btn btn-secondary" onclick="Incidents.closeIncident('${inc.id}')">Close Ticket</button>`;
        }

        footer.innerHTML = btns;
      }
    } catch (err) {
      body.innerHTML = `
        <div style="text-align:center; padding:30px; color:#ef4444;">
          Failed to load incident details: ${Utils.escapeHtml(err.message)}
        </div>
      `;
    }
  },

  closeDetailModal() {
    const modal = document.getElementById("incident-detail-modal");
    if (modal) modal.classList.remove("active");
    this.activeIncidentId = null;
  },

  async acknowledge(incId) {
    try {
      await API.post(`/api/incidents/${incId}/acknowledge`);
      Utils.showToast(`Incident ${incId} acknowledged.`, "success");
      this.fetchIncidents();
      if (this.activeIncidentId === incId) this.openDetailModal(incId);
    } catch (err) {
      Utils.showToast(`Failed to acknowledge: ${err.message}`, "danger");
    }
  },

  async investigate(incId) {
    try {
      await API.post(`/api/incidents/${incId}/investigate`);
      Utils.showToast(`Incident ${incId} set to INVESTIGATING.`, "success");
      this.fetchIncidents();
      if (this.activeIncidentId === incId) this.openDetailModal(incId);
    } catch (err) {
      Utils.showToast(`Failed to investigate: ${err.message}`, "danger");
    }
  },

  async mitigate(incId) {
    try {
      await API.post(`/api/incidents/${incId}/mitigate`, { action: "BLOCK" });
      Utils.showToast(`OpenFlow mitigation dispatched for ${incId}.`, "success");
      this.fetchIncidents();
      if (this.activeIncidentId === incId) this.openDetailModal(incId);
    } catch (err) {
      Utils.showToast(`Mitigation dispatch failed: ${err.message}`, "danger");
    }
  },

  async resolve(incId) {
    try {
      await API.post(`/api/incidents/${incId}/resolve`, { notes: "Resolved and verified by operator" });
      Utils.showToast(`Incident ${incId} marked as RESOLVED.`, "success");
      this.fetchIncidents();
      if (this.activeIncidentId === incId) this.openDetailModal(incId);
    } catch (err) {
      Utils.showToast(`Failed to resolve: ${err.message}`, "danger");
    }
  },

  async closeIncident(incId) {
    try {
      await API.post(`/api/incidents/${incId}/close`);
      Utils.showToast(`Incident ${incId} CLOSED.`, "info");
      this.fetchIncidents();
      this.closeDetailModal();
    } catch (err) {
      Utils.showToast(`Failed to close: ${err.message}`, "danger");
    }
  },

  async updateStatus(incId, status) {
    try {
      const assigned = Auth.currentUser ? (Auth.currentUser.full_name || Auth.currentUser.username) : "OPERATOR";
      await API.post(`/api/incidents/${incId}/status`, { status: status, assigned_to: assigned });
      Utils.showToast(`Incident ${incId} status updated to ${status}.`, "success");
      this.fetchIncidents();
      if (this.activeIncidentId === incId) this.openDetailModal(incId);
    } catch (err) {
      Utils.showToast(`Failed: ${err.message}`, "danger");
    }
  }
};
