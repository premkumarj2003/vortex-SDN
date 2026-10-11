/**
 * VORTEX-SDN Security Center View Controller
 * Manages live threat feeds, attack classification cards, mitigation execution, and mode toggle.
 */

const Security = {
  async init() {
    await this.fetchData();
    State.subscribe("summary:updated", () => this.fetchData());
  },

  async fetchData() {
    try {
      const summary = await API.get("/api/security/summary");
      const events = await API.get("/api/security/events?limit=30");
      this.renderSummary(summary);
      this.renderThreatsTable(summary.active_threats || []);
      this.renderEventsTable(events.events || []);
    } catch (err) {
      console.warn("[Security] Error fetching data:", err);
    }
  },

  renderSummary(data) {
    const levelEl = document.getElementById("sec-threat-level");
    if (levelEl) {
      levelEl.textContent = data.threat_level || "NORMAL";
      levelEl.className = `badge ${data.threat_level === 'CRITICAL' ? 'badge-critical' : (data.threat_level === 'HIGH' ? 'badge-stale' : 'badge-live')}`;
    }

    const activeEl = document.getElementById("sec-active-threats-count");
    if (activeEl) activeEl.textContent = data.active_threats_count || 0;

    const critEl = document.getElementById("sec-critical-count");
    if (critEl) critEl.textContent = data.critical_threats || 0;

    const mitEl = document.getElementById("sec-mitigated-count");
    if (mitEl) mitEl.textContent = data.mitigated_count || 0;

    // Render Attack Type Breakdown Bars
    const breakdownItems = [];
    if (data.attack_type_distribution) {
      for (const [k, v] of Object.entries(data.attack_type_distribution)) {
        breakdownItems.push({ label: k, class_name: k, flows: v, percentage: Math.round((v / Math.max(1, data.active_threats_count)) * 100) });
      }
    }
    Charts.renderDistributionBars("sec-attack-dist-bars", breakdownItems);
  },

  renderThreatsTable(threats) {
    const tbody = document.getElementById("sec-threats-tbody");
    if (!tbody) return;

    if (!threats || threats.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: #10b981; padding: 24px;">✅ No active threats detected. All OpenFlow fabric paths are secure.</td></tr>`;
      return;
    }

    let html = "";
    threats.forEach(t => {
      html += `
        <tr>
          <td class="mono" style="color: var(--status-danger); font-weight: 700;">${t.id}</td>
          <td><span class="badge badge-critical">${t.attack_type}</span></td>
          <td class="mono">${t.source_ip}</td>
          <td class="mono">${t.destination_ip}</td>
          <td class="mono">${t.packet_rate || 0} pps</td>
          <td><strong style="color: #ffffff;">${t.risk_score}</strong> / 100</td>
          <td><span class="badge badge-stale">${t.recommended_action}</span></td>
          <td>
            <button class="btn btn-danger btn-sm" onclick="Security.openMitigationModal('${t.id}', '${t.source_ip}', '${t.destination_ip}', '${t.recommended_action}')">
              Mitigate
            </button>
          </td>
        </tr>
      `;
    });
    tbody.innerHTML = html;
  },

  renderEventsTable(events) {
    const tbody = document.getElementById("sec-events-tbody");
    if (!tbody) return;

    if (!events || events.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: #64748b; padding: 18px;">No recorded security events.</td></tr>`;
      return;
    }

    let html = "";
    events.slice(0, 10).forEach(e => {
      html += `
        <tr>
          <td class="mono">${Utils.formatRelativeTime(e.timestamp)}</td>
          <td><span class="badge ${e.severity === 'CRITICAL' ? 'badge-critical' : 'badge-stale'}">${e.attack_type}</span></td>
          <td class="mono">${e.source_ip}</td>
          <td class="mono">${e.destination_ip}</td>
          <td class="mono">${e.risk_score}</td>
          <td><span class="badge badge-live">${e.recommended_action}</span></td>
        </tr>
      `;
    });
    tbody.innerHTML = html;
  },

  openMitigationModal(threatId, srcIp, dstIp, action) {
    const modal = document.getElementById("mitigation-modal");
    if (!modal) return;

    document.getElementById("modal-mit-threat-id").textContent = threatId;
    document.getElementById("modal-mit-src").textContent = srcIp;
    document.getElementById("modal-mit-dst").textContent = dstIp;
    document.getElementById("modal-mit-action-select").value = action || "BLOCK";

    modal.classList.add("active");
  },

  closeMitigationModal() {
    const modal = document.getElementById("mitigation-modal");
    if (modal) modal.classList.remove("active");
  },

  async executeMitigation() {
    const threatId = document.getElementById("modal-mit-threat-id").textContent;
    const action = document.getElementById("modal-mit-action-select").value;

    try {
      const res = await API.post("/api/security/mitigate", {
        threat_id: threatId,
        action: action
      });
      Utils.showToast(res.message || "Mitigation executed successfully.", "success");
      this.closeMitigationModal();
      this.fetchData();
      if (typeof Telemetry !== "undefined" && Telemetry.pollNow) {
        Telemetry.pollNow();
      }
    } catch (err) {
      Utils.showToast(`Mitigation failed: ${err.message}`, "danger");
    }
  }
};
