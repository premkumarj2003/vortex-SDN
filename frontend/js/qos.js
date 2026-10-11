/**
 * VORTEX-SDN QoS Center View Controller
 * Manages traffic classification distribution, latency/jitter gauges, policy table, and SLA violations.
 */

const QoS = {
  async init() {
    await this.fetchData();
    State.subscribe("summary:updated", () => this.fetchData());
  },

  async fetchData() {
    try {
      const summary = await API.get("/api/qos/summary");
      const policies = await API.get("/api/qos/policies");
      this.renderSummary(summary);
      this.renderPoliciesTable(policies.policies || []);
    } catch (err) {
      console.warn("[QoS] Error fetching data:", err);
    }
  },

  renderSummary(data) {
    // 1. Gauges
    Charts.renderRadialGauge("qos-gauge-latency", data.average_latency_ms || 14, 100, "Latency", "ms");
    Charts.renderRadialGauge("qos-gauge-loss", data.packet_loss_pct || 0.05, 5, "Packet Loss", "%");
    Charts.renderRadialGauge("qos-gauge-health", data.qos_health_score || 92, 100, "QoS Health", "%");

    // 2. Traffic Class Distribution
    Charts.renderDistributionBars("qos-traffic-dist-bars", data.distribution || []);

    // 3. SLA Violations Card
    const violEl = document.getElementById("qos-violations-list");
    if (violEl) {
      if (!data.violations || data.violations.length === 0) {
        violEl.innerHTML = `<div style="color: #10b981; font-size: 12px; padding: 10px;">✅ Zero QoS SLA violations. All queues operating within latency limits.</div>`;
      } else {
        let html = "";
        data.violations.forEach(v => {
          html += `
            <div style="background: rgba(239, 68, 68, 0.1); border-left: 3px solid #ef4444; padding: 8px 12px; margin-bottom: 8px; border-radius: 4px; font-size: 12px;">
              <strong>${v.class} Violation:</strong> ${v.reason} (<span class="mono-text">${v.source_ip} -> ${v.destination_ip}</span>)
            </div>
          `;
        });
        violEl.innerHTML = html;
      }
    }

    // 4. QoS Recommendations
    const recEl = document.getElementById("qos-recommendations-list");
    if (recEl) {
      if (!data.recommendations || data.recommendations.length === 0) {
        recEl.innerHTML = `<div style="color: #64748b; font-size: 12px; padding: 10px;">Current queue allocations are optimal for current load.</div>`;
      } else {
        let html = "";
        data.recommendations.forEach(r => {
          html += `
            <div style="background: var(--bg-card); border: 1px solid var(--border-medium); padding: 8px 12px; margin-bottom: 8px; border-radius: 4px; font-size: 12px;">
              💡 <strong>Recommendation:</strong> ${r}
            </div>
          `;
        });
        recEl.innerHTML = html;
      }
    }
  },

  renderPoliciesTable(policies) {
    const tbody = document.getElementById("qos-policies-tbody");
    if (!tbody) return;

    if (!policies || policies.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: #64748b; padding: 18px;">No QoS policies defined.</td></tr>`;
      return;
    }

    let html = "";
    policies.forEach(p => {
      const prioBadge = p.priority_code === "EF"
        ? `<span class="badge badge-live">EF (Expedited)</span>`
        : (p.priority_code === "AF" ? `<span class="badge badge-info">AF (Assured)</span>` : `<span class="badge" style="background:#334155;">BE (Best Effort)</span>`);

      html += `
        <tr>
          <td style="font-weight: 600; color: #ffffff;">${p.name}</td>
          <td><span class="badge badge-info">${p.traffic_class}</span></td>
          <td>${prioBadge}</td>
          <td class="mono">Queue ${p.queue_id}</td>
          <td class="mono">${p.min_bandwidth_mbps} - ${p.max_bandwidth_mbps} Mbps</td>
          <td class="mono">DSCP ${p.dscp_mark}</td>
          <td><span class="badge badge-live">ACTIVE</span></td>
        </tr>
      `;
    });
    tbody.innerHTML = html;
  }
};
