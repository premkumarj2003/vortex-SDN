/**
 * VORTEX-SDN Network Digital Twin & What-If Simulation Engine Controller
 * Manages isolated virtual snapshots, SVG graph topology rendering, dynamic rerouting visualization,
 * before/after comparisons, resilience scoring, and simulation history.
 */

const DigitalTwin = {
  snapshot: null,
  activeSimulation: null,
  isSimulationActive: false,
  selectedElement: null,

  async init() {
    this.setupListeners();
    await this.fetchSnapshot();
    await this.fetchHistory();
  },

  setupListeners() {
    const scenSelect = document.getElementById("twin-scenario-select");
    if (scenSelect) {
      scenSelect.addEventListener("change", () => this.onScenarioChange());
    }
  },

  async fetchSnapshot() {
    try {
      const data = await API.get("/api/digital-twin/snapshot");
      this.snapshot = data;
      this.activeSimulation = null;
      this.isSimulationActive = false;
      this.updateModeIndicator();
      this.renderCanvas();
      this.renderResilienceCard();
      this.renderComparisonCard();
      this.renderCriticalNodes(data.critical_analysis);
      this.renderTimeline([]);
      this.renderInsights(null);
    } catch (err) {
      console.warn("[Digital Twin] Error fetching snapshot:", err);
      Utils.showToast("Failed to load Digital Twin snapshot.", "danger");
    }
  },

  updateModeIndicator() {
    const modePill = document.getElementById("twin-mode-pill");
    const snapTime = document.getElementById("twin-snapshot-time");
    
    if (modePill) {
      if (this.isSimulationActive) {
        modePill.className = "twin-mode-pill sim";
        modePill.innerHTML = "◉ DIGITAL TWIN — SIMULATION";
      } else {
        modePill.className = "twin-mode-pill live";
        modePill.innerHTML = "● LIVE SNAPSHOT SYNCHRONIZED";
      }
    }

    if (snapTime && this.snapshot) {
      snapTime.textContent = Utils.formatRelativeTime(this.snapshot.timestamp);
    }
  },

  onScenarioChange() {
    const scenSelect = document.getElementById("twin-scenario-select");
    const targetGroup = document.getElementById("twin-target-group");
    const paramGroup = document.getElementById("twin-param-group");
    if (!scenSelect || !targetGroup || !paramGroup) return;

    const scen = scenSelect.value;
    targetGroup.style.display = "block";
    paramGroup.style.display = "none";

    if (scen === "link_failure" || scen === "disable_link") {
      targetGroup.innerHTML = `
        <label class="twin-field-label">Target Link</label>
        <select id="twin-target-select" class="form-select form-select-sm">
          <option value="s1-s2" selected>Switch 1 <-> Switch 2 (s1-s2)</option>
          <option value="s1-s3">Switch 1 <-> Switch 3 (s1-s3)</option>
          <option value="s2-s4">Switch 2 <-> Switch 4 (s2-s4)</option>
          <option value="s3-s4">Switch 3 <-> Switch 4 (s3-s4)</option>
          <option value="s1-s4">Switch 1 <-> Switch 4 (s1-s4)</option>
          <option value="s2-s3">Switch 2 <-> Switch 3 (s2-s3)</option>
        </select>
      `;
    } else if (scen === "switch_failure" || scen === "disable_switch") {
      targetGroup.innerHTML = `
        <label class="twin-field-label">Target Switch</label>
        <select id="twin-target-select" class="form-select form-select-sm">
          <option value="s3" selected>Switch 3 (s3) - Aggregation (Recommended test)</option>
          <option value="s2">Switch 2 (s2) - Core Transit</option>
          <option value="s1">Switch 1 (s1) - Edge Gateway</option>
          <option value="s4">Switch 4 (s4) - Edge Gateway</option>
        </select>
      `;
    } else if (scen === "host_failure" || scen === "isolate_host") {
      targetGroup.innerHTML = `
        <label class="twin-field-label">Target Host</label>
        <select id="twin-target-select" class="form-select form-select-sm">
          <option value="h4" selected>Host 4 (10.0.0.4) - External Attacker</option>
          <option value="h1">Host 1 (10.0.0.1) - Web App Server</option>
          <option value="h2">Host 2 (10.0.0.2) - VoIP Database</option>
          <option value="h3">Host 3 (10.0.0.3) - Video Storage Server</option>
        </select>
      `;
    } else if (scen === "congestion" || scen === "increase_traffic") {
      targetGroup.innerHTML = `
        <label class="twin-field-label">Load Multiplier</label>
        <select id="twin-target-select" class="form-select form-select-sm">
          <option value="1.25">125% Load (+25% Surge)</option>
          <option value="1.5" selected>150% Load (+50% Surge)</option>
          <option value="1.75">175% Load (+75% Surge)</option>
          <option value="2.0">200% Load (Double Bandwidth)</option>
        </select>
      `;
    } else if (scen === "ddos" || scen === "simulate_ddos") {
      targetGroup.innerHTML = `
        <label class="twin-field-label">Attack Corridor</label>
        <select id="twin-target-select" class="form-select form-select-sm">
          <option value="h4-s1" selected>H4 (10.0.0.4) -> Target S1 Edge</option>
          <option value="h4-s2">H4 (10.0.0.4) -> Target S2 Core</option>
        </select>
      `;
    } else if (scen === "apply_qos_policy") {
      targetGroup.innerHTML = `
        <label class="twin-field-label">QoS Policy to Apply</label>
        <select id="twin-target-select" class="form-select form-select-sm">
          <option value="voip_video_prio" selected>VoIP & Video Priority Queue (DSCP 46/EF) - S1/S2</option>
          <option value="database_reserve">Critical Database Bandwidth Reservation (200 Mbps) - S3</option>
          <option value="bulk_rate_limit">Bulk Data Rate Limiter (Max 150 Mbps) - S4</option>
        </select>
      `;
    } else if (scen === "remove_qos_policy") {
      targetGroup.innerHTML = `
        <label class="twin-field-label">QoS Policy to Revoke</label>
        <select id="twin-target-select" class="form-select form-select-sm">
          <option value="voip_video_prio" selected>VoIP & Video Priority Queue (Revoke S1/S2)</option>
          <option value="database_reserve">Critical Database Bandwidth Reservation (Revoke S3)</option>
        </select>
      `;
    } else if (scen === "add_traffic_load") {
      targetGroup.innerHTML = `
        <label class="twin-field-label">Additional Traffic Surge</label>
        <select id="twin-target-select" class="form-select form-select-sm">
          <option value="150" selected>+150 Mbps (High-Definition Video Stream)</option>
          <option value="250">+250 Mbps (Heavy Database Replication)</option>
          <option value="400">+400 Mbps (Full Fabric Capacity Test)</option>
        </select>
      `;
    } else if (scen === "packet_loss") {
      targetGroup.innerHTML = `
        <label class="twin-field-label">Drop Rate (%)</label>
        <select id="twin-target-select" class="form-select form-select-sm">
          <option value="1.0">1% Packet Drop</option>
          <option value="2.0">2% Packet Drop</option>
          <option value="5.0" selected>5% Packet Drop</option>
          <option value="10.0">10% Packet Drop</option>
          <option value="20.0">20% Packet Drop</option>
        </select>
      `;
    } else if (scen === "high_latency") {
      targetGroup.innerHTML = `
        <label class="twin-field-label">Added Latency</label>
        <select id="twin-target-select" class="form-select form-select-sm">
          <option value="15.0">+15 ms Transit Delay</option>
          <option value="30.0" selected>+30 ms Transit Delay</option>
          <option value="50.0">+50 ms Transit Delay</option>
          <option value="100.0">+100 ms Severe Delay</option>
        </select>
      `;
    } else if (scen === "multi_failure") {
      targetGroup.innerHTML = `
        <label class="twin-field-label">Simultaneous Outages</label>
        <select id="twin-target-select" class="form-select form-select-sm">
          <option value="s2_s1-s3" selected>Switch S2 + Link S1-S3</option>
          <option value="s1_s3-s4">Switch S1 + Link S3-S4</option>
        </select>
      `;
    }
  },

  async runSimulation() {
    const scenSelect = document.getElementById("twin-scenario-select");
    const targetSelect = document.getElementById("twin-target-select");
    const btn = document.getElementById("twin-run-btn");
    if (!scenSelect) return;

    const scenario = scenSelect.value;
    const targetVal = targetSelect ? targetSelect.value : "";
    const params = {};

    if (scenario === "link_failure" || scenario === "disable_link") {
      params.link = targetVal;
      const parts = targetVal.split("-");
      params.source = parts[0];
      params.target = parts[1];
    } else if (scenario === "switch_failure" || scenario === "disable_switch") {
      params.switch = targetVal || "s3";
    } else if (scenario === "host_failure" || scenario === "isolate_host") {
      params.host = targetVal || "h4";
    } else if (scenario === "congestion" || scenario === "increase_traffic") {
      params.load_multiplier = parseFloat(targetVal) || 1.5;
    } else if (scenario === "ddos" || scenario === "simulate_ddos") {
      params.source = "h4";
      params.target = "s1";
    } else if (scenario === "apply_qos_policy") {
      params.policy = targetVal || "voip_video_prio";
    } else if (scenario === "remove_qos_policy") {
      params.policy = targetVal || "voip_video_prio";
    } else if (scenario === "add_traffic_load") {
      params.extra_mbps = parseFloat(targetVal) || 150.0;
    } else if (scenario === "packet_loss") {
      params.loss_pct = parseFloat(targetVal);
    } else if (scenario === "high_latency") {
      params.latency_delta_ms = parseFloat(targetVal);
    } else if (scenario === "multi_failure") {
      params.switch = "s2";
      params.source = "s1";
      params.target = "s3";
    }

    if (btn) btn.disabled = true;

    try {
      const result = await API.post("/api/digital-twin/simulate", { scenario, params });
      this.activeSimulation = result;
      this.isSimulationActive = true;

      this.updateModeIndicator();
      this.renderCanvas();
      this.renderResilienceCard();
      this.renderComparisonCard();
      this.renderTimeline(result.timeline || []);
      this.renderInsights(result);
      await this.fetchHistory();
      this.updateDashboardWidget(result);

      Utils.showToast(`Simulation completed: ${result.scenario} (${result.survivability})`, "info");
    } catch (err) {
      console.warn("[Digital Twin] Simulation failed:", err);
      Utils.showToast(`Simulation error: ${err.message}`, "danger");
    } finally {
      if (btn) btn.disabled = false;
    }
  },

  async resetSimulation() {
    try {
      await API.post("/api/digital-twin/reset");
      await this.fetchSnapshot();
      Utils.showToast("Digital Twin reset to live synchronized snapshot.", "success");
    } catch (err) {
      Utils.showToast(`Reset error: ${err.message}`, "danger");
    }
  },

  renderCanvas() {
    const container = document.getElementById("twin-svg-container");
    if (!container || !this.snapshot) return;

    const nodes = this.snapshot.nodes || [];
    const links = this.snapshot.links || [];

    // Failed / Rerouted set from active simulation
    const failedNodes = new Set((this.activeSimulation?.failed_nodes || []).map(n => n.toLowerCase()));
    const failedLinks = new Set((this.activeSimulation?.failed_links || []).map(l => l.toLowerCase()));
    const highlightedReroutes = this.activeSimulation?.highlighted_paths || [];

    // Coordinates normalization
    const nodePos = {
      c0: { x: 380, y: 50 },
      s1: { x: 200, y: 170 },
      s2: { x: 560, y: 170 },
      s3: { x: 200, y: 310 },
      s4: { x: 560, y: 310 },
      h1: { x: 80,  y: 170 },
      h2: { x: 80,  y: 310 },
      h3: { x: 680, y: 170 },
      h4: { x: 680, y: 310 }
    };

    let svgHtml = `
      <svg class="twin-svg-canvas" viewBox="0 0 760 380" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <filter id="twin-glow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>
    `;

    // 1. Draw Links
    links.forEach(l => {
      const srcId = l.source.toLowerCase();
      const dstId = l.target.toLowerCase();
      const p1 = nodePos[srcId];
      const p2 = nodePos[dstId];
      if (!p1 || !p2) return;

      const normId = srcId <= dstId ? `${srcId}-${dstId}` : `${dstId}-${srcId}`;
      const isFailed = failedLinks.has(normId) || failedNodes.has(srcId) || failedNodes.has(dstId);
      const isControl = l.type === "control";

      let cls = "twin-link";
      if (isControl) cls += " control";
      if (isFailed) cls += " failed";

      svgHtml += `
        <line class="${cls}" data-link="${normId}" x1="${p1.x}" y1="${p1.y}" x2="${p2.x}" y2="${p2.y}" />
      `;
    });

    // 2. Draw Highlighted Rerouted Path Overlay (if simulation active)
    if (highlightedReroutes.length > 0) {
      highlightedReroutes.forEach(path => {
        for (let i = 0; i < path.length - 1; i++) {
          const u = path[i].toLowerCase();
          const v = path[i + 1].toLowerCase();
          const pu = nodePos[u];
          const pv = nodePos[v];
          if (pu && pv) {
            svgHtml += `
              <line class="twin-link rerouted" x1="${pu.x}" y1="${pu.y}" x2="${pv.x}" y2="${pv.y}" />
            `;
          }
        }
      });
    }

    // 3. Draw Nodes
    nodes.forEach(n => {
      const id = n.id.toLowerCase();
      const pos = nodePos[id] || { x: n.x || 300, y: n.y || 200 };
      const isFailed = failedNodes.has(id);
      const isSwitch = n.type === "switch";
      const isHost = n.type === "host";
      const isCtrl = n.type === "controller";

      let fill = "#0f172a";
      let stroke = "#38bdf8";
      let r = 18;

      if (isCtrl) {
        fill = "#082f49";
        stroke = "#00f2fe";
        r = 20;
      } else if (isSwitch) {
        fill = "#064e3b";
        stroke = "#00f5a0";
        r = 18;
      } else if (isHost) {
        fill = "#1e293b";
        stroke = "#60a5fa";
        r = 14;
      }

      if (isFailed) {
        fill = "#450a0a";
        stroke = "#ef4444";
      }

      const nodeGroupCls = isFailed ? "twin-node-group twin-node-failed" : "twin-node-group";

      svgHtml += `
        <g class="${nodeGroupCls}" onclick="DigitalTwin.inspectNode('${n.id}')">
          <circle class="twin-node-circle" cx="${pos.x}" cy="${pos.y}" r="${r}" fill="${fill}" stroke="${stroke}" stroke-width="2.5" />
          <text x="${pos.x}" y="${pos.y + 4}" text-anchor="middle" font-size="11" font-weight="700" fill="#ffffff" font-family="monospace">${n.id.toUpperCase()}</text>
          <text x="${pos.x}" y="${pos.y + r + 13}" text-anchor="middle" font-size="10" font-weight="600" fill="#94a3b8">${Utils.escapeHtml(n.name.split(' ')[0])}</text>
          ${isFailed ? `
            <line x1="${pos.x - 11}" y1="${pos.y - 11}" x2="${pos.x + 11}" y2="${pos.y + 11}" stroke="#ef4444" stroke-width="3.5" stroke-linecap="round" />
            <line x1="${pos.x + 11}" y1="${pos.y - 11}" x2="${pos.x - 11}" y2="${pos.y + 11}" stroke="#ef4444" stroke-width="3.5" stroke-linecap="round" />
            <circle cx="${pos.x}" cy="${pos.y}" r="${r + 5}" fill="none" stroke="#ef4444" stroke-width="1.5" stroke-dasharray="4,3" />
          ` : ''}
        </g>
      `;
    });

    svgHtml += `</svg>`;
    container.innerHTML = svgHtml;
  },

  inspectNode(nodeId) {
    const node = (this.snapshot?.nodes || []).find(n => n.id.toLowerCase() === nodeId.toLowerCase());
    if (!node) return;

    Utils.showToast(`Node ${node.id.toUpperCase()} selected: ${node.role || node.type} (${node.status})`, "info");
    const scenSelect = document.getElementById("twin-scenario-select");
    const targetSelect = document.getElementById("twin-target-select");

    if (node.type === "switch" && scenSelect) {
      scenSelect.value = "switch_failure";
      this.onScenarioChange();
      const newTargetSelect = document.getElementById("twin-target-select");
      if (newTargetSelect) newTargetSelect.value = node.id.toLowerCase();
    } else if (node.type === "host" && scenSelect) {
      scenSelect.value = "host_failure";
      this.onScenarioChange();
      const newTargetSelect = document.getElementById("twin-target-select");
      if (newTargetSelect) newTargetSelect.value = node.id.toLowerCase();
    }
  },

  renderResilienceCard() {
    const scoreValEl = document.getElementById("twin-resilience-val");
    const scoreDeltaEl = document.getElementById("twin-resilience-delta");
    const scoreBarEl = document.getElementById("twin-resilience-bar");
    if (!scoreValEl) return;

    if (this.activeSimulation && this.activeSimulation.resilience_score) {
      const rs = this.activeSimulation.resilience_score;
      scoreValEl.textContent = `${rs.after}%`;
      if (scoreDeltaEl) {
        const sign = rs.change > 0 ? `+${rs.change}` : `${rs.change}`;
        scoreDeltaEl.textContent = `(${sign}%)`;
        scoreDeltaEl.className = rs.change < 0 ? "twin-score-delta negative" : "twin-score-delta neutral";
      }
      if (scoreBarEl) scoreBarEl.style.width = `${rs.after}%`;
    } else {
      scoreValEl.textContent = "96%";
      if (scoreDeltaEl) {
        scoreDeltaEl.textContent = "(Live Mesh Baseline)";
        scoreDeltaEl.className = "twin-score-delta neutral";
      }
      if (scoreBarEl) scoreBarEl.style.width = "96%";
    }
  },

  renderComparisonCard() {
    const tbody = document.getElementById("twin-comp-tbody");
    if (!tbody || !this.snapshot) return;

    const base = this.snapshot.metrics || {};
    const sim = this.activeSimulation?.after_metrics || base;
    const isSim = this.isSimulationActive;
    const deltas = this.activeSimulation?.impact_deltas || {};

    const formatDelta = (delta, unit, invertGood = false) => {
      if (!isSim || delta === undefined || delta === 0) return "";
      const isPos = delta > 0;
      const sign = isPos ? `+${delta}` : `${delta}`;
      const isGood = invertGood ? !isPos : isPos;
      const color = isGood ? "#10b981" : "#ef4444";
      return `<span style="font-size:11px; margin-left:6px; color:${color}; font-weight:600;">(${sign}${unit})</span>`;
    };

    tbody.innerHTML = `
      <tr>
        <td>Network Health Score</td>
        <td class="twin-val-live">${base.network_health ?? 96.0}%</td>
        <td class="twin-val-sim">${sim.network_health ?? 96.0}% ${formatDelta(deltas.health_delta, "%")}</td>
      </tr>
      <tr>
        <td>Aggregate Throughput</td>
        <td class="twin-val-live">${base.aggregate_throughput_mbps ?? 52.4} Mbps</td>
        <td class="twin-val-sim">${sim.aggregate_throughput_mbps ?? 52.4} Mbps ${formatDelta(deltas.throughput_delta_mbps, " Mbps")}</td>
      </tr>
      <tr>
        <td>Average Transit Latency</td>
        <td class="twin-val-live">${base.average_latency_ms ?? 14.5} ms</td>
        <td class="twin-val-sim">${sim.average_latency_ms ?? 14.5} ms ${formatDelta(deltas.latency_delta_ms, " ms", true)}</td>
      </tr>
      <tr>
        <td>Packet Loss Rate</td>
        <td class="twin-val-live">${base.packet_loss_pct ?? 0.1}%</td>
        <td class="twin-val-sim">${sim.packet_loss_pct ?? 0.1}% ${formatDelta(deltas.loss_delta_pct, "%", true)}</td>
      </tr>
      <tr>
        <td>Security Health Score</td>
        <td class="twin-val-live">${base.security_health ?? 95.0}%</td>
        <td class="twin-val-sim">${sim.security_health ?? 95.0}%</td>
      </tr>
      <tr>
        <td>QoS Health Score</td>
        <td class="twin-val-live">${base.qos_health ?? 98.0}%</td>
        <td class="twin-val-sim">${sim.qos_health ?? 98.0}%</td>
      </tr>
    `;
  },

  renderCriticalNodes(critAnalysis) {
    const listEl = document.getElementById("twin-critical-list");
    if (!listEl) return;

    const nodes = critAnalysis?.critical_nodes || [
      { device: "S2", criticality: "HIGH", reason: "Core transit node" },
      { device: "S1", criticality: "HIGH", reason: "Edge host attachment" },
      { device: "S3", criticality: "MEDIUM", reason: "Mesh redundancy path" },
      { device: "S4", criticality: "LOW", reason: "Edge gateway" }
    ];

    listEl.innerHTML = nodes.map(n => {
      const cls = (n.criticality || "LOW").toLowerCase();
      return `
        <div class="twin-critical-item">
          <div>
            <strong>Switch ${n.device}</strong>
            <span style="color:#94a3b8; font-size:11px; margin-left:6px;">${Utils.escapeHtml(n.reason || '')}</span>
          </div>
          <span class="twin-crit-badge ${cls}">${n.criticality}</span>
        </div>
      `;
    }).join("");
  },

  renderTimeline(steps) {
    const listEl = document.getElementById("twin-timeline-list");
    if (!listEl) return;

    if (!steps || steps.length === 0) {
      listEl.innerHTML = `<div style="color:#64748b; font-size:11.5px; padding:6px 0;">No active simulation running. Select a scenario above and click "Run What-If Simulation".</div>`;
      return;
    }

    listEl.innerHTML = steps.map(s => `
      <div class="twin-timeline-item">
        <span class="twin-timeline-step-tag">${s.time}</span>
        <span class="twin-timeline-desc">${Utils.escapeHtml(s.step)}</span>
      </div>
    `).join("");
  },

  renderInsights(result) {
    const el = document.getElementById("twin-insights-content");
    if (!el) return;

    if (!result) {
      el.innerHTML = `
        <div style="font-size:12px; color:#94a3b8; line-height:1.5;">
          The Digital Twin maintains an isolated virtual copy of your 4-switch OpenFlow full mesh.
          Experiment with switch outages (e.g. S3), link failures, volumetric DDoS surges, or QoS adjustments without touching the live SDN controller.
        </div>
      `;
      return;
    }

    let insightsHtml = `<div style="font-weight:700; color:#00f2fe; margin-bottom:6px;">${Utils.escapeHtml(result.conclusion || '')}</div>`;

    if (result.affected_summary || result.impact_deltas) {
      const aff = result.affected_summary || {};
      const deltas = result.impact_deltas || {};
      insightsHtml += `
        <div style="margin: 8px 0; padding: 8px 12px; background: rgba(15,23,42,0.6); border-radius: 6px; border-left: 3px solid #38bdf8; font-size: 11.5px; color: #cbd5e1;">
          <div><strong>Impact Assessment:</strong></div>
          <div style="margin-top:4px;">
            &bull; Affected Flows: <strong>${result.affected_flows || 0}</strong> &bull; Rerouted Paths: <strong>${(result.rerouted_paths || []).length}</strong>
          </div>
          ${aff.hosts_rerouted ? `<div>&bull; Hosts Rerouted: <strong>${aff.hosts_rerouted}</strong></div>` : ''}
          ${aff.traffic_diverted_through ? `<div>&bull; Traffic Diverted: <strong>${aff.traffic_diverted_through}</strong></div>` : ''}
          ${deltas.latency_delta_ms ? `<div>&bull; Latency Change: <strong style="color:${deltas.latency_delta_ms > 0 ? '#ef4444' : '#10b981'};">${deltas.latency_delta_ms > 0 ? '+' : ''}${deltas.latency_delta_ms} ms</strong></div>` : ''}
        </div>
      `;
    }

    if (result.insights && result.insights.length > 0) {
      insightsHtml += `<ul style="margin:4px 0 0 16px; padding:0; font-size:11.5px; color:#cbd5e1; line-height:1.5;">` +
        result.insights.map(i => `<li>${Utils.escapeHtml(i)}</li>`).join("") +
        `</ul>`;
    }

    if (result.recommendation) {
      insightsHtml += `
        <div style="margin-top:10px; padding:10px 12px; background:rgba(0,242,254,0.08); border:1px solid rgba(0,242,254,0.25); border-radius:6px; font-size:11.5px; color:#f1f5f9;">
          <strong style="color:#00f2fe;">💡 Operational Recommendation:</strong> ${Utils.escapeHtml(result.recommendation)}
        </div>
      `;
    }

    el.innerHTML = insightsHtml;
  },

  updateDashboardWidget(result) {
    const badgeEl = document.getElementById("dash-twin-badge");
    const statusEl = document.getElementById("dash-twin-status");
    const subtextEl = document.getElementById("dash-twin-subtext");
    const resEl = document.getElementById("dash-twin-resilience");

    if (!statusEl) return;
    if (result && this.isSimulationActive) {
      if (badgeEl) {
        badgeEl.textContent = "SIMULATION ACTIVE";
        badgeEl.className = "badge badge-critical";
      }
      statusEl.textContent = `${result.scenario || "What-If Simulation"}`;
      if (subtextEl) {
        const deltas = result.impact_deltas || {};
        subtextEl.textContent = `Predicted Health: ${result.after_metrics?.network_health}% | Latency: ${result.after_metrics?.average_latency_ms} ms (${deltas.latency_delta_ms > 0 ? '+' : ''}${deltas.latency_delta_ms || 0} ms)`;
      }
      if (resEl) {
        resEl.textContent = `Survivability: ${result.survivability || "RESILIENT"}`;
      }
    } else {
      if (badgeEl) {
        badgeEl.textContent = "SYNCHRONIZED";
        badgeEl.className = "badge badge-live";
      }
      statusEl.textContent = "Virtual Mirror Active";
      if (subtextEl) {
        subtextEl.textContent = "Safe in-memory sandbox ready for 8 failure & traffic scenarios.";
      }
      if (resEl) {
        resEl.textContent = "Resilience: 96%";
      }
    }
  },

  async fetchHistory() {
    const tbody = document.getElementById("twin-history-tbody");
    if (!tbody) return;

    try {
      const data = await API.get("/api/digital-twin/history");
      const history = data.history || [];

      if (history.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:#64748b; padding:16px;">No simulation runs in current session.</td></tr>`;
        return;
      }

      tbody.innerHTML = history.map(h => `
        <tr>
          <td class="mono" style="color:var(--accent-cyan); font-weight:700;">${h.sim_id}</td>
          <td>${Utils.escapeHtml(h.scenario)}</td>
          <td class="mono">${Utils.escapeHtml(h.target)}</td>
          <td><span class="badge ${h.survivability === 'RESILIENT' ? 'badge-live' : 'badge-stale'}">${h.survivability}</span></td>
          <td class="mono" style="font-weight:700; color:#00f2fe;">${h.resilience_score?.after}%</td>
          <td class="mono" style="font-size:11px;">${Utils.formatRelativeTime(h.timestamp)}</td>
          <td style="text-align:right;">
            <button class="btn btn-secondary btn-sm" onclick="DigitalTwin.loadHistoryItem('${h.sim_id}')">Load</button>
          </td>
        </tr>
      `).join("");
    } catch (err) {
      console.warn("[Digital Twin] Error fetching history:", err);
    }
  },

  loadHistoryItem(simId) {
    API.get(`/api/digital-twin/history/${simId}`).then(res => {
      if (res.simulation) {
        this.activeSimulation = res.simulation;
        this.isSimulationActive = true;
        this.updateModeIndicator();
        this.renderCanvas();
        this.renderResilienceCard();
        this.renderComparisonCard();
        this.renderTimeline(res.simulation.timeline || []);
        this.renderInsights(res.simulation);
        Utils.showToast(`Loaded simulation run ${simId}`, "info");
      }
    });
  },

  async clearHistory() {
    try {
      await API.post("/api/digital-twin/history/clear");
      await this.fetchHistory();
      Utils.showToast("Simulation history cleared.", "info");
    } catch (err) {
      Utils.showToast(`Error clearing history: ${err.message}`, "danger");
    }
  },

  exportReport() {
    if (!this.activeSimulation) {
      Utils.showToast("No simulation active to export. Run a simulation first.", "warning");
      return;
    }

    const sim = this.activeSimulation;
    const reportText = `
============================================================
VORTEX-SDN DIGITAL TWIN — WHAT-IF SIMULATION REPORT
============================================================
Simulation Run ID : ${sim.sim_id}
Timestamp         : ${sim.timestamp}
Scenario          : ${sim.scenario}
Target Component  : ${sim.target}
Survivability     : ${sim.survivability}
Resilience Score  : ${sim.resilience_score?.after}% (Change: ${sim.resilience_score?.change}%)

------------------------------------------------------------
BEFORE VS SIMULATED PREDICTED METRICS
------------------------------------------------------------
Network Health    : ${sim.before_metrics?.network_health}% -> ${sim.after_metrics?.network_health}%
Security Score    : ${sim.before_metrics?.security_health}% -> ${sim.after_metrics?.security_health}%
QoS Score         : ${sim.before_metrics?.qos_health}% -> ${sim.after_metrics?.qos_health}%
Average Latency   : ${sim.before_metrics?.average_latency_ms} ms -> ${sim.after_metrics?.average_latency_ms} ms
Packet Loss       : ${sim.before_metrics?.packet_loss_pct}% -> ${sim.after_metrics?.packet_loss_pct}%
Throughput        : ${sim.before_metrics?.aggregate_throughput_mbps} Mbps -> ${sim.after_metrics?.aggregate_throughput_mbps} Mbps

------------------------------------------------------------
AFFECTED COMPONENTS & REROUTED PATHS
------------------------------------------------------------
Affected Devices  : ${sim.affected_devices?.join(", ") || "None"}
Affected Links    : ${sim.affected_links?.join(", ") || "None"}
Affected Flows    : ${sim.affected_flows || 0}
Rerouted Paths    : ${sim.rerouted_paths?.map(p => `${p.flow}: ${p.old_path?.join("->")} ===> ${p.new_path?.join("->")}`).join("\n                    ") || "N/A"}

------------------------------------------------------------
SIMULATION CONCLUSION
------------------------------------------------------------
${sim.conclusion}

============================================================
Generated by VORTEX-SDN Digital Twin Engine
============================================================
    `.trim();

    // Trigger browser download of text report
    const blob = new Blob([reportText], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `VORTEX_Digital_Twin_${sim.sim_id}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    Utils.showToast(`Simulation report ${sim.sim_id} exported.`, "success");
  }
};
