/**
 * VORTEX-SDN Predictive Network Intelligence Controller
 * Manages statistical anomaly forecasting, dynamic baselines, early warnings,
 * device risk rankings, and Digital Twin simulation routing.
 */

const Predictive = {
  currentWindow: "15m",
  activeCategory: "ALL",
  summary: null,
  forecast: null,
  risks: null,
  anomalies: [],

  async init() {
    this.setupListeners();
    await this.fetchData();
  },

  setupListeners() {
    // Window pills
    const pills = document.querySelectorAll(".pred-time-pill");
    pills.forEach(p => {
      p.addEventListener("click", () => {
        pills.forEach(el => el.classList.remove("active"));
        p.classList.add("active");
        this.currentWindow = p.getAttribute("data-window") || "15m";
        this.fetchData();
      });
    });
  },

  async fetchData() {
    try {
      const [sumRes, fcRes, riskRes, anomRes] = await Promise.all([
        API.get(`/api/predictive/summary?window=${this.currentWindow}`),
        API.get(`/api/predictive/forecast?window=${this.currentWindow}`),
        API.get(`/api/predictive/risks?window=${this.currentWindow}`),
        API.get(`/api/predictive/anomalies?window=${this.currentWindow}`)
      ]);

      this.summary = sumRes;
      this.forecast = fcRes;
      this.risks = riskRes;
      this.anomalies = anomRes.anomalies || [];

      this.renderKPIs();
      this.renderContrastBanner();
      const hf = this.summary?.health_forecast || this.forecast?.health_forecast;
      const sf = this.summary?.security_forecast || this.forecast?.security_forecast;
      const qf = this.summary?.qos_forecast || this.forecast?.qos_forecast;
      const mm = this.summary?.metric_forecasts || this.forecast?.metric_forecasts;

      this.renderPredictiveIntelligenceHero(hf);
      this.renderSecurityQosForecasts(sf, qf);
      this.renderMultiMetricsTable(mm);
      this.renderForecastChart();
      this.renderEarlyWarnings();
      this.renderDeviceRisks();
      this.renderAnomaliesTable();
      this.renderModelInfo();
      this.updateDashboardWidget(hf, this.summary);
    } catch (err) {
      console.warn("[Predictive Intelligence] Error fetching data:", err);
      Utils.showToast("Failed to load predictive analysis.", "danger");
    }
  },

  async refresh() {
    try {
      await API.post("/api/predictive/refresh", { window: this.currentWindow });
      await this.fetchData();
      Utils.showToast("Predictive analysis refreshed.", "success");
    } catch (err) {
      Utils.showToast(`Refresh error: ${err.message}`, "danger");
    }
  },

  renderKPIs() {
    if (!this.summary) return;
    const s = this.summary;

    // 1. Network Risk
    const netRiskEl = document.getElementById("pred-kpi-network-risk");
    const netRiskBadge = document.getElementById("pred-kpi-risk-badge");
    if (netRiskEl) netRiskEl.textContent = `${s.network_risk}%`;
    if (netRiskBadge) {
      netRiskBadge.textContent = s.risk_level;
      netRiskBadge.className = `badge ${s.risk_level === 'CRITICAL' || s.risk_level === 'HIGH' ? 'badge-critical' : (s.risk_level === 'MODERATE' ? 'badge-demo' : 'badge-live')}`;
    }

    // 2. Traffic Trend
    const trendEl = document.getElementById("pred-kpi-traffic-trend");
    if (trendEl) {
      const trend = s.traffic_trend || "STABLE";
      const icon = trend === "INCREASING" ? "↑" : (trend === "DECREASING" ? "↓" : "→");
      const cls = trend.toLowerCase();
      trendEl.innerHTML = `<span class="trend-indicator ${cls}">${icon} ${trend}</span>`;
    }

    // 3. Security Risk
    const secRiskEl = document.getElementById("pred-kpi-security-risk");
    if (secRiskEl) secRiskEl.textContent = `${s.security_risk}%`;

    // 4. QoS Risk
    const qosRiskEl = document.getElementById("pred-kpi-qos-risk");
    if (qosRiskEl) qosRiskEl.textContent = `${s.qos_risk}%`;

    // 5. Predicted Anomalies
    const anomCountEl = document.getElementById("pred-kpi-anomalies-count");
    if (anomCountEl) anomCountEl.textContent = s.predicted_anomalies_count;

    // 6. Early Warnings
    const warnCountEl = document.getElementById("pred-kpi-warnings-count");
    if (warnCountEl) warnCountEl.textContent = s.early_warnings_count;
  },

  renderContrastBanner() {
    if (!this.summary) return;
    const s = this.summary;

    const healthValEl = document.getElementById("pred-contrast-health-val");
    const riskValEl = document.getElementById("pred-contrast-risk-val");
    const riskDescEl = document.getElementById("pred-contrast-risk-desc");

    if (healthValEl) healthValEl.textContent = `${s.current_network_health ?? 96}%`;
    if (riskValEl) {
      riskValEl.textContent = `${s.network_risk}%`;
      const lvlCls = s.risk_level === "CRITICAL" || s.risk_level === "HIGH" ? "risk-high" : (s.risk_level === "MODERATE" ? "risk-mod" : "risk-low");
      riskValEl.className = `pred-contrast-val ${lvlCls}`;
    }

    if (riskDescEl) {
      if (s.network_risk >= 50) {
        riskDescEl.textContent = `Current operations remain online, but predictive engine detects high trend trajectory requiring proactive investigation.`;
      } else if (s.network_risk >= 25) {
        riskDescEl.textContent = `Current fabric health is optimal. Moderate telemetry variance observed across ingress queues.`;
      } else {
        riskDescEl.textContent = `Live network is healthy and telemetry operates within normal baseline bounds. Predictive risk is minimal.`;
      }
    }
  },

  renderForecastChart() {
    const container = document.getElementById("pred-svg-chart-container");
    if (!container || !this.forecast) return;

    if (!this.forecast.is_sufficient) {
      container.innerHTML = `
        <div style="display:flex; align-items:center; justify-content:center; height:100%; color:#64748b; font-size:12px;">
          INSUFFICIENT HISTORICAL DATA — Additional telemetry observations required.
        </div>
      `;
      return;
    }

    const series = this.forecast.chart_series || [];
    if (series.length < 2) return;

    const width = 680;
    const height = 220;
    const padding = { top: 25, right: 30, bottom: 30, left: 45 };

    const maxVal = 100.0;
    const minVal = 0.0;

    const xScale = (i) => padding.left + (i / (series.length - 1)) * (width - padding.left - padding.right);
    const yScale = (v) => height - padding.bottom - ((v - minVal) / (maxVal - minVal)) * (height - padding.top - padding.bottom);

    // Build historical path vs forecast path
    let histPath = "";
    let fcPath = "";
    let currIdx = -1;

    series.forEach((pt, i) => {
      const x = xScale(i);
      const y = yScale(pt.throughput_mbps);

      if (pt.type === "past") {
        histPath += (histPath === "" ? `M ${x} ${y}` : ` L ${x} ${y}`);
      } else if (pt.type === "current") {
        currIdx = i;
        histPath += ` L ${x} ${y}`;
        fcPath = `M ${x} ${y}`;
      } else if (pt.type === "forecast") {
        fcPath += ` L ${x} ${y}`;
      }
    });

    // Reference Risk Threshold line (80 Mbps)
    const yThresh = yScale(80.0);

    let svgHtml = `
      <svg class="w-100 h-100" viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg" style="overflow:visible;">
        <!-- Grid horizontal reference lines -->
        <line x1="${padding.left}" y1="${yScale(20)}" x2="${width - padding.right}" y2="${yScale(20)}" stroke="rgba(255,255,255,0.05)" stroke-width="1" />
        <line x1="${padding.left}" y1="${yScale(50)}" x2="${width - padding.right}" y2="${yScale(50)}" stroke="rgba(255,255,255,0.05)" stroke-width="1" />
        <line x1="${padding.left}" y1="${yScale(80)}" x2="${width - padding.right}" y2="${yScale(80)}" stroke="rgba(239,68,68,0.3)" stroke-dasharray="4,4" stroke-width="1" />
        <text x="${width - padding.right}" y="${yScale(80) - 4}" font-size="9" fill="#ef4444" text-anchor="end" font-weight="700">Risk Threshold (80 Mbps)</text>

        <!-- Y Axis Labels -->
        <text x="${padding.left - 8}" y="${yScale(0) + 4}" font-size="10" fill="#64748b" text-anchor="end">0</text>
        <text x="${padding.left - 8}" y="${yScale(50) + 4}" font-size="10" fill="#64748b" text-anchor="end">50M</text>
        <text x="${padding.left - 8}" y="${yScale(100) + 4}" font-size="10" fill="#64748b" text-anchor="end">100M</text>

        <!-- Historical Path (Solid Blue) -->
        <path d="${histPath}" fill="none" stroke="#38bdf8" stroke-width="2.5" stroke-linecap="round" />

        <!-- Forecast Path (Dashed Cyan) -->
        <path d="${fcPath}" fill="none" stroke="#00f2fe" stroke-width="2.5" stroke-dasharray="5,5" stroke-linecap="round" />
    `;

    // Points
    series.forEach((pt, i) => {
      const x = xScale(i);
      const y = yScale(pt.throughput_mbps);

      if (pt.type === "current") {
        svgHtml += `
          <circle cx="${x}" cy="${y}" r="6" fill="#00f2fe" stroke="#ffffff" stroke-width="2" />
          <text x="${x}" y="${y - 10}" font-size="10" font-weight="800" fill="#00f2fe" text-anchor="middle">${pt.throughput_mbps}M</text>
        `;
      } else if (pt.type === "forecast") {
        svgHtml += `
          <circle cx="${x}" cy="${y}" r="3" fill="#00f2fe" />
        `;
      }

      // X Axis Label
      if (i % 2 === 0 || i === series.length - 1) {
        svgHtml += `
          <text x="${x}" y="${height - 8}" font-size="9.5" fill="#94a3b8" text-anchor="middle" font-family="monospace">${pt.time}</text>
        `;
      }
    });

    svgHtml += `</svg>`;
    container.innerHTML = svgHtml;
  },

  renderEarlyWarnings() {
    const listEl = document.getElementById("pred-warning-list");
    if (!listEl || !this.risks) return;

    const warnings = this.risks.early_warnings || [];
    if (warnings.length === 0) {
      listEl.innerHTML = `<div style="color:#64748b; font-size:12px; padding:8px 0;">No active early warnings. Baseline metrics nominal.</div>`;
      return;
    }

    listEl.innerHTML = warnings.map(w => {
      const sevCls = (w.severity || "MEDIUM").toLowerCase();
      const dtAction = w.digital_twin_scenario ? `
        <button class="btn btn-secondary btn-sm" onclick="Predictive.openDigitalTwin('${w.digital_twin_scenario}', '${w.digital_twin_target}')" title="Simulate scenario in Digital Twin">
          Simulate in Digital Twin
        </button>
      ` : '';

      const ackBtn = !w.is_acknowledged ? `
        <button class="btn btn-secondary btn-sm" onclick="Predictive.acknowledge('${w.id}')">Acknowledge</button>
      ` : `<span style="font-size:11px; color:#10b981; font-weight:700;">✓ Acknowledged</span>`;

      return `
        <div class="pred-warning-card ${sevCls}">
          <div class="pred-warning-header">
            <span class="pred-warning-title">
              <span class="badge ${sevCls === 'critical' || sevCls === 'high' ? 'badge-critical' : 'badge-demo'}">${w.severity}</span>
              ${Utils.escapeHtml(w.title)}
            </span>
            <span style="font-size:11px; color:#94a3b8; font-family:monospace;">Confidence: <strong>${w.confidence}%</strong></span>
          </div>
          <div class="pred-warning-msg">${Utils.escapeHtml(w.message)}</div>
          <div class="pred-warning-action-bar">
            <span class="pred-warning-rec">Action: ${Utils.escapeHtml(w.recommended_action)}</span>
            <div class="pred-warning-btns">
              ${dtAction}
              ${ackBtn}
            </div>
          </div>
        </div>
      `;
    }).join("");
  },

  renderDeviceRisks() {
    const listEl = document.getElementById("pred-device-risk-list");
    if (!listEl || !this.risks) return;

    const devices = this.risks.device_risks || [];
    if (devices.length === 0) {
      listEl.innerHTML = `<div style="color:#64748b; font-size:12px;">No device risk assessment data available.</div>`;
      return;
    }

    listEl.innerHTML = devices.slice(0, 6).map(d => {
      const lvlCls = (d.risk_level || "LOW").toLowerCase();
      const badgeCls = lvlCls === "critical" || lvlCls === "high" ? "badge-critical" : (lvlCls === "moderate" ? "badge-demo" : "badge-live");
      return `
        <div class="pred-device-item">
          <div class="pred-device-name-group">
            <strong>${d.device}</strong>
            <span class="pred-device-factor">${Utils.escapeHtml(d.factors[0] || '')}</span>
          </div>
          <div style="display:flex; align-items:center; gap:8px;">
            <span class="mono" style="font-weight:700; color:#00f2fe;">${d.risk_score}%</span>
            <span class="badge ${badgeCls}">${d.risk_level}</span>
          </div>
        </div>
      `;
    }).join("");
  },

  renderAnomaliesTable() {
    const tbody = document.getElementById("pred-anomalies-tbody");
    if (!tbody) return;

    let list = this.anomalies || [];
    if (this.activeCategory !== "ALL") {
      list = list.filter(a => a.category === this.activeCategory);
    }

    if (list.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:#64748b; padding:16px;">No statistical anomalies detected.</td></tr>`;
      return;
    }

    tbody.innerHTML = list.map(a => {
      const sevCls = (a.severity || "MEDIUM").toLowerCase();
      const badgeCls = sevCls === "critical" || sevCls === "high" ? "badge-critical" : "badge-demo";
      return `
        <tr>
          <td class="mono" style="color:var(--accent-cyan); font-weight:700;">${a.id}</td>
          <td><span class="badge badge-subtle">${a.category}</span></td>
          <td><strong>${Utils.escapeHtml(a.title)}</strong></td>
          <td><span class="badge ${badgeCls}">${a.severity}</span></td>
          <td class="mono">${a.observed_value} <span style="color:#64748b; font-size:10.5px;">(${a.deviation_pct})</span></td>
          <td class="mono" style="color:#00f2fe; font-weight:700;">${a.confidence}%</td>
          <td style="font-size:11.5px; color:#cbd5e1;">${Utils.escapeHtml(a.recommendation)}</td>
        </tr>
      `;
    }).join("");
  },

  filterAnomalies(category) {
    this.activeCategory = category;
    const tabs = document.querySelectorAll(".pred-anom-tab");
    tabs.forEach(t => {
      if (t.getAttribute("data-cat") === category) t.classList.add("active");
      else t.classList.remove("active");
    });
    this.renderAnomaliesTable();
  },

  renderModelInfo() {
    const el = document.getElementById("pred-model-info-grid");
    if (!el || !this.summary) return;

    const info = this.summary.model_info || {};
    el.innerHTML = `
      <div class="pred-meta-item">
        <div class="pred-meta-label">Forecasting Algorithm</div>
        <div class="pred-meta-val">${info.algorithm || 'Holt Linear Trend Extrapolation'}</div>
      </div>
      <div class="pred-meta-item">
        <div class="pred-meta-label">Training Telemetry</div>
        <div class="pred-meta-val">${info.training_data || 'Live OpenFlow Buffers'}</div>
      </div>
      <div class="pred-meta-item">
        <div class="pred-meta-label">Prediction Window</div>
        <div class="pred-meta-val">${info.prediction_window || '15–30 Minutes'}</div>
      </div>
      <div class="pred-meta-item">
        <div class="pred-meta-label">Engine Status</div>
        <div class="pred-meta-val" style="color:#10b981;">● ${this.summary.status || 'READY'}</div>
      </div>
    `;
  },

  async acknowledge(warningId) {
    try {
      await API.post(`/api/predictive/warnings/${warningId}/acknowledge`);
      Utils.showToast(`Warning ${warningId} acknowledged.`, "info");
      await this.fetchData();
    } catch (err) {
      Utils.showToast(`Acknowledge failed: ${err.message}`, "danger");
    }
  },

  openDigitalTwin(scenario, target) {
    Utils.showToast(`Routing to Digital Twin with scenario: ${scenario} (${target})...`, "info");
    App.navigate("digital-twin");
    setTimeout(() => {
      const scenSelect = document.getElementById("twin-scenario-select");
      if (scenSelect) {
        scenSelect.value = scenario;
        DigitalTwin.onScenarioChange();
        const targetSelect = document.getElementById("twin-target-select");
        if (targetSelect && target) targetSelect.value = target;
      }
    }, 200);
  },

  renderPredictiveIntelligenceHero(hf) {
    if (!hf) return;
    const curEl = document.getElementById("pred-hero-cur-health");
    const predEl = document.getElementById("pred-hero-pred-health");
    const riskBadge = document.getElementById("pred-hero-risk-badge");
    const confEl = document.getElementById("pred-hero-confidence");
    const reasonEl = document.getElementById("pred-hero-reason");

    if (curEl) curEl.textContent = `${hf.current}%`;
    if (predEl) predEl.textContent = `${hf.predicted || hf.predicted_5m}%`;
    if (confEl) confEl.textContent = `${hf.confidence || 91}%`;
    if (reasonEl) reasonEl.textContent = hf.reason || "Traffic within normal baseline";

    if (riskBadge) {
      riskBadge.textContent = hf.risk_level || "MEDIUM";
      const lvl = (hf.risk_level || "MEDIUM").toUpperCase();
      if (lvl === "HIGH" || lvl === "CRITICAL") {
        riskBadge.style.background = "rgba(239, 68, 68, 0.2)";
        riskBadge.style.color = "#f87171";
        riskBadge.style.borderColor = "rgba(239, 68, 68, 0.4)";
      } else if (lvl === "WARNING" || lvl === "MEDIUM") {
        riskBadge.style.background = "rgba(251, 191, 36, 0.2)";
        riskBadge.style.color = "#fbbf24";
        riskBadge.style.borderColor = "rgba(251, 191, 36, 0.4)";
      } else {
        riskBadge.style.background = "rgba(16, 185, 129, 0.15)";
        riskBadge.style.color = "#34d399";
        riskBadge.style.borderColor = "rgba(16, 185, 129, 0.35)";
      }
    }

    // Step cards: NOW, 1m, 5m, 10m
    const stepNow = document.getElementById("pred-step-now");
    const step1m = document.getElementById("pred-step-1m");
    const step5m = document.getElementById("pred-step-5m");
    const step10m = document.getElementById("pred-step-10m");

    if (stepNow) stepNow.textContent = `${hf.current}%`;
    if (step1m) step1m.textContent = `${hf.predicted_1m}%`;
    if (step5m) step5m.textContent = `${hf.predicted_5m}%`;
    if (step10m) step10m.textContent = `${hf.predicted_10m}%`;

    this.renderSmoothForecastCurve(hf.timeline || [
      { step: "NOW", health: hf.current },
      { step: "1m", health: hf.predicted_1m },
      { step: "5m", health: hf.predicted_5m },
      { step: "10m", health: hf.predicted_10m }
    ]);
  },

  renderSmoothForecastCurve(timeline) {
    const container = document.getElementById("pred-smooth-curve-container");
    if (!container || !timeline || timeline.length === 0) return;

    const vals = timeline.map(t => Number(t.health) || 90);
    const minVal = Math.min(...vals, 70);
    const maxVal = Math.max(...vals, 100);
    const range = Math.max(1, maxVal - minVal);

    const w = 700;
    const h = 60;
    const paddingX = 40;
    const paddingY = 10;

    const points = vals.map((v, idx) => {
      const x = paddingX + (idx / (vals.length - 1)) * (w - 2 * paddingX);
      const y = h - paddingY - ((v - minVal) / range) * (h - 2 * paddingY);
      return { x, y, val: v };
    });

    let pathD = `M ${points[0].x} ${points[0].y}`;
    for (let i = 0; i < points.length - 1; i++) {
      const p0 = points[i];
      const p1 = points[i + 1];
      const mx = (p0.x + p1.x) / 2;
      pathD += ` C ${mx} ${p0.y}, ${mx} ${p1.y}, ${p1.x} ${p1.y}`;
    }

    let svg = `
      <svg viewBox="0 0 ${w} ${h}" style="width:100%; height:100%; overflow:visible;">
        <defs>
          <linearGradient id="predCurveGrad" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stop-color="#10b981" />
            <stop offset="35%" stop-color="#38bdf8" />
            <stop offset="70%" stop-color="#fbbf24" />
            <stop offset="100%" stop-color="#f87171" />
          </linearGradient>
        </defs>
        <path d="${pathD}" fill="none" stroke="url(#predCurveGrad)" stroke-width="3" stroke-linecap="round" />
        ${points.map(p => `
          <circle cx="${p.x}" cy="${p.y}" r="4" fill="#0b1329" stroke="#38bdf8" stroke-width="2.5" />
          <text x="${p.x}" y="${p.y - 8}" text-anchor="middle" font-size="10" font-weight="700" fill="#f8fafc" font-family="monospace">${p.val}%</text>
        `).join("")}
      </svg>
    `;
    container.innerHTML = svg;
  },

  renderSecurityQosForecasts(sf, qf) {
    if (sf) {
      const secCur = document.getElementById("pred-sec-curr");
      const secPred = document.getElementById("pred-sec-pred");
      const secReason = document.getElementById("pred-sec-reason");
      if (secCur) secCur.textContent = sf.current_risk || "LOW";
      if (secPred) secPred.textContent = sf.predicted_risk || "MEDIUM";
      if (secReason) secReason.textContent = sf.reason || "No abnormal traffic patterns observed.";
    }

    if (qf) {
      const qosCur = document.getElementById("pred-qos-curr");
      const qosPred = document.getElementById("pred-qos-pred");
      const qosIssue = document.getElementById("pred-qos-issue");
      if (qosCur) qosCur.textContent = `${qf.current || 98}%`;
      if (qosPred) qosPred.textContent = `${qf.predicted || 93}%`;
      if (qosIssue) qosIssue.textContent = qf.potential_issue || "SLA compliance optimal on priority queues.";
    }
  },

  renderMultiMetricsTable(mm) {
    const tbody = document.getElementById("pred-multi-metrics-tbody");
    if (!tbody) return;

    if (!mm || Object.keys(mm).length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:#64748b; padding:12px;">Collecting telemetry for prediction...</td></tr>`;
      return;
    }

    const labels = {
      network_health: "Network Health Score",
      security_risk: "Security Threat Risk",
      qos_health: "QoS Health Index",
      throughput: "Throughput Rate",
      latency: "Average Latency",
      packet_loss: "Packet Loss Rate",
      bandwidth_utilization: "Bandwidth Utilization"
    };

    tbody.innerHTML = Object.keys(mm).map(k => {
      const item = mm[k];
      const unit = item.unit === "%" ? "%" : (item.unit === "ms" ? " ms" : (item.unit === "Mbps" ? " Mbps" : ""));
      const trendIcon = item.trend === "INCREASING" ? "↑" : (item.trend === "DECREASING" ? "↓" : "→");
      const trendCls = (item.trend || "STABLE").toLowerCase();
      const riskStatus = (item.trend === "DEGRADING" || (k === "packet_loss" && item.pred_5m > 1.0) || (k === "latency" && item.pred_5m > 25.0)) ? "WARNING" : "NOMINAL";
      const badgeCls = riskStatus === "WARNING" ? "badge-critical" : "badge-live";

      return `
        <tr>
          <td><strong style="color:var(--text-primary);">${labels[k] || k}</strong></td>
          <td class="mono">${item.current}${unit}</td>
          <td class="mono" style="color:#38bdf8;">${item.pred_1m}${unit}</td>
          <td class="mono" style="color:#fbbf24;">${item.pred_5m}${unit}</td>
          <td class="mono" style="color:#f87171;">${item.pred_10m}${unit}</td>
          <td><span class="trend-indicator ${trendCls}">${trendIcon} ${item.trend}</span></td>
          <td><span class="badge ${badgeCls}">${riskStatus}</span></td>
        </tr>
      `;
    }).join("");
  },

  updateDashboardWidget(hf, summary) {
    const curEl = document.getElementById("dash-pred-cur");
    const fcEl = document.getElementById("dash-pred-fc");
    const descEl = document.getElementById("dash-pred-desc");
    const badgeEl = document.getElementById("dash-pred-badge");

    if (hf) {
      if (curEl) curEl.textContent = `${hf.current}%`;
      if (fcEl) fcEl.textContent = `${hf.predicted || hf.predicted_5m}%`;
      if (descEl) descEl.textContent = `Risk Level: ${hf.risk_level} • Confidence ${hf.confidence || 91}%`;
      if (badgeEl) badgeEl.textContent = hf.trend_label || "FORECAST";
    }
  }
};
