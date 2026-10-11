/**
 * VORTEX-SDN Pure Canvas & SVG Real-Time Chart Engine
 * Lightweight, high-performance, dual-axis telemetry streaming chart with interactive crosshairs.
 */

const Charts = {
  _chartState: {
    hoverIndex: -1,
    mouseX: -1,
    mouseY: -1,
    isHovered: false,
    initializedCanvas: null
  },

  // Combined Bar + Line Telemetry Chart (Option 3 NOC-Grade Visualizer)
  renderLineChart(canvasId, historyData = [], series = []) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    // Attach interaction listener once
    if (this._chartState.initializedCanvas !== canvasId) {
      this._attachChartListeners(canvas, canvasId);
      this._chartState.initializedCanvas = canvasId;
    }

    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();

    if (canvas.width !== Math.round(rect.width * dpr) || canvas.height !== Math.round(rect.height * dpr)) {
      canvas.width = Math.round(rect.width * dpr);
      canvas.height = Math.round(rect.height * dpr);
      ctx.scale(dpr, dpr);
    }

    const width = rect.width;
    const height = rect.height;
    const padding = { top: 32, right: 60, bottom: 32, left: 60 };

    ctx.clearRect(0, 0, width, height);

    // Update Header Badges & Timestamps
    this._updateChartHeader(historyData);

    // Initial / Empty State
    if (!historyData || historyData.length === 0) {
      ctx.save();
      ctx.fillStyle = "#64748b";
      ctx.font = "500 12.5px Inter, sans-serif";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText("● Receiving telemetry stream...", width / 2, height / 2);
      ctx.restore();
      return;
    }

    const plotW = width - padding.left - padding.right;
    const plotH = height - padding.top - padding.bottom;
    const count = historyData.length;

    // 1. Compute Independent Dual-Axis Ranges
    let maxThroughput = 10;
    let maxLatency = 5;

    historyData.forEach(d => {
      const tp = parseFloat(d.throughput_mbps || 0);
      const lat = parseFloat(d.latency_ms || 0);
      if (tp > maxThroughput) maxThroughput = tp;
      if (lat > maxLatency) maxLatency = lat;
    });

    maxThroughput = Math.ceil(maxThroughput * 1.25 / 5) * 5;
    if (maxThroughput < 5) maxThroughput = 5;
    maxLatency = Math.ceil(maxLatency * 1.25 / 5) * 5;
    if (maxLatency < 5) maxLatency = 5;

    // Check Light vs Dark mode
    const isLight = document.documentElement.getAttribute("data-theme") === "light";

    // 2. Draw Dual-Axis Titles
    ctx.save();
    ctx.font = "600 10.5px Inter, sans-serif";
    ctx.fillStyle = isLight ? "#0284c7" : "#00f2fe";
    ctx.textAlign = "left";
    ctx.fillText("Throughput (Mbps)", padding.left, padding.top - 14);

    ctx.fillStyle = isLight ? "#d97706" : "#f59e0b";
    ctx.textAlign = "right";
    ctx.fillText("Latency (ms)", width - padding.right, padding.top - 14);

    // 3. Draw Subtle Grid Lines & Y-Axes
    ctx.lineWidth = 1;
    ctx.font = "10px JetBrains Mono, monospace";

    const gridLines = 4;
    for (let i = 0; i <= gridLines; i++) {
      const y = padding.top + (plotH / gridLines) * i;
      const tpVal = maxThroughput - (maxThroughput / gridLines) * i;
      const latVal = maxLatency - (maxLatency / gridLines) * i;

      // Horizontal Grid Line
      ctx.strokeStyle = i === gridLines 
        ? (isLight ? "#cbd5e1" : "rgba(255, 255, 255, 0.14)") 
        : (isLight ? "#e2e8f0" : "rgba(255, 255, 255, 0.05)");
      ctx.beginPath();
      ctx.moveTo(padding.left, y);
      ctx.lineTo(width - padding.right, y);
      ctx.stroke();

      // Left Y-Axis Label (Throughput - Cyan/Blue)
      ctx.fillStyle = isLight ? "#0284c7" : "rgba(0, 242, 254, 0.85)";
      ctx.textAlign = "right";
      ctx.fillText(`${tpVal.toFixed(0)}M`, padding.left - 8, y + 3.5);

      // Right Y-Axis Label (Latency - Amber/Orange)
      ctx.fillStyle = isLight ? "#d97706" : "rgba(245, 158, 11, 0.85)";
      ctx.textAlign = "left";
      ctx.fillText(`${latVal.toFixed(0)}ms`, width - padding.right + 8, y + 3.5);
    }

    // 4. Draw X-Axis Baseline & Time Markers
    ctx.strokeStyle = isLight ? "#cbd5e1" : "rgba(255, 255, 255, 0.12)";
    ctx.beginPath();
    ctx.moveTo(padding.left, padding.top + plotH);
    ctx.lineTo(width - padding.right, padding.top + plotH);
    ctx.stroke();

    ctx.fillStyle = isLight ? "#475569" : "#64748b";
    ctx.font = "500 10px Inter, sans-serif";
    ctx.textAlign = "center";
    ctx.fillText("Time", width / 2, height - 4);

    const slotW = plotW / count;
    const barW = Math.max(4, Math.min(22, slotW * 0.62));

    // Sample timestamps on X-axis (up to 5 evenly spaced labels)
    ctx.fillStyle = isLight ? "#64748b" : "#94a3b8";
    ctx.font = "9.5px JetBrains Mono, monospace";
    const sampleStep = Math.max(1, Math.floor(count / 4));
    const sampleIndices = [];
    for (let i = 0; i < count; i += sampleStep) sampleIndices.push(i);
    if (sampleIndices[sampleIndices.length - 1] !== count - 1) sampleIndices.push(count - 1);

    sampleIndices.forEach(idx => {
      const d = historyData[idx];
      if (d && d.time) {
        const cx = padding.left + idx * slotW + slotW / 2;
        ctx.fillText(d.time, cx, height - 16);
      }
    });
    ctx.restore();

    // 5. Draw Throughput Vertical Bars (Cyan / Blue Gradient)
    for (let i = 0; i < count; i++) {
      const d = historyData[i];
      const tp = Math.max(0, parseFloat(d.throughput_mbps || 0));
      const barH = Math.max(2, (tp / maxThroughput) * plotH);
      const barX = padding.left + i * slotW + (slotW - barW) / 2;
      const barY = padding.top + plotH - barH;
      const isHovered = (this._chartState.isHovered && this._chartState.hoverIndex === i);
      const isLatest = (i === count - 1);

      ctx.save();
      const grad = ctx.createLinearGradient(0, barY, 0, barY + barH);
      if (isHovered) {
        grad.addColorStop(0, "#38bdf8");
        grad.addColorStop(1, "rgba(2, 132, 199, 0.8)");
      } else if (isLatest) {
        grad.addColorStop(0, "#00f2fe");
        grad.addColorStop(1, "rgba(2, 132, 199, 0.45)");
      } else {
        grad.addColorStop(0, "rgba(0, 242, 254, 0.75)");
        grad.addColorStop(1, "rgba(2, 132, 199, 0.22)");
      }

      ctx.fillStyle = grad;
      const r = Math.min(3, barW / 2);
      ctx.beginPath();
      ctx.moveTo(barX, barY + barH);
      ctx.lineTo(barX, barY + r);
      ctx.quadraticCurveTo(barX, barY, barX + r, barY);
      ctx.lineTo(barX + barW - r, barY);
      ctx.quadraticCurveTo(barX + barW, barY, barX + barW, barY + r);
      ctx.lineTo(barX + barW, barY + barH);
      ctx.closePath();
      ctx.fill();

      // Top edge cap stroke
      ctx.strokeStyle = isHovered ? "#38bdf8" : "rgba(0, 242, 254, 0.85)";
      ctx.lineWidth = isHovered ? 1.5 : 1;
      ctx.beginPath();
      ctx.moveTo(barX, barY + r);
      ctx.quadraticCurveTo(barX, barY, barX + r, barY);
      ctx.lineTo(barX + barW - r, barY);
      ctx.quadraticCurveTo(barX + barW, barY, barX + barW, barY + r);
      ctx.stroke();

      if (isHovered) {
        ctx.shadowColor = "rgba(0, 242, 254, 0.7)";
        ctx.shadowBlur = 8;
        ctx.stroke();
      }
      ctx.restore();
    }

    // 6. Draw Latency Smooth Line Overlay (Amber / Orange)
    const latPoints = historyData.map((d, i) => {
      const barX = padding.left + i * slotW + (slotW - barW) / 2;
      const lat = Math.max(0, parseFloat(d.latency_ms || 0));
      return {
        x: barX + barW / 2,
        y: padding.top + plotH - (lat / maxLatency) * plotH,
        val: lat,
        time: d.time
      };
    });

    if (latPoints.length >= 2) {
      this._drawSmoothLine(ctx, latPoints, "#f59e0b", 2.5, "rgba(245, 158, 11, 0.4)");
    }

    // Draw circular dots on latency line
    ctx.save();
    latPoints.forEach((p) => {
      ctx.beginPath();
      ctx.arc(p.x, p.y, 2.5, 0, Math.PI * 2);
      ctx.fillStyle = "#f59e0b";
      ctx.fill();
    });
    ctx.restore();

    // 7. Live Right Edge Indicators
    const latestLat = latPoints[latPoints.length - 1];
    if (latestLat) {
      this._drawGlowingPoint(ctx, latestLat.x, latestLat.y, "#f59e0b", 5.5, 2.5);
    }

    // 8. Interactive Crosshair & Tooltip on Hover
    if (this._chartState.isHovered && this._chartState.hoverIndex >= 0 && this._chartState.hoverIndex < count) {
      const idx = this._chartState.hoverIndex;
      const p = latPoints[idx];
      const dataPoint = historyData[idx];

      if (p && dataPoint) {
        // Vertical dashed crosshair
        ctx.save();
        ctx.strokeStyle = isLight ? "rgba(15, 23, 42, 0.22)" : "rgba(255, 255, 255, 0.3)";
        ctx.lineWidth = 1;
        ctx.setLineDash([3, 3]);
        ctx.beginPath();
        ctx.moveTo(p.x, padding.top);
        ctx.lineTo(p.x, padding.top + plotH);
        ctx.stroke();
        ctx.restore();

        // Highlight Hovered Latency Point
        this._drawGlowingPoint(ctx, p.x, p.y, isLight ? "#d97706" : "#f59e0b", 6, 3);

        // Position & Show Tooltip
        this._showTooltip(canvas, p.x, p.y, dataPoint);
      }
    } else {
      this._hideTooltip();
    }
  },

  _drawSmoothLine(ctx, points, color, lineWidth, glowColor) {
    if (points.length < 2) return;
    ctx.save();
    ctx.strokeStyle = color;
    ctx.lineWidth = lineWidth;
    ctx.lineJoin = "round";
    ctx.lineCap = "round";

    if (glowColor) {
      ctx.shadowColor = glowColor;
      ctx.shadowBlur = 6;
    }

    ctx.beginPath();
    ctx.moveTo(points[0].x, points[0].y);

    for (let i = 0; i < points.length - 1; i++) {
      const p0 = points[i];
      const p1 = points[i + 1];
      const cp1x = p0.x + (p1.x - p0.x) / 2;
      const cp1y = p0.y;
      const cp2x = p0.x + (p1.x - p0.x) / 2;
      const cp2y = p1.y;
      ctx.bezierCurveTo(cp1x, cp1y, cp2x, cp2y, p1.x, p1.y);
    }

    ctx.stroke();
    ctx.restore();
  },

  _drawSmoothArea(ctx, points, top, plotH, left, right) {
    if (points.length < 2) return;
    ctx.save();
    ctx.beginPath();
    ctx.moveTo(points[0].x, points[0].y);

    for (let i = 0; i < points.length - 1; i++) {
      const p0 = points[i];
      const p1 = points[i + 1];
      const cp1x = p0.x + (p1.x - p0.x) / 2;
      const cp1y = p0.y;
      const cp2x = p0.x + (p1.x - p0.x) / 2;
      const cp2y = p1.y;
      ctx.bezierCurveTo(cp1x, cp1y, cp2x, cp2y, p1.x, p1.y);
    }

    const last = points[points.length - 1];
    ctx.lineTo(last.x, top + plotH);
    ctx.lineTo(points[0].x, top + plotH);
    ctx.closePath();

    const grad = ctx.createLinearGradient(0, top, 0, top + plotH);
    grad.addColorStop(0, "rgba(0, 242, 254, 0.22)");
    grad.addColorStop(0.7, "rgba(0, 242, 254, 0.05)");
    grad.addColorStop(1, "rgba(0, 242, 254, 0.0)");

    ctx.fillStyle = grad;
    ctx.fill();
    ctx.restore();
  },

  _drawGlowingPoint(ctx, x, y, color, outerR, innerR) {
    ctx.save();
    ctx.beginPath();
    ctx.arc(x, y, outerR, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.shadowColor = color;
    ctx.shadowBlur = 8;
    ctx.fill();

    ctx.beginPath();
    ctx.arc(x, y, innerR, 0, Math.PI * 2);
    ctx.fillStyle = "#ffffff";
    ctx.shadowBlur = 0;
    ctx.fill();
    ctx.restore();
  },

  _attachChartListeners(canvas, canvasId) {
    canvas.addEventListener("mousemove", (e) => {
      const rect = canvas.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;

      const paddingLeft = 60;
      const paddingRight = 60;
      const plotW = rect.width - paddingLeft - paddingRight;

      if (plotW > 0 && Telemetry && Telemetry.historyTimeSeries && Telemetry.historyTimeSeries.length > 0) {
        const count = Telemetry.historyTimeSeries.length;
        const slotW = plotW / count;
        const relX = mouseX - paddingLeft;
        const nearestIdx = Math.max(0, Math.min(count - 1, Math.floor(relX / slotW)));

        this._chartState.hoverIndex = nearestIdx;
        this._chartState.mouseX = mouseX;
        this._chartState.mouseY = mouseY;
        this._chartState.isHovered = true;

        if (Dashboard && typeof Dashboard.renderCharts === 'function') {
          Dashboard.renderCharts(Telemetry.historyTimeSeries);
        }
      }
    });

    canvas.addEventListener("mouseleave", () => {
      this._chartState.isHovered = false;
      this._chartState.hoverIndex = -1;
      this._hideTooltip();
      if (Dashboard && typeof Dashboard.renderCharts === 'function' && Telemetry && Telemetry.historyTimeSeries) {
        Dashboard.renderCharts(Telemetry.historyTimeSeries);
      }
    });
  },

  _showTooltip(canvas, x, y, data) {
    const tooltip = document.getElementById("chart-tooltip");
    if (!tooltip) return;

    const isLight = document.documentElement.getAttribute("data-theme") === "light";
    const tpVal = parseFloat(data.throughput_mbps || 0).toFixed(1);
    const latVal = parseFloat(data.latency_ms || 0).toFixed(1);
    const timeStr = data.time || "Now";

    const tpColor = isLight ? "#0284c7" : "#00f2fe";
    const latColor = isLight ? "#d97706" : "#f59e0b";
    const timeColor = isLight ? "#0f172a" : "#ffffff";
    const timeLabelColor = isLight ? "#64748b" : "var(--text-muted, #94a3b8)";

    tooltip.innerHTML = `
      <div class="noc-tooltip">
        <div class="noc-tooltip-block">
          <div class="noc-tooltip-label" style="color: ${timeLabelColor};">TIME</div>
          <div class="noc-tooltip-val" style="color: ${timeColor};">${timeStr}</div>
        </div>
        <div class="noc-tooltip-block tp" style="border-left-color: ${tpColor};">
          <div class="noc-tooltip-label" style="color: ${tpColor};">THROUGHPUT</div>
          <div class="noc-tooltip-val" style="color: ${tpColor};">${tpVal} Mbps</div>
        </div>
        <div class="noc-tooltip-block lat" style="border-left-color: ${latColor};">
          <div class="noc-tooltip-label" style="color: ${latColor};">LATENCY</div>
          <div class="noc-tooltip-val" style="color: ${latColor};">${latVal} ms</div>
        </div>
      </div>
    `;

    tooltip.style.left = `${x}px`;
    tooltip.style.top = `${Math.max(20, y - 10)}px`;
    tooltip.style.display = "block";
  },

  _hideTooltip() {
    const tooltip = document.getElementById("chart-tooltip");
    if (tooltip) {
      tooltip.style.display = "none";
    }
  },

  _updateChartHeader(historyData) {
    // 1. Update Telemetry Status Badge
    const badge = document.getElementById("chart-telemetry-badge");
    if (badge) {
      const summary = State.summary || (typeof Telemetry !== 'undefined' && Telemetry._lastValidSummary);
      const telState = State.telemetry || {};
      const status = telState.status || (summary && summary.telemetry_status) || "LIVE";
      const source = telState.source || (summary && summary.source) || "DEMO";
      const isDemo = (source === "DEMO" || status === "DEMO");

      if (status === "OFFLINE" || status === "DISCONNECTED") {
        badge.className = "badge badge-critical";
        badge.textContent = "○ OFFLINE";
      } else if (status === "STALE") {
        badge.className = "badge badge-warning";
        badge.textContent = "● TELEMETRY STALE";
      } else if (isDemo) {
        badge.className = "badge badge-demo";
        badge.textContent = "● DEMO SIMULATION";
      } else {
        badge.className = "badge badge-live";
        badge.textContent = "● LIVE TELEMETRY";
      }
    }

    // 2. Update Latest Sample Time Pill
    const timePill = document.getElementById("chart-latest-timestamp");
    if (timePill) {
      if (historyData && historyData.length > 0) {
        const lastSample = historyData[historyData.length - 1];
        const elapsedSec = (typeof Telemetry !== 'undefined' && Telemetry._lastSuccessfulEpoch)
          ? Math.max(0, Math.floor((Date.now() - Telemetry._lastSuccessfulEpoch) / 1000))
          : 0;
        timePill.textContent = `Sample: ${lastSample.time || 'Now'} (${elapsedSec}s ago)`;
      } else {
        timePill.textContent = "Waiting for stream...";
      }
    }
  },

  _gaugeState: {},

  // Semi-Circular Gauge (SVG) with In-Place Smooth Transition & Live Deltas
  renderRadialGauge(containerId, value = 0, max = 100, label = "Health", unit = "%", isHero = false) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const numVal = typeof value === "number" ? value : parseFloat(value) || 0;
    const clampedVal = Math.max(0, Math.min(max, Math.round(numVal * 10) / 10));
    const pct = clampedVal / max;

    // Dimensions based on Hero or Secondary gauge
    const radius = isHero ? 68 : 50;
    const circumference = Math.PI * radius;
    const strokeDashoffset = circumference * (1 - pct);
    const strokeW = isHero ? 11 : 8;
    const vb = isHero ? "0 0 190 105" : "0 0 140 80";
    const trackD = isHero ? "M 27 92 A 68 68 0 0 1 163 92" : "M 20 70 A 50 50 0 0 1 120 70";

    // Status Level & Color
    let color = "#10b981";
    let statusLabel = "EXCELLENT";
    if (pct >= 0.9) {
      color = "#10b981";
      statusLabel = "EXCELLENT";
    } else if (pct >= 0.7) {
      color = "#00f2fe";
      statusLabel = "HEALTHY";
    } else if (pct >= 0.5) {
      color = "#f59e0b";
      statusLabel = "DEGRADED";
    } else if (pct >= 0.3) {
      color = "#fb923c";
      statusLabel = "WARNING";
    } else {
      color = "#ef4444";
      statusLabel = "CRITICAL";
    }

    // Delta vs Previous Real Value
    const prevEntry = this._gaugeState[containerId];
    const prevVal = prevEntry !== undefined ? prevEntry.val : undefined;
    let deltaHtml = `<span class="gauge-delta stable">— Stable</span>`;

    if (prevVal !== undefined) {
      const diff = Math.round((clampedVal - prevVal) * 10) / 10;
      if (diff > 0.05) {
        deltaHtml = `<span class="gauge-delta up">↑ +${diff.toFixed(1)}%</span>`;
      } else if (diff < -0.05) {
        deltaHtml = `<span class="gauge-delta down">↓ ${Math.abs(diff).toFixed(1)}%</span>`;
      } else {
        deltaHtml = `<span class="gauge-delta stable">— Stable</span>`;
      }
    }

    // Update gauge state
    this._gaugeState[containerId] = { val: clampedVal, color, statusLabel };

    const isLight = document.documentElement.getAttribute("data-theme") === "light";
    const trackColor = isLight ? "#e2e8f0" : "#172033";

    // Check if the gauge DOM is already initialized in this container
    const existingActivePath = container.querySelector(".gauge-active-track");
    const existingBgPath = container.querySelector(".gauge-bg-track");
    const existingValEl = container.querySelector(".gauge-number");
    const existingLabelEl = container.querySelector(".gauge-sublabel");
    const existingMetaEl = container.querySelector(".gauge-meta");

    if (existingActivePath && existingValEl && existingLabelEl && existingMetaEl) {
      // In-place update: zero DOM destruction, smooth CSS stroke transition
      if (existingBgPath) {
        existingBgPath.setAttribute("stroke", trackColor);
      }
      existingActivePath.setAttribute("stroke", color);
      existingActivePath.style.strokeDashoffset = strokeDashoffset;
      existingValEl.textContent = `${clampedVal}${unit}`;
      if (existingLabelEl.textContent !== label) {
        existingLabelEl.textContent = label;
      }
      existingMetaEl.innerHTML = `
        <span class="gauge-status-badge" style="color:${color}">● ${statusLabel}</span>
        ${deltaHtml}
      `;

      // Trigger subtle visual pulse on container if real value changed
      if (prevVal !== undefined && prevVal !== clampedVal) {
        container.classList.remove("gauge-updated-pulse");
        void container.offsetWidth; // trigger reflow
        container.classList.add("gauge-updated-pulse");
      }
      return;
    }

    // Initial DOM creation
    container.innerHTML = `
      <div class="gauge-svg-wrap">
        <svg viewBox="${vb}" style="width: 100%; height: 100%;">
          <!-- Background Ambient Glow Track -->
          <path class="gauge-bg-track" d="${trackD}" fill="none" stroke="${trackColor}" stroke-width="${strokeW}" stroke-linecap="round" />
          <!-- Active Value Track -->
          <path class="gauge-active-track" d="${trackD}" fill="none" stroke="${color}" stroke-width="${strokeW}" stroke-linecap="round"
                stroke-dasharray="${circumference}" stroke-dashoffset="${strokeDashoffset}"
                style="transition: stroke-dashoffset 0.4s cubic-bezier(0.4, 0, 0.2, 1), stroke 0.4s ease;" />
        </svg>
        <div class="gauge-center-val">
          <div class="gauge-number">${clampedVal}${unit}</div>
          <div class="gauge-sublabel">${label}</div>
        </div>
      </div>
      <div class="gauge-meta">
        <span class="gauge-status-badge" style="color:${color}">● ${statusLabel}</span>
        ${deltaHtml}
      </div>
    `;
  },

  // Distribution Bars
  renderDistributionBars(containerId, items = []) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (!items || items.length === 0) {
      container.innerHTML = `<div style="color: #64748b; font-size: 12px; text-align: center; padding: 20px;">No distribution data available.</div>`;
      return;
    }

    const colorPalette = ["#00f2fe", "#38bdf8", "#6366f1", "#a855f7", "#10b981", "#f59e0b", "#94a3b8", "#ec4899"];

    let html = "";
    items.forEach((item, idx) => {
      const col = colorPalette[idx % colorPalette.length];
      const pct = parseFloat(item.percentage || 0);
      html += `
        <div class="dist-bar-row">
          <div class="dist-bar-labels">
            <span><strong style="color: ${col};">●</strong> ${item.class_name || item.label}</span>
            <span class="mono-text">${pct}% (${item.flows || 0} flows)</span>
          </div>
          <div class="dist-bar-track">
            <div class="dist-bar-fill" style="width: ${pct}%; background: ${col};"></div>
          </div>
        </div>
      `;
    });
    container.innerHTML = html;
  }
};
