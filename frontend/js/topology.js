/**
 * VORTEX-SDN Enterprise Interactive Network Topology Controller
 * Real-Time SDN Control Plane & Datapath Mesh Visualization
 * Features:
 * 1. World/Screen coordinate zoom & pan with mouse-wheel and toolbar controls.
 * 2. Data-driven directional packet flow particles scaled by live telemetry throughput.
 * 3. Distinct Controller, Switch, and Host node visualization with health halos and metrics.
 * 4. Multi-state links (Control, Access, Backbone Mesh) with live bandwidth utilization.
 * 5. Security threat radar-pulse waves and OpenFlow mitigation visualization.
 * 6. Interactive hover tooltips and rich slide-out Node & Link Inspector drawer.
 * 7. Flow path highlighting, toggleable layers, and pause/resume capabilities.
 */

const Topology = {
  canvas: null,
  ctx: null,
  nodes: [],
  links: [],
  selectedNode: null,
  selectedLink: null,
  hoveredNode: null,
  hoveredLink: null,
  draggedNode: null,
  highlightedPath: null, // Array of node IDs e.g. ['h4', 's4', 's1', 'h1']

  // Viewport Transform (Zoom & Pan)
  transform: {
    scale: 1.0,
    panX: 0,
    panY: 0,
    minScale: 0.5,
    maxScale: 2.5
  },

  // Interactive Layer Toggles
  showTraffic: true,
  showLabels: true,
  showRates: true,
  isPaused: false,

  // Pan interaction state
  isPanning: false,
  panStart: { x: 0, y: 0 },
  mousePos: { x: 0, y: 0 },
  worldMousePos: { x: 0, y: 0 },

  animFrameId: null,
  _initializedLayout: false,

  async init() {
    this.canvas = document.getElementById("topology-canvas");
    if (!this.canvas) return;

    this.ctx = this.canvas.getContext("2d");
    this.setupEventListeners();
    await this.fetchTopology();

    // Subscribe to existing global telemetry updates (Zero duplicate polling)
    State.subscribe("summary:updated", (summary) => this.syncTelemetry(summary));

    if (!this.animFrameId) {
      this.animate();
    }
  },

  async fetchTopology() {
    try {
      const data = await API.get("/api/topology");
      this.nodes = (data && data.nodes) || [];
      this.links = (data && data.links) || [];
      State.setTopology(data);

      this.initDefaultLayout();
      this.updateStatusBadge(data.summary);
      if (this.selectedNode) {
        const refreshed = this.nodes.find(n => n.id === this.selectedNode.id);
        if (refreshed) this.openDrawer(refreshed, "node");
      }
    } catch (err) {
      console.warn("[Topology] Error fetching topology:", err);
      this.updateStatusBadge({ status: "OFFLINE", label: "○ TOPOLOGY OFFLINE" });
    }
  },

  syncTelemetry(summary) {
    if (!summary) return;
    const secSummary = summary.security_summary || {};
    const activeThreats = secSummary.active_threats || [];
    const activeThreatIps = new Set(activeThreats.map(t => t.source_ip));
    const targetThreatIps = new Set(activeThreats.map(t => t.destination_ip));

    const recentFlows = summary.recent_flows || [];
    const hasAttackerFlow = recentFlows.some(f => f.source_ip === "10.0.0.4" && f.threat_label === "ATTACK");

    this.nodes.forEach(n => {
      if (n.type === "controller") {
        n.status = summary.telemetry_status === "OFFLINE" ? "OFFLINE" : "ONLINE";
        n.active_flows = summary.total_flows || 12;
      } else if (n.type === "switch") {
        n.status = (hasAttackerFlow && (n.id === "s4" || n.id === "s1")) ? "WARNING" : "ONLINE";
      } else if (n.type === "host") {
        if (n.ip === "10.0.0.4") {
          if (n.status === "MITIGATED") {
            // Keep mitigated state if already mitigated
          } else {
            n.status = (activeThreatIps.has(n.ip) || hasAttackerFlow) ? "MALICIOUS" : "HEALTHY";
          }
        } else if (targetThreatIps.has(n.ip) && hasAttackerFlow) {
          n.status = "ATTACKED";
        } else {
          n.status = "HEALTHY";
        }
      }
    });

    // Update link active traffic states based on threat status
    this.links.forEach(l => {
      if (hasAttackerFlow && (l.source === "h4" || l.target === "h4" || (l.source === "s1" && l.target === "s4"))) {
        l.status = "ATTACKED";
        l.traffic_mbps = Math.max(l.traffic_mbps || 0, summary.throughput_mbps || 88.5);
      } else if (l.status === "ATTACKED" && !hasAttackerFlow) {
        l.status = "ACTIVE";
      }
    });

    this.updateStatusBadge(summary);
  },

  updateStatusBadge(summary) {
    const badge = document.getElementById("topo-status-badge");
    if (!badge) return;
    const status = (summary && summary.telemetry_status) || (summary && summary.status) || "LIVE";
    const src = (summary && summary.source) || "DEMO";

    if (status === "LIVE") {
      badge.className = "badge badge-live";
      badge.textContent = `● LIVE TOPOLOGY (${src})`;
    } else if (status === "DEMO") {
      badge.className = "badge badge-demo";
      badge.textContent = "● DEMO TOPOLOGY (SIM)";
    } else if (status === "STALE") {
      badge.className = "badge badge-warning";
      badge.textContent = "● TOPOLOGY STALE";
    } else {
      badge.className = "badge badge-critical";
      badge.textContent = "○ BACKEND OFFLINE";
    }
  },

  initDefaultLayout() {
    if (!this.canvas || this.nodes.length === 0) return;

    // Fixed Hierarchical SDN Layout Grid (Stable World Coordinates)
    const predefinedPositions = {
      c0: { x: 400, y: 70 },
      s1: { x: 260, y: 190 },
      s2: { x: 540, y: 190 },
      s3: { x: 260, y: 330 },
      s4: { x: 540, y: 330 },
      h1: { x: 90, y: 190 },
      h2: { x: 90, y: 330 },
      h3: { x: 710, y: 190 },
      h4: { x: 710, y: 330 }
    };

    this.nodes.forEach(n => {
      const p = predefinedPositions[n.id];
      if (p) {
        n.x = p.x;
        n.y = p.y;
      }
    });

    this._initializedLayout = true;
    this.fitToScreen(false);
  },

  /* ==========================================================================
     COORDINATE CONVERSION & VIEWPORT TRANSFORM
     ========================================================================== */

  screenToWorld(sx, sy) {
    return {
      x: (sx - this.transform.panX) / this.transform.scale,
      y: (sy - this.transform.panY) / this.transform.scale
    };
  },

  worldToScreen(wx, wy) {
    return {
      x: wx * this.transform.scale + this.transform.panX,
      y: wy * this.transform.scale + this.transform.panY
    };
  },

  zoomAt(sx, sy, zoomFactor) {
    const oldScale = this.transform.scale;
    const newScale = Math.max(this.transform.minScale, Math.min(this.transform.maxScale, oldScale * zoomFactor));
    if (newScale === oldScale) return;

    // Zoom centered on cursor position
    this.transform.panX = sx - (sx - this.transform.panX) * (newScale / oldScale);
    this.transform.panY = sy - (sy - this.transform.panY) * (newScale / oldScale);
    this.transform.scale = newScale;
  },

  zoomIn() {
    if (!this.canvas) return;
    const rect = this.canvas.getBoundingClientRect();
    this.zoomAt(rect.width / 2, rect.height / 2, 1.25);
  },

  zoomOut() {
    if (!this.canvas) return;
    const rect = this.canvas.getBoundingClientRect();
    this.zoomAt(rect.width / 2, rect.height / 2, 0.8);
  },

  resetView() {
    this.transform.scale = 1.0;
    this.transform.panX = 0;
    this.transform.panY = 0;
    this.fitToScreen(false);
  },

  fitToScreen(animate = true) {
    if (!this.canvas || this.nodes.length === 0) return;
    const rect = this.canvas.getBoundingClientRect();
    const w = rect.width || 800;
    const h = rect.height || 520;

    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    this.nodes.forEach(n => {
      if (n.x < minX) minX = n.x;
      if (n.x > maxX) maxX = n.x;
      if (n.y < minY) minY = n.y;
      if (n.y > maxY) maxY = n.y;
    });

    const padding = 70;
    const bboxW = (maxX - minX) + padding * 2;
    const bboxH = (maxY - minY) + padding * 2;
    const scale = Math.min(1.4, Math.max(0.6, Math.min(w / bboxW, h / bboxH)));

    const centerX = (minX + maxX) / 2;
    const centerY = (minY + maxY) / 2;

    this.transform.scale = scale;
    this.transform.panX = w / 2 - centerX * scale;
    this.transform.panY = h / 2 - centerY * scale;
  },

  toggleAnimation() {
    this.isPaused = !this.isPaused;
    const btn = document.getElementById("topo-btn-pause");
    const icon = document.getElementById("topo-icon-playpause");
    if (btn && icon) {
      if (this.isPaused) {
        btn.classList.add("active");
        btn.title = "Resume Animation";
        icon.innerHTML = `<polygon points="5 3 19 12 5 21 5 3"/>`;
      } else {
        btn.classList.remove("active");
        btn.title = "Pause Animation";
        icon.innerHTML = `<rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>`;
      }
    }
  },

  toggleTrafficFlow() {
    this.showTraffic = !this.showTraffic;
    const pill = document.getElementById("topo-toggle-traffic");
    if (pill) pill.classList.toggle("active", this.showTraffic);
  },

  toggleLabels() {
    this.showLabels = !this.showLabels;
    const pill = document.getElementById("topo-toggle-labels");
    if (pill) pill.classList.toggle("active", this.showLabels);
  },

  toggleRates() {
    this.showRates = !this.showRates;
    const pill = document.getElementById("topo-toggle-rates");
    if (pill) pill.classList.toggle("active", this.showRates);
  },

  highlightPath(nodeIds) {
    this.highlightedPath = nodeIds && nodeIds.length > 1 ? nodeIds : null;
  },

  clearHighlight() {
    this.highlightedPath = null;
  },

  /* ==========================================================================
     EVENT LISTENERS & USER INTERACTIONS
     ========================================================================== */

  setupEventListeners() {
    // Wheel Zooming
    this.canvas.addEventListener("wheel", (e) => {
      e.preventDefault();
      const rect = this.canvas.getBoundingClientRect();
      const sx = e.clientX - rect.left;
      const sy = e.clientY - rect.top;
      const zoomFactor = e.deltaY < 0 ? 1.12 : 0.89;
      this.zoomAt(sx, sy, zoomFactor);
    }, { passive: false });

    // Mouse Down
    this.canvas.addEventListener("mousedown", (e) => {
      const rect = this.canvas.getBoundingClientRect();
      const sx = e.clientX - rect.left;
      const sy = e.clientY - rect.top;
      const worldPos = this.screenToWorld(sx, sy);

      // 1. Check Node Click
      const clickedNode = this.nodes.find(n => {
        const dx = n.x - worldPos.x;
        const dy = n.y - worldPos.y;
        const radius = n.type === "controller" ? 28 : (n.type === "switch" ? 24 : 20);
        return Math.sqrt(dx * dx + dy * dy) <= radius;
      });

      if (clickedNode) {
        this.selectedNode = clickedNode;
        this.selectedLink = null;
        this.draggedNode = clickedNode;
        this.openDrawer(clickedNode, "node");
        return;
      }

      // 2. Check Link Click
      const clickedLink = this.findLinkNear(worldPos.x, worldPos.y);
      if (clickedLink) {
        this.selectedLink = clickedLink;
        this.selectedNode = null;
        this.openDrawer(clickedLink, "link");
        return;
      }

      // 3. Pan Background
      this.isPanning = true;
      this.panStart = { x: sx - this.transform.panX, y: sy - this.transform.panY };
      this.canvas.style.cursor = "grabbing";
    });

    // Mouse Move
    this.canvas.addEventListener("mousemove", (e) => {
      const rect = this.canvas.getBoundingClientRect();
      const sx = e.clientX - rect.left;
      const sy = e.clientY - rect.top;
      this.mousePos = { x: sx, y: sy };
      this.worldMousePos = this.screenToWorld(sx, sy);

      if (this.draggedNode) {
        this.draggedNode.x = this.worldMousePos.x;
        this.draggedNode.y = this.worldMousePos.y;
      } else if (this.isPanning) {
        this.transform.panX = sx - this.panStart.x;
        this.transform.panY = sy - this.panStart.y;
      } else {
        // Hover detection
        this.hoveredNode = this.nodes.find(n => {
          const dx = n.x - this.worldMousePos.x;
          const dy = n.y - this.worldMousePos.y;
          const radius = n.type === "controller" ? 28 : (n.type === "switch" ? 24 : 20);
          return Math.sqrt(dx * dx + dy * dy) <= radius;
        }) || null;

        if (!this.hoveredNode) {
          this.hoveredLink = this.findLinkNear(this.worldMousePos.x, this.worldMousePos.y);
        } else {
          this.hoveredLink = null;
        }

        this.canvas.style.cursor = this.hoveredNode ? "pointer" : (this.hoveredLink ? "crosshair" : "grab");
      }
    });

    // Mouse Up & Leave
    const endInteraction = () => {
      this.draggedNode = null;
      this.isPanning = false;
      if (this.canvas) {
        this.canvas.style.cursor = this.hoveredNode ? "pointer" : (this.hoveredLink ? "crosshair" : "grab");
      }
    };

    window.addEventListener("mouseup", endInteraction);
    this.canvas.addEventListener("mouseleave", () => {
      this.hoveredNode = null;
      this.hoveredLink = null;
      endInteraction();
    });

    // Mobile & Tablet Touchscreen Interaction Support
    let touchStartDist = 0;
    this.canvas.addEventListener("touchstart", (e) => {
      if (e.touches.length === 1) {
        const touch = e.touches[0];
        const rect = this.canvas.getBoundingClientRect();
        const sx = touch.clientX - rect.left;
        const sy = touch.clientY - rect.top;
        const worldPos = this.screenToWorld(sx, sy);

        // 1. Check Node Tap
        const clickedNode = this.nodes.find(n => {
          const dx = n.x - worldPos.x;
          const dy = n.y - worldPos.y;
          const radius = n.type === "controller" ? 30 : (n.type === "switch" ? 26 : 22);
          return Math.sqrt(dx * dx + dy * dy) <= radius;
        });

        if (clickedNode) {
          this.selectedNode = clickedNode;
          this.selectedLink = null;
          this.openDrawer(clickedNode, "node");
          return;
        }

        // 2. Check Link Tap
        const clickedLink = this.findLinkNear(worldPos.x, worldPos.y);
        if (clickedLink) {
          this.selectedLink = clickedLink;
          this.selectedNode = null;
          this.openDrawer(clickedLink, "link");
          return;
        }

        // 3. Pan Background
        this.isPanning = true;
        this.panStart = { x: sx - this.transform.panX, y: sy - this.transform.panY };
      } else if (e.touches.length === 2) {
        this.isPanning = false;
        const dx = e.touches[0].clientX - e.touches[1].clientX;
        const dy = e.touches[0].clientY - e.touches[1].clientY;
        touchStartDist = Math.sqrt(dx * dx + dy * dy);
      }
    }, { passive: true });

    this.canvas.addEventListener("touchmove", (e) => {
      if (e.touches.length === 1 && this.isPanning) {
        const touch = e.touches[0];
        const rect = this.canvas.getBoundingClientRect();
        const sx = touch.clientX - rect.left;
        const sy = touch.clientY - rect.top;
        this.transform.panX = sx - this.panStart.x;
        this.transform.panY = sy - this.panStart.y;
        this.draw();
      } else if (e.touches.length === 2 && touchStartDist > 0) {
        const dx = e.touches[0].clientX - e.touches[1].clientX;
        const dy = e.touches[0].clientY - e.touches[1].clientY;
        const newDist = Math.sqrt(dx * dx + dy * dy);
        const factor = newDist / touchStartDist;
        if (factor > 0.5 && factor < 2.0) {
          const rect = this.canvas.getBoundingClientRect();
          const midX = (e.touches[0].clientX + e.touches[1].clientX) / 2 - rect.left;
          const midY = (e.touches[0].clientY + e.touches[1].clientY) / 2 - rect.top;
          this.zoomAt(midX, midY, factor > 1 ? 1.03 : 0.97);
          touchStartDist = newDist;
        }
      }
    }, { passive: true });

    this.canvas.addEventListener("touchend", () => {
      this.isPanning = false;
      touchStartDist = 0;
    });
  },

  findLinkNear(wx, wy) {
    const threshold = 8 / this.transform.scale;
    for (const l of this.links) {
      const src = this.nodes.find(n => n.id === l.source);
      const dst = this.nodes.find(n => n.id === l.target);
      if (!src || !dst) continue;

      const dist = this.pointToSegmentDist(wx, wy, src.x, src.y, dst.x, dst.y);
      if (dist <= threshold) {
        return l;
      }
    }
    return null;
  },

  pointToSegmentDist(px, py, x1, y1, x2, y2) {
    const l2 = (x2 - x1) * (x2 - x1) + (y2 - y1) * (y2 - y1);
    if (l2 === 0) return Math.sqrt((px - x1) * (px - x1) + (py - y1) * (py - y1));
    let t = ((px - x1) * (x2 - x1) + (py - y1) * (y2 - y1)) / l2;
    t = Math.max(0, Math.min(1, t));
    const projX = x1 + t * (x2 - x1);
    const projY = y1 + t * (y2 - y1);
    return Math.sqrt((px - projX) * (px - projX) + (py - projY) * (py - projY));
  },

  /* ==========================================================================
     MAIN RENDERING LOOP
     ========================================================================== */

  animate() {
    this.draw();
    this.animFrameId = requestAnimationFrame(() => this.animate());
  },

  draw() {
    if (!this.ctx || !this.canvas) return;

    const dpr = window.devicePixelRatio || 1;
    const rect = this.canvas.getBoundingClientRect();
    if (this.canvas.width !== rect.width * dpr || this.canvas.height !== rect.height * dpr) {
      this.canvas.width = rect.width * dpr;
      this.canvas.height = rect.height * dpr;
      this.ctx.scale(dpr, dpr);
    }

    const width = rect.width;
    const height = rect.height;
    const time = performance.now() / 1000;

    this.ctx.clearRect(0, 0, width, height);

    // 1. Draw Static Screen Grid
    this.drawBackgroundGrid(width, height);

    // Apply Viewport Transform
    this.ctx.save();
    this.ctx.translate(this.transform.panX, this.transform.panY);
    this.ctx.scale(this.transform.scale, this.transform.scale);

    // 2. Draw Links & Animated Flow Particles
    this.drawLinks(time);

    // 3. Draw Nodes with Status Halos & Badges
    this.drawNodes(time);

    this.ctx.restore();

    // 4. Draw Floating Tooltip on Hover (in Screen Coordinates)
    if (this.hoveredNode && !this.draggedNode && !this.isPanning) {
      this.drawNodeTooltip(this.hoveredNode);
    } else if (this.hoveredLink && !this.isPanning) {
      this.drawLinkTooltip(this.hoveredLink);
    }
  },

  drawBackgroundGrid(width, height) {
    const gridSize = 36;
    this.ctx.save();
    this.ctx.strokeStyle = "rgba(255, 255, 255, 0.025)";
    this.ctx.lineWidth = 1;

    for (let x = (this.transform.panX % (gridSize * this.transform.scale)); x < width; x += gridSize * this.transform.scale) {
      this.ctx.beginPath();
      this.ctx.moveTo(x, 0);
      this.ctx.lineTo(x, height);
      this.ctx.stroke();
    }

    for (let y = (this.transform.panY % (gridSize * this.transform.scale)); y < height; y += gridSize * this.transform.scale) {
      this.ctx.beginPath();
      this.ctx.moveTo(0, y);
      this.ctx.lineTo(width, y);
      this.ctx.stroke();
    }
    this.ctx.restore();
  },

  /* ==========================================================================
     LINK & TRAFFIC PACKET RENDERING
     ========================================================================== */

  drawLinks(time) {
    this.links.forEach((l, idx) => {
      const srcNode = this.nodes.find(n => n.id === l.source);
      const dstNode = this.nodes.find(n => n.id === l.target);
      if (!srcNode || !dstNode) return;

      const isControl = l.type === "control";
      const isBackbone = l.type === "backbone";
      const isSelected = this.selectedLink === l;
      const isHovered = this.hoveredLink === l;
      const isThreat = l.status === "ATTACKED" || l.status === "MALICIOUS" || srcNode.status === "ATTACKED" || dstNode.status === "ATTACKED" || srcNode.status === "MALICIOUS";
      const isCongested = l.status === "CONGESTED" || l.status === "HIGH_TRAFFIC";
      const isPathHighlighted = this.isLinkOnHighlightedPath(l.source, l.target);

      this.ctx.save();

      // 1. Link Glow & Trail
      if (isSelected || isHovered || isPathHighlighted) {
        this.ctx.beginPath();
        this.ctx.moveTo(srcNode.x, srcNode.y);
        this.ctx.lineTo(dstNode.x, dstNode.y);
        this.ctx.strokeStyle = isPathHighlighted ? "#00f2fe" : "rgba(0, 242, 254, 0.45)";
        this.ctx.lineWidth = isBackbone ? 8 : 6;
        this.ctx.stroke();
      }

      // 2. Base Link Line
      this.ctx.beginPath();
      this.ctx.moveTo(srcNode.x, srcNode.y);
      this.ctx.lineTo(dstNode.x, dstNode.y);

      if (isControl) {
        this.ctx.strokeStyle = "rgba(0, 242, 254, 0.28)";
        this.ctx.lineWidth = 1.6;
        this.ctx.setLineDash([4, 4]);
        this.ctx.lineDashOffset = this.isPaused ? 0 : -time * 14;
        this.ctx.stroke();
      } else if (isBackbone) {
        this.ctx.strokeStyle = isThreat ? "#ef4444" : (isCongested ? "#f59e0b" : "rgba(56, 189, 248, 0.55)");
        this.ctx.lineWidth = 3.2;
        this.ctx.setLineDash([]);
        this.ctx.stroke();

        // Underglow line
        this.ctx.strokeStyle = isThreat ? "rgba(239, 68, 68, 0.2)" : (isCongested ? "rgba(245, 158, 11, 0.2)" : "rgba(0, 242, 254, 0.12)");
        this.ctx.lineWidth = 7;
        this.ctx.stroke();
      } else {
        // Access Links
        this.ctx.strokeStyle = isThreat ? "#ef4444" : (isCongested ? "#f59e0b" : "rgba(0, 242, 254, 0.4)");
        this.ctx.lineWidth = 2.2;
        this.ctx.setLineDash([]);
        this.ctx.stroke();
      }

      // 3. Link Midpoint Throughput Pill
      if (this.showRates && !isControl && l.traffic_mbps !== undefined) {
        const midX = (srcNode.x + dstNode.x) / 2;
        const midY = (srcNode.y + dstNode.y) / 2;
        this.drawLinkRatePill(midX, midY, l.traffic_mbps, isThreat, isCongested);
      }

      this.ctx.restore();

      // 4. Directional Animated Traffic Particles
      if (this.showTraffic && !this.isPaused) {
        const tp = parseFloat(l.traffic_mbps || 5);
        let speed = isControl ? 0.25 : (isThreat ? 0.85 : (isCongested ? 0.7 : Math.max(0.3, Math.min(0.65, tp / 60))));
        let particleColor = isThreat ? "#ef4444" : (isCongested ? "#f59e0b" : (isControl ? "#00f2fe" : (l.qos_class === "EF" ? "#00f5a0" : "#38bdf8")));
        let particleCount = isControl ? 1 : (isThreat ? 4 : (tp > 50 ? 3 : 2));

        for (let p = 0; p < particleCount; p++) {
          const offset = (time * speed + (p / particleCount) + (idx * 0.18)) % 1.0;
          const px = srcNode.x + (dstNode.x - srcNode.x) * offset;
          const py = srcNode.y + (dstNode.y - srcNode.y) * offset;

          this.ctx.save();
          this.ctx.beginPath();
          this.ctx.arc(px, py, isControl ? 2.5 : (isThreat ? 3.5 : 3), 0, Math.PI * 2);
          this.ctx.fillStyle = particleColor;
          this.ctx.shadowColor = particleColor;
          this.ctx.shadowBlur = isThreat ? 10 : 6;
          this.ctx.fill();
          this.ctx.restore();
        }
      }
    });
  },

  drawLinkRatePill(x, y, rateMbps, isThreat, isCongested) {
    const text = `${parseFloat(rateMbps).toFixed(1)}M`;
    this.ctx.save();
    this.ctx.font = "bold 9px JetBrains Mono";
    const textWidth = this.ctx.measureText(text).width;
    const padW = 4;
    const padH = 2;

    this.ctx.fillStyle = "rgba(7, 11, 22, 0.88)";
    this.ctx.strokeStyle = isThreat ? "#ef4444" : (isCongested ? "#f59e0b" : "rgba(255, 255, 255, 0.15)");
    this.ctx.lineWidth = 1;

    this.ctx.beginPath();
    this.ctx.roundRect(x - textWidth / 2 - padW, y - 7 - padH, textWidth + padW * 2, 14 + padH * 2, 3);
    this.ctx.fill();
    this.ctx.stroke();

    this.ctx.fillStyle = isThreat ? "#ef4444" : (isCongested ? "#f59e0b" : "rgba(0, 242, 254, 0.9)");
    this.ctx.textAlign = "center";
    this.ctx.textBaseline = "middle";
    this.ctx.fillText(text, x, y);
    this.ctx.restore();
  },

  isLinkOnHighlightedPath(s, t) {
    if (!this.highlightedPath) return false;
    for (let i = 0; i < this.highlightedPath.length - 1; i++) {
      const a = this.highlightedPath[i];
      const b = this.highlightedPath[i + 1];
      if ((s === a && t === b) || (s === b && t === a)) return true;
    }
    return false;
  },

  /* ==========================================================================
     NODE RENDERING & STATUS HALOS
     ========================================================================== */

  drawNodes(time) {
    this.nodes.forEach(n => {
      const isSelected = this.selectedNode && this.selectedNode.id === n.id;
      const isHovered = this.hoveredNode && this.hoveredNode.id === n.id;
      const isAttacked = n.status === "ATTACKED" || n.status === "MALICIOUS";
      const isMitigated = n.status === "MITIGATED";
      const isController = n.type === "controller";
      const isSwitch = n.type === "switch";
      const radius = isController ? 26 : (isSwitch ? 23 : 19);

      this.ctx.save();

      // 1. Radar-Pulse Warning Wave Ripple for Threats
      if (isAttacked && !this.isPaused) {
        const ripplePhase = (time * 2.2) % 1.0;
        this.ctx.beginPath();
        this.ctx.arc(n.x, n.y, radius + ripplePhase * 20, 0, Math.PI * 2);
        this.ctx.strokeStyle = `rgba(239, 68, 68, ${0.7 * (1 - ripplePhase)})`;
        this.ctx.lineWidth = 2.2;
        this.ctx.stroke();
      }

      // 2. Controller Ambient Communication Halo
      if (isController) {
        const pulse = Math.sin(time * 3) * 3;
        this.ctx.beginPath();
        this.ctx.arc(n.x, n.y, radius + 5 + (this.isPaused ? 0 : pulse), 0, Math.PI * 2);
        this.ctx.strokeStyle = "rgba(0, 242, 254, 0.35)";
        this.ctx.lineWidth = 1.6;
        this.ctx.setLineDash([3, 3]);
        this.ctx.lineDashOffset = this.isPaused ? 0 : -time * 10;
        this.ctx.stroke();
        this.ctx.setLineDash([]);
      }

      // 3. Selection & Hover Halo
      if (isSelected || isHovered) {
        this.ctx.beginPath();
        this.ctx.arc(n.x, n.y, radius + 6, 0, Math.PI * 2);
        this.ctx.strokeStyle = "#00f2fe";
        this.ctx.lineWidth = 2.5;
        this.ctx.shadowColor = "#00f2fe";
        this.ctx.shadowBlur = 12;
        this.ctx.stroke();
      }

      // 4. Node Background Fill
      this.ctx.beginPath();
      this.ctx.arc(n.x, n.y, radius, 0, Math.PI * 2);

      if (isController) {
        const grad = this.ctx.createRadialGradient(n.x - 5, n.y - 5, 2, n.x, n.y, radius);
        grad.addColorStop(0, "#00f2fe");
        grad.addColorStop(1, "#0284c7");
        this.ctx.fillStyle = grad;
      } else if (isSwitch) {
        this.ctx.fillStyle = "#0c1322";
      } else {
        this.ctx.fillStyle = "#090d16";
      }
      this.ctx.fill();

      // 5. Node Border Ring
      this.ctx.lineWidth = isSelected ? 2.8 : 2;
      if (isAttacked) {
        this.ctx.strokeStyle = "#ef4444";
      } else if (isMitigated) {
        this.ctx.strokeStyle = "#10b981";
      } else if (isController) {
        this.ctx.strokeStyle = "#00f2fe";
      } else if (isSwitch) {
        this.ctx.strokeStyle = n.status === "WARNING" ? "#f59e0b" : "#00f5a0";
      } else {
        this.ctx.strokeStyle = "#38bdf8";
      }
      this.ctx.stroke();

      // 6. Node Main Text Label
      this.ctx.fillStyle = isController ? "#050811" : "#ffffff";
      this.ctx.font = isController ? "bold 10.5px JetBrains Mono" : "bold 11px JetBrains Mono";
      this.ctx.textAlign = "center";
      this.ctx.textBaseline = "middle";
      const shortId = isController ? "RYU" : n.id.toUpperCase();
      this.ctx.fillText(shortId, n.x, n.y);

      // 7. Sub-labels (Labels, DPID, IP, QoS Tag)
      if (this.showLabels) {
        this.ctx.fillStyle = isSelected ? "#00f2fe" : "#cbd5e1";
        this.ctx.font = "600 11px Inter";
        const displayName = n.name || n.id;
        this.ctx.fillText(displayName, n.x, n.y + radius + 13);

        // Micro-meta label below
        let metaText = "";
        if (isController) metaText = "OpenFlow 1.3";
        else if (isSwitch) metaText = n.dpid ? `DPID: ${n.dpid.slice(-4)}` : `${n.ports_count || 4} Ports`;
        else metaText = `${n.ip || ''} ${n.qos_class ? `• ${n.qos_class}` : ''}`;

        this.ctx.fillStyle = isAttacked ? "#fca5a5" : (isMitigated ? "#86efac" : "#64748b");
        this.ctx.font = "9.5px JetBrains Mono";
        this.ctx.fillText(metaText, n.x, n.y + radius + 26);
      }

      this.ctx.restore();
    });
  },

  /* ==========================================================================
     HOVER TOOLTIPS
     ========================================================================== */

  drawNodeTooltip(node) {
    const screenPos = this.worldToScreen(node.x, node.y);
    const padding = 10;
    const title = node.name || node.id;
    const typeStr = `Type: ${node.type.toUpperCase()}`;
    const statusStr = `Status: ${node.status}`;
    const dpidOrIp = node.type === "switch" ? `DPID: ${node.dpid || node.id}` : (node.ip ? `IP: ${node.ip} (MAC: ${node.mac || '00:..'})` : "");
    const qosStr = node.qos_class ? `QoS Class: ${node.qos_class}` : "";
    const trafficStr = node.traffic_mbps !== undefined ? `Traffic: ${node.traffic_mbps} Mbps` : "";

    this.ctx.save();
    this.ctx.font = "bold 12px Inter";
    const w1 = this.ctx.measureText(title).width;
    this.ctx.font = "10px JetBrains Mono";
    const w2 = this.ctx.measureText(dpidOrIp).width;
    const boxWidth = Math.max(w1, w2, 170) + padding * 2;
    const boxHeight = qosStr ? 78 : 64;

    let tipX = screenPos.x + 30;
    let tipY = screenPos.y - 34;

    const rect = this.canvas.getBoundingClientRect();
    if (tipX + boxWidth > rect.width) tipX = screenPos.x - boxWidth - 16;
    if (tipY + boxHeight > rect.height) tipY = rect.height - boxHeight - 12;
    if (tipY < 12) tipY = 12;

    this.ctx.fillStyle = "rgba(7, 10, 19, 0.94)";
    this.ctx.strokeStyle = node.status === "MALICIOUS" || node.status === "ATTACKED" ? "#ef4444" : "rgba(0, 242, 254, 0.4)";
    this.ctx.lineWidth = 1;
    this.ctx.shadowColor = "rgba(0, 0, 0, 0.75)";
    this.ctx.shadowBlur = 10;

    this.ctx.beginPath();
    this.ctx.roundRect(tipX, tipY, boxWidth, boxHeight, 6);
    this.ctx.fill();
    this.ctx.stroke();

    this.ctx.shadowBlur = 0;
    this.ctx.textAlign = "left";
    this.ctx.textBaseline = "top";

    // Title
    this.ctx.fillStyle = "#ffffff";
    this.ctx.font = "bold 12px Inter";
    this.ctx.fillText(title, tipX + padding, tipY + padding);

    // Status
    const statusCol = node.status === "MALICIOUS" || node.status === "ATTACKED" ? "#ef4444" : (node.status === "MITIGATED" ? "#10b981" : "#00f5a0");
    this.ctx.fillStyle = statusCol;
    this.ctx.font = "10px Inter";
    this.ctx.fillText(`● ${statusStr} • ${typeStr}`, tipX + padding, tipY + padding + 17);

    // Meta
    this.ctx.fillStyle = "#94a3b8";
    this.ctx.font = "9.5px JetBrains Mono";
    this.ctx.fillText(dpidOrIp, tipX + padding, tipY + padding + 33);

    if (qosStr || trafficStr) {
      this.ctx.fillStyle = "#38bdf8";
      this.ctx.fillText(`${qosStr} ${trafficStr ? `• ${trafficStr}` : ''}`, tipX + padding, tipY + padding + 47);
    }

    this.ctx.restore();
  },

  drawLinkTooltip(link) {
    const srcNode = this.nodes.find(n => n.id === link.source);
    const dstNode = this.nodes.find(n => n.id === link.target);
    if (!srcNode || !dstNode) return;

    const midWorld = { x: (srcNode.x + dstNode.x) / 2, y: (srcNode.y + dstNode.y) / 2 };
    const screenPos = this.worldToScreen(midWorld.x, midWorld.y);

    const padding = 10;
    const title = `Link: ${srcNode.name || srcNode.id} ↔ ${dstNode.name || dstNode.id}`;
    const capStr = `Capacity: ${link.bandwidth_mbps || 1000} Mbps (${link.type.toUpperCase()})`;
    const rateStr = `Traffic: ${link.traffic_mbps || 0} Mbps • Rate: ${link.packet_rate || 0} pps`;
    const latStr = link.latency_ms ? `Latency: ${link.latency_ms} ms • Status: ${link.status}` : `Status: ${link.status}`;

    this.ctx.save();
    this.ctx.font = "bold 11.5px Inter";
    const w1 = this.ctx.measureText(title).width;
    this.ctx.font = "9.5px JetBrains Mono";
    const w2 = this.ctx.measureText(capStr).width;
    const boxWidth = Math.max(w1, w2, 190) + padding * 2;
    const boxHeight = 74;

    let tipX = screenPos.x + 20;
    let tipY = screenPos.y - 30;

    const rect = this.canvas.getBoundingClientRect();
    if (tipX + boxWidth > rect.width) tipX = screenPos.x - boxWidth - 14;
    if (tipY + boxHeight > rect.height) tipY = rect.height - boxHeight - 12;
    if (tipY < 12) tipY = 12;

    this.ctx.fillStyle = "rgba(7, 10, 19, 0.94)";
    this.ctx.strokeStyle = link.status === "ATTACKED" ? "#ef4444" : "rgba(0, 242, 254, 0.4)";
    this.ctx.lineWidth = 1;
    this.ctx.shadowColor = "rgba(0, 0, 0, 0.75)";
    this.ctx.shadowBlur = 10;

    this.ctx.beginPath();
    this.ctx.roundRect(tipX, tipY, boxWidth, boxHeight, 6);
    this.ctx.fill();
    this.ctx.stroke();

    this.ctx.shadowBlur = 0;
    this.ctx.textAlign = "left";
    this.ctx.textBaseline = "top";

    this.ctx.fillStyle = "#ffffff";
    this.ctx.font = "bold 11.5px Inter";
    this.ctx.fillText(title, tipX + padding, tipY + padding);

    this.ctx.fillStyle = "#38bdf8";
    this.ctx.font = "9.5px JetBrains Mono";
    this.ctx.fillText(capStr, tipX + padding, tipY + padding + 17);

    this.ctx.fillStyle = "#00f5a0";
    this.ctx.fillText(rateStr, tipX + padding, tipY + padding + 32);

    this.ctx.fillStyle = link.status === "ATTACKED" ? "#ef4444" : "#94a3b8";
    this.ctx.fillText(latStr, tipX + padding, tipY + padding + 47);

    this.ctx.restore();
  },

  /* ==========================================================================
     SLIDE-OUT INSPECTOR DRAWER
     ========================================================================== */

  openDrawer(item, type) {
    const drawer = document.getElementById("topology-drawer");
    const content = document.getElementById("topology-drawer-content");
    if (!drawer || !content) return;

    drawer.classList.add("open");

    if (type === "node") {
      const isThreat = item.status === "ATTACKED" || item.status === "MALICIOUS";
      const isMitigated = item.status === "MITIGATED";
      const statusColor = isThreat ? "var(--status-danger)" : (isMitigated ? "var(--status-success)" : "var(--accent-cyan)");

      let threatActionHtml = "";
      if (isThreat) {
        threatActionHtml = `
          <div style="background: rgba(239, 68, 68, 0.12); border: 1px solid var(--status-danger); border-radius: var(--radius-md); padding: 12px; margin-top: 14px;">
            <div style="font-size: 11.5px; color: var(--status-danger); font-weight: 700; margin-bottom: 6px;">SECURITY THREAT ACTIVE</div>
            <div style="font-size: 11px; color: var(--text-secondary); margin-bottom: 8px;">Automated OpenFlow mitigation policy is recommended.</div>
            <button class="btn btn-danger btn-sm" style="width: 100%;" onclick="App.navigate('security')">Inspect in Security Center</button>
          </div>
        `;
      } else if (isMitigated) {
        threatActionHtml = `
          <div style="background: rgba(16, 185, 129, 0.12); border: 1px solid var(--status-success); border-radius: var(--radius-md); padding: 12px; margin-top: 14px;">
            <div style="font-size: 11.5px; color: var(--status-success); font-weight: 700;">MITIGATION ENFORCED</div>
            <div style="font-size: 11px; color: var(--text-secondary);">OpenFlow drop rule installed. Host isolated from fabric.</div>
          </div>
        `;
      }

      content.innerHTML = `
        <div style="text-align: center; margin-bottom: 16px;">
          <div style="font-size: 15px; font-weight: 700; color: #ffffff;">${Utils.escapeHtml(item.name || item.id)}</div>
          <div style="font-size: 11px; color: ${statusColor}; font-weight: 600; margin-top: 2px;">● ${Utils.escapeHtml(item.status || 'ONLINE')}</div>
        </div>
        <div class="topo-prop-row"><span class="topo-prop-label">Node Type:</span><span class="topo-prop-value">${Utils.escapeHtml(item.type.toUpperCase())}</span></div>
        <div class="topo-prop-row"><span class="topo-prop-label">DPID / ID:</span><span class="topo-prop-value">${Utils.escapeHtml(item.dpid || item.id)}</span></div>
        <div class="topo-prop-row"><span class="topo-prop-label">IP Address:</span><span class="topo-prop-value">${Utils.escapeHtml(item.ip || '127.0.0.1')}</span></div>
        <div class="topo-prop-row"><span class="topo-prop-label">MAC Address:</span><span class="topo-prop-value">${Utils.escapeHtml(item.mac || '00:00:00:00:00:01')}</span></div>
        <div class="topo-prop-row"><span class="topo-prop-label">OpenFlow Ports:</span><span class="topo-prop-value">${item.ports_count || 4} Ports</span></div>
        <div class="topo-prop-row"><span class="topo-prop-label">Live Traffic Rate:</span><span class="topo-prop-value" style="color:var(--accent-cyan);">${item.traffic_mbps || 12.5} Mbps</span></div>
        <div class="topo-prop-row"><span class="topo-prop-label">Active Flow Rules:</span><span class="topo-prop-value">${item.active_flows || 8} Flows</span></div>
        ${item.qos_class ? `<div class="topo-prop-row"><span class="topo-prop-label">QoS Category:</span><span class="topo-prop-value" style="color:var(--accent-cyan);">${item.qos_class}</span></div>` : ''}
        ${threatActionHtml}
        <div style="margin-top: 18px; display: flex; gap: 8px;">
          <button class="btn btn-secondary btn-sm" style="flex:1;" onclick="App.navigate('flows')">View Flows</button>
          <button class="btn btn-secondary btn-sm" style="flex:1;" onclick="Topology.fitToScreen()">Focus Node</button>
        </div>
      `;
    } else if (type === "link") {
      const srcNode = this.nodes.find(n => n.id === item.source);
      const dstNode = this.nodes.find(n => n.id === item.target);
      const cap = item.bandwidth_mbps || 1000;
      const tp = item.traffic_mbps || 24.5;
      const utilPct = Math.min(100, ((tp / cap) * 100).toFixed(1));

      content.innerHTML = `
        <div style="text-align: center; margin-bottom: 16px;">
          <div style="font-size: 15px; font-weight: 700; color: #ffffff;">Link Details</div>
          <div style="font-size: 11px; color: var(--accent-cyan); font-weight: 600; margin-top: 2px;">${item.source.toUpperCase()} ↔ ${item.target.toUpperCase()}</div>
        </div>
        <div class="topo-prop-row"><span class="topo-prop-label">Link Type:</span><span class="topo-prop-value">${item.type.toUpperCase()}</span></div>
        <div class="topo-prop-row"><span class="topo-prop-label">Source Node:</span><span class="topo-prop-value">${srcNode ? srcNode.name : item.source}</span></div>
        <div class="topo-prop-row"><span class="topo-prop-label">Target Node:</span><span class="topo-prop-value">${dstNode ? dstNode.name : item.target}</span></div>
        <div class="topo-prop-row"><span class="topo-prop-label">Link Capacity:</span><span class="topo-prop-value">${cap} Mbps</span></div>
        <div class="topo-prop-row"><span class="topo-prop-label">Current Throughput:</span><span class="topo-prop-value" style="color:var(--accent-cyan);">${tp} Mbps</span></div>
        <div class="topo-prop-row"><span class="topo-prop-label">Bandwidth Load:</span><span class="topo-prop-value">${utilPct}%</span></div>
        <div class="topo-prop-row"><span class="topo-prop-label">Latency:</span><span class="topo-prop-value">${item.latency_ms || 2.1} ms</span></div>
        <div class="topo-prop-row"><span class="topo-prop-label">Status:</span><span class="topo-prop-value" style="color:${item.status === 'ATTACKED' ? 'var(--status-danger)' : 'var(--status-success)'};">${item.status}</span></div>
        <div style="margin-top: 18px;">
          <button class="btn btn-secondary btn-sm" style="width:100%;" onclick="Topology.highlightPath(['${item.source}', '${item.target}'])">Highlight Link Path</button>
        </div>
      `;
    }
  },

  closeDrawer() {
    const drawer = document.getElementById("topology-drawer");
    if (drawer) drawer.classList.remove("open");
    this.selectedNode = null;
    this.selectedLink = null;
    this.clearHighlight();
  }
};

