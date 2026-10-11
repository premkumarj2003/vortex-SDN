/**
 * VORTEX-SDN Main Application Bootstrap
 * Orchestrates navigation, two-state sidebar collapse with localStorage persistence,
 * real-time clocks, user profile menus, and modal dialogs.
 */

const App = {
  currentView: "dashboard",

  async init() {
    console.log("VORTEX-SDN Enterprise Control Center Initializing...");

    // 1. Restore Sidebar Collapsed Preference from localStorage
    this.initSidebarState();

    // 2. Initialize Auth Profile
    await Auth.init();

    // 3. Initialize Topbar Live Clock
    this.startLiveClock();

    // 4. Initialize Subsystem Controllers
    Search.init();
    Notifications.init();
    Chatbot.init();
    Settings.init();
    Topology.init();
    Dashboard.init();
    RootCause.init();

    // 5. Start Telemetry Poller
    Telemetry.init();

    // 6. Setup Navigation & Layout Listeners
    this.setupNavigation();
    this.setupDropdowns();

    // 7. Handle URL Hash Routing
    const initialView = window.location.hash.replace("#", "") || "dashboard";
    this.navigate(initialView);

    // 8. Initialize Subtle Panel Cursor Interactions
    this.initCardInteractions();
  },

  initSidebarState() {
    const sidebar = document.getElementById("sidebar");
    const collapseBtn = document.getElementById("sidebar-collapse-btn");
    const isCollapsed = localStorage.getItem("vortex_sidebar_collapsed") === "true";

    if (sidebar) {
      if (isCollapsed) {
        sidebar.classList.add("collapsed");
      } else {
        sidebar.classList.remove("collapsed");
      }
    }

    this.updateCollapseBtnIcon(isCollapsed);
  },

  toggleSidebar() {
    const sidebar = document.getElementById("sidebar");
    if (!sidebar) return;

    sidebar.classList.toggle("collapsed");
    const isCollapsed = sidebar.classList.contains("collapsed");
    localStorage.setItem("vortex_sidebar_collapsed", isCollapsed ? "true" : "false");
    this.updateCollapseBtnIcon(isCollapsed);
  },

  updateCollapseBtnIcon(isCollapsed) {
    const collapseBtn = document.getElementById("sidebar-collapse-btn");
    if (collapseBtn) {
      collapseBtn.innerHTML = isCollapsed ? Utils.icons.chevronRight : Utils.icons.chevronLeft;
      collapseBtn.title = isCollapsed ? "Expand Sidebar (260px)" : "Collapse Sidebar (72px)";
    }
  },

  navigate(viewName) {
    const validViews = [
      "dashboard", "topology", "security", "qos", "ai", "digital-twin",
      "flows", "incidents", "policies", "reports", "audit", "health", "settings", "scenarios",
      "predictive", "root-cause", "admin-users"
    ];

    if (!validViews.includes(viewName)) {
      viewName = "dashboard";
    }

    // Role boundary guard: only ADMIN can access admin-users or audit views
    if ((viewName === "admin-users" || viewName === "audit") && Auth.currentUser && Auth.currentUser.role !== "ADMIN") {
      viewName = "dashboard";
    }

    this.currentView = viewName;
    window.location.hash = viewName;

    // Toggle active view container
    const viewEls = document.querySelectorAll(".view-section");
    viewEls.forEach(el => {
      if (el.id === `view-${viewName}`) {
        el.classList.add("active");
      } else {
        el.classList.remove("active");
      }
    });

    // Toggle active sidebar nav item
    const navItems = document.querySelectorAll(".nav-item");
    navItems.forEach(item => {
      if (item.getAttribute("data-view") === viewName) {
        item.classList.add("active");
      } else {
        item.classList.remove("active");
      }
    });

    // Update Topbar Breadcrumb
    const bcEl = document.getElementById("topbar-breadcrumb-title");
    if (bcEl) {
      bcEl.textContent = this.formatViewTitle(viewName);
    }

    // Lazy load or refresh view-specific datasets
    if (viewName === "dashboard" && State.summary) Dashboard.render(State.summary);
    if (viewName === "security") Security.init();
    if (viewName === "qos") QoS.init();
    if (viewName === "ai") AI.init();
    if (viewName === "digital-twin") DigitalTwin.init();
    if (viewName === "predictive") Predictive.init();
    if (viewName === "root-cause") RootCause.init();
    if (viewName === "incidents") Incidents.init();
    if (viewName === "policies") Policies.init();
    if (viewName === "audit") Audit.init();
    if (viewName === "topology") Topology.fetchTopology();
    if (viewName === "flows") this.fetchFlowsView();
    if (viewName === "health") this.fetchHealthView();
    if (viewName === "admin-users" && typeof Admin !== "undefined") Admin.loadData();
    if (viewName === "settings") {
      if (typeof Settings !== "undefined" && typeof Settings.init === "function") Settings.init();
      if (typeof Auth !== "undefined" && typeof Auth.updateAccessTierDisplay === "function") Auth.updateAccessTierDisplay();
    }

    // Close any open popovers or dropdowns
    this.closeDropdowns();

    // Close mobile sidebar if open
    this.closeMobileDrawer();
  },

  formatViewTitle(viewName) {
    const titles = {
      dashboard: "Operations Dashboard",
      topology: "Network Topology Map",
      security: "Security Intelligence Center",
      qos: "QoS Optimization Center",
      ai: "AI & Machine Learning Center",
      "digital-twin": "Network Digital Twin & Resilience Center",
      flows: "Live OpenFlow Flow Table",
      incidents: "Incident Management",
      policies: "Network Policies & Rules",
      reports: "Analytics & Export Reports",
      audit: "System Audit Trail",
      health: "System Component Health",
      settings: "User & Network Settings",
      scenarios: "Demo Simulation Scenarios",
      predictive: "Predictive Network Intelligence Center",
      "root-cause": "AI Root-Cause Analysis Center",
      "admin-users": "Access Control & User Administration"
    };
    return titles[viewName] || "Operations Dashboard";
  },

  setupNavigation() {
    // Nav Items click handlers
    const navItems = document.querySelectorAll(".nav-item[data-view]");
    navItems.forEach(item => {
      item.addEventListener("click", () => {
        const view = item.getAttribute("data-view");
        this.navigate(view);
      });
    });

    // Sidebar Collapse Button Toggle
    const collapseBtn = document.getElementById("sidebar-collapse-btn");
    if (collapseBtn) {
      collapseBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        this.toggleSidebar();
      });
    }

    // Mobile Hamburger Toggle
    const mobileToggle = document.getElementById("mobile-menu-btn");
    const sidebar = document.getElementById("sidebar");
    const backdrop = document.getElementById("sidebar-backdrop");

    if (mobileToggle && sidebar && backdrop) {
      mobileToggle.addEventListener("click", () => {
        sidebar.classList.toggle("mobile-open");
        backdrop.classList.toggle("active");
      });

      const mobileClose = document.getElementById("mobile-sidebar-close-btn");
      if (mobileClose) {
        mobileClose.addEventListener("click", () => {
          this.closeMobileDrawer();
        });
      }

      backdrop.addEventListener("click", () => {
        this.closeMobileDrawer();
      });
    }

    // Responsive Window Resize & Orientation Change Observer
    let resizeTimer = null;
    window.addEventListener("resize", () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        if (window.innerWidth > 768) {
          this.closeMobileDrawer();
        }
        if (window.Topology && typeof Topology.draw === "function" && Topology.canvas) {
          Topology.draw();
        }
      }, 120);
    });

    // Global Keyboard Shortcuts (Ctrl + K for Search, ESC for modals)
    document.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        Search.open();
      } else if (e.key === "Escape") {
        Search.close();
        Security.closeMitigationModal();
        this.closeDropdowns();
      }
    });
  },

  setupDropdowns() {
    // User Profile Dropdown
    const profileTrigger = document.getElementById("profile-trigger-btn");
    const profileMenu = document.getElementById("profile-dropdown-menu");

    if (profileTrigger && profileMenu) {
      profileTrigger.addEventListener("click", (e) => {
        e.stopPropagation();
        profileMenu.classList.toggle("open");
        const notifPopover = document.getElementById("notif-popover");
        if (notifPopover) notifPopover.classList.remove("open");
      });
    }

    // Close dropdowns on outside click
    document.addEventListener("click", (e) => {
      if (profileMenu && !profileMenu.contains(e.target) && !profileTrigger.contains(e.target)) {
        profileMenu.classList.remove("open");
      }
      const notifPopover = document.getElementById("notif-popover");
      const notifWrapper = document.querySelector(".notif-btn-wrapper");
      if (notifPopover && !notifPopover.contains(e.target) && !(notifWrapper && notifWrapper.contains(e.target))) {
        notifPopover.classList.remove("open");
        if (window.Notifications) Notifications.isOpen = false;
      }
    });
  },

  closeDropdowns() {
    const profileMenu = document.getElementById("profile-dropdown-menu");
    if (profileMenu) profileMenu.classList.remove("open");
    const notifPopover = document.getElementById("notif-popover");
    if (notifPopover) notifPopover.classList.remove("open");
    if (window.Notifications) Notifications.isOpen = false;
  },

  closeMobileDrawer() {
    const sidebar = document.getElementById("sidebar");
    const backdrop = document.getElementById("sidebar-backdrop");
    if (sidebar) sidebar.classList.remove("mobile-open");
    if (backdrop) backdrop.classList.remove("active");
  },

  startLiveClock() {
    const clockEl = document.getElementById("topbar-live-clock");
    if (!clockEl) return;

    try {
      const tzId = Intl.DateTimeFormat().resolvedOptions().timeZone;
      if (tzId) clockEl.title = `Local Timezone: ${tzId}`;
    } catch (e) {}

    const formatter = new Intl.DateTimeFormat(undefined, {
      dateStyle: "medium",
      timeStyle: "medium"
    });

    const update = () => {
      const now = new Date();
      const timeStr = formatter.format(now);
      const tzName = (window.Utils && typeof Utils.getLocalTimezoneName === "function")
        ? Utils.getLocalTimezoneName(now)
        : "";
      clockEl.textContent = tzName ? `${timeStr} ${tzName}` : timeStr;
    };
    update();
    setInterval(update, 1000);
  },

  async fetchFlowsView() {
    try {
      const res = await API.get("/api/flows?limit=50");
      const tbody = document.getElementById("flows-view-tbody");
      if (!tbody) return;

      if (!res.flows || res.flows.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: #64748b; padding: 24px;">No OpenFlow rules discovered in data plane.</td></tr>`;
        return;
      }

      let html = "";
      res.flows.forEach(f => {
        const isThreat = f.threat_label === "ATTACK";
        const threatBadge = isThreat
          ? `<span class="badge badge-critical">${f.attack_type || 'ATTACK'}</span>`
          : `<span class="badge badge-live">BENIGN</span>`;

        html += `
          <tr>
            <td class="mono" style="color: var(--accent-cyan); font-weight: 700;">${f.flow_id || 'flw_01'}</td>
            <td class="mono">${f.source_ip || '*'}:${f.source_port || '*'}</td>
            <td class="mono">${f.destination_ip || '*'}:${f.destination_port || '*'}</td>
            <td><span class="badge badge-info">${f.protocol || 'TCP'}</span></td>
            <td class="mono">${Utils.formatPackets(f.packets)}</td>
            <td class="mono">${Utils.formatBytes(f.bytes)}</td>
            <td class="mono">${Utils.formatRates(f.packet_rate)}</td>
            <td><span class="badge ${f.priority_code === 'EF' ? 'badge-live' : 'badge-info'}">${f.traffic_class || 'WEB'}</span></td>
            <td>${threatBadge}</td>
          </tr>
        `;
      });
      tbody.innerHTML = html;
    } catch (err) {
      console.warn("[Flows View] Error:", err);
    }
  },

  async fetchHealthView() {
    try {
      const res = await API.get("/api/health");
      const health = res.health || {};

      const setT = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
      };

      setT("health-net-score", `${health.network_health}%`);
      setT("health-sec-score", `${health.security_health}%`);
      setT("health-qos-score", `${health.qos_health}%`);
      setT("health-avg-lat", `${health.average_latency_ms} ms`);
      setT("health-pkt-loss", `${health.packet_loss_pct}%`);
      setT("health-jitter", `${health.jitter_ms} ms`);
    } catch (err) {
      console.warn("[Health View] Error:", err);
    }
  },

  initCardInteractions() {
    // Only activate cursor tracking when a fine pointer (mouse/trackpad) is available
    if (!window.matchMedia('(hover: hover) and (pointer: fine)').matches) return;

    const cardSelector = '.card, .kpi-card, .card-ops, .card-intel, .settings-status-card, .settings-section-panel, .rca-panel, .twin-control-card, .pred-chart-card, .nav-item';
    let currentCard = null;
    let animFrame = null;

    document.addEventListener('mousemove', (e) => {
      const card = e.target.closest(cardSelector);

      if (card !== currentCard) {
        if (currentCard) {
          currentCard.style.removeProperty('--mouse-x');
          currentCard.style.removeProperty('--mouse-y');
          currentCard.style.removeProperty('--tilt-x');
          currentCard.style.removeProperty('--tilt-y');
        }
        currentCard = card;
      }

      if (!currentCard) return;

      if (animFrame) cancelAnimationFrame(animFrame);
      animFrame = requestAnimationFrame(() => {
        if (!currentCard) return;
        const rect = currentCard.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;

        currentCard.style.setProperty('--mouse-x', `${Math.round(x)}px`);
        currentCard.style.setProperty('--mouse-y', `${Math.round(y)}px`);

        // Subtle 3D tilt restricted to major panels only (max ±1.5deg)
        const isMajorCard = currentCard.classList.contains('card-ops') ||
                            currentCard.classList.contains('card-intel') ||
                            (currentCard.id && currentCard.id.startsWith('card-'));
        if (isMajorCard && rect.width > 0 && rect.height > 0) {
          const centerX = rect.width / 2;
          const centerY = rect.height / 2;
          const normX = (x - centerX) / centerX;
          const normY = (y - centerY) / centerY;
          const tiltX = Math.max(-1.5, Math.min(1.5, -normY * 1.5)).toFixed(2);
          const tiltY = Math.max(-1.5, Math.min(1.5, normX * 1.5)).toFixed(2);
          currentCard.style.setProperty('--tilt-x', `${tiltX}deg`);
          currentCard.style.setProperty('--tilt-y', `${tiltY}deg`);
        }
      });
    }, { passive: true });

    document.addEventListener('mouseleave', () => {
      if (currentCard) {
        currentCard.style.removeProperty('--mouse-x');
        currentCard.style.removeProperty('--mouse-y');
        currentCard.style.removeProperty('--tilt-x');
        currentCard.style.removeProperty('--tilt-y');
        currentCard = null;
      }
    });
  }
};

// Start application when DOM is ready
document.addEventListener("DOMContentLoaded", () => App.init());
