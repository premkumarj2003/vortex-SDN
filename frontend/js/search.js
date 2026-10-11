/**
 * VORTEX-SDN Global Search Overlay Controller
 * Indexes switches, hosts, flows, security alerts, and policies with keyboard navigation.
 */

const Search = {
  isOpen: false,

  init() {
    this.setupListeners();
  },

  setupListeners() {
    // Global keyboard shortcuts (Ctrl + K to open, Escape to close when open)
    window.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        this.open();
      } else if (e.key === "Escape" && this.isOpen) {
        e.preventDefault();
        this.close();
      }
    });

    const triggerBtn = document.getElementById("global-search-trigger");
    if (triggerBtn) {
      triggerBtn.addEventListener("click", () => this.open());
    }

    const escBtn = document.getElementById("search-modal-esc");
    if (escBtn) {
      escBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        this.close();
      });
    }

    const modal = document.getElementById("search-modal");
    if (modal) {
      modal.addEventListener("click", (e) => {
        if (e.target === modal) this.close();
      });
    }

    const searchInput = document.getElementById("search-modal-input");
    if (searchInput) {
      searchInput.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
          e.preventDefault();
          this.close();
        }
      });
      searchInput.addEventListener("input", (e) => this.handleSearch(e.target.value));
    }
  },

  open() {
    const modal = document.getElementById("search-modal");
    if (modal) {
      modal.classList.add("active");
      this.isOpen = true;
      const input = document.getElementById("search-modal-input");
      if (input) {
        input.value = "";
        input.focus();
        this.handleSearch("");
      }
    }
  },

  close() {
    const modal = document.getElementById("search-modal");
    if (modal) {
      modal.classList.remove("active");
      this.isOpen = false;
    }
  },

  handleSearch(query) {
    const resultsContainer = document.getElementById("search-results-list");
    if (!resultsContainer) return;

    const q = (query || "").toLowerCase().trim();

    // Searchable items catalogue
    const items = [
      { title: "Switch 1 (s1)", subtitle: "Core Switch (DPID 0000000000000001)", category: "DEVICE", action: "topology" },
      { title: "Switch 2 (s2)", subtitle: "Distribution Switch (DPID 0000000000000002)", category: "DEVICE", action: "topology" },
      { title: "Host 1 (h1 - 10.0.0.1)", subtitle: "Web / Application Server", category: "HOST", action: "topology" },
      { title: "Host 4 (h4 - 10.0.0.4)", subtitle: "Edge Node / Attacker Subnet", category: "HOST", action: "topology" },
      { title: "Security Intelligence Center", subtitle: "Active Threats, Anomaly Detector, Mitigations", category: "NAVIGATION", action: "security" },
      { title: "QoS Optimization Center", subtitle: "Traffic Classifications, Policies, SLA Gauges", category: "NAVIGATION", action: "qos" },
      { title: "AI & ML Center", subtitle: "Random Forest Models, Feature Importance, Predictor Sandbox", category: "NAVIGATION", action: "ai" },
      { title: "Incident Management", subtitle: "Open Security & SLA Incidents", category: "NAVIGATION", action: "incidents" },
      { title: "Audit Trail", subtitle: "User Actions & OpenFlow Rule Logs", category: "NAVIGATION", action: "audit" },
      { title: "Demo Scenarios Controller", subtitle: "DDoS Attack, Port Scan, Congestion, Recovery", category: "DEMO", action: "scenarios" }
    ];

    const filtered = q ? items.filter(i => i.title.toLowerCase().includes(q) || i.subtitle.toLowerCase().includes(q) || i.category.toLowerCase().includes(q)) : items;

    let html = "";
    filtered.forEach(item => {
      const cat = item.category.toUpperCase();
      const badgeClass = cat === 'DEVICE' ? 'badge-live' : (cat === 'HOST' ? 'badge-info' : (cat === 'DEMO' ? 'badge-warning' : 'badge-demo'));
      html += `
        <div class="search-result-item" onclick="Search.selectItem('${item.action}')">
          <div class="search-res-info">
            <div class="search-res-title">${Utils.escapeHtml(item.title)}</div>
            <div class="search-res-sub">${Utils.escapeHtml(item.subtitle)}</div>
          </div>
          <span class="badge ${badgeClass}" style="font-size: 9.5px; padding: 2px 7px;">${cat}</span>
        </div>
      `;
    });

    resultsContainer.innerHTML = html || `<div style="text-align: center; color: var(--text-muted); padding: 28px 16px; font-size: 12.5px;">No matching network resources found.</div>`;
  },

  selectItem(targetView) {
    this.close();
    App.navigate(targetView);
  }
};
