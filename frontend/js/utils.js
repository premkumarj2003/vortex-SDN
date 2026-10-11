/**
 * VORTEX-SDN Common Utilities & Professional SVG Icon Registry
 */

const Utils = {
  // SVG Icon Registry
  icons: {
    dashboard: `<svg class="icon" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/></svg>`,
    topology: `<svg class="icon" viewBox="0 0 24 24"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>`,
    flows: `<svg class="icon" viewBox="0 0 24 24"><line x1="6" y1="3" x2="6" y2="15"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M18 9a9 9 0 0 1-9 9"/></svg>`,
    scenarios: `<svg class="icon" viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3"/></svg>`,
    security: `<svg class="icon" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
    qos: `<svg class="icon" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`,
    ai: `<svg class="icon" viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/></svg>`,
    incidents: `<svg class="icon" viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
    policies: `<svg class="icon" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>`,
    reports: `<svg class="icon" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>`,
    audit: `<svg class="icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`,
    health: `<svg class="icon" viewBox="0 0 24 24"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>`,
    settings: `<svg class="icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>`,
    user: `<svg class="icon" viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>`,
    logout: `<svg class="icon" viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>`,
    bell: `<svg class="icon" viewBox="0 0 24 24"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>`,
    search: `<svg class="icon" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`,
    refresh: `<svg class="icon" viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>`,
    chevronLeft: `<svg class="icon" viewBox="0 0 24 24"><polyline points="15 18 9 12 15 6"/></svg>`,
    chevronRight: `<svg class="icon" viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"/></svg>`,
    close: `<svg class="icon" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`,
    menu: `<svg class="icon" viewBox="0 0 24 24"><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="18" x2="21" y2="18"/></svg>`,
    check: `<svg class="icon" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>`,
    alert: `<svg class="icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`
  },

  getIcon(name) {
    return this.icons[name] || "";
  },

  formatBytes(bytes, decimals = 2) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  },

  formatPackets(pkts) {
    if (!pkts) return '0 pkts';
    if (pkts >= 1000000) return (pkts / 1000000).toFixed(2) + 'M pkts';
    if (pkts >= 1000) return (pkts / 1000).toFixed(1) + 'k pkts';
    return pkts + ' pkts';
  },

  formatRates(rate) {
    if (!rate || rate === 0) return '0.0 pps';
    if (rate >= 1000000) return (rate / 1000000).toFixed(2) + ' Mpps';
    if (rate >= 1000) return (rate / 1000).toFixed(1) + ' kpps';
    return parseFloat(rate).toFixed(1) + ' pps';
  },

  formatDate(dateOrIso) {
    return this.formatDateTime(dateOrIso);
  },

  formatDateTime(dateOrIso) {
    if (!dateOrIso) return '--';
    const d = dateOrIso instanceof Date ? dateOrIso : new Date(dateOrIso);
    if (isNaN(d.getTime())) return '--';
    try {
      return new Intl.DateTimeFormat(undefined, {
        dateStyle: 'medium',
        timeStyle: 'medium'
      }).format(d);
    } catch (e) {
      return d.toLocaleString();
    }
  },

  getLocalTimezoneName(date = new Date()) {
    try {
      const parts = new Intl.DateTimeFormat(undefined, { timeZoneName: 'short' }).formatToParts(date);
      const tzPart = parts.find(p => p.type === 'timeZoneName');
      return (tzPart && tzPart.value) || '';
    } catch (e) {
      return '';
    }
  },

  formatTimestamp(isoString) {
    if (!isoString) return '--';
    const d = new Date(isoString);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  },

  formatRelativeTime(isoString) {
    if (!isoString) return '--';
    const d = new Date(isoString);
    const now = new Date();
    const diffSec = Math.floor((now - d) / 1000);
    if (isNaN(diffSec)) return '--';
    if (diffSec < 5) return 'just now';
    if (diffSec < 60) return `${diffSec}s ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHours = Math.floor(diffMin / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    return d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  },

  showToast(message, type = "info") {
    let container = document.getElementById("toast-container");
    if (!container) {
      container = document.createElement("div");
      container.id = "toast-container";
      document.body.appendChild(container);
    }

    // Deduplication: prevent stacking identical toasts
    const cleanMsg = String(message || '').trim();
    if (!cleanMsg) return;

    const existingToasts = container.querySelectorAll(".toast");
    for (const existing of existingToasts) {
      if (existing.dataset.message === cleanMsg || existing.textContent.trim().includes(cleanMsg)) {
        return; // Already actively displayed
      }
    }

    const normalizedType = (type === "error") ? "danger" : type;
    const toast = document.createElement("div");
    toast.className = `toast ${normalizedType}`;
    toast.dataset.message = cleanMsg;
    toast.setAttribute("role", (normalizedType === "danger" || normalizedType === "warning") ? "alert" : "status");
    toast.setAttribute("aria-live", "polite");
    
    let iconSvg = this.icons.alert;
    if (normalizedType === "success") iconSvg = this.icons.check;
    else if (normalizedType === "danger") iconSvg = this.icons.incidents;
    else if (normalizedType === "warning") iconSvg = this.icons.alert;
    else if (normalizedType === "info") iconSvg = this.icons.alert;

    const contentWrap = document.createElement("div");
    contentWrap.className = "toast-content-wrap";
    contentWrap.innerHTML = `
      ${iconSvg}
      <span>${this.escapeHtml(cleanMsg)}</span>
    `;

    const closeBtn = document.createElement("button");
    closeBtn.type = "button";
    closeBtn.className = "toast-close-btn";
    closeBtn.setAttribute("aria-label", "Close notification");
    closeBtn.innerHTML = "&times;";

    const dismissToast = () => {
      if (toast.classList.contains("toast-leaving")) return;
      toast.classList.add("toast-leaving");
      setTimeout(() => {
        if (toast.parentElement) toast.remove();
      }, 220);
    };

    closeBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      dismissToast();
    });

    toast.appendChild(contentWrap);
    toast.appendChild(closeBtn);
    container.appendChild(toast);

    // Auto-dismiss timeout (errors/warnings stay slightly longer: 5000ms; success/info: 3500ms)
    const timeoutDuration = (normalizedType === "danger" || normalizedType === "warning") ? 5000 : 3500;
    setTimeout(() => {
      dismissToast();
    }, timeoutDuration);
  },

  escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  },

  showConfirm(options = {}) {
    const {
      title = "Confirm Action",
      message = "Are you sure you want to proceed?",
      confirmText = "Confirm",
      cancelText = "Cancel",
      type = "warning",
      destructive = false
    } = typeof options === "string" ? { message: options } : options;

    return new Promise((resolve) => {
      const existing = document.getElementById("vortex-confirm-overlay");
      if (existing) existing.remove();

      const overlay = document.createElement("div");
      overlay.id = "vortex-confirm-overlay";
      overlay.className = "vortex-confirm-overlay";
      overlay.setAttribute("role", "dialog");
      overlay.setAttribute("aria-modal", "true");
      overlay.setAttribute("aria-labelledby", "vortex-confirm-title");

      const backdrop = document.createElement("div");
      backdrop.className = "vortex-confirm-backdrop";

      const normalizedType = (type === "error") ? "danger" : type;
      const typeClass = `type-${normalizedType}`;
      
      let iconSvg = this.icons.alert;
      if (normalizedType === "danger" || destructive) {
        iconSvg = this.icons.incidents || this.icons.alert;
      } else if (normalizedType === "success") {
        iconSvg = this.icons.check;
      }

      const dialog = document.createElement("div");
      dialog.className = `vortex-confirm-dialog ${typeClass}`;

      const confirmBtnClass = (destructive || normalizedType === "danger") 
        ? "btn-danger" 
        : (normalizedType === "warning" ? "btn-warning" : "btn-primary");

      dialog.innerHTML = `
        <div class="vortex-confirm-header">
          <div class="vortex-confirm-title-row">
            <span class="vortex-confirm-icon">${iconSvg}</span>
            <h3 id="vortex-confirm-title" class="vortex-confirm-title">${this.escapeHtml(title)}</h3>
          </div>
          <button type="button" class="vortex-confirm-close" aria-label="Close dialog">&times;</button>
        </div>
        <div class="vortex-confirm-body">
          <p class="vortex-confirm-message">${this.escapeHtml(message)}</p>
        </div>
        <div class="vortex-confirm-footer">
          <button type="button" class="btn btn-secondary vortex-confirm-btn-cancel">${this.escapeHtml(cancelText)}</button>
          <button type="button" class="btn ${confirmBtnClass} vortex-confirm-btn-action">${this.escapeHtml(confirmText)}</button>
        </div>
      `;

      overlay.appendChild(backdrop);
      overlay.appendChild(dialog);
      document.body.appendChild(overlay);

      let resolved = false;
      const cleanup = (result) => {
        if (resolved) return;
        resolved = true;
        document.removeEventListener("keydown", keyHandler);
        overlay.classList.add("leaving");
        setTimeout(() => {
          if (overlay.parentElement) overlay.remove();
        }, 180);
        resolve(result);
      };

      const actionBtn = dialog.querySelector(".vortex-confirm-btn-action");
      const cancelBtn = dialog.querySelector(".vortex-confirm-btn-cancel");
      const closeBtn = dialog.querySelector(".vortex-confirm-close");

      actionBtn.addEventListener("click", () => cleanup(true));
      cancelBtn.addEventListener("click", () => cleanup(false));
      closeBtn.addEventListener("click", () => cleanup(false));

      backdrop.addEventListener("click", () => {
        if (!destructive) cleanup(false);
      });

      const keyHandler = (e) => {
        if (e.key === "Escape") {
          e.preventDefault();
          cleanup(false);
        } else if (e.key === "Enter" && !e.shiftKey) {
          if (document.activeElement === cancelBtn) {
            cleanup(false);
          } else {
            e.preventDefault();
            cleanup(true);
          }
        }
      };
      document.addEventListener("keydown", keyHandler);

      setTimeout(() => {
        if (destructive) {
          cancelBtn.focus();
        } else {
          actionBtn.focus();
        }
      }, 50);
    });
  },

  showPrompt(options = {}) {
    const {
      title = "Input Required",
      message = "Please enter a value:",
      defaultValue = "",
      placeholder = "",
      confirmText = "Confirm",
      cancelText = "Cancel",
      type = "info",
      destructive = false
    } = typeof options === "string" ? { message: options } : options;

    return new Promise((resolve) => {
      const existing = document.getElementById("vortex-confirm-overlay");
      if (existing) existing.remove();

      const overlay = document.createElement("div");
      overlay.id = "vortex-confirm-overlay";
      overlay.className = "vortex-confirm-overlay";
      overlay.setAttribute("role", "dialog");
      overlay.setAttribute("aria-modal", "true");
      overlay.setAttribute("aria-labelledby", "vortex-confirm-title");

      const backdrop = document.createElement("div");
      backdrop.className = "vortex-confirm-backdrop";

      const normalizedType = (type === "error") ? "danger" : type;
      const typeClass = `type-${normalizedType}`;
      
      let iconSvg = this.icons.alert;
      if (normalizedType === "danger" || destructive) {
        iconSvg = this.icons.incidents || this.icons.alert;
      } else if (normalizedType === "success") {
        iconSvg = this.icons.check;
      }

      const dialog = document.createElement("div");
      dialog.className = `vortex-confirm-dialog ${typeClass}`;

      const confirmBtnClass = (destructive || normalizedType === "danger") 
        ? "btn-danger" 
        : (normalizedType === "warning" ? "btn-warning" : "btn-primary");

      dialog.innerHTML = `
        <div class="vortex-confirm-header">
          <div class="vortex-confirm-title-row">
            <span class="vortex-confirm-icon">${iconSvg}</span>
            <h3 id="vortex-confirm-title" class="vortex-confirm-title">${this.escapeHtml(title)}</h3>
          </div>
          <button type="button" class="vortex-confirm-close" aria-label="Close dialog">&times;</button>
        </div>
        <div class="vortex-confirm-body">
          <p class="vortex-confirm-message">${this.escapeHtml(message)}</p>
          <input type="text" class="vortex-confirm-input" placeholder="${this.escapeHtml(placeholder)}" value="${this.escapeHtml(defaultValue)}">
        </div>
        <div class="vortex-confirm-footer">
          <button type="button" class="btn btn-secondary vortex-confirm-btn-cancel">${this.escapeHtml(cancelText)}</button>
          <button type="button" class="btn ${confirmBtnClass} vortex-confirm-btn-action">${this.escapeHtml(confirmText)}</button>
        </div>
      `;

      overlay.appendChild(backdrop);
      overlay.appendChild(dialog);
      document.body.appendChild(overlay);

      const input = dialog.querySelector(".vortex-confirm-input");
      const actionBtn = dialog.querySelector(".vortex-confirm-btn-action");
      const cancelBtn = dialog.querySelector(".vortex-confirm-btn-cancel");
      const closeBtn = dialog.querySelector(".vortex-confirm-close");

      let resolved = false;
      const cleanup = (result) => {
        if (resolved) return;
        resolved = true;
        document.removeEventListener("keydown", keyHandler);
        overlay.classList.add("leaving");
        setTimeout(() => {
          if (overlay.parentElement) overlay.remove();
        }, 180);
        resolve(result);
      };

      actionBtn.addEventListener("click", () => cleanup(input.value));
      cancelBtn.addEventListener("click", () => cleanup(null));
      closeBtn.addEventListener("click", () => cleanup(null));

      backdrop.addEventListener("click", () => {
        if (!destructive) cleanup(null);
      });

      const keyHandler = (e) => {
        if (e.key === "Escape") {
          e.preventDefault();
          cleanup(null);
        } else if (e.key === "Enter") {
          e.preventDefault();
          cleanup(input.value);
        }
      };
      document.addEventListener("keydown", keyHandler);

      setTimeout(() => {
        input.focus();
        input.select();
      }, 50);
    });
  },

  showAlert(options = {}) {
    const {
      title = "System Notification",
      message = "",
      buttonText = "OK",
      type = "info"
    } = typeof options === "string" ? { message: options } : options;

    return this.showConfirm({
      title,
      message,
      confirmText: buttonText,
      cancelText: "Dismiss",
      type
    });
  }
};

// Global unified top-center helpers and native dialog protection
if (typeof window !== "undefined") {
  window.showVortexToast = (msg, type) => Utils.showToast(msg, type);
  window.showVortexConfirm = (opts) => Utils.showConfirm(opts);
  window.showVortexPrompt = (opts) => Utils.showPrompt(opts);
  window.showVortexAlert = (opts) => Utils.showAlert(opts);

  // Guarantee that native browser alert never shows unstyled "localhost:5000 says"
  window.alert = (msg) => {
    Utils.showToast(String(msg || ""), "warning");
  };
}
