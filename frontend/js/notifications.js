/**
 * VORTEX-SDN Topbar Notifications Controller
 * Real-time event notifications across Security, QoS, Controller, Telemetry, and System.
 */

const Notifications = {
  isOpen: false,
  cachedNotifications: [],

  async init() {
    await this.fetchNotifications();
    State.subscribe("summary:updated", () => this.fetchNotifications());
  },

  async fetchNotifications() {
    try {
      const data = await API.get("/api/notifications");
      this.cachedNotifications = (data && data.notifications) || [];

      // Filter based on user preferences if defined
      const filtered = this.filterByPreferences(this.cachedNotifications);
      const unreadCount = filtered.filter(n => !n.is_read).length;

      this.renderBadge(unreadCount);
      this.renderList(filtered);
    } catch (err) {
      console.warn("[Notifications] Error fetching notifications:", err.message);
      this.renderError();
    }
  },

  filterByPreferences(notifications) {
    const prefs = (window.Settings && Settings.currentSettings && Settings.currentSettings.notifications) || {};
    return notifications.filter(n => {
      const cat = (n.category || "").toLowerCase();
      if (cat.includes("sec") && prefs.security_alerts === false) return false;
      if (cat.includes("qos") && prefs.qos_alerts === false) return false;
      if (cat.includes("ai") && prefs.ai_alerts === false) return false;
      if (cat.includes("sys") && prefs.system_alerts === false) return false;
      return true;
    });
  },

  renderBadge(count) {
    const badge = document.getElementById("topbar-notif-badge");
    if (badge) {
      const unreadNum = Number(count) || 0;
      if (unreadNum > 0) {
        badge.style.display = "block";
        badge.textContent = unreadNum > 99 ? "99+" : unreadNum;
      } else {
        badge.style.display = "none";
        badge.textContent = "0";
      }
    }
  },

  togglePopover(event) {
    if (event) event.stopPropagation();
    const popover = document.getElementById("notif-popover");
    if (!popover) return;

    this.isOpen = !popover.classList.contains("open");
    if (this.isOpen) {
      popover.classList.add("open");
      this.fetchNotifications();
    } else {
      popover.classList.remove("open");
    }
  },

  toggleDropdown(event) {
    this.togglePopover(event);
  },

  closePopover() {
    const popover = document.getElementById("notif-popover");
    if (popover) {
      popover.classList.remove("open");
      this.isOpen = false;
    }
  },

  closeDropdown() {
    this.closePopover();
  },

  renderList(notifications) {
    const listEl = document.getElementById("notif-popover-list") || document.getElementById("topbar-notif-list");
    if (!listEl) return;

    if (!notifications || notifications.length === 0) {
      listEl.innerHTML = `
        <div class="notif-empty-state">
          <svg class="icon icon-lg" viewBox="0 0 24 24" style="color:var(--text-muted); opacity:0.6; margin-bottom:8px;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          <div style="font-weight:600; color:var(--text-secondary); margin-bottom:2px;">No new notifications</div>
          <div style="font-size:11.5px; color:var(--text-muted);">All systems and telemetry are operating normally.</div>
        </div>
      `;
      return;
    }

    listEl.innerHTML = notifications.map(n => {
      const isUnread = !n.is_read;
      const sevClass = (n.severity || "INFO").toLowerCase();
      const timeAgo = this.formatTimeAgo(n.created_at || n.timestamp);
      const icon = this.getCategoryIcon(n.category);
      const link = this.getCategoryLink(n.category);

      return `
        <div class="notif-item ${isUnread ? 'unread' : 'read'}" data-id="${n.id}">
          <div class="notif-item-icon ${sevClass}">
            ${icon}
          </div>
          <div class="notif-item-body">
            <div class="notif-item-title">
              <span>${Utils.escapeHtml(n.title || "System Alert")}</span>
              ${isUnread ? `<button class="notif-mark-single-btn" onclick="Notifications.markSingleAsRead('${n.id}', event)" title="Mark as read">✓ Mark read</button>` : ''}
            </div>
            <div class="notif-item-desc">${Utils.escapeHtml(n.message || "")}</div>
            <div class="notif-item-meta">
              <span class="badge ${sevClass === 'critical' ? 'badge-critical' : (sevClass === 'high' ? 'badge-critical' : (sevClass === 'medium' ? 'badge-warning' : 'badge-info'))}" style="font-size:9px; padding:1px 5px;">${n.severity || 'INFO'}</span>
              <span class="notif-item-time">${timeAgo}</span>
              ${link ? `<a href="javascript:void(0)" onclick="Notifications.navigateTo('${link}', '${n.id}', event)" class="notif-item-link">View Details →</a>` : ''}
            </div>
          </div>
        </div>
      `;
    }).join("");
  },

  renderLoading() {
    const listEl = document.getElementById("notif-popover-list") || document.getElementById("topbar-notif-list");
    if (listEl) {
      listEl.innerHTML = `
        <div class="notif-empty-state">
          <div style="font-size:12px; color:var(--text-muted);">Loading notifications...</div>
        </div>
      `;
    }
  },

  renderError() {
    const listEl = document.getElementById("notif-popover-list") || document.getElementById("topbar-notif-list");
    if (listEl) {
      listEl.innerHTML = `
        <div class="notif-empty-state">
          <div style="font-size:12px; color:var(--status-danger);">Unable to load notifications</div>
        </div>
      `;
    }
  },

  async markSingleAsRead(id, event) {
    if (event) event.stopPropagation();
    try {
      await API.post(`/api/notifications/${id}/read`);
      await this.fetchNotifications();
    } catch (err) {
      console.warn("[Notifications] Error marking notification as read:", err.message);
    }
  },

  async markAllAsRead(event) {
    if (event) event.stopPropagation();
    try {
      await API.post("/api/notifications/read-all");
      await this.fetchNotifications();
      Utils.showToast("All notifications marked as read.", "info");
    } catch (err) {
      console.warn("[Notifications] Error marking all as read:", err.message);
    }
  },

  async navigateTo(viewName, id, event) {
    if (event) event.stopPropagation();
    if (id) {
      try {
        await API.post(`/api/notifications/${id}/read`);
      } catch (e) {}
    }
    this.closePopover();
    if (window.App && typeof window.App.navigate === 'function') {
      window.App.navigate(viewName);
    }
  },

  formatTimeAgo(isoString) {
    if (!isoString) return "Just now";
    try {
      const past = new Date(isoString.includes("Z") ? isoString : isoString + "Z").getTime();
      const diffSec = Math.max(0, Math.floor((Date.now() - past) / 1000));
      if (diffSec < 60) return `${diffSec}s ago`;
      if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
      if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
      return `${Math.floor(diffSec / 86400)}d ago`;
    } catch (e) {
      return "Recently";
    }
  },

  getCategoryIcon(cat) {
    const c = (cat || "").toLowerCase();
    if (c.includes("sec")) {
      return `<svg class="icon icon-sm" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`;
    } else if (c.includes("qos")) {
      return `<svg class="icon icon-sm" viewBox="0 0 24 24"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>`;
    } else if (c.includes("inc")) {
      return `<svg class="icon icon-sm" viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
    } else if (c.includes("ctl") || c.includes("controller") || c.includes("net")) {
      return `<svg class="icon icon-sm" viewBox="0 0 24 24"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>`;
    }
    return `<svg class="icon icon-sm" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
  },

  getCategoryLink(cat) {
    const c = (cat || "").toLowerCase();
    if (c.includes("sec")) return "security";
    if (c.includes("qos")) return "qos";
    if (c.includes("inc")) return "incidents";
    if (c.includes("policy") || c.includes("pol")) return "policies";
    if (c.includes("telemetry") || c.includes("flow")) return "dashboard";
    return null;
  }
};
