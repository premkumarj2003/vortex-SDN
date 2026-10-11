/**
 * VORTEX-SDN User Settings Controller
 * Handles Appearance & Theme, Dashboard & Polling, Notifications, and Profile preferences.
 */

const Settings = {
  currentSettings: {},
  autoSaveTimer: null,
  activeTab: "profile",

  async init() {
    // Restore cached appearance preferences immediately
    this.restoreCachedAppearance();

    await this.fetchSettings();
    this.setupListeners();
    this.startStatusUpdater();
  },

  restoreCachedAppearance() {
    const cachedTheme = localStorage.getItem("vortex_theme") || "dark";
    const cachedAccent = localStorage.getItem("vortex_accent") || "cyan";
    const cachedDensity = localStorage.getItem("vortex_density") || "comfortable";
    const cachedMotion = localStorage.getItem("vortex_reduce_motion") === "true";

    this.applyAppearance({
      theme: cachedTheme,
      accent: cachedAccent,
      density: cachedDensity,
      reduce_motion: cachedMotion
    });
  },

  async fetchSettings() {
    try {
      const data = await API.get("/api/user/settings");
      this.currentSettings = data || {};
      this.populateForm(this.currentSettings);
    } catch (err) {
      console.warn("[Settings] Error fetching settings:", err);
    }
  },

  switchTab(tabName) {
    this.activeTab = tabName;

    // Update active tab buttons
    const tabBtns = document.querySelectorAll(".settings-tab-btn");
    tabBtns.forEach(btn => {
      if (btn.getAttribute("data-tab") === tabName) {
        btn.classList.add("active");
      } else {
        btn.classList.remove("active");
      }
    });

    // Update active section panels
    const panels = document.querySelectorAll(".settings-section-panel");
    panels.forEach(p => {
      if (p.id === `settings-panel-${tabName}`) {
        p.classList.add("active");
      } else {
        p.classList.remove("active");
      }
    });

    if (tabName === "dashboard") {
      this.updatePollingStatusCard();
    }
  },

  populateForm(s) {
    if (!s) return;

    // 1. Profile Info
    if (Auth.currentUser) {
      const nameInput = document.getElementById("set-full-name");
      if (nameInput) nameInput.value = Auth.currentUser.full_name || Auth.currentUser.username || "";
      const emailInput = document.getElementById("set-email");
      if (emailInput) emailInput.value = Auth.currentUser.email || "";
    }

    // 2. Appearance & Theme
    const app = s.appearance || {};
    const theme = app.theme || localStorage.getItem("vortex_theme") || "dark";
    const accent = app.accent || localStorage.getItem("vortex_accent") || "cyan";
    const density = app.density || localStorage.getItem("vortex_density") || "comfortable";
    const reduceMotion = app.reduce_motion !== undefined ? app.reduce_motion : (localStorage.getItem("vortex_reduce_motion") === "true");

    const themeSelect = document.getElementById("set-theme");
    if (themeSelect) themeSelect.value = theme;
    const accentSelect = document.getElementById("set-accent");
    if (accentSelect) accentSelect.value = accent;
    const densitySelect = document.getElementById("set-density");
    if (densitySelect) densitySelect.value = density;
    const motionCheck = document.getElementById("set-reduce-motion");
    if (motionCheck) motionCheck.checked = reduceMotion;

    this.applyAppearance({ theme, accent, density, reduce_motion: reduceMotion });

    // 3. Dashboard & Polling
    const dash = s.dashboard || {};
    const autoRefresh = dash.auto_refresh !== false;
    const refreshInterval = parseInt(dash.refresh_interval || 5) || 5;
    const chartHistory = parseInt(dash.chart_history || 20) || 20;

    const autoCheck = document.getElementById("set-auto-refresh");
    if (autoCheck) autoCheck.checked = autoRefresh;
    const intervalSelect = document.getElementById("set-refresh-interval");
    if (intervalSelect) intervalSelect.value = refreshInterval;
    const historySelect = document.getElementById("set-chart-history");
    if (historySelect) historySelect.value = chartHistory;

    // Apply to Telemetry poller without creating duplicate timers
    State.isPaused = !autoRefresh;
    Telemetry.setPollingInterval(refreshInterval);
    Telemetry.setMaxPoints(chartHistory);
    this.updatePollingStatusCard();

    // 4. Notifications preferences
    const notifs = s.notifications || {};
    const setCheck = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.checked = val !== false;
    };

    setCheck("set-notif-master", notifs.master_enabled);
    setCheck("set-notif-sec", notifs.security_alerts);
    setCheck("set-notif-crit", notifs.critical_threats);
    setCheck("set-notif-net", notifs.network_events);
    setCheck("set-notif-qos", notifs.qos_alerts);
    setCheck("set-notif-inc", notifs.incident_updates);
    setCheck("set-notif-sys", notifs.system_alerts);
    setCheck("set-notif-audit", notifs.audit_alerts);

    setCheck("set-sev-crit", notifs.severity_critical);
    setCheck("set-sev-high", notifs.severity_high);
    setCheck("set-sev-med", notifs.severity_medium);
    setCheck("set-sev-low", notifs.severity_low);
    setCheck("set-sev-info", notifs.severity_info);

    const soundCheck = document.getElementById("set-notif-sound");
    if (soundCheck) soundCheck.checked = notifs.sound_enabled === true;
    const quietCheck = document.getElementById("set-notif-quiet");
    if (quietCheck) quietCheck.checked = notifs.quiet_mode === true;
    const markReadCheck = document.getElementById("set-notif-mark-read");
    if (markReadCheck) markReadCheck.checked = notifs.mark_read_on_click !== false;
  },

  setupListeners() {
    const saveBtn = document.getElementById("save-settings-btn");
    if (saveBtn) {
      saveBtn.addEventListener("click", () => this.saveSettings(true));
    }

    const nameInput = document.getElementById("set-full-name");
    if (nameInput) {
      nameInput.addEventListener("input", () => this.scheduleAutoSave());
    }
  },

  startStatusUpdater() {
    setInterval(() => {
      if (this.activeTab === "dashboard") {
        this.updatePollingStatusCard();
      }
    }, 1000);
  },

  updatePollingStatusCard() {
    const statusEl = document.getElementById("settings-polling-status");
    const intervalEl = document.getElementById("settings-current-interval-val");
    const lastUpEl = document.getElementById("settings-last-update-val");
    const pauseBtn = document.getElementById("settings-pause-btn");

    const isPaused = State.isPaused;
    const intSec = (State.pollingIntervalMs || 5000) / 1000;

    if (statusEl) {
      statusEl.innerHTML = isPaused
        ? `<span class="status-dot yellow"></span><span>Paused</span>`
        : `<span class="status-dot green"></span><span>Active</span>`;
    }

    if (intervalEl) {
      intervalEl.textContent = `${intSec} seconds`;
    }

    if (lastUpEl) {
      lastUpEl.textContent = Telemetry.lastUpdateTime || "Just now";
    }

    if (pauseBtn) {
      pauseBtn.textContent = isPaused ? "Resume Live Updates" : "Pause Live Updates";
    }
  },

  applyAppearance(app) {
    const theme = app.theme || "dark";
    const accent = app.accent || "cyan";
    const density = app.density || "comfortable";
    const reduceMotion = !!app.reduce_motion;

    // Theme: dark, light, system
    localStorage.setItem("vortex_theme", theme);
    if (theme === "light") {
      document.documentElement.setAttribute("data-theme", "light");
    } else if (theme === "system") {
      const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
      if (prefersDark) {
        document.documentElement.removeAttribute("data-theme");
      } else {
        document.documentElement.setAttribute("data-theme", "light");
      }
    } else {
      document.documentElement.removeAttribute("data-theme");
    }

    // Accent
    localStorage.setItem("vortex_accent", accent);
    if (accent === "blue" || accent === "violet") {
      document.documentElement.setAttribute("data-accent", accent);
    } else {
      document.documentElement.removeAttribute("data-accent");
    }

    // Density
    localStorage.setItem("vortex_density", density);
    if (density === "compact") {
      document.documentElement.setAttribute("data-density", "compact");
    } else {
      document.documentElement.removeAttribute("data-density");
    }

    // Reduce motion
    localStorage.setItem("vortex_reduce_motion", reduceMotion ? "true" : "false");
    if (reduceMotion) {
      document.documentElement.setAttribute("data-reduce-motion", "true");
    } else {
      document.documentElement.removeAttribute("data-reduce-motion");
    }

    // Broadcast theme change to active views (Dashboard, Charts, Gauges)
    window.dispatchEvent(new CustomEvent("vortex:theme-changed", { detail: { theme } }));
  },

  toggleTheme() {
    const currentTheme = document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
    const nextTheme = currentTheme === "light" ? "dark" : "light";
    const themeSelect = document.getElementById("set-theme");
    if (themeSelect) {
      themeSelect.value = nextTheme;
    }
    this.onThemeChange(nextTheme);
  },

  onThemeChange(theme) {
    this.applyAppearance({
      theme: theme,
      accent: document.getElementById("set-accent") ? document.getElementById("set-accent").value : "cyan",
      density: document.getElementById("set-density") ? document.getElementById("set-density").value : "comfortable",
      reduce_motion: document.getElementById("set-reduce-motion") ? document.getElementById("set-reduce-motion").checked : false
    });
    this.scheduleAutoSave();
  },

  onAccentChange(accent) {
    this.applyAppearance({
      theme: document.getElementById("set-theme") ? document.getElementById("set-theme").value : "dark",
      accent: accent,
      density: document.getElementById("set-density") ? document.getElementById("set-density").value : "comfortable",
      reduce_motion: document.getElementById("set-reduce-motion") ? document.getElementById("set-reduce-motion").checked : false
    });
    this.scheduleAutoSave();
  },

  onDensityChange(density) {
    this.applyAppearance({
      theme: document.getElementById("set-theme") ? document.getElementById("set-theme").value : "dark",
      accent: document.getElementById("set-accent") ? document.getElementById("set-accent").value : "cyan",
      density: density,
      reduce_motion: document.getElementById("set-reduce-motion") ? document.getElementById("set-reduce-motion").checked : false
    });
    this.scheduleAutoSave();
  },

  onReduceMotionChange(reduceMotion) {
    this.applyAppearance({
      theme: document.getElementById("set-theme") ? document.getElementById("set-theme").value : "dark",
      accent: document.getElementById("set-accent") ? document.getElementById("set-accent").value : "cyan",
      density: document.getElementById("set-density") ? document.getElementById("set-density").value : "comfortable",
      reduce_motion: reduceMotion
    });
    this.scheduleAutoSave();
  },

  onAutoRefreshChange(enabled) {
    if (enabled) {
      Telemetry.resumePolling();
    } else {
      Telemetry.pausePolling();
    }
    this.updatePollingStatusCard();
    this.scheduleAutoSave();
  },

  onPollingIntervalChange(seconds) {
    const sec = parseInt(seconds) || 5;
    Telemetry.setPollingInterval(sec);
    this.updatePollingStatusCard();
    this.scheduleAutoSave();
  },

  onChartHistoryChange(points) {
    const pts = parseInt(points) || 20;
    Telemetry.setMaxPoints(pts);
    this.scheduleAutoSave();
  },

  onNotifChange() {
    this.scheduleAutoSave();
    if (window.Notifications) {
      Notifications.fetchNotifications();
    }
  },

  togglePausePolling() {
    if (State.isPaused) {
      Telemetry.resumePolling();
      const autoCheck = document.getElementById("set-auto-refresh");
      if (autoCheck) autoCheck.checked = true;
    } else {
      Telemetry.pausePolling();
      const autoCheck = document.getElementById("set-auto-refresh");
      if (autoCheck) autoCheck.checked = false;
    }
    this.updatePollingStatusCard();
    this.scheduleAutoSave();
  },

  refreshNow() {
    Telemetry.pollNow();
    this.updatePollingStatusCard();
    Utils.showToast("Telemetry data refreshed.", "info");
  },

  async resetAppearance() {
    const confirmed = await Utils.showConfirm({
      title: "Reset Appearance Settings",
      message: "Are you sure you want to reset appearance to system defaults (Dark NOC Mode, Cyan Accent, Comfortable Density)?",
      confirmText: "Reset Defaults",
      cancelText: "Cancel",
      type: "warning"
    });
    if (!confirmed) return;

    const themeSelect = document.getElementById("set-theme");
    if (themeSelect) themeSelect.value = "dark";
    const accentSelect = document.getElementById("set-accent");
    if (accentSelect) accentSelect.value = "cyan";
    const densitySelect = document.getElementById("set-density");
    if (densitySelect) densitySelect.value = "comfortable";
    const motionCheck = document.getElementById("set-reduce-motion");
    if (motionCheck) motionCheck.checked = false;

    this.applyAppearance({ theme: "dark", accent: "cyan", density: "comfortable", reduce_motion: false });
    this.saveSettings(true);
  },

  async resetDashboard() {
    const confirmed = await Utils.showConfirm({
      title: "Reset Dashboard Settings",
      message: "Are you sure you want to reset telemetry polling settings to defaults (Auto Refresh ON, 5s interval, Standard 20-point history)?",
      confirmText: "Reset Defaults",
      cancelText: "Cancel",
      type: "warning"
    });
    if (!confirmed) return;

    const autoCheck = document.getElementById("set-auto-refresh");
    if (autoCheck) autoCheck.checked = true;
    const intervalSelect = document.getElementById("set-refresh-interval");
    if (intervalSelect) intervalSelect.value = 5;
    const historySelect = document.getElementById("set-chart-history");
    if (historySelect) historySelect.value = 20;

    Telemetry.resumePolling();
    Telemetry.setPollingInterval(5);
    Telemetry.setMaxPoints(20);
    this.updatePollingStatusCard();
    this.saveSettings(true);
  },

  async resetNotifications() {
    const confirmed = await Utils.showConfirm({
      title: "Reset Notification Preferences",
      message: "Are you sure you want to reset all notification category and severity preferences to defaults?",
      confirmText: "Reset Defaults",
      cancelText: "Cancel",
      type: "warning"
    });
    if (!confirmed) return;
    const setC = (id, val) => { const el = document.getElementById(id); if (el) el.checked = val; };
    setC("set-notif-master", true);
    setC("set-notif-sec", true);
    setC("set-notif-crit", true);
    setC("set-notif-net", true);
    setC("set-notif-qos", true);
    setC("set-notif-inc", true);
    setC("set-notif-sys", true);
    setC("set-notif-audit", true);

    setC("set-sev-crit", true);
    setC("set-sev-high", true);
    setC("set-sev-med", true);
    setC("set-sev-low", true);
    setC("set-sev-info", true);

    setC("set-notif-sound", false);
    setC("set-notif-quiet", false);
    setC("set-notif-mark-read", true);

    this.saveSettings(true);
    if (window.Notifications) Notifications.fetchNotifications();
  },

  scheduleAutoSave() {
    if (this.autoSaveTimer) clearTimeout(this.autoSaveTimer);
    this.autoSaveTimer = setTimeout(() => {
      this.saveSettings(false);
    }, 400);
  },

  async saveSettings(showToast = false) {
    const saveBtn = document.getElementById("save-settings-btn");
    const indicator = document.getElementById("settings-saved-indicator");

    if (saveBtn) {
      saveBtn.disabled = true;
      saveBtn.textContent = "Saving...";
    }

    const theme = document.getElementById("set-theme") ? document.getElementById("set-theme").value : "dark";
    const accent = document.getElementById("set-accent") ? document.getElementById("set-accent").value : "cyan";
    const density = document.getElementById("set-density") ? document.getElementById("set-density").value : "comfortable";
    const reduceMotion = document.getElementById("set-reduce-motion") ? document.getElementById("set-reduce-motion").checked : false;

    const autoRefresh = document.getElementById("set-auto-refresh") ? document.getElementById("set-auto-refresh").checked : true;
    const refreshInterval = parseInt(document.getElementById("set-refresh-interval") ? document.getElementById("set-refresh-interval").value : 5) || 5;
    const chartHistory = parseInt(document.getElementById("set-chart-history") ? document.getElementById("set-chart-history").value : 20) || 20;

    const fullName = document.getElementById("set-full-name") ? document.getElementById("set-full-name").value.trim() : "";

    const getC = (id, def = true) => { const el = document.getElementById(id); return el ? el.checked : def; };

    const payload = {
      appearance: { theme, accent, density, reduce_motion: reduceMotion },
      dashboard: { auto_refresh: autoRefresh, refresh_interval: refreshInterval, chart_history: chartHistory },
      notifications: {
        master_enabled: getC("set-notif-master", true),
        security_alerts: getC("set-notif-sec", true),
        critical_threats: getC("set-notif-crit", true),
        network_events: getC("set-notif-net", true),
        qos_alerts: getC("set-notif-qos", true),
        incident_updates: getC("set-notif-inc", true),
        system_alerts: getC("set-notif-sys", true),
        audit_alerts: getC("set-notif-audit", true),
        severity_critical: getC("set-sev-crit", true),
        severity_high: getC("set-sev-high", true),
        severity_medium: getC("set-sev-med", true),
        severity_low: getC("set-sev-low", true),
        severity_info: getC("set-sev-info", true),
        sound_enabled: getC("set-notif-sound", false),
        quiet_mode: getC("set-notif-quiet", false),
        mark_read_on_click: getC("set-notif-mark-read", true)
      }
    };

    try {
      await API.put("/api/user/settings", payload);

      if (fullName && Auth.currentUser && fullName !== Auth.currentUser.full_name) {
        await API.put("/api/user/profile", { full_name: fullName });
        Auth.currentUser.full_name = fullName;
        Auth.updateUI();
      }

      this.currentSettings = payload;
      this.applyAppearance({ theme, accent, density, reduce_motion: reduceMotion });

      if (indicator) {
        indicator.classList.add("visible");
        setTimeout(() => indicator.classList.remove("visible"), 2500);
      }

      if (showToast) {
        Utils.showToast("Preferences saved successfully!", "success");
      }
    } catch (err) {
      Utils.showToast(`Failed to save settings: ${err.message}`, "danger");
    } finally {
      if (saveBtn) {
        saveBtn.disabled = false;
        saveBtn.textContent = "Save Preferences";
      }
    }
  },

  async changePassword(event) {
    if (event) event.preventDefault();
    const currentPwdInput = document.getElementById("set-current-password");
    const newPwdInput = document.getElementById("set-new-password");
    const confirmPwdInput = document.getElementById("set-confirm-password");
    const btn = document.getElementById("btn-change-password");
    const statusEl = document.getElementById("change-password-status-msg");

    const currentPassword = currentPwdInput ? currentPwdInput.value : "";
    const newPassword = newPwdInput ? newPwdInput.value : "";
    const confirmPassword = confirmPwdInput ? confirmPwdInput.value : "";

    if (!currentPassword || !newPassword) {
      Utils.showToast("Current and new passwords are required.", "danger");
      return;
    }

    const hasLen = newPassword.length >= 8;
    const hasUpper = /[A-Z]/.test(newPassword);
    const hasLower = /[a-z]/.test(newPassword);
    const hasNum = /[0-9]/.test(newPassword);
    const hasSpecial = /[^A-Za-z0-9]/.test(newPassword);

    const missing = [];
    if (!hasLen) missing.push("minimum 8 characters");
    if (!hasUpper) missing.push("uppercase letter");
    if (!hasLower) missing.push("lowercase letter");
    if (!hasNum) missing.push("number");
    if (!hasSpecial) missing.push("special character");

    if (missing.length > 0) {
      const missingMsg = "New password must include at least one " + missing.join(", ") + ".";
      Utils.showToast(missingMsg, "danger");
      if (statusEl) {
        statusEl.style.display = "block";
        statusEl.style.color = "var(--status-danger)";
        statusEl.textContent = missingMsg;
      }
      if (newPwdInput) newPwdInput.focus();
      return;
    }

    if (newPassword !== confirmPassword) {
      Utils.showToast("New passwords do not match.", "danger");
      return;
    }

    if (btn) {
      btn.disabled = true;
      btn.textContent = "Updating Password...";
    }

    try {
      const res = await API.post("/api/auth/change-password", {
        current_password: currentPassword,
        new_password: newPassword,
        confirm_password: confirmPassword
      });

      const msg = (res && res.message) || "Password changed successfully.";
      Utils.showToast(msg, "success");

      if (currentPwdInput) currentPwdInput.value = "";
      if (newPwdInput) newPwdInput.value = "";
      if (confirmPwdInput) confirmPwdInput.value = "";

      if (statusEl) {
        statusEl.style.display = "block";
        statusEl.style.color = "var(--status-success)";
        statusEl.textContent = "Password changed successfully. Security confirmation email sent.";
        setTimeout(() => { statusEl.style.display = "none"; }, 5000);
      }
    } catch (err) {
      const errMsg = (err && err.message) || "Failed to change password.";
      Utils.showToast(errMsg, "danger");
      if (statusEl) {
        statusEl.style.display = "block";
        statusEl.style.color = "var(--status-danger)";
        statusEl.textContent = errMsg;
      }
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Update Password";
      }
    }
  }
};
