/**
 * VORTEX-SDN Authentication & User Session Manager
 * Dynamically binds authenticated user identity to all views and enforces role permissions.
 * Supports Single Administrator, Approval-Based Operator, and Read-Only Reader roles.
 */

const Auth = {
  currentUser: null,
  _authSeq: 0,

  async init() {
    const path = window.location.pathname;
    const publicPages = ["login", "register", "verify-email", "forgot-password", "reset-password"];
    const isPublic = publicPages.some(p => path.includes(p));
    const currentSeq = ++this._authSeq;

    try {
      const data = await API.get("/api/auth/me");
      if (currentSeq !== this._authSeq) return null; // Discard stale out-of-order responses

      if (data && data.authenticated && data.user) {
        this.currentUser = data.user;
        State.setAuth({ isAuthenticated: true, token: API.getToken(), user: data.user, version: currentSeq });
        State.setUserPresence({ status: "ONLINE", label: "ONLINE", version: currentSeq });
        this.updateUI();

        // If ADMIN, initialize Admin controller
        if (data.user.role === "ADMIN" && typeof Admin !== "undefined") {
          Admin.init();
        }

        return this.currentUser;
      } else {
        State.setAuth({ isAuthenticated: false, token: null, user: null, version: currentSeq });
        State.setUserPresence({ status: "OFFLINE", label: "OFFLINE", version: currentSeq });
        if (!isPublic) {
          API.clearToken();
          window.location.href = "login.html";
          return null;
        }
      }
    } catch (err) {
      if (currentSeq !== this._authSeq) return null;
      console.warn("[Auth] Profile fetch error:", err);
      if (err.status === 401 && !isPublic) {
        State.setAuth({ isAuthenticated: false, token: null, user: null, version: currentSeq });
        State.setUserPresence({ status: "OFFLINE", label: "OFFLINE", version: currentSeq });
        API.clearToken();
        window.location.href = "login.html";
        return null;
      }
      if (API.getToken() && !isPublic) {
        State.setUserPresence({ status: "ONLINE", label: "ONLINE", version: currentSeq });
      }
    }
  },

  updateUI() {
    if (!this.currentUser) return;

    const fullName = this.currentUser.full_name || this.currentUser.name || this.currentUser.username || "Operator";
    const username = this.currentUser.username || "";
    const email = this.currentUser.email || "";
    const role = this.currentUser.role || "READER";

    // 1. Dynamic User Name across all elements
    const nameEls = document.querySelectorAll(".dynamic-user-name");
    nameEls.forEach(el => {
      if (el.tagName === "INPUT") {
        el.value = fullName;
      } else {
        el.textContent = fullName;
      }
    });

    // 2. Dynamic User Role across all elements
    const roleEls = document.querySelectorAll(".dynamic-user-role");
    roleEls.forEach(el => {
      if (el.tagName === "INPUT") {
        el.value = role;
      } else {
        el.textContent = role;
      }
    });

    // 3. Dynamic User Avatar Circle Initials
    const avatarEls = document.querySelectorAll(".dynamic-user-avatar");
    avatarEls.forEach(el => {
      const nameParts = fullName.trim().split(/\s+/).filter(Boolean);
      let initials = "";
      if (nameParts.length >= 2) {
        initials = (nameParts[0][0] + nameParts[nameParts.length - 1][0]).toUpperCase();
      } else if (nameParts.length === 1 && nameParts[0].length >= 2) {
        initials = nameParts[0].substring(0, 2).toUpperCase();
      } else if (nameParts.length === 1) {
        initials = nameParts[0][0].toUpperCase();
      } else {
        initials = role === "ADMIN" ? "AD" : (role === "OPERATOR" ? "OP" : "RD");
      }
      el.textContent = initials;
    });

    // 4. Dynamic Email Displays
    const emailEls = document.querySelectorAll(".dynamic-user-email");
    emailEls.forEach(el => {
      if (el.tagName === "INPUT") {
        el.value = email;
      } else {
        el.textContent = email;
      }
    });

    // 5. Dynamic User Presence Badges
    const statusEls = document.querySelectorAll(".dynamic-user-status");
    statusEls.forEach(el => {
      const isOnline = State.userPresence && State.userPresence.status === "ONLINE";
      el.textContent = isOnline ? "ONLINE" : "OFFLINE";
      if (el.classList.contains("badge")) {
        el.classList.remove("badge-live", "badge-critical", "badge-demo", "badge-warning");
        el.classList.add(isOnline ? "badge-live" : "badge-critical");
      }
    });

    // 5b. Dedicated Topbar Authenticated User Presence Pill
    const userPill = document.getElementById("status-user");
    if (userPill) {
      const isOnline = State.userPresence && State.userPresence.status === "ONLINE";
      userPill.innerHTML = `
        <span class="status-dot ${isOnline ? 'green' : 'red'}"></span>
        <span>${isOnline ? 'USER ONLINE' : 'USER OFFLINE'}</span>
      `;
    }

    // 6. Dashboard Hero Welcome Banner
    const welcomeEl = document.getElementById("hero-welcome-username");
    if (welcomeEl) {
      welcomeEl.textContent = fullName;
    }
    const greetingEl = document.getElementById("hero-greeting-text");
    if (greetingEl) {
      const h = new Date().getHours();
      greetingEl.textContent = h < 12 ? "Good morning" : (h < 18 ? "Good afternoon" : "Good evening");
    }

    // 7. Settings Inputs
    const setFullName = document.getElementById("set-full-name");
    if (setFullName) setFullName.value = fullName;
    const setEmail = document.getElementById("set-email");
    if (setEmail) setEmail.value = email;

    // 8. Enforce Role Permissions
    // Admin only elements
    const adminOnlyEls = document.querySelectorAll(".role-admin-only");
    adminOnlyEls.forEach(el => {
      el.style.display = role === "ADMIN" ? "" : "none";
    });

    // Operator & Admin only elements
    const operatorOnlyEls = document.querySelectorAll(".role-operator-only");
    operatorOnlyEls.forEach(el => {
      el.style.display = (role === "ADMIN" || role === "OPERATOR") ? "" : "none";
    });

    // Strict Reader Read-Only Enforcement in UI
    const isReader = (role === "READER" || role === "VIEWER");
    if (isReader) {
      // Disable mitigation buttons
      const mitBtns = document.querySelectorAll(".btn-mitigate-trigger");
      mitBtns.forEach(btn => {
        btn.disabled = true;
        btn.title = "Reader accounts have read-only access";
        btn.classList.add("disabled");
      });

      // Disable or hide scenario trigger buttons
      const simBtns = document.querySelectorAll(".btn-sim-trigger");
      simBtns.forEach(btn => {
        btn.disabled = true;
        btn.title = "Reader accounts cannot alter network simulation scenarios";
      });

      // Hide or disable policy create buttons
      const policyCreateBtns = document.querySelectorAll(".btn-policy-create");
      policyCreateBtns.forEach(btn => {
        btn.disabled = true;
        btn.title = "Reader accounts cannot create policies";
      });
    }

    // 9. Synchronize Role Access Tier and Operator Request Display
    this.updateAccessTierDisplay();
  },

  updateAccessTierDisplay() {
    if (!this.currentUser) return;
    const box = document.getElementById("operator-request-box");
    const btn = document.getElementById("btn-request-operator");
    const title = document.getElementById("op-req-status-title");
    const desc = document.getElementById("op-req-status-desc");
    if (!box || !title || !desc) return;

    const role = (this.currentUser.role || "").toUpperCase();

    if (role === "ADMIN") {
      box.style.display = "block";
      box.style.background = "rgba(239, 68, 68, 0.08)";
      box.style.borderColor = "rgba(239, 68, 68, 0.25)";
      title.innerHTML = 'Access Tier: <span class="badge" style="background:rgba(239,68,68,0.2);color:#ef4444;border:1px solid rgba(239,68,68,0.4);">ADMIN</span>';
      desc.textContent = "Full platform administration, policy management, user management, security controls and audit access.";
      if (btn) btn.style.display = "none";
      return;
    }

    if (role === "OPERATOR") {
      box.style.display = "block";
      box.style.background = "rgba(14, 165, 233, 0.08)";
      box.style.borderColor = "rgba(14, 165, 233, 0.25)";
      title.innerHTML = 'Access Tier: <span class="badge badge-info">OPERATOR</span>';
      desc.textContent = "Approved operational access based on administrator-granted permissions.";
      if (btn) btn.style.display = "none";
      return;
    }

    // READER / VIEWER role: check dynamic request status
    box.style.display = "block";
    box.style.background = "rgba(148, 163, 184, 0.08)";
    box.style.borderColor = "rgba(148, 163, 184, 0.2)";
    this.checkOperatorRequestStatus();
  },

  _cooldownInterval: null,
  startCooldownTimer(seconds) {
    const btn = document.getElementById("btn-request-operator");
    if (!btn) return;
    if (this._cooldownInterval) clearInterval(this._cooldownInterval);

    let remaining = seconds;
    btn.disabled = true;
    btn.textContent = `Resend Request (${remaining}s)`;

    this._cooldownInterval = setInterval(() => {
      remaining -= 1;
      if (remaining <= 0) {
        clearInterval(this._cooldownInterval);
        this._cooldownInterval = null;
        btn.disabled = false;
        btn.textContent = "Resend Request";
      } else {
        btn.textContent = `Resend Request (${remaining}s)`;
      }
    }, 1000);
  },

  async checkOperatorRequestStatus() {
    try {
      const box = document.getElementById("operator-request-box");
      const btn = document.getElementById("btn-request-operator");
      const title = document.getElementById("op-req-status-title");
      const desc = document.getElementById("op-req-status-desc");

      if (!box || !btn || !title || !desc) return;
      const userRole = (this.currentUser && this.currentUser.role ? this.currentUser.role : "").toUpperCase();
      if (userRole === "ADMIN" || userRole === "OPERATOR") {
        btn.style.display = "none";
        return;
      }

      const res = await API.get("/api/auth/operator-request/status");
      const status = (res && res.status ? res.status : "NONE").toUpperCase();

      if (status === "PENDING") {
        title.innerHTML = 'Access Tier: <span class="badge badge-warning">OPERATOR REQUEST PENDING</span>';
        desc.textContent = "Operator access request is pending approval.";
        btn.style.display = "inline-flex";
        btn.className = "btn btn-secondary btn-sm";
        btn.onclick = () => Auth.resendOperatorRequest();

        const cooldownRemaining = (res && res.cooldown_remaining) || 0;
        if (cooldownRemaining > 0) {
          btn.disabled = true;
          this.startCooldownTimer(cooldownRemaining);
        } else {
          btn.disabled = false;
          btn.textContent = "Resend Request";
        }
      } else {
        // READER role with REVOKED, REJECTED, NONE, or inactive state
        title.innerHTML = 'Access Tier: <span class="badge badge-secondary">READER</span>';
        desc.textContent = "Read-only NOC observability.";
        btn.style.display = "inline-flex";
        btn.className = "btn btn-primary btn-sm";
        btn.disabled = false;
        btn.textContent = "Request Operator Access";
        btn.onclick = () => Auth.requestOperatorAccess();
      }
    } catch (e) {
      console.warn("[Auth] Could not check operator request status:", e);
      const btn = document.getElementById("btn-request-operator");
      const userRole = (this.currentUser && this.currentUser.role ? this.currentUser.role : "").toUpperCase();
      if (btn && userRole !== "ADMIN" && userRole !== "OPERATOR") {
        btn.style.display = "inline-flex";
        btn.className = "btn btn-primary btn-sm";
        btn.disabled = false;
        btn.textContent = "Request Operator Access";
        btn.onclick = () => Auth.requestOperatorAccess();
      }
    }
  },

  async resendOperatorRequest() {
    const btn = document.getElementById("btn-request-operator");
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Resending...";
    }

    try {
      const res = await API.post("/api/auth/operator-request/resend", {});
      Utils.showToast(res.message || "Operator access request notification resent to administrator.", "success");
      await this.checkOperatorRequestStatus();
    } catch (err) {
      const msg = (err.data && err.data.message) || err.message || "Please wait before resending the operator access request.";
      Utils.showToast(msg, "warning");
      const retryAfter = (err.data && err.data.retry_after) || 60;
      this.startCooldownTimer(retryAfter);
    }
  },

  async requestOperatorAccess() {
    const btn = document.getElementById("btn-request-operator");
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Submitting...";
    }

    try {
      const res = await API.post("/api/auth/operator-request", {});
      Utils.showToast(res.message || "Operator access request submitted.", "success");
      await this.checkOperatorRequestStatus();
    } catch (err) {
      if (err.status === 409 || (err.data && err.data.status === "PENDING")) {
        Utils.showToast((err.data && err.data.message) || "Operator access request is pending approval.", "info");
        await this.checkOperatorRequestStatus();
        return;
      }
      const msg = (err.data && err.data.message) || err.message || "Failed to submit request.";
      Utils.showToast(msg, "danger");
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Request Operator Access";
      }
    }
  },

  async login(identifier, password, remember = true) {
    const currentSeq = ++this._authSeq;
    const data = await API.post("/api/auth/login", {
      username: identifier,
      email: identifier,
      password: password
    });
    if (data.token && data.user) {
      API.setToken(data.token, remember);
      this.currentUser = data.user;
      State.setAuth({ isAuthenticated: true, token: data.token, user: data.user, version: currentSeq });
      State.setUserPresence({ status: "ONLINE", label: "ONLINE", version: currentSeq });
      this.updateUI();
      Utils.showToast(`Authenticated as ${data.user.full_name}`, "success");
      return data;
    }
    throw new Error(data.message || "Login failed.");
  },

  async logout() {
    const currentSeq = ++this._authSeq;
    try {
      await API.post("/api/auth/logout");
    } catch (e) {
      // Continue cleanup on network failure
    }
    API.clearToken();
    this.currentUser = null;
    State.setAuth({ isAuthenticated: false, token: null, user: null, version: currentSeq });
    State.setUserPresence({ status: "OFFLINE", label: "OFFLINE", version: currentSeq });
    window.location.href = "login.html";
  }
};

// Reactively keep #status-user updated without touching any other subsystems
if (typeof State !== "undefined" && typeof State.subscribe === "function") {
  State.subscribe("userPresence:updated", (presence) => {
    const userPill = document.getElementById("status-user");
    if (userPill) {
      const isOnline = presence && presence.status === "ONLINE";
      userPill.innerHTML = `
        <span class="status-dot ${isOnline ? 'green' : 'red'}"></span>
        <span>${isOnline ? 'USER ONLINE' : 'USER OFFLINE'}</span>
      `;
    }
  });
}
