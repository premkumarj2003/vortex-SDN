/**
 * VORTEX-SDN Administrator Access Control & Operator Approval Controller
 * Manages pending operator requests, active users directory, granular permissions,
 * and user enablement states strictly for the single platform administrator.
 */

const Admin = {
  requests: [],
  users: [],
  allPermissions: [],
  currentModalUserId: null,
  _loadingPromise: null,

  async init() {
    if (!Auth.currentUser || Auth.currentUser.role !== "ADMIN") return;
    await this.loadData();
  },

  async loadData() {
    if (this._loadingPromise) {
      return this._loadingPromise;
    }
    this._loadingPromise = this._fetchAdminData();
    try {
      await this._loadingPromise;
    } finally {
      this._loadingPromise = null;
    }
  },

  async _fetchAdminData() {
    const reqTbody = document.getElementById("admin-requests-tbody");
    const userTbody = document.getElementById("admin-users-tbody");

    if (reqTbody && (!this.requests || this.requests.length === 0)) {
      reqTbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding: 20px; color: var(--text-muted);">Loading pending requests...</td></tr>`;
    }
    if (userTbody && (!this.users || this.users.length === 0)) {
      userTbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding: 20px; color: var(--text-muted);">Loading user records...</td></tr>`;
    }

    try {
      const [reqRes, userRes, permRes] = await Promise.allSettled([
        API.get("/api/admin/operator-requests"),
        API.get("/api/admin/users"),
        API.get("/api/admin/permissions")
      ]);

      // 1. Process Operator Requests
      if (reqRes.status === "fulfilled" && reqRes.value) {
        const val = reqRes.value;
        this.requests = (val.requests || val.data) || (Array.isArray(val) ? val : []);
        this.renderRequests(this.requests);
      } else {
        console.error("[Admin] Failed to load operator requests:", reqRes.reason);
        if (reqTbody) {
          const errMsg = reqRes.reason && reqRes.reason.message ? reqRes.reason.message : "Check server/API response.";
          reqTbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding: 24px; color: var(--status-danger);">Unable to load pending operator requests. ${Utils.escapeHtml(errMsg)}</td></tr>`;
        }
      }

      // 2. Process Users Directory
      if (userRes.status === "fulfilled" && userRes.value) {
        const val = userRes.value;
        this.users = (val.users || val.data) || (Array.isArray(val) ? val : []);
        this.renderUsers(this.users);
      } else {
        console.error("[Admin] Failed to load users directory:", userRes.reason);
        if (userTbody) {
          const errMsg = userRes.reason && userRes.reason.message ? userRes.reason.message : "Check server/API response.";
          userTbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding: 24px; color: var(--status-danger);">Unable to load platform users directory. ${Utils.escapeHtml(errMsg)}</td></tr>`;
        }
      }

      // 3. Process Permissions Catalog
      if (permRes.status === "fulfilled" && permRes.value) {
        const val = permRes.value;
        this.allPermissions = (val.permissions || val.data) || (Array.isArray(val) ? val : []);
      }

      this.updateBadges();
    } catch (err) {
      console.error("[Admin] Error loading admin data:", err);
      Utils.showToast("Unable to load access control data: " + (err.message || "Server error"), "danger");
    }
  },

  updateBadges() {
    const pendingCount = this.requests.filter(r => (r.status || "").toUpperCase() === "PENDING").length;
    const pendingBadge = document.getElementById("admin-pending-badge");
    if (pendingBadge) {
      pendingBadge.textContent = `${pendingCount} PENDING`;
    }

    const navBadge = document.getElementById("pending-requests-count-badge");
    if (navBadge) {
      navBadge.textContent = pendingCount;
      navBadge.style.display = pendingCount > 0 ? "inline-block" : "none";
    }

    const usersBadge = document.getElementById("admin-users-count-badge");
    if (usersBadge) {
      usersBadge.textContent = `${this.users.length} USERS`;
    }
  },

  renderRequests(requests) {
    const tbody = document.getElementById("admin-requests-tbody");
    if (!tbody) return;

    const pending = (requests || []).filter(r => (r.status || "").toUpperCase() === "PENDING");
    this.updateBadges();

    if (pending.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding: 24px; color: var(--text-muted);">No pending operator requests.</td></tr>`;
      return;
    }

    tbody.innerHTML = pending.map(r => {
      const reqDate = r.requested_at ? Utils.formatDateTime(r.requested_at) : "--";
      const requesterName = r.full_name || r.name || r.username || "Operator Applicant";
      return `
        <tr id="req-row-${Utils.escapeHtml(r.id)}">
          <td>
            <div class="user-identity-cell" title="${Utils.escapeHtml(requesterName)}">${Utils.escapeHtml(requesterName)}</div>
          </td>
          <td class="mono user-email-cell" title="${Utils.escapeHtml(r.email || "")}">${Utils.escapeHtml(r.email || "")}</td>
          <td class="user-date-cell">${reqDate}</td>
          <td><span class="badge badge-warning">PENDING</span></td>
          <td class="user-client-cell">
            <div class="client-ip-text">${Utils.escapeHtml(r.client_ip || "127.0.0.1")}</div>
            <div class="client-device-sub" title="${Utils.escapeHtml(r.user_agent || "Web Browser")}">${Utils.escapeHtml(r.user_agent || "Web Browser")}</div>
          </td>
          <td class="user-actions-cell">
            <div class="admin-actions-cell">
              <button id="btn-approve-${Utils.escapeHtml(r.id)}" class="btn btn-primary btn-xs" onclick="Admin.approve('${Utils.escapeHtml(r.id)}')">
                APPROVE
              </button>
              <button id="btn-reject-${Utils.escapeHtml(r.id)}" class="btn btn-secondary btn-xs btn-reject" onclick="Admin.reject('${Utils.escapeHtml(r.id)}')">
                REJECT
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join("");
  },

  async approve(requestId) {
    const req = (this.operatorRequests || []).find(r => r.id === requestId);
    const applicant = (req && (req.full_name || req.email || req.username)) || "this applicant";

    const confirmed = await Utils.showConfirm({
      title: "Approve Operator Access",
      message: `Are you sure you want to approve Operator privileges for ${applicant}? They will gain operational control over policies and flow rules.`,
      confirmText: "Approve",
      cancelText: "Cancel",
      type: "info"
    });
    if (!confirmed) return;

    const btn = document.getElementById(`btn-approve-${requestId}`);
    if (btn) {
      btn.disabled = true;
      btn.textContent = "APPROVING...";
    }

    try {
      const res = await API.post(`/api/admin/operator-requests/${requestId}/approve`, {});
      Utils.showToast(res.message || "Operator request approved successfully.", "success");
      await this.loadData();
    } catch (err) {
      console.error("[Admin] Approve failed:", err);
      Utils.showToast(err.message || "Failed to approve request.", "danger");
      if (btn) {
        btn.disabled = false;
        btn.textContent = "APPROVE";
      }
    }
  },

  async reject(requestId) {
    const req = (this.operatorRequests || []).find(r => r.id === requestId);
    const applicant = (req && (req.full_name || req.email || req.username)) || "this applicant";

    const reason = await Utils.showPrompt({
      title: "Reject Operator Request",
      message: `Specify reason for rejecting operator request from ${applicant} (optional):`,
      defaultValue: "Request rejected by Administrator",
      placeholder: "Enter reason for rejection...",
      confirmText: "Reject Request",
      cancelText: "Cancel",
      type: "danger",
      destructive: true
    });
    if (reason === null) return; // User cancelled prompt

    const btn = document.getElementById(`btn-reject-${requestId}`);
    if (btn) {
      btn.disabled = true;
      btn.textContent = "REJECTING...";
    }

    try {
      const res = await API.post(`/api/admin/operator-requests/${requestId}/reject`, {
        reason: (reason || "").trim() || "Request rejected by Administrator"
      });
      Utils.showToast(res.message || "Operator request rejected.", "info");
      await this.loadData();
    } catch (err) {
      console.error("[Admin] Reject failed:", err);
      Utils.showToast(err.message || "Failed to reject request.", "danger");
      if (btn) {
        btn.disabled = false;
        btn.textContent = "REJECT";
      }
    }
  },

  renderUsers(users) {
    const tbody = document.getElementById("admin-users-tbody");
    if (!tbody) return;

    const usersBadge = document.getElementById("admin-users-count-badge");
    if (usersBadge) {
      usersBadge.textContent = `${(users || []).length} USERS`;
    }

    if (!users || users.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding: 24px; color: var(--text-muted);">No users found.</td></tr>`;
      return;
    }

    tbody.innerHTML = users.map(u => {
      const isSelf = Auth.currentUser && Auth.currentUser.id === u.id;
      const isAdmin = u.role === "ADMIN";
      const isOperator = u.role === "OPERATOR";
      const isReader = u.role === "READER" || u.role === "VIEWER";

      const roleBadge = isAdmin
        ? '<span class="badge" style="background:rgba(239,68,68,0.18);color:#ef4444;border:1px solid rgba(239,68,68,0.4);">ADMIN</span>'
        : (isOperator
          ? '<span class="badge badge-info">OPERATOR</span>'
          : '<span class="badge badge-secondary">READER</span>');

      const isActive = (u.is_active === 1 || u.is_active === true || u.is_active === "1");
      const statusPill = isActive
        ? '<span class="status-dot green"></span> <span style="font-size:11.5px;color:#10b981;">Active</span>'
        : '<span class="status-dot red"></span> <span style="font-size:11.5px;color:#ef4444;">Disabled</span>';

      const isVerified = (u.email_verified === 1 || u.email_verified === true || u.email_verified === "1");
      const emailVerifPill = isVerified
        ? '<span style="color:#10b981;font-size:11.5px;">✓ Verified</span>'
        : '<span style="color:#f59e0b;font-size:11.5px;">Pending</span>';

      // Permissions preview
      let permSummary = "";
      if (isAdmin) {
        permSummary = '<span style="font-size:11px;color:var(--accent-cyan);">Full System Access (*)</span>';
      } else if (u.permissions && u.permissions.length > 0) {
        const modCount = u.permissions.filter(p => !p.endsWith(".view") && p !== "*").length;
        permSummary = `<span style="font-size:11px;color:#94a3b8;">${u.permissions.length} perms (${modCount} control)</span>`;
      } else {
        permSummary = '<span style="font-size:11px;color:var(--text-disabled);">Read-Only (Default)</span>';
      }

      // Action buttons
      let actionBtns = "";
      if (!isAdmin) {
        actionBtns += `
          <button class="btn btn-secondary btn-xs" onclick="Admin.openPermissionsModal('${Utils.escapeHtml(u.id)}')" title="Manage Permissions">
            Permissions
          </button>
        `;

        if (isOperator) {
          actionBtns += `
            <button class="btn btn-secondary btn-xs btn-revoke" onclick="Admin.revokeOperator('${Utils.escapeHtml(u.id)}')" title="Revoke Operator Access">
              Revoke
            </button>
          `;
        }

        const disableLabel = isActive ? "Disable" : "Enable";
        const disableClass = isActive ? "btn-disable" : "btn-enable";
        actionBtns += `
          <button id="btn-toggle-${Utils.escapeHtml(u.id)}" class="btn btn-secondary btn-xs ${disableClass}" onclick="Admin.toggleStatus('${Utils.escapeHtml(u.id)}')" title="${disableLabel} Account">
            ${disableLabel}
          </button>
          <button class="btn btn-danger btn-xs" onclick="Admin.deleteUser('${Utils.escapeHtml(u.id)}', '${Utils.escapeHtml(u.username)}')" title="Delete Account">
            Delete
          </button>
        `;
      } else {
        actionBtns = `<span class="protected-admin-label">(Protected Admin)</span>`;
      }

      return `
        <tr id="user-row-${Utils.escapeHtml(u.id)}">
          <td>
            <div class="user-identity-cell" title="${Utils.escapeHtml(u.full_name || u.username)}">${Utils.escapeHtml(u.full_name || u.username)}</div>
            <div class="user-username-sub" title="${Utils.escapeHtml(u.username)}">${Utils.escapeHtml(u.username)}</div>
          </td>
          <td class="mono user-email-cell" title="${Utils.escapeHtml(u.email)}">${Utils.escapeHtml(u.email)}</td>
          <td>${roleBadge}</td>
          <td>${statusPill}</td>
          <td>${emailVerifPill}</td>
          <td class="user-perm-cell" title="${isAdmin ? 'Full System Access (*)' : (u.permissions ? u.permissions.join(', ') : 'Read-Only')}">${permSummary}</td>
          <td class="user-actions-cell">
            <div class="admin-actions-cell">${actionBtns}</div>
          </td>
        </tr>
      `;
    }).join("");
  },

  filterUsers(query) {
    const q = (query || "").trim().toLowerCase();
    if (!q) {
      this.renderUsers(this.users);
      return;
    }
    const filtered = this.users.filter(u =>
      (u.full_name && u.full_name.toLowerCase().includes(q)) ||
      (u.username && u.username.toLowerCase().includes(q)) ||
      (u.email && u.email.toLowerCase().includes(q))
    );
    this.renderUsers(filtered);
  },

  async openPermissionsModal(userId) {
    this.currentModalUserId = userId;
    const user = this.users.find(u => u.id === userId);
    if (!user) return;

    document.getElementById("admin-modal-username").textContent = user.full_name || user.username;
    document.getElementById("admin-modal-useremail").textContent = `${user.email} • Current Role: ${user.role}`;

    try {
      const res = await API.get(`/api/admin/users/${userId}/permissions`);
      const userPerms = (res && res.permissions) || [];

      const container = document.getElementById("admin-modal-perms-container");
      if (container) {
        container.innerHTML = this.allPermissions.map(p => {
          const isChecked = userPerms.includes(p.name);
          const isView = p.name.endsWith(".view");
          const tagClass = isView ? "color:var(--accent-cyan);" : "color:#f59e0b;";

          return `
            <label style="display:flex; align-items:flex-start; gap:8px; padding:8px 10px; background:rgba(255,255,255,0.02); border:1px solid var(--border-subtle); border-radius:6px; cursor:pointer;">
              <input type="checkbox" class="admin-perm-checkbox" value="${Utils.escapeHtml(p.name)}" ${isChecked ? "checked" : ""} style="margin-top:3px;">
              <div>
                <div style="font-size:12px; font-weight:600; color:#ffffff;">
                  ${Utils.escapeHtml(p.name)}
                  <span style="font-size:10px; margin-left:4px; ${tagClass}">[${Utils.escapeHtml(p.category)}]</span>
                </div>
                <div style="font-size:11px; color:var(--text-muted); line-height:1.3; margin-top:2px;">
                  ${Utils.escapeHtml(p.description)}
                </div>
              </div>
            </label>
          `;
        }).join("");
      }

      const modal = document.getElementById("admin-permissions-modal");
      if (modal) modal.classList.add("active");
    } catch (err) {
      console.error("[Admin] Could not load user permissions:", err);
      Utils.showToast("Could not load user permissions.", "danger");
    }
  },

  closePermissionsModal() {
    this.currentModalUserId = null;
    const modal = document.getElementById("admin-permissions-modal");
    if (modal) modal.classList.remove("active");
  },

  async savePermissions() {
    if (!this.currentModalUserId) return;
    const checkboxes = document.querySelectorAll(".admin-perm-checkbox:checked");
    const selected = Array.from(checkboxes).map(cb => cb.value);

    const btn = document.getElementById("admin-modal-save-btn");
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Saving...";
    }

    try {
      const res = await API.post(`/api/admin/users/${this.currentModalUserId}/permissions`, {
        permissions: selected
      });
      Utils.showToast(res.message || "Permissions updated successfully.", "success");
      this.closePermissionsModal();
      await this.loadData();
    } catch (err) {
      console.error("[Admin] Save permissions failed:", err);
      Utils.showToast(err.message || "Failed to update permissions.", "danger");
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Save Permissions";
      }
    }
  },

  async toggleStatus(userId) {
    const user = (this.users || []).find(u => u.id === userId);
    const username = (user && (user.username || user.full_name)) || "this user";
    const willDisable = user ? user.is_active : true;
    const actionLabel = willDisable ? "Disable" : "Enable";

    const confirmed = await Utils.showConfirm({
      title: `${actionLabel} User Account`,
      message: willDisable 
        ? `Are you sure you want to disable account '${username}'? The user will be blocked from logging into VORTEX-SDN.`
        : `Are you sure you want to enable account '${username}'? User login access will be restored.`,
      confirmText: actionLabel,
      cancelText: "Cancel",
      type: willDisable ? "warning" : "info",
      destructive: willDisable
    });
    if (!confirmed) return;

    const btn = document.getElementById(`btn-toggle-${userId}`);
    if (btn) {
      btn.disabled = true;
    }

    try {
      const res = await API.post(`/api/admin/users/${userId}/toggle-status`, {});
      Utils.showToast(res.message || `User ${willDisable ? 'disabled' : 'enabled'} successfully.`, "info");
      await this.loadData();
    } catch (err) {
      console.error("[Admin] Toggle status failed:", err);
      Utils.showToast(err.message || "Failed to toggle user status.", "danger");
      if (btn) {
        btn.disabled = false;
      }
    }
  },

  async revokeOperator(userId) {
    const user = (this.users || []).find(u => u.id === userId);
    const username = (user && (user.username || user.full_name)) || "this user";

    const confirmed = await Utils.showConfirm({
      title: "Revoke Operator Access",
      message: `Are you sure you want to revoke Operator privileges from '${username}'? This user will be downgraded to Reader and lose Operator privileges.`,
      confirmText: "Revoke Access",
      cancelText: "Cancel",
      type: "warning",
      destructive: true
    });
    if (!confirmed) return;

    try {
      const res = await API.post(`/api/admin/users/${userId}/revoke-operator`, {});
      Utils.showToast(res.message || "Operator privileges revoked.", "info");
      await this.loadData();
    } catch (err) {
      console.error("[Admin] Revoke operator failed:", err);
      Utils.showToast(err.message || "Failed to revoke operator access.", "danger");
    }
  },

  async deleteUser(userId, username) {
    const confirmed = await Utils.showConfirm({
      title: "Delete User Account",
      message: `Are you sure you want to permanently delete user '${username}'? This permanently removes the selected user account and cannot be undone.`,
      confirmText: "Delete User",
      cancelText: "Cancel",
      type: "danger",
      destructive: true
    });
    if (!confirmed) return;

    try {
      const res = await API.delete(`/api/admin/users/${userId}`);
      Utils.showToast(res.message || "User account deleted.", "info");
      await this.loadData();
    } catch (err) {
      console.error("[Admin] Delete user failed:", err);
      Utils.showToast(err.message || "Failed to delete user.", "danger");
    }
  }
};
