/**
 * VORTEX-SDN Policy Management View Controller (QoS and Security Policies CRUD)
 * Strictly enforces ADMIN-ONLY management in the UI:
 * - ADMIN: full visibility and control (Create, Edit, Delete, Enable/Disable)
 * - OPERATOR: Strictly VIEW ONLY (no management controls shown)
 * - READER: Strictly VIEW ONLY (no management controls shown)
 */

const Policies = {
  cachedData: null,
  _escBound: false,

  async init() {
    this.bindEvents();
    this.updateControlsVisibility();
    await this.fetchPolicies();
  },

  bindEvents() {
    if (!this._escBound) {
      this._escBound = true;
      document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
          const modal = document.getElementById("policy-modal");
          if (modal && modal.classList.contains("active")) {
            Policies.closeModal();
          }
        }
      });
    }
  },

  isAdmin() {
    return !!(typeof Auth !== "undefined" && Auth.currentUser && Auth.currentUser.role === "ADMIN");
  },

  updateControlsVisibility() {
    const admin = this.isAdmin();
    const createBtn = document.getElementById("btn-create-policy");
    if (createBtn) {
      createBtn.style.display = admin ? "inline-flex" : "none";
    }
  },

  async fetchPolicies() {
    this.updateControlsVisibility();
    try {
      const data = await API.get("/api/policies");
      this.cachedData = data;
      this.renderTables(data);
    } catch (err) {
      console.warn("[Policies] Error fetching:", err);
    }
  },

  renderTables(data) {
    const admin = this.isAdmin();

    const qosTbody = document.getElementById("pol-qos-tbody");
    if (qosTbody) {
      let html = "";
      (data.qos_policies || []).forEach(p => {
        const isActive = p.is_active === 1 || p.is_active === true || p.is_active === "1";
        const statusBadge = isActive
          ? `<span class="badge badge-live">ENABLED</span>`
          : `<span class="badge" style="background:#475569; color:#94a3b8;">DISABLED</span>`;

        let actionHtml = "";
        if (admin) {
          const toggleLabel = isActive ? "Disable" : "Enable";
          const toggleClass = isActive ? "btn-secondary" : "btn-primary";
          actionHtml = `
            <div style="display:flex; gap:4px; justify-content:flex-start; align-items:center;">
              <button class="btn btn-secondary btn-xs" style="font-size:11px; padding:3px 8px;" onclick="Policies.openEditModal('${Utils.escapeHtml(p.id)}')" title="Edit Policy">Edit</button>
              <button class="btn ${toggleClass} btn-xs" style="font-size:11px; padding:3px 8px;" onclick="Policies.togglePolicy('${Utils.escapeHtml(p.id)}')" title="${toggleLabel} Policy">${toggleLabel}</button>
              <button class="btn btn-danger btn-xs" style="font-size:11px; padding:3px 8px;" onclick="Policies.deletePolicy('${Utils.escapeHtml(p.id)}')" title="Delete Policy">Delete</button>
            </div>
          `;
        } else {
          actionHtml = `<span style="font-size:11.5px; color:var(--text-muted); font-weight:500;">View Only</span>`;
        }

        html += `
          <tr id="row-${Utils.escapeHtml(p.id)}">
            <td style="font-weight: 600; color: #fff;">
              ${Utils.escapeHtml(p.name)}
              <div style="margin-top:2px;">${statusBadge}</div>
            </td>
            <td><span class="badge badge-info">${Utils.escapeHtml(p.traffic_class)}</span></td>
            <td><span class="badge badge-live">${Utils.escapeHtml(p.priority_code)}</span></td>
            <td class="mono">Queue ${p.queue_id}</td>
            <td class="mono">${p.min_bandwidth_mbps} - ${p.max_bandwidth_mbps} Mbps</td>
            <td>${actionHtml}</td>
          </tr>
        `;
      });
      qosTbody.innerHTML = html || `<tr><td colspan="6" style="text-align: center; color:#64748b; padding:20px;">No QoS policies defined.</td></tr>`;
    }

    const secTbody = document.getElementById("pol-sec-tbody");
    if (secTbody) {
      let html = "";
      (data.security_policies || []).forEach(p => {
        const isActive = p.is_active === 1 || p.is_active === true || p.is_active === "1";
        const statusBadge = isActive
          ? `<span class="badge badge-live">ENABLED</span>`
          : `<span class="badge" style="background:#475569; color:#94a3b8;">DISABLED</span>`;

        let actionHtml = "";
        if (admin) {
          const toggleLabel = isActive ? "Disable" : "Enable";
          const toggleClass = isActive ? "btn-secondary" : "btn-primary";
          actionHtml = `
            <div style="display:flex; gap:4px; justify-content:flex-start; align-items:center;">
              <button class="btn btn-secondary btn-xs" style="font-size:11px; padding:3px 8px;" onclick="Policies.openEditModal('${Utils.escapeHtml(p.id)}')" title="Edit Rule">Edit</button>
              <button class="btn ${toggleClass} btn-xs" style="font-size:11px; padding:3px 8px;" onclick="Policies.togglePolicy('${Utils.escapeHtml(p.id)}')" title="${toggleLabel} Rule">${toggleLabel}</button>
              <button class="btn btn-danger btn-xs" style="font-size:11px; padding:3px 8px;" onclick="Policies.deletePolicy('${Utils.escapeHtml(p.id)}')" title="Delete Rule">Delete</button>
            </div>
          `;
        } else {
          actionHtml = `<span style="font-size:11.5px; color:var(--text-muted); font-weight:500;">View Only</span>`;
        }

        html += `
          <tr id="row-${Utils.escapeHtml(p.id)}">
            <td style="font-weight: 600; color: #fff;">
              ${Utils.escapeHtml(p.name)}
              <div style="margin-top:2px;">${statusBadge}</div>
            </td>
            <td><span class="badge badge-critical">${Utils.escapeHtml(p.rule_type)}</span></td>
            <td class="mono">${Utils.escapeHtml(p.source_ip || '*')}</td>
            <td class="mono">${Utils.escapeHtml(p.destination_ip || '*')}</td>
            <td class="mono">${p.threshold_pps} pps</td>
            <td>${actionHtml}</td>
          </tr>
        `;
      });
      secTbody.innerHTML = html || `<tr><td colspan="6" style="text-align: center; color:#64748b; padding:20px;">No security rules defined.</td></tr>`;
    }
  },

  handleTypeChange() {
    const type = document.getElementById("policy-form-type").value;
    const qosFields = document.getElementById("policy-fields-qos");
    const secFields = document.getElementById("policy-fields-sec");
    const infoText = document.getElementById("policy-modal-info-text");
    if (qosFields && secFields) {
      if (type === "QOS") {
        qosFields.style.display = "block";
        secFields.style.display = "none";
        if (infoText) {
          infoText.textContent = "QoS Policy configures traffic class prioritization and queue DSCP mappings on OpenFlow switches.";
        }
      } else {
        qosFields.style.display = "none";
        secFields.style.display = "block";
        if (infoText) {
          infoText.textContent = "Security Rule defines OpenFlow packet inspection, access control actions (BLOCK/RATE_LIMIT), and attack thresholds.";
        }
      }
    }
  },

  openCreateModal() {
    if (!this.isAdmin()) {
      Utils.showToast("Only administrator can create policies.", "danger");
      return;
    }
    const modal = document.getElementById("policy-modal");
    if (!modal) return;

    document.getElementById("policy-modal-title").textContent = "Create Policy / Rule";
    const subtitle = document.getElementById("policy-modal-subtitle");
    if (subtitle) {
      subtitle.textContent = "Define a new network policy or rule for the SDN environment";
    }
    const iconBadge = document.getElementById("policy-modal-icon-badge");
    if (iconBadge) {
      iconBadge.innerHTML = `<svg class="icon" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>`;
    }

    document.getElementById("policy-form-id").value = "";
    const typeSelect = document.getElementById("policy-form-type");
    typeSelect.value = "QOS";
    typeSelect.disabled = false;
    document.getElementById("policy-form-status").value = "1";
    document.getElementById("policy-form-name").value = "";

    // Reset QoS
    document.getElementById("policy-form-traffic-class").value = "WEB";
    document.getElementById("policy-form-priority-code").value = "AF";
    document.getElementById("policy-form-min-bw").value = "10";
    document.getElementById("policy-form-max-bw").value = "50";
    document.getElementById("policy-form-queue-id").value = "2";
    document.getElementById("policy-form-dscp").value = "26";
    document.getElementById("policy-form-criteria").value = "";

    // Reset Security
    document.getElementById("policy-form-rule-type").value = "BLOCK";
    document.getElementById("policy-form-protocol").value = "TCP";
    document.getElementById("policy-form-src-ip").value = "*";
    document.getElementById("policy-form-dst-ip").value = "*";
    document.getElementById("policy-form-threshold").value = "5000";

    const submitBtn = document.getElementById("policy-modal-submit-btn");
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = "Create Policy";
    }

    this.handleTypeChange();
    modal.classList.add("active");

    setTimeout(() => {
      const nameInput = document.getElementById("policy-form-name");
      if (nameInput) nameInput.focus();
    }, 50);
  },

  async openEditModal(polId) {
    if (!this.isAdmin()) {
      Utils.showToast("Only administrator can edit policies.", "danger");
      return;
    }
    const modal = document.getElementById("policy-modal");
    if (!modal) return;

    // Load REAL values from the database via API endpoint
    let target = null;
    try {
      const res = await API.get(`/api/policies/${encodeURIComponent(polId)}`);
      if (res && res.policy) {
        target = res.policy;
      }
    } catch (err) {
      console.warn("[Policies] Could not fetch single policy, falling back to cache:", err);
    }

    if (!target && this.cachedData) {
      target = (this.cachedData.qos_policies || []).find(p => p.id === polId) ||
               (this.cachedData.security_policies || []).find(p => p.id === polId);
    }

    if (!target) {
      Utils.showToast(`Policy or rule '${polId}' could not be loaded.`, "danger");
      return;
    }

    const type = target.type || (target.traffic_class !== undefined ? "QOS" : "SECURITY");

    document.getElementById("policy-modal-title").textContent = `Edit Policy: ${target.name || polId}`;
    const subtitle = document.getElementById("policy-modal-subtitle");
    if (subtitle) {
      subtitle.textContent = "Update policy settings and apply changes to the SDN environment";
    }
    const iconBadge = document.getElementById("policy-modal-icon-badge");
    if (iconBadge) {
      iconBadge.innerHTML = `<svg class="icon" viewBox="0 0 24 24"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>`;
    }

    document.getElementById("policy-form-id").value = target.id;
    const typeSelect = document.getElementById("policy-form-type");
    typeSelect.value = type;
    typeSelect.disabled = true; // Cannot alter policy category when editing existing record

    const isActive = target.is_active === 1 || target.is_active === true || target.is_active === "1";
    document.getElementById("policy-form-status").value = isActive ? "1" : "0";
    document.getElementById("policy-form-name").value = target.name || "";

    if (type === "QOS") {
      document.getElementById("policy-form-traffic-class").value = target.traffic_class || "WEB";
      document.getElementById("policy-form-priority-code").value = target.priority_code || "AF";
      document.getElementById("policy-form-min-bw").value = target.min_bandwidth_mbps !== undefined ? target.min_bandwidth_mbps : 10;
      document.getElementById("policy-form-max-bw").value = target.max_bandwidth_mbps !== undefined ? target.max_bandwidth_mbps : 50;
      document.getElementById("policy-form-queue-id").value = target.queue_id !== undefined ? target.queue_id : 2;
      document.getElementById("policy-form-dscp").value = target.dscp_mark !== undefined ? target.dscp_mark : 26;
      document.getElementById("policy-form-criteria").value = target.match_criteria || "";
    } else {
      document.getElementById("policy-form-rule-type").value = target.rule_type || "BLOCK";
      document.getElementById("policy-form-protocol").value = target.protocol || "TCP";
      document.getElementById("policy-form-src-ip").value = target.source_ip || "*";
      document.getElementById("policy-form-dst-ip").value = target.destination_ip || "*";
      document.getElementById("policy-form-threshold").value = target.threshold_pps !== undefined ? target.threshold_pps : 5000;
    }

    const submitBtn = document.getElementById("policy-modal-submit-btn");
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = "Save Changes";
    }

    this.handleTypeChange();
    modal.classList.add("active");

    setTimeout(() => {
      const nameInput = document.getElementById("policy-form-name");
      if (nameInput) nameInput.focus();
    }, 50);
  },

  closeModal() {
    const modal = document.getElementById("policy-modal");
    if (modal) modal.classList.remove("active");
  },

  async submitModal() {
    if (!this.isAdmin()) {
      Utils.showToast("Only administrator can manage policies.", "danger");
      return;
    }

    const id = document.getElementById("policy-form-id").value;
    const type = document.getElementById("policy-form-type").value;
    const name = (document.getElementById("policy-form-name").value || "").trim();
    const isActive = parseInt(document.getElementById("policy-form-status").value, 10) === 1 ? 1 : 0;

    // Frontend validations
    if (!name || name.length < 2) {
      Utils.showToast("Please enter a valid policy name (at least 2 characters).", "warning");
      const nameInput = document.getElementById("policy-form-name");
      if (nameInput) nameInput.focus();
      return;
    }

    const payload = { type, name, is_active: isActive };

    if (type === "QOS") {
      const minBw = parseFloat(document.getElementById("policy-form-min-bw").value);
      const maxBw = parseFloat(document.getElementById("policy-form-max-bw").value);
      const queueId = parseInt(document.getElementById("policy-form-queue-id").value, 10);
      const dscp = parseInt(document.getElementById("policy-form-dscp").value, 10);

      if (isNaN(minBw) || minBw < 0) {
        Utils.showToast("Minimum bandwidth must be a non-negative number.", "warning");
        return;
      }
      if (isNaN(maxBw) || maxBw <= 0) {
        Utils.showToast("Maximum bandwidth must be greater than 0 Mbps.", "warning");
        return;
      }
      if (minBw > maxBw) {
        Utils.showToast("Minimum bandwidth cannot exceed maximum bandwidth.", "warning");
        return;
      }
      if (isNaN(queueId) || queueId < 0 || queueId > 8) {
        Utils.showToast("Queue ID must be between 0 and 8.", "warning");
        return;
      }
      if (isNaN(dscp) || dscp < 0 || dscp > 63) {
        Utils.showToast("DSCP mark must be between 0 and 63.", "warning");
        return;
      }

      payload.traffic_class = document.getElementById("policy-form-traffic-class").value;
      payload.priority_code = document.getElementById("policy-form-priority-code").value;
      payload.min_bandwidth_mbps = minBw;
      payload.max_bandwidth_mbps = maxBw;
      payload.queue_id = queueId;
      payload.dscp_mark = dscp;
      payload.match_criteria = (document.getElementById("policy-form-criteria").value || "").trim() || "Custom Criteria";
      payload.action = "ENQUEUE";
    } else {
      const threshold = parseFloat(document.getElementById("policy-form-threshold").value);
      if (isNaN(threshold) || threshold <= 0) {
        Utils.showToast("Threshold must be greater than 0 packets/sec.", "warning");
        return;
      }

      payload.rule_type = document.getElementById("policy-form-rule-type").value;
      payload.protocol = document.getElementById("policy-form-protocol").value;
      payload.source_ip = (document.getElementById("policy-form-src-ip").value || "*").trim() || "*";
      payload.destination_ip = (document.getElementById("policy-form-dst-ip").value || "*").trim() || "*";
      payload.threshold_pps = threshold;
      payload.action = payload.rule_type;
    }

    const submitBtn = document.getElementById("policy-modal-submit-btn");
    const originalText = id ? "Save Changes" : "Create Policy";
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = "Saving...";
    }

    try {
      if (id) {
        // Edit existing policy with same real ID
        await API.put(`/api/policies/${encodeURIComponent(id)}`, payload);
        Utils.showToast(`Policy updated successfully.`, "success");
      } else {
        // Create new policy
        await API.post("/api/policies", payload);
        Utils.showToast(`Policy created successfully.`, "success");
      }
      this.closeModal();
      await this.fetchPolicies();
    } catch (err) {
      const errMsg = (err && (err.message || (err.data && err.data.message))) || String(err);
      Utils.showToast(`Operation failed: ${errMsg}`, "danger");
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = originalText;
      }
    }
  },

  async togglePolicy(polId) {
    if (!this.isAdmin()) {
      Utils.showToast("Only administrator can change policy status.", "danger");
      return;
    }
    try {
      const res = await API.post(`/api/policies/${encodeURIComponent(polId)}/toggle`, {});
      Utils.showToast(res.message || "Policy status updated.", "info");
      await this.fetchPolicies();
    } catch (err) {
      const errMsg = (err && (err.message || (err.data && err.data.message))) || String(err);
      Utils.showToast(`Status change failed: ${errMsg}`, "danger");
    }
  },

  async deletePolicy(polId) {
    if (!this.isAdmin()) {
      Utils.showToast("Only administrator can delete policies.", "danger");
      return;
    }
    const confirmed = await Utils.showConfirm({
      title: "Delete Policy / Rule",
      message: `Are you sure you want to permanently delete policy '${polId}'? This policy will be removed from OpenFlow switch enforcement.`,
      confirmText: "Delete Policy",
      cancelText: "Cancel",
      type: "danger",
      destructive: true
    });
    if (!confirmed) return;

    try {
      await API.delete(`/api/policies/${encodeURIComponent(polId)}`);
      Utils.showToast(`Policy deleted.`, "info");
      await this.fetchPolicies();
    } catch (err) {
      const errMsg = (err && (err.message || (err.data && err.data.message))) || String(err);
      Utils.showToast(`Delete failed: ${errMsg}`, "danger");
    }
  }
};
