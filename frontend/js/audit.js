/**
 * VORTEX-SDN Audit Trail View Controller
 * Displays persistent, tamper-evident logs for administrative and system operations.
 */

const Audit = {
  async init() {
    await this.fetchLogs();
  },

  async fetchLogs(actionFilter = "ALL") {
    const tbody = document.getElementById("audit-table-tbody");
    if (tbody && !tbody.innerHTML.includes("tr")) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: #94a3b8; padding: 24px;">Loading audit logs...</td></tr>`;
    }

    try {
      const data = await API.get("/api/audit", { action: actionFilter, limit: 50 });
      this.renderTable(data.logs || []);
    } catch (err) {
      console.warn("[Audit] Error fetching logs:", err);
      if (tbody) {
        tbody.innerHTML = `
          <tr>
            <td colspan="7" style="text-align: center; color: #ef4444; padding: 24px;">
              Failed to load audit logs.
              <button class="btn btn-secondary btn-sm" style="margin-left: 10px;" onclick="Audit.fetchLogs()">Retry</button>
            </td>
          </tr>
        `;
      }
    }
  },

  renderTable(logs) {
    const tbody = document.getElementById("audit-table-tbody");
    if (!tbody) return;

    if (!logs || logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: #64748b; padding: 24px;">No audit records yet.</td></tr>`;
      return;
    }

    let html = "";
    logs.forEach(l => {
      const resBadge = l.result === "SUCCESS"
        ? `<span class="badge badge-live">SUCCESS</span>`
        : `<span class="badge badge-critical">${l.result}</span>`;

      html += `
        <tr>
          <td class="mono audit-time-cell">${Utils.formatRelativeTime(l.timestamp)}</td>
          <td class="audit-user-cell" title="${Utils.escapeHtml(l.username)}">${Utils.escapeHtml(l.username)}</td>
          <td class="audit-role-cell"><span class="badge badge-info">${Utils.escapeHtml(l.role)}</span></td>
          <td class="mono audit-action-cell" title="${Utils.escapeHtml(l.action)}">${Utils.escapeHtml(l.action)}</td>
          <td class="audit-resource-cell" title="${Utils.escapeHtml(l.resource)}">${Utils.escapeHtml(l.resource)}</td>
          <td class="audit-result-cell">${resBadge}</td>
          <td class="mono audit-ip-cell">${Utils.escapeHtml(l.client_ip || '127.0.0.1')}</td>
        </tr>
      `;
    });
    tbody.innerHTML = html;
  }
};
