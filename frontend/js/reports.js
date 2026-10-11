/**
 * VORTEX-SDN Reports & Analytics Export Controller
 */

const Reports = {
  async exportReport(type) {
    Utils.showToast(`Generating ${type} report...`, "info");
    try {
      let data = [];
      let filename = `vortex_${type.toLowerCase()}_report.csv`;

      if (type === "FLOWS" || type === "TRAFFIC") {
        const res = await API.get("/api/flows?limit=200");
        data = res.flows || [];
      } else if (type === "SECURITY") {
        const res = await API.get("/api/security/events?limit=200");
        data = res.events || [];
      } else if (type === "AUDIT") {
        const res = await API.get("/api/audit?limit=200");
        data = res.logs || [];
      }

      if (!data || data.length === 0) {
        Utils.showToast("No data available to export.", "warning");
        return;
      }

      // Convert JSON array to CSV
      const headers = Object.keys(data[0]);
      const csvRows = [headers.join(",")];
      data.forEach(row => {
        const values = headers.map(h => {
          const val = row[h] === null || row[h] === undefined ? "" : String(row[h]);
          return `"${val.replace(/"/g, '""')}"`;
        });
        csvRows.push(values.join(","));
      });

      const csvContent = "data:text/csv;charset=utf-8," + csvRows.join("\n");
      const encodedUri = encodeURI(csvContent);
      const link = document.createElement("a");
      link.setAttribute("href", encodedUri);
      link.setAttribute("download", filename);
      document.body.appendChild(link);
      link.click();
      link.remove();

      Utils.showToast(`Exported ${filename} successfully!`, "success");
    } catch (err) {
      Utils.showToast(`Export failed: ${err.message}`, "danger");
    }
  }
};
