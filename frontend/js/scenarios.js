/**
 * VORTEX-SDN Demo Scenario Selector
 * Allows users to trigger stateful network conditions (DDoS, Port Scan, Congestion, Recovery).
 */

const Scenarios = {
  currentScenario: "NORMAL",

  async setScenario(scenarioName) {
    try {
      Utils.showToast(`Activating Scenario: ${scenarioName.replace(/_/g, ' ')}...`, "info");
      const res = await API.post("/api/demo/scenario", { scenario: scenarioName });
      this.currentScenario = res.active_scenario;
      this.updateUI();
      Utils.showToast(`Scenario active: ${this.currentScenario}`, "success");
      
      // Trigger instant telemetry poll to reflect changes
      Telemetry.pollNow();
    } catch (err) {
      Utils.showToast(`Failed to set scenario: ${err.message}`, "danger");
    }
  },

  updateUI() {
    const bannerBadge = document.getElementById("active-scenario-badge");
    if (bannerBadge) {
      bannerBadge.textContent = this.currentScenario.replace(/_/g, ' ');
    }

    // Highlight active scenario button
    const btns = document.querySelectorAll(".scenario-trigger-btn");
    btns.forEach(b => {
      const targetScen = b.getAttribute("data-scenario");
      if (targetScen === this.currentScenario) {
        b.classList.add("btn-primary");
        b.classList.remove("btn-secondary");
      } else {
        b.classList.add("btn-secondary");
        b.classList.remove("btn-primary");
      }
    });
  }
};
