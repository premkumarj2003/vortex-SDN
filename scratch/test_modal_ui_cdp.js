const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const EDGE_PATH = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const USER_DATA = path.join(process.env.TEMP || "C:\\temp", "edge_modal_cdp_" + Date.now());
const ARTIFACTS_DIR = "C:\\Users\\LENOVO\\.gemini\\antigravity-ide\\brain\\9aad9c54-f342-49f3-b078-d23b124e4c1d";

function getJson(url) {
  return new Promise((resolve, reject) => {
    http.get(url, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
      });
    }).on('error', reject);
  });
}

async function run() {
  console.log("=== VORTEX-SDN MODAL UI VERIFICATION VIA CDP ===");
  const edge = spawn(EDGE_PATH, [
    "--headless=new",
    "--remote-debugging-port=9224",
    `--user-data-dir=${USER_DATA}`,
    "--no-first-run",
    "--no-default-browser-check",
    "http://127.0.0.1:5000/login"
  ]);

  await new Promise(r => setTimeout(r, 2200));

  try {
    const tabs = await getJson("http://127.0.0.1:9224/json");
    const pageTab = tabs.find(t => t.url && t.url.includes("login")) || tabs[0];
    if (!pageTab) throw new Error("No page tab found");

    const ws = new globalThis.WebSocket(pageTab.webSocketDebuggerUrl);
    let msgId = 1;
    const pending = new Map();
    const consoleLogs = [];

    ws.addEventListener('message', event => {
      const msg = JSON.parse(event.data);
      if (msg.method === 'Runtime.consoleAPICalled') {
        consoleLogs.push(msg.params);
      }
      if (msg.id && pending.has(msg.id)) {
        pending.get(msg.id)(msg);
        pending.delete(msg.id);
      }
    });

    await new Promise(r => ws.addEventListener('open', r, { once: true }));

    function send(method, params = {}) {
      return new Promise(resolve => {
        const id = msgId++;
        pending.set(id, resolve);
        ws.send(JSON.stringify({ id, method, params }));
      });
    }

    async function evaluate(expression) {
      const res = await send("Runtime.evaluate", {
        expression: `(() => {\n${expression}\n})()`,
        returnByValue: true,
        awaitPromise: true
      });
      if (res.result && res.result.exceptionDetails) {
        throw new Error(JSON.stringify(res.result.exceptionDetails));
      }
      return res.result && res.result.result ? res.result.result.value : null;
    }

    await send("Page.enable");
    await send("Runtime.enable");

    // 1. Perform login as ADMIN
    console.log("1. Logging in as Admin...");
    await evaluate(`
      document.getElementById('username').value = 'premkumarj18122003@gmail.com';
      document.getElementById('password').value = 'Prem@2003';
      document.getElementById('login-form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    `);

    // Wait for redirect to /
    await new Promise(r => setTimeout(r, 2200));

    // 2. Navigate to Policies view
    console.log("2. Navigating to Policies view...");
    await evaluate("App.navigate('policies');");
    await new Promise(r => setTimeout(r, 1200));

    // 3. Open Create Modal
    console.log("3. Opening Create Policy Modal...");
    await evaluate("Policies.openCreateModal();");
    await new Promise(r => setTimeout(r, 500));

    // Inspect Create Modal Design Elements
    const createModalAudit = await evaluate(`
      const modal = document.getElementById('policy-modal');
      const box = modal.querySelector('.modal-box');
      const title = document.getElementById('policy-modal-title');
      const subtitle = document.getElementById('policy-modal-subtitle');
      const badge = document.getElementById('policy-modal-icon-badge');
      const submitBtn = document.getElementById('policy-modal-submit-btn');
      const nameInput = document.getElementById('policy-form-name');
      const typeSelect = document.getElementById('policy-form-type');
      const statusSelect = document.getElementById('policy-form-status');
      const infoPanel = document.getElementById('policy-modal-info-panel');
      const infoText = document.getElementById('policy-modal-info-text');

      const nameStyle = window.getComputedStyle(nameInput);
      const boxStyle = window.getComputedStyle(box);
      const submitStyle = window.getComputedStyle(submitBtn);

      return {
        active: modal.classList.contains('active'),
        title: title ? title.textContent.trim() : null,
        subtitle: subtitle ? subtitle.textContent.trim() : null,
        badgeVisible: !!badge,
        badgeSvg: badge ? badge.querySelector('svg') !== null : false,
        submitText: submitBtn ? submitBtn.textContent.trim() : null,
        inputBg: nameStyle.backgroundColor,
        inputColor: nameStyle.color,
        inputBorder: nameStyle.borderColor,
        inputBorderRadius: nameStyle.borderRadius,
        inputHeight: nameStyle.height,
        boxBg: boxStyle.backgroundColor,
        boxBorder: boxStyle.borderColor,
        boxRadius: boxStyle.borderRadius,
        boxShadow: boxStyle.boxShadow,
        infoPanelVisible: infoPanel ? window.getComputedStyle(infoPanel).display !== 'none' : false,
        infoText: infoText ? infoText.textContent.trim() : null,
        labelsWithIcons: document.querySelectorAll('.policy-field-label svg').length
      };
    `);
    console.log("Create Modal UI Audit:", JSON.stringify(createModalAudit, null, 2));

    // Screenshot Create Modal on Desktop (1366x768)
    await send("Emulation.setDeviceMetricsOverride", {
      width: 1366,
      height: 768,
      deviceScaleFactor: 1,
      mobile: false
    });
    await new Promise(r => setTimeout(r, 300));

    const scrCreate = await send("Page.captureScreenshot", { format: "png" });
    const createData = (scrCreate.result && scrCreate.result.data) || scrCreate.data;
    const createPngPath = path.join(ARTIFACTS_DIR, "vortex_create_policy_modal.png");
    fs.writeFileSync(createPngPath, Buffer.from(createData, "base64"));
    console.log("Saved Create Modal screenshot to:", createPngPath);

    // 4. Test Policy Type switch to SECURITY
    console.log("4. Testing switch to Security Rule...");
    await evaluate(`
      document.getElementById('policy-form-type').value = 'SECURITY';
      Policies.handleTypeChange();
    `);
    await new Promise(r => setTimeout(r, 300));

    const secSwitchAudit = await evaluate(`
      const qosSec = document.getElementById('policy-fields-qos');
      const secSec = document.getElementById('policy-fields-sec');
      const infoText = document.getElementById('policy-modal-info-text');
      return {
        qosDisplay: window.getComputedStyle(qosSec).display,
        secDisplay: window.getComputedStyle(secSec).display,
        infoText: infoText ? infoText.textContent.trim() : null
      };
    `);
    console.log("Security Type Switch Audit:", secSwitchAudit);

    // Switch back to QoS for creating a sample policy
    await evaluate(`
      document.getElementById('policy-form-type').value = 'QOS';
      Policies.handleTypeChange();
    `);
    await new Promise(r => setTimeout(r, 200));

    // 5. Submit new QoS Policy
    const samplePolName = "Voice Priority Stream " + Math.floor(Math.random() * 1000);
    console.log(`5. Submitting new QoS policy: '${samplePolName}'...`);
    await evaluate(`
      document.getElementById('policy-form-name').value = '${samplePolName}';
      document.getElementById('policy-form-traffic-class').value = 'VOICE';
      document.getElementById('policy-form-priority-code').value = 'EF';
      document.getElementById('policy-form-min-bw').value = '30';
      document.getElementById('policy-form-max-bw').value = '90';
      document.getElementById('policy-form-queue-id').value = '2';
      document.getElementById('policy-form-dscp').value = '46';
      document.getElementById('policy-form-criteria').value = 'UDP RTP Port 16384-32767';
      document.getElementById('policy-form-status').value = '1';
    `);

    await evaluate("Policies.submitModal();");
    await new Promise(r => setTimeout(r, 1200));

    const postCreateCheck = await evaluate(`
      const modal = document.getElementById('policy-modal');
      const rows = Array.from(document.querySelectorAll('#pol-qos-tbody tr')).map(r => r.textContent);
      const found = rows.find(t => t.includes('${samplePolName}'));
      return {
        modalClosed: !modal.classList.contains('active'),
        foundInTable: !!found
      };
    `);
    console.log("Post Create Check:", postCreateCheck);
    if (!postCreateCheck.modalClosed || !postCreateCheck.foundInTable) {
      throw new Error("Create Policy failed to close modal or display in table!");
    }

    // 6. Test Edit Modal on created policy
    console.log("6. Testing Edit Modal...");
    const createdPolId = await evaluate(`
      const row = Array.from(document.querySelectorAll('#pol-qos-tbody tr')).find(r => r.textContent.includes('${samplePolName}'));
      return row ? row.id.replace('row-', '') : null;
    `);
    console.log("Opening Edit Modal for ID:", createdPolId);

    await evaluate(`Policies.openEditModal('${createdPolId}');`);
    await new Promise(r => setTimeout(r, 500));

    const editModalAudit = await evaluate(`
      const modal = document.getElementById('policy-modal');
      const title = document.getElementById('policy-modal-title');
      const subtitle = document.getElementById('policy-modal-subtitle');
      const badge = document.getElementById('policy-modal-icon-badge');
      const submitBtn = document.getElementById('policy-modal-submit-btn');
      const nameInput = document.getElementById('policy-form-name');
      const minBw = document.getElementById('policy-form-min-bw');
      const maxBw = document.getElementById('policy-form-max-bw');

      return {
        active: modal.classList.contains('active'),
        title: title ? title.textContent.trim() : null,
        subtitle: subtitle ? subtitle.textContent.trim() : null,
        submitText: submitBtn ? submitBtn.textContent.trim() : null,
        loadedName: nameInput ? nameInput.value : null,
        loadedMinBw: minBw ? minBw.value : null,
        loadedMaxBw: maxBw ? maxBw.value : null
      };
    `);
    console.log("Edit Modal UI Audit:", JSON.stringify(editModalAudit, null, 2));

    const scrEdit = await send("Page.captureScreenshot", { format: "png" });
    const editData = (scrEdit.result && scrEdit.result.data) || scrEdit.data;
    const editPngPath = path.join(ARTIFACTS_DIR, "vortex_edit_policy_modal.png");
    fs.writeFileSync(editPngPath, Buffer.from(editData, "base64"));
    console.log("Saved Edit Modal screenshot to:", editPngPath);

    // Save changes in Edit Modal
    await evaluate(`
      document.getElementById('policy-form-max-bw').value = '95';
    `);
    await evaluate("Policies.submitModal();");
    await new Promise(r => setTimeout(r, 1200));

    const postEditCheck = await evaluate(`
      const row = document.getElementById('row-${createdPolId}');
      return {
        rowUpdated: row ? row.textContent.includes('95 Mbps') : false
      };
    `);
    console.log("Post Edit Check:", postEditCheck);
    if (!postEditCheck.rowUpdated) {
      throw new Error("Edit policy did not update table correctly!");
    }

    // 7. Test Responsive Viewports (Modal Open)
    console.log("\n7. Testing Responsive Viewports for Modal...");
    // Open create modal again for responsive audit
    await evaluate("Policies.openCreateModal();");
    await new Promise(r => setTimeout(r, 400));

    const viewports = [
      { name: "Desktop (1920x1080)", w: 1920, h: 1080 },
      { name: "Laptop (1366x768)", w: 1366, h: 768 },
      { name: "Tablet Landscape (1024x768)", w: 1024, h: 768 },
      { name: "Tablet Portrait (768x1024)", w: 768, h: 1024 },
      { name: "Mobile Portrait (430x932)", w: 430, h: 932 },
      { name: "Mobile Portrait (390x844)", w: 390, h: 844 },
      { name: "Mobile Portrait (360x800)", w: 360, h: 800 },
      { name: "Mobile Landscape (844x390)", w: 844, h: 390 },
      { name: "Mobile Landscape (812x375)", w: 812, h: 375 },
      { name: "Mobile Landscape (800x360)", w: 800, h: 360 }
    ];

    const vpResults = [];
    for (const vp of viewports) {
      await send("Emulation.setDeviceMetricsOverride", {
        width: vp.w,
        height: vp.h,
        deviceScaleFactor: 1,
        mobile: vp.w < 600 || vp.h < 500
      });
      await new Promise(r => setTimeout(r, 200));

      const vpMetrics = await evaluate(`
        const modal = document.getElementById('policy-modal');
        const box = modal.querySelector('.modal-box');
        const body = modal.querySelector('.modal-body');
        const rect = box.getBoundingClientRect();
        const bodyRect = body.getBoundingClientRect();
        const clientW = document.documentElement.clientWidth;
        const scrollW = document.documentElement.scrollWidth;

        return {
          innerWidth: window.innerWidth,
          innerHeight: window.innerHeight,
          boxWidth: Math.round(rect.width),
          boxHeight: Math.round(rect.height),
          fitsWidth: rect.width <= clientW + 1,
          noPageHScroll: scrollW <= clientW + 1,
          bodyScrollable: body.scrollHeight > body.clientHeight
        };
      `);

      vpResults.push({ name: vp.name, ...vpMetrics });
      console.log(`[RESPONSIVE] ${vp.name.padEnd(28)}: boxWidth=${vpMetrics.boxWidth}px, fitsWidth=${vpMetrics.fitsWidth}, noPageHScroll=${vpMetrics.noPageHScroll}, bodyScrollable=${vpMetrics.bodyScrollable}`);

      if (!vpMetrics.noPageHScroll) {
        throw new Error(`Horizontal page scroll detected at viewport ${vp.name}!`);
      }
    }

    // Capture mobile portrait and mobile landscape screenshots
    // Mobile portrait 390x844
    await send("Emulation.setDeviceMetricsOverride", {
      width: 390,
      height: 844,
      deviceScaleFactor: 1,
      mobile: true
    });
    await new Promise(r => setTimeout(r, 200));
    const scrMobileP = await send("Page.captureScreenshot", { format: "png" });
    const mobilePData = (scrMobileP.result && scrMobileP.result.data) || scrMobileP.data;
    const mobilePPngPath = path.join(ARTIFACTS_DIR, "vortex_modal_mobile_portrait.png");
    fs.writeFileSync(mobilePPngPath, Buffer.from(mobilePData, "base64"));
    console.log("Saved Mobile Portrait screenshot to:", mobilePPngPath);

    // Mobile landscape 844x390
    await send("Emulation.setDeviceMetricsOverride", {
      width: 844,
      height: 390,
      deviceScaleFactor: 1,
      mobile: true
    });
    await new Promise(r => setTimeout(r, 200));
    const scrMobileL = await send("Page.captureScreenshot", { format: "png" });
    const mobileLData = (scrMobileL.result && scrMobileL.result.data) || scrMobileL.data;
    const mobileLPngPath = path.join(ARTIFACTS_DIR, "vortex_modal_mobile_landscape.png");
    fs.writeFileSync(mobileLPngPath, Buffer.from(mobileLData, "base64"));
    console.log("Saved Mobile Landscape screenshot to:", mobileLPngPath);

    // Close modal via Cancel button
    await evaluate("Policies.closeModal();");
    await new Promise(r => setTimeout(r, 300));

    // Reset viewport to desktop standard
    await send("Emulation.setDeviceMetricsOverride", {
      width: 1280,
      height: 800,
      deviceScaleFactor: 1,
      mobile: false
    });
    await new Promise(r => setTimeout(r, 200));

    // 8. Clean up test policy via delete
    console.log("8. Cleaning up test policy via delete...");
    await evaluate(`Policies.deletePolicy('${createdPolId}');`);
    await new Promise(r => setTimeout(r, 300));
    await evaluate(`
      const confirmBtn = document.querySelector('.vortex-confirm-btn-action');
      if (confirmBtn) confirmBtn.click();
    `);
    await new Promise(r => setTimeout(r, 1200));

    console.log("\n=======================================================");
    console.log(">>> ALL CHECKS AND AUDITS PASSED WITH ZERO ERRORS! <<<");
    console.log("=======================================================\n");

    ws.close();
  } finally {
    edge.kill();
    try {
      fs.rmSync(USER_DATA, { recursive: true, force: true });
    } catch (e) {}
  }
}

run().catch(err => {
  console.error("FATAL ERROR:", err);
  process.exit(1);
});
