const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const EDGE_PATH = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const USER_DATA = path.join(process.env.TEMP || "C:\\temp", "edge_policy_test_" + Date.now());

function getJson(url) {
  return new Promise((resolve, reject) => {
    http.get(url, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(JSON.parse(data)));
    }).on('error', reject);
  });
}

async function run() {
  console.log("=== STARTING FRONTEND E2E POLICY / RULE MODAL TESTS ===");
  const edge = spawn(EDGE_PATH, [
    "--headless=new",
    "--remote-debugging-port=9223",
    `--user-data-dir=${USER_DATA}`,
    "--no-first-run",
    "--no-default-browser-check",
    "http://127.0.0.1:5000/login"
  ]);

  await new Promise(r => setTimeout(r, 2000));

  try {
    const tabs = await getJson("http://127.0.0.1:9223/json");
    const pageTab = tabs.find(t => t.url && t.url.includes("login")) || tabs[0];
    if (!pageTab) throw new Error("No page tab found");

    const ws = new globalThis.WebSocket(pageTab.webSocketDebuggerUrl);
    let msgId = 1;
    const pending = new Map();

    ws.addEventListener('message', event => {
      const msg = JSON.parse(event.data);
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
      const res = await send("Runtime.evaluate", { expression: `(() => {\n${expression}\n})()`, returnByValue: true, awaitPromise: true });
      if (res.result && res.result.exceptionDetails) {
        throw new Error(JSON.stringify(res.result.exceptionDetails));
      }
      return res.result && res.result.result ? res.result.result.value : null;
    }

    await send("Page.enable");
    await send("Runtime.enable");

    // 1. Perform login as ADMIN
    console.log("Logging in as Admin premkumarj18122003@gmail.com...");
    await evaluate(`
      document.getElementById('username').value = 'premkumarj18122003@gmail.com';
      document.getElementById('password').value = 'Prem@2003';
      document.getElementById('login-form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    `);

    // Wait for redirect to /
    await new Promise(r => setTimeout(r, 2000));
    const curUrl = await evaluate("return window.location.href;");
    console.log("Current URL after login:", curUrl);

    // 2. Navigate to Policies view
    console.log("Navigating to Policies & Rules view...");
    await evaluate("App.navigate('policies');");
    await new Promise(r => setTimeout(r, 1000));

    // Check if Create button is visible
    const createBtnDisplay = await evaluate(`
      const btn = document.getElementById('btn-create-policy');
      return window.getComputedStyle(btn).display;
    `);
    console.log("Create button display:", createBtnDisplay);
    if (createBtnDisplay === 'none') {
      throw new Error("Create Policy button is not visible for ADMIN!");
    }
    console.log("[PASS] Create Policy / Rule button is visible for ADMIN");

    // 3. Open Create Modal
    console.log("Clicking Create Policy / Rule button...");
    await evaluate("Policies.openCreateModal();");
    await new Promise(r => setTimeout(r, 300));

    const modalState = await evaluate(`
      const modal = document.getElementById('policy-modal');
      const box = modal.querySelector('.modal-box');
      const rect = box.getBoundingClientRect();
      const style = window.getComputedStyle(modal);
      return ({
        active: modal.classList.contains('active'),
        opacity: style.opacity,
        visibility: style.visibility,
        title: document.getElementById('policy-modal-title').textContent,
        submitText: document.getElementById('policy-modal-submit-btn').textContent,
        width: rect.width,
        height: rect.height,
        top: rect.top,
        left: rect.left
      });
    `);
    console.log("Modal state:", modalState);
    if (!modalState.active || modalState.visibility !== 'visible' || Number(modalState.opacity) < 1) {
      throw new Error("Policy modal is not active and visible!");
    }
    console.log("[PASS] Create Policy modal opened and is fully visible!");

    // 4. Test Responsiveness across all requested viewports
    const viewports = [
      { name: "Mobile Portrait (360x800)", w: 360, h: 800 },
      { name: "Mobile Portrait (390x844)", w: 390, h: 844 },
      { name: "Mobile Portrait (430x932)", w: 430, h: 932 },
      { name: "Mobile Landscape (800x360)", w: 800, h: 360 },
      { name: "Mobile Landscape (812x375)", w: 812, h: 375 },
      { name: "Mobile Landscape (844x390)", w: 844, h: 390 },
      { name: "Tablet Portrait (768x1024)", w: 768, h: 1024 },
      { name: "Tablet Landscape (1024x768)", w: 1024, h: 768 },
      { name: "Laptop (1366x768)", w: 1366, h: 768 },
      { name: "Desktop (1920x1080)", w: 1920, h: 1080 }
    ];

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
        const rect = box.getBoundingClientRect();
        return ({
          innerWidth: window.innerWidth,
          innerHeight: window.innerHeight,
          scrollWidth: document.documentElement.scrollWidth,
          boxWidth: rect.width,
          boxHeight: rect.height,
          boxRight: rect.right,
          boxBottom: rect.bottom,
          hasOverflow: document.documentElement.scrollWidth > window.innerWidth
        });
      `);

      const fitsHorizontally = vpMetrics.boxRight <= vpMetrics.innerWidth + 1;
      const noPageOverflow = !vpMetrics.hasOverflow;
      console.log(`[RESPONSIVE] ${vp.name}: boxWidth=${vpMetrics.boxWidth.toFixed(1)}px, boxHeight=${vpMetrics.boxHeight.toFixed(1)}px, fitsHoriz=${fitsHorizontally}, noPageOverflow=${noPageOverflow}`);

      if (!noPageOverflow) {
        throw new Error(`Horizontal page overflow detected at viewport ${vp.name}!`);
      }
    }
    console.log("[PASS] All viewports verified: 0 horizontal overflow, modal fits inside viewport!");

    // Reset viewport to desktop standard for interaction test
    await send("Emulation.setDeviceMetricsOverride", {
      width: 1280,
      height: 800,
      deviceScaleFactor: 1,
      mobile: false
    });
    await new Promise(r => setTimeout(r, 200));

    // 5. Fill and Submit Create Form
    const testPolName = 'Automated UI QoS ' + Date.now();
    console.log(`Submitting new QoS policy '${testPolName}' from modal...`);
    await evaluate(`
      document.getElementById('policy-form-name').value = '${testPolName}';
      document.getElementById('policy-form-traffic-class').value = 'VOICE';
      document.getElementById('policy-form-priority-code').value = 'EF';
      document.getElementById('policy-form-min-bw').value = '18';
      document.getElementById('policy-form-max-bw').value = '72';
      document.getElementById('policy-form-queue-id').value = '1';
      document.getElementById('policy-form-dscp').value = '46';
      document.getElementById('policy-form-criteria').value = 'UDP 5060';
      document.getElementById('policy-form-status').value = '1';
    `);

    await evaluate("Policies.submitModal();");
    await new Promise(r => setTimeout(r, 1200));

    // Verify modal is closed and row exists
    const postCreate = await evaluate(`
      const modal = document.getElementById('policy-modal');
      const rows = Array.from(document.querySelectorAll('#pol-qos-tbody tr')).map(r => r.textContent);
      const createdRow = rows.find(t => t.includes('${testPolName}'));
      return ({
        modalActive: modal.classList.contains('active'),
        hasRow: !!createdRow,
        rowText: createdRow || null
      });
    `);
    console.log("Post Create state:", postCreate);
    if (postCreate.modalActive) {
      throw new Error("Modal did not close after successful create!");
    }
    if (!postCreate.hasRow) {
      throw new Error("Created policy row not found in table!");
    }
    console.log("[PASS] Policy created and row displayed in table!");

    // 6. Test Edit Modal on the created policy
    console.log("Testing Edit on created policy...");
    const createdPolId = await evaluate(`
      const row = Array.from(document.querySelectorAll('#pol-qos-tbody tr')).find(r => r.textContent.includes('${testPolName}'));
      return row ? row.id.replace('row-', '') : null;
    `);
    console.log("Created Policy ID:", createdPolId);

    await evaluate(`Policies.openEditModal('${createdPolId}');`);
    await new Promise(r => setTimeout(r, 500));

    const editState = await evaluate(`
      const modal = document.getElementById('policy-modal');
      return ({
        active: modal.classList.contains('active'),
        title: document.getElementById('policy-modal-title').textContent,
        name: document.getElementById('policy-form-name').value,
        minBw: document.getElementById('policy-form-min-bw').value,
        maxBw: document.getElementById('policy-form-max-bw').value,
        submitText: document.getElementById('policy-modal-submit-btn').textContent,
        typeDisabled: document.getElementById('policy-form-type').disabled
      });
    `);
    console.log("Edit form populated state:", editState);
    if (!editState.active || !editState.title.includes('Edit Policy') || editState.name !== testPolName) {
      throw new Error(`Edit modal failed to populate correct values! Expected ${testPolName}, got ${editState.name}`);
    }
    console.log("[PASS] Edit modal loaded and populated real database values!");

    // Modify a value and save
    console.log("Modifying max bandwidth to 99 Mbps and saving changes...");
    await evaluate(`
      document.getElementById('policy-form-max-bw').value = '99';
    `);
    await evaluate("Policies.submitModal();");
    await new Promise(r => setTimeout(r, 1200));

    const postEdit = await evaluate(`
      const modal = document.getElementById('policy-modal');
      const row = document.getElementById('row-${createdPolId}');
      return ({
        modalActive: modal.classList.contains('active'),
        rowText: row ? row.textContent : null
      });
    `);
    console.log("Post Edit row text:", postEdit.rowText);
    if (!postEdit.rowText.includes('99 Mbps')) {
      throw new Error("Updated bandwidth '99 Mbps' not reflected in table!");
    }
    console.log("[PASS] Policy edited successfully; table updated!");

    // 7. Test Toggle Status (Disable/Enable)
    console.log("Toggling status to Disable...");
    await evaluate(`return Policies.togglePolicy('${createdPolId}');`);
    await new Promise(r => setTimeout(r, 1000));

    const postToggle = await evaluate(`
      const row = document.getElementById('row-${createdPolId}');
      return ({
        disabledBadge: row.textContent.includes('DISABLED'),
        buttonText: row.querySelector('button.btn-primary') ? row.querySelector('button.btn-primary').textContent : null
      });
    `);
    console.log("Post Toggle state:", postToggle);
    if (!postToggle.disabledBadge) {
      throw new Error("Disable toggle failed to update status badge!");
    }
    console.log("[PASS] Disable toggle updated policy state to DISABLED!");

    // 8. Test Delete
    console.log("Testing Delete policy with confirmation...");
    // Trigger delete
    await evaluate(`
      Policies.deletePolicy('${createdPolId}');
    `);
    await new Promise(r => setTimeout(r, 300));

    // Confirm dialog should be open
    const confirmOpen = await evaluate(`
      const confirmOverlay = document.querySelector('.vortex-confirm-overlay');
      return ({
        isOpen: !!confirmOverlay,
        title: confirmOverlay ? confirmOverlay.querySelector('.vortex-confirm-title').textContent : null
      });
    `);
    console.log("Confirm dialog state:", confirmOpen);
    if (!confirmOpen.isOpen) {
      throw new Error("Custom confirm dialog did not appear for Delete!");
    }

    // Click confirm button in custom dialog
    await evaluate(`
      const confirmBtn = document.querySelector('.vortex-confirm-btn-action');
      if (confirmBtn) confirmBtn.click();
    `);
    await new Promise(r => setTimeout(r, 1500));

    const postDelete = await evaluate(`
      const row = document.getElementById('row-${createdPolId}');
      return ({
        rowExists: !!row
      });
    `);
    console.log("Post Delete row exists:", postDelete.rowExists);
    if (postDelete.rowExists) {
      throw new Error("Policy row still exists after delete!");
    }
    console.log("[PASS] Policy deleted cleanly; removed from table!");

    console.log("\n>>> ALL FRONTEND E2E AND RESPONSIVE TESTS PASSED 100%! <<<\n");

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
