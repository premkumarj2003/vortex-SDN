const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const EDGE_PATH = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const USER_DATA = path.join(process.env.TEMP || "C:\\temp", "edge_hero_cdp_" + Date.now());

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
  console.log("Launching Edge with remote debugging...");
  const edge = spawn(EDGE_PATH, [
    "--headless=new",
    "--remote-debugging-port=9222",
    `--user-data-dir=${USER_DATA}`,
    "--no-first-run",
    "--no-default-browser-check",
    "http://127.0.0.1:5000/login.html"
  ]);

  await new Promise(r => setTimeout(r, 2500));

  try {
    const tabs = await getJson("http://127.0.0.1:9222/json");
    const pageTab = tabs.find(t => t.url && t.url.includes("login")) || tabs[0];
    if (!pageTab) throw new Error("No page tab found");

    const wsUrl = pageTab.webSocketDebuggerUrl;
    console.log("Connected to WebSocket:", wsUrl);

    const ws = new globalThis.WebSocket(wsUrl);
    let msgId = 1;
    const pending = new Map();
    const consoleLogs = [];

    ws.addEventListener('message', event => {
      const msg = JSON.parse(event.data);
      if (msg.method === 'Runtime.consoleAPICalled') {
        consoleLogs.push(msg.params);
      }
      if (msg.method === 'Runtime.exceptionThrown') {
        consoleLogs.push({ type: 'error', text: JSON.stringify(msg.params.exceptionDetails) });
      }
      if (msg.id && pending.has(msg.id)) {
        pending.get(msg.id)(msg.result);
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

    await send("Page.enable");
    await send("Runtime.enable");

    // Wait for initial render and data fetch
    await new Promise(r => setTimeout(r, 1500));

    const viewports = [
      { name: "desktop_1920x1080", width: 1920, height: 1080 },
      { name: "desktop_1366x768", width: 1366, height: 768 },
      { name: "tablet_landscape_1024x768", width: 1024, height: 768 },
      { name: "tablet_portrait_820x1180", width: 820, height: 1180 },
      { name: "mobile_portrait_430x932", width: 430, height: 932 },
      { name: "mobile_portrait_390x844", width: 390, height: 844 },
      { name: "mobile_portrait_360x800", width: 360, height: 800 },
      { name: "mobile_landscape_915x412", width: 915, height: 412 },
      { name: "mobile_landscape_844x390", width: 844, height: 390 },
      { name: "mobile_landscape_800x360", width: 800, height: 360 }
    ];

    console.log("\n=================== VIEWPORT AUDIT ===================");
    let allPassed = true;

    for (const vp of viewports) {
      await send("Emulation.setDeviceMetricsOverride", {
        width: vp.width,
        height: vp.height,
        deviceScaleFactor: 1,
        mobile: vp.width <= 844
      });

      await new Promise(r => setTimeout(r, 400));

      const evalRes = await send("Runtime.evaluate", {
        expression: `
          (() => {
            const body = document.body;
            const html = document.documentElement;
            const scrollW = Math.max(body.scrollWidth, html.scrollWidth);
            const clientW = html.clientWidth;
            const hasHOverflow = scrollW > clientW + 1;

            const img = document.getElementById('vortex-hero-visual');
            const imgFrame = document.getElementById('vortex-hero-frame');
            const hudText = document.getElementById('guardian-hud-text');
            const hudIndicator = document.getElementById('guardian-hud-indicator');
            const sdnOverview = document.querySelector('.network-overview-panel');
            const controllers = document.getElementById('net-controllers');
            const switches = document.getElementById('net-switches');
            const hosts = document.getElementById('net-hosts');
            const traffic = document.getElementById('net-traffic');

            const imgRect = img ? img.getBoundingClientRect() : null;
            const hudRect = hudText ? hudText.getBoundingClientRect() : null;
            const overviewRect = sdnOverview ? sdnOverview.getBoundingClientRect() : null;

            return {
              scrollW,
              clientW,
              hasHOverflow,
              imgFound: !!img,
              imgComplete: img ? img.complete : false,
              imgNaturalWidth: img ? img.naturalWidth : 0,
              imgNaturalHeight: img ? img.naturalHeight : 0,
              imgVisible: imgRect ? (imgRect.width > 0 && imgRect.height > 0) : false,
              imgWidth: imgRect ? Math.round(imgRect.width) : 0,
              imgHeight: imgRect ? Math.round(imgRect.height) : 0,
              hudText: hudText ? hudText.textContent.trim() : null,
              hudVisible: hudRect ? (hudRect.width > 0 && hudRect.height > 0) : false,
              controllers: controllers ? controllers.textContent.trim() : null,
              switches: switches ? switches.textContent.trim() : null,
              hosts: hosts ? hosts.textContent.trim() : null,
              traffic: traffic ? traffic.textContent.trim() : null,
              overviewVisible: overviewRect ? (overviewRect.width > 0 && overviewRect.height > 0) : false
            };
          })()
        `,
        returnByValue: true
      });

      const d = evalRes.result.value;

      // Capture screenshot for visual audit
      const screenRes = await send("Page.captureScreenshot", { format: "png" });
      const scrPath = path.join(__dirname, `audit_${vp.name}.png`);
      fs.writeFileSync(scrPath, Buffer.from(screenRes.data, "base64"));

      const isPass = !d.hasHOverflow && d.imgFound && d.imgComplete && d.imgVisible;
      if (!isPass) allPassed = false;

      console.log(`[${vp.name.padEnd(25)}] Pass:${isPass ? 'OK ' : 'FAIL'} | Overflow:${d.hasHOverflow} | Img:${d.imgWidth}x${d.imgHeight} (${d.imgNaturalWidth}x${d.imgNaturalHeight}) | HUD:"${d.hudText}" | Fabric: ${d.controllers}C/${d.switches}S/${d.hosts}H/${d.traffic}`);
    }

    // Privacy mode test
    console.log("\n=================== PRIVACY MODE TEST ===================");
    await send("Emulation.setDeviceMetricsOverride", { width: 1366, height: 768, deviceScaleFactor: 1 });
    await send("Runtime.evaluate", { expression: "document.getElementById('password').focus();" });
    await new Promise(r => setTimeout(r, 300));

    const privFocus = await send("Runtime.evaluate", {
      expression: `
        (() => {
          const stage = document.getElementById('guardian-stage');
          const hud = document.getElementById('guardian-hud-text');
          return {
            privacyClass: stage.classList.contains('privacy-active'),
            hudText: hud.textContent.trim()
          };
        })()
      `,
      returnByValue: true
    });
    console.log("Password focus (Privacy mode):", privFocus.result.value);

    await send("Runtime.evaluate", { expression: "document.getElementById('password').blur();" });
    await new Promise(r => setTimeout(r, 300));

    const privBlur = await send("Runtime.evaluate", {
      expression: `
        (() => {
          const stage = document.getElementById('guardian-stage');
          const hud = document.getElementById('guardian-hud-text');
          return {
            privacyClass: stage.classList.contains('privacy-active'),
            hudText: hud.textContent.trim()
          };
        })()
      `,
      returnByValue: true
    });
    console.log("Password blur (Restore monitoring):", privBlur.result.value);

    console.log("\n=================== CONSOLE ERRORS ===================");
    const errors = consoleLogs.filter(l => l.type === 'error');
    console.log("Console errors:", errors.length === 0 ? "NONE" : errors);

    console.log("\nOVERALL STATUS:", allPassed ? "ALL AUDITS PASSED!" : "AUDIT FAILED");

    ws.close();
  } finally {
    edge.kill();
  }
}

run().catch(e => {
  console.error("FATAL:", e);
  process.exit(1);
});
