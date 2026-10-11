const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const EDGE_PATH = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const USER_DATA = path.join(process.env.TEMP || "C:\\temp", "edge_cdp_profile_" + Date.now());

async function run() {
  console.log("Launching Edge with remote debugging...");
  const edge = spawn(EDGE_PATH, [
    "--headless=new",
    "--remote-debugging-port=9222",
    `--user-data-dir=${USER_DATA}`,
    "--no-first-run",
    "--no-default-browser-check",
    "http://127.0.0.1:5000/login"
  ]);

  // Wait 2s for edge to start
  await new Promise(r => setTimeout(r, 2000));

  try {
    // Get target tabs
    const tabs = await getJson("http://127.0.0.1:9222/json");
    console.log("Tabs:", tabs.map(t => ({ title: t.title, url: t.url })));
    const pageTab = tabs.find(t => t.url && t.url.includes("login")) || tabs[0];
    if (!pageTab) throw new Error("No page tab found");

    const wsUrl = pageTab.webSocketDebuggerUrl;
    console.log("Connecting WebSocket:", wsUrl);

    const ws = new globalThis.WebSocket(wsUrl);

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

    // Enable Runtime & Page
    await send("Page.enable");
    await send("Runtime.enable");

    const viewports = [
      { name: "portrait_360x800", width: 360, height: 800 },
      { name: "portrait_375x812", width: 375, height: 812 },
      { name: "portrait_390x844", width: 390, height: 844 },
      { name: "portrait_412x915", width: 412, height: 915 },
      { name: "portrait_430x932", width: 430, height: 932 },
      { name: "landscape_800x360", width: 800, height: 360 },
      { name: "landscape_812x375", width: 812, height: 375 },
      { name: "landscape_844x390", width: 844, height: 390 },
      { name: "landscape_915x412", width: 915, height: 412 },
      { name: "tablet_768x1024", width: 768, height: 1024 },
      { name: "tablet_820x1180", width: 820, height: 1180 },
      { name: "tablet_1024x768", width: 1024, height: 768 },
      { name: "desktop_1366x768", width: 1366, height: 768 },
      { name: "desktop_1920x1080", width: 1920, height: 1080 }
    ];

    for (const vp of viewports) {
      await send("Emulation.setDeviceMetricsOverride", {
        width: vp.width,
        height: vp.height,
        deviceScaleFactor: 1,
        mobile: vp.width <= 844
      });

      await new Promise(r => setTimeout(r, 500));

      const evalRes = await send("Runtime.evaluate", {
        expression: `JSON.stringify({
          innerWidth: window.innerWidth,
          innerHeight: window.innerHeight,
          scrollWidth: document.documentElement.scrollWidth,
          scrollHeight: document.documentElement.scrollHeight,
          hasHorizontalOverflow: document.documentElement.scrollWidth > window.innerWidth,
          formVisible: !!document.getElementById("login-form"),
          usernameVisible: !!document.getElementById("username"),
          passwordVisible: !!document.getElementById("password"),
          toggleBtnVisible: !!document.getElementById("toggle-pwd-btn"),
          submitBtnVisible: !!document.getElementById("login-submit-btn"),
          forgotLinkVisible: !!document.querySelector(".forgot-password-link"),
          registerLinkVisible: !!document.querySelector(".register-account-link"),
          wrapperRect: document.querySelector(".login-experience-wrapper") ? document.querySelector(".login-experience-wrapper").getBoundingClientRect() : null,
          heroRect: document.querySelector(".hero-environment-column") ? document.querySelector(".hero-environment-column").getBoundingClientRect() : null,
          cardBoundingRect: document.getElementById("login-card") ? document.getElementById("login-card").getBoundingClientRect() : null
        })`,
        returnByValue: true
      });

      const metrics = JSON.parse(evalRes.result.result.value);
      console.log(`\n=== Viewport: ${vp.name} (${vp.width}x${vp.height}) ===`);
      console.log("Scroll metrics:", {
        innerWidth: metrics.innerWidth,
        scrollWidth: metrics.scrollWidth,
        hasHorizontalOverflow: metrics.hasHorizontalOverflow,
        scrollHeight: metrics.scrollHeight
      });
      console.log("Elements visible:", {
        username: metrics.usernameVisible,
        password: metrics.passwordVisible,
        toggleBtn: metrics.toggleBtnVisible,
        submitBtn: metrics.submitBtnVisible,
        forgotLink: metrics.forgotLinkVisible,
        registerLink: metrics.registerLinkVisible
      });
      if (metrics.wrapperRect) {
        console.log("Wrapper rect:", {
          width: Math.round(metrics.wrapperRect.width),
          height: Math.round(metrics.wrapperRect.height),
          left: Math.round(metrics.wrapperRect.left)
        });
      }
      if (metrics.heroRect) {
        console.log("Hero rect:", {
          width: Math.round(metrics.heroRect.width),
          height: Math.round(metrics.heroRect.height),
          left: Math.round(metrics.heroRect.left)
        });
      }
      if (metrics.cardBoundingRect) {
        console.log("Card rect:", {
          width: Math.round(metrics.cardBoundingRect.width),
          height: Math.round(metrics.cardBoundingRect.height),
          top: Math.round(metrics.cardBoundingRect.top),
          left: Math.round(metrics.cardBoundingRect.left)
        });
      }

      // Take screenshot
      const shotRes = await send("Page.captureScreenshot", { format: "png" });
      if (shotRes.result && shotRes.result.data) {
        const outPath = path.join(__dirname, `login_${vp.name}.png`);
        fs.writeFileSync(outPath, Buffer.from(shotRes.result.data, 'base64'));
        console.log(`Saved screenshot: ${outPath}`);
      }
    }

    ws.close();
  } finally {
    edge.kill();
  }
}

function getJson(url) {
  return new Promise((resolve, reject) => {
    http.get(url, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
      });
    }).on('error', reject);
  });
}

run().catch(console.error);
