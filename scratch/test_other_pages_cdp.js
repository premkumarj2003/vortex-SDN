const http = require('http');
const path = require('path');
const { spawn } = require('child_process');

const EDGE_PATH = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const USER_DATA = path.join(process.env.TEMP || "C:\\temp", "edge_other_profile_" + Date.now());

const pages = [
  { name: "register", url: "http://127.0.0.1:5000/register" },
  { name: "forgot-password", url: "http://127.0.0.1:5000/forgot-password" },
  { name: "reset-password", url: "http://127.0.0.1:5000/reset-password?token=test" },
  { name: "verify-email", url: "http://127.0.0.1:5000/verify-email?token=test" }
];

const viewports = [
  { name: "portrait_390x844", width: 390, height: 844 },
  { name: "landscape_844x390", width: 844, height: 390 },
  { name: "tablet_1024x768", width: 1024, height: 768 }
];

async function run() {
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
    const pageTab = tabs.find(t => t.url && !t.url.startsWith("chrome") && !t.url.startsWith("edge")) || tabs[0];
    const ws = new globalThis.WebSocket(pageTab.webSocketDebuggerUrl);

    let msgId = 1;
    const pending = new Map();
    ws.addEventListener('message', ev => {
      const msg = JSON.parse(ev.data);
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

    await send("Page.enable");
    await send("Runtime.enable");

    for (const page of pages) {
      console.log(`\n========================================\nPAGE: ${page.name}`);
      await send("Page.navigate", { url: page.url });
      await new Promise(r => setTimeout(r, 600));

      for (const vp of viewports) {
        await send("Emulation.setDeviceMetricsOverride", {
          width: vp.width,
          height: vp.height,
          deviceScaleFactor: 1,
          mobile: vp.width <= 844
        });
        await new Promise(r => setTimeout(r, 300));

        const evalRes = await send("Runtime.evaluate", {
          expression: `JSON.stringify({
            innerWidth: window.innerWidth,
            scrollWidth: document.documentElement.scrollWidth,
            hasHorizontalOverflow: document.documentElement.scrollWidth > window.innerWidth,
            scrollHeight: document.documentElement.scrollHeight
          })`,
          returnByValue: true
        });

        const m = JSON.parse(evalRes.result.result.value);
        console.log(`  [${vp.name}] innerWidth=${m.innerWidth}, scrollWidth=${m.scrollWidth}, overflow=${m.hasHorizontalOverflow}`);
        if (m.hasHorizontalOverflow) {
          console.error(`  ERROR: Horizontal overflow detected on ${page.name} in ${vp.name}!`);
          process.exitCode = 1;
        }
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
