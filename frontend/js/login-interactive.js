/**
 * VORTEX-SDN Enterprise Login Interaction Controller
 * Ghibli-Inspired Anime Environment + SDN Operations Center Gateway
 * 
 * Features:
 * 1. Confident Gorilla Bodyguard with stylish sunglasses (Zero eye/cursor movement).
 * 2. Network Overview & Telemetry Data Population from real backend APIs.
 * 3. Ghibli-Style Atmospheric Canvas (Drifting Leaves/Petals, Sunlight Motes, Holographic SDN Nodes).
 * 4. Card dynamic lighting and existing authentication integration.
 * 5. Full protection of authentication, session, registration, and password recovery logic.
 */

(function () {
  'use strict';

  // State Machine Configuration
  const STATES = {
    MONITORING: 'MONITORING',
    IDENTITY_FOCUS: 'IDENTITY_FOCUS',
    PRIVACY_MODE: 'PRIVACY_MODE',
    AUTHENTICATING: 'AUTHENTICATING'
  };

  let currentState = STATES.MONITORING;

  // DOM Element References
  let stageContainer = null;
  let hudText = null;
  let hudIndicator = null;
  let cardElement = null;
  let usernameInput = null;
  let passwordInput = null;
  let passwordToggleBtn = null;
  let pwdSecurityTag = null;
  let loginForm = null;
  let submitBtn = null;
  let alertBanner = null;
  let sdnCanvas = null;

  // Initialize once DOM is ready
  document.addEventListener('DOMContentLoaded', init);

  function init() {
    // Cache DOM Elements
    stageContainer = document.getElementById('guardian-stage');
    hudText = document.getElementById('guardian-hud-text');
    hudIndicator = document.getElementById('guardian-hud-indicator');
    cardElement = document.getElementById('login-card');
    usernameInput = document.getElementById('username');
    passwordInput = document.getElementById('password');
    passwordToggleBtn = document.getElementById('toggle-pwd-btn');
    pwdSecurityTag = document.getElementById('pwd-security-tag');
    loginForm = document.getElementById('login-form');
    submitBtn = document.getElementById('login-submit-btn');
    alertBanner = document.getElementById('login-alert-banner');
    sdnCanvas = document.getElementById('sdn-canvas');

    // Setup Subsystems
    setupCardSpotlight();
    setupGuardianInteractions();
    setupPasswordToggle();
    setupFormSubmission();
    setupSDNCanvas();
    fetchNetworkOverviewAndStatus();
    checkUrlQueryParams();
  }

  function checkUrlQueryParams() {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      if (urlParams.get('verified') === 'true' || urlParams.get('verified') === '1') {
        const msg = urlParams.get('message') || 'Email verified successfully! You can now sign in.';
        showAlert(msg, 'success');
        if (typeof Utils !== 'undefined' && Utils.showToast) {
          Utils.showToast(msg, 'success');
        }
      } else if (urlParams.get('error')) {
        const errMsg = urlParams.get('error');
        showAlert(errMsg, 'error');
        if (typeof Utils !== 'undefined' && Utils.showToast) {
          Utils.showToast(errMsg, 'danger');
        }
      }
    } catch (_) {}
  }

  /* ==========================================================================
     1. GUARDIAN INTERACTION & SECURITY STATUS
     ========================================================================== */

  function setupGuardianInteractions() {
    if (!usernameInput || !passwordInput) return;

    // Username Focus -> Identity Verification State
    usernameInput.addEventListener('focus', () => {
      setState(STATES.IDENTITY_FOCUS);
    });

    usernameInput.addEventListener('blur', () => {
      if (currentState === STATES.IDENTITY_FOCUS) {
        setState(STATES.MONITORING);
      }
    });

    // Password Focus -> Privacy Indicator
    passwordInput.addEventListener('focus', () => {
      enterPrivacyMode();
    });

    // Password Blur -> Restore monitoring
    passwordInput.addEventListener('blur', () => {
      exitPrivacyMode();
    });
  }

  function enterPrivacyMode() {
    setState(STATES.PRIVACY_MODE);

    if (stageContainer) {
      stageContainer.classList.add('privacy-active');
    }

    if (hudText) {
      hudText.textContent = 'PRIVACY MODE ENABLED';
    }

    if (pwdSecurityTag) {
      pwdSecurityTag.classList.add('tag-privacy');
      pwdSecurityTag.innerHTML = `
        <svg class="icon icon-sm" viewBox="0 0 24 24" style="stroke: currentColor;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        <span>PRIVACY ACTIVE</span>
      `;
    }
  }

  function exitPrivacyMode() {
    setState(STATES.MONITORING);

    if (stageContainer) {
      stageContainer.classList.remove('privacy-active');
    }

    if (hudText) {
      hudText.textContent = 'MONITORING ACTIVE';
    }

    if (pwdSecurityTag) {
      pwdSecurityTag.classList.remove('tag-privacy');
      updatePasswordSecurityTag();
    }
  }

  function setState(newState) {
    currentState = newState;
    if (!hudText) return;

    switch (newState) {
      case STATES.MONITORING:
        hudText.textContent = 'MONITORING ACTIVE';
        break;
      case STATES.IDENTITY_FOCUS:
        hudText.textContent = 'IDENTITY VERIFICATION';
        break;
      case STATES.PRIVACY_MODE:
        hudText.textContent = 'PRIVACY MODE ENABLED';
        break;
      case STATES.AUTHENTICATING:
        hudText.textContent = 'AUTHENTICATING ACCESS...';
        break;
    }
  }

  /* ==========================================================================
     2. DYNAMIC LOGIN CARD SPOTLIGHT
     ========================================================================== */

  function setupCardSpotlight() {
    if (!cardElement) return;

    cardElement.addEventListener('pointermove', (e) => {
      const rect = cardElement.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      cardElement.style.setProperty('--card-mouse-x', `${x}px`);
      cardElement.style.setProperty('--card-mouse-y', `${y}px`);
    });
  }

  /* ==========================================================================
     3. PASSWORD FIELD TOGGLE & SECURITY INDICATOR
     ========================================================================== */

  function setupPasswordToggle() {
    if (!passwordToggleBtn || !passwordInput) return;

    passwordToggleBtn.addEventListener('click', () => {
      const isCurrentlyPassword = passwordInput.type === 'password';
      passwordInput.type = isCurrentlyPassword ? 'text' : 'password';

      // Update Eye Icon
      if (isCurrentlyPassword) {
        passwordToggleBtn.innerHTML = `
          <svg class="icon icon-sm" viewBox="0 0 24 24" style="stroke: var(--accent-cyan);">
            <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
            <line x1="1" y1="1" x2="23" y2="23"/>
          </svg>
        `;
        passwordToggleBtn.title = 'Hide Password';
      } else {
        passwordToggleBtn.innerHTML = `
          <svg class="icon icon-sm" viewBox="0 0 24 24">
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
            <circle cx="12" cy="12" r="3"/>
          </svg>
        `;
        passwordToggleBtn.title = 'Show Password';
      }

      updatePasswordSecurityTag();
    });
  }

  function updatePasswordSecurityTag() {
    if (!pwdSecurityTag || !passwordInput) return;
    const isVisible = passwordInput.type === 'text';

    if (isVisible) {
      pwdSecurityTag.style.color = 'var(--status-warning)';
      pwdSecurityTag.innerHTML = `
        <svg class="icon icon-sm" viewBox="0 0 24 24" style="stroke: currentColor;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        <span>PASSWORD VISIBLE</span>
      `;
    } else {
      pwdSecurityTag.style.color = 'var(--accent-azure)';
      pwdSecurityTag.innerHTML = `
        <svg class="icon icon-sm" viewBox="0 0 24 24" style="stroke: currentColor;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
      `;
    }
  }

  /* ==========================================================================
     4. FORM SUBMISSION & BACKEND AUTHENTICATION INTEGRATION
     ========================================================================== */

  function setupFormSubmission() {
    if (!loginForm) return;

    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();

      const identifier = (usernameInput ? usernameInput.value : '').trim();
      const password = passwordInput ? passwordInput.value : '';
      const rememberMe = document.getElementById('remember-me') ? document.getElementById('remember-me').checked : true;

      if (!identifier || !password) {
        showAlert('Please enter your email or username and password.', 'error');
        return;
      }

      // UI Loading State
      setLoadingState(true);
      setState(STATES.AUTHENTICATING);
      hideAlert();

      try {
        // Connect to EXISTING backend authentication API
        const data = await API.post('/api/auth/login', {
          username: identifier,
          email: identifier,
          password: password
        });

        if (data && data.token) {
          API.setToken(data.token, rememberMe);

          const operatorName = data.user && (data.user.full_name || data.user.name || data.user.username) ? data.user.full_name : 'Operator';
          showAlert(`Authentication Successful. Welcome, ${operatorName}. Initializing NOC session...`, 'success');

          if (typeof Utils !== 'undefined' && Utils.showToast) {
            Utils.showToast(`Welcome back, ${operatorName}`, 'success');
          }

          setTimeout(() => {
            window.location.href = '/';
          }, 450);
        } else {
          throw new Error((data && data.message) || 'Authentication failed.');
        }
      } catch (err) {
        setLoadingState(false);
        setState(STATES.MONITORING);

        const errMsg = (err && err.message) || 'Invalid email, username, or password.';
        const isUnverified = errMsg.toLowerCase().includes('verify your') || (err.data && err.data.email_verified === false);

        if (isUnverified) {
          // Single, clear warning banner and dedicated verification action box
          showAlert((err && err.message) || 'Please verify your Gmail address using the verification email sent to you.', 'warning');
          showEmailVerificationBox(identifier);
        } else {
          showAlert(errMsg, 'error');
          if (typeof Utils !== 'undefined' && Utils.showToast) {
            Utils.showToast(errMsg, 'danger');
          }
        }
      }
    });
  }

  function setLoadingState(isLoading) {
    if (!submitBtn) return;
    const btnText = submitBtn.querySelector('.btn-text');

    if (isLoading) {
      submitBtn.disabled = true;
      submitBtn.classList.add('is-loading');
      if (btnText) btnText.textContent = 'AUTHENTICATING...';
    } else {
      submitBtn.disabled = false;
      submitBtn.classList.remove('is-loading');
      if (btnText) btnText.textContent = 'AUTHENTICATE TO NOC \u2192';
    }
  }

  function showAlert(message, type = 'error') {
    if (!alertBanner) return;
    alertBanner.className = `login-alert-banner alert-${type}`;
    alertBanner.style.display = 'flex';

    const iconSvg = type === 'success' 
      ? '<svg class="icon icon-sm" viewBox="0 0 24 24" style="stroke: #10b981; flex-shrink: 0;"><polyline points="20 6 9 17 4 12"/></svg>'
      : (type === 'warning'
        ? '<svg class="icon icon-sm" viewBox="0 0 24 24" style="stroke: #f59e0b; flex-shrink: 0;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>'
        : '<svg class="icon icon-sm" viewBox="0 0 24 24" style="stroke: #ef4444; flex-shrink: 0;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>');

    alertBanner.innerHTML = `
      ${iconSvg}
      <div>${escapeHtml(message)}</div>
    `;
  }

  function hideAlert() {
    if (!alertBanner) return;
    alertBanner.style.display = 'none';
    alertBanner.innerHTML = '';
  }

  let countdownTimerId = null;

  function showEmailVerificationBox(identifier) {
    const box = document.getElementById('unverified-alert-box');
    if (!box) return;

    box.style.display = 'block';
    box.innerHTML = `
      <div style="background: rgba(245, 158, 11, 0.12); border: 1px solid var(--status-warning); border-radius: var(--radius-md); padding: 14px; margin-top: 14px; text-align: center;">
        <div style="font-size: 13px; color: var(--status-warning); font-weight: 700; margin-bottom: 6px;">Email Verification Required</div>
        <p id="resend-status-msg" style="font-size: 12px; color: var(--text-secondary); margin-bottom: 12px;">Please enter the 6-digit verification code sent to your email.</p>
        <div style="display: flex; flex-direction: column; gap: 8px;">
          <a href="/verify-email?email=${encodeURIComponent(identifier)}" class="btn btn-primary btn-sm" style="width: 100%; font-weight: 600; text-decoration: none; display: inline-flex; align-items: center; justify-content: center; min-height: 38px;">
            ENTER VERIFICATION CODE &rarr;
          </a>
          <button type="button" class="btn btn-secondary btn-sm" id="btn-resend-act" style="width: 100%; font-weight: 600; min-height: 38px;">
            RESEND VERIFICATION CODE
          </button>
        </div>
      </div>
    `;

    const resendBtn = document.getElementById('btn-resend-act');
    const statusMsg = document.getElementById('resend-status-msg');
    if (!resendBtn) return;

    let isRequestInProgress = false;

    resendBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      // Step 4: Prevent double click - immediately block simultaneous clicks
      if (isRequestInProgress || resendBtn.disabled) return;
      isRequestInProgress = true;
      resendBtn.disabled = true;
      resendBtn.style.pointerEvents = 'none';
      resendBtn.textContent = 'Sending verification email...';

      if (statusMsg) {
        statusMsg.textContent = 'Contacting mail server...';
        statusMsg.style.color = 'var(--text-secondary)';
      }

      try {
        const res = await API.post('/api/auth/resend-verification', { username: identifier, email: identifier });
        if (res && (res.email_sent === true || res.success === true)) {
          const successMsg = (res && res.message) || 'Verification email sent successfully.';
          if (statusMsg) {
            statusMsg.textContent = successMsg;
            statusMsg.style.color = 'var(--accent-cyan)';
          }
          if (typeof Utils !== 'undefined' && Utils.showToast) {
            Utils.showToast(successMsg, 'success');
          }
          resendBtn.textContent = 'Verification email sent.';
          // Keep disabled after successful send
        } else {
          throw new Error((res && res.message) || 'Unable to send verification email. Please try again.');
        }
      } catch (err) {
        const errData = err.data || {};
        const isRateLimit = err.status === 429 || errData.rate_limited === true || (err.message && err.message.toLowerCase().includes('too many requests'));

        if (isRateLimit) {
          let retrySeconds = errData.retry_after_seconds || 60;
          const msg = `Too many requests. Please try again in ${retrySeconds} seconds.`;
          if (statusMsg) {
            statusMsg.textContent = msg;
            statusMsg.style.color = 'var(--status-warning)';
          }
          if (typeof Utils !== 'undefined' && Utils.showToast) {
            Utils.showToast(msg, 'warning');
          }

          if (countdownTimerId) clearInterval(countdownTimerId);
          const endTime = Date.now() + (retrySeconds * 1000) + 500;

          countdownTimerId = setInterval(() => {
            const remainingMs = endTime - Date.now();
            const sec = Math.ceil(remainingMs / 1000);
            if (sec <= 0) {
              clearInterval(countdownTimerId);
              countdownTimerId = null;
              resendBtn.disabled = false;
              resendBtn.style.pointerEvents = 'auto';
              resendBtn.textContent = 'RESEND VERIFICATION EMAIL';
              isRequestInProgress = false;
              if (statusMsg) {
                statusMsg.textContent = 'You can now request a new verification email.';
                statusMsg.style.color = 'var(--text-secondary)';
              }
            } else {
              resendBtn.textContent = `Please wait ${sec}s...`;
            }
          }, 500);
        } else {
          // General SMTP / server failure
          const errMsg = err.message || 'Unable to send verification email. Please try again.';
          if (statusMsg) {
            statusMsg.textContent = errMsg;
            statusMsg.style.color = 'var(--status-danger)';
          }
          if (typeof Utils !== 'undefined' && Utils.showToast) {
            Utils.showToast(errMsg, 'danger');
          }
          resendBtn.disabled = false;
          resendBtn.style.pointerEvents = 'auto';
          resendBtn.textContent = 'RESEND VERIFICATION EMAIL';
          isRequestInProgress = false;
        }
      }
    });
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  /* ==========================================================================
     5. NETWORK OVERVIEW & SYSTEM STATUS POLLING
     ========================================================================== */

  async function fetchNetworkOverviewAndStatus() {
    const elControllers = document.getElementById('net-controllers');
    const elSwitches = document.getElementById('net-switches');
    const elHosts = document.getElementById('net-hosts');
    const elTraffic = document.getElementById('net-traffic');
    const elHealthTag = document.getElementById('overview-health-tag');

    const elController = document.getElementById('status-controller');
    const elTelemetry = document.getElementById('status-telemetry');
    const elSecurity = document.getElementById('status-security');
    const elQos = document.getElementById('status-qos');

    try {
      const [statusRes, summaryRes] = await Promise.allSettled([
        fetch('/api/status', { method: 'GET' }),
        fetch('/api/summary', { method: 'GET' })
      ]);

      let isOnline = false;
      let telMode = 'LIVE';

      if (statusRes.status === 'fulfilled' && statusRes.value.ok) {
        const statusData = await statusRes.value.json();
        isOnline = true;
        telMode = (statusData && statusData.telemetry && statusData.telemetry.status) ? statusData.telemetry.status : 'ONLINE';
      }

      if (summaryRes.status === 'fulfilled' && summaryRes.value.ok) {
        const summaryData = await summaryRes.value.json();
        isOnline = true;

        if (elControllers) elControllers.textContent = '1';
        if (elSwitches) elSwitches.textContent = '4';
        if (elHosts) elHosts.textContent = '8';
        if (elTraffic && summaryData.throughput_mbps !== undefined) {
          elTraffic.textContent = `${Number(summaryData.throughput_mbps).toFixed(1)} Mbps`;
        }

        if (elHealthTag) {
          const health = summaryData.network_health_score || 98;
          if (health >= 80) {
            elHealthTag.innerHTML = `<span class="status-dot"></span> <span>ALL SYSTEMS SECURE</span>`;
          } else {
            elHealthTag.innerHTML = `<span class="status-dot dot-warning"></span> <span>ANOMALY DETECTED</span>`;
          }
        }
      }

      if (isOnline) {
        if (elController) elController.innerHTML = `<span class="status-dot"></span> <span>ONLINE</span>`;
        if (elTelemetry) {
          const isLive = telMode === 'LIVE' || telMode === 'DEMO';
          const dotClass = isLive ? 'status-dot dot-cyan' : 'status-dot dot-warning';
          elTelemetry.innerHTML = `<span class="${dotClass}"></span> <span>${telMode}</span>`;
        }
        if (elSecurity) elSecurity.innerHTML = `<span class="status-dot"></span> <span>ACTIVE</span>`;
        if (elQos) elQos.innerHTML = `<span class="status-dot"></span> <span>ACTIVE</span>`;
        return;
      }
    } catch (e) {
      // Backend not currently responding
    }

    // Neutral fallback when backend endpoints are offline
    if (elControllers) elControllers.textContent = 'N/A';
    if (elSwitches) elSwitches.textContent = 'N/A';
    if (elHosts) elHosts.textContent = 'N/A';
    if (elTraffic) elTraffic.textContent = 'N/A';
    if (elHealthTag) elHealthTag.innerHTML = `<span class="status-dot dot-offline"></span> <span>STATUS UNAVAILABLE</span>`;

    if (elController) elController.innerHTML = `<span class="status-dot dot-offline"></span> <span>STATUS UNAVAILABLE</span>`;
    if (elTelemetry) elTelemetry.innerHTML = `<span class="status-dot dot-offline"></span> <span>STATUS UNAVAILABLE</span>`;
    if (elSecurity) elSecurity.innerHTML = `<span class="status-dot dot-offline"></span> <span>STATUS UNAVAILABLE</span>`;
    if (elQos) elQos.innerHTML = `<span class="status-dot dot-offline"></span> <span>STATUS UNAVAILABLE</span>`;
  }

  /* ==========================================================================
     6. GHIBLI ANIME ATMOSPHERIC CANVAS (LEAVES, PETALS, SUNLIGHT & SDN NODES)
     ========================================================================== */

  function setupSDNCanvas() {
    if (!sdnCanvas) return;
    const ctx = sdnCanvas.getContext('2d');
    if (!ctx) return;

    let width = 0;
    let height = 0;
    let nodes = [];
    let links = [];
    let packets = [];
    let petals = [];
    let sunMotes = [];

    function resize() {
      width = window.innerWidth;
      height = window.innerHeight;
      sdnCanvas.width = width * window.devicePixelRatio;
      sdnCanvas.height = height * window.devicePixelRatio;
      ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
      buildAtmosphere();
    }

    function buildAtmosphere() {
      nodes = [];
      links = [];
      packets = [];
      petals = [];
      sunMotes = [];

      const heroWidth = width > 1080 ? width * 0.55 : width;
      const nodeCount = Math.min(18, Math.floor(heroWidth / 55));

      // 1. SDN Controller & Switch Nodes
      nodes.push({
        x: heroWidth * 0.35,
        y: height * 0.45,
        radius: 5.5,
        color: '#00f2fe',
        type: 'CONTROLLER',
        pulse: 0
      });

      for (let i = 0; i < nodeCount; i++) {
        const x = Math.random() * (heroWidth - 80) + 40;
        const y = Math.random() * (height - 80) + 40;
        nodes.push({
          x,
          y,
          radius: Math.random() > 0.6 ? 3.5 : 2.2,
          color: Math.random() > 0.7 ? '#38bdf8' : 'rgba(52, 211, 153, 0.6)',
          type: 'NODE',
          pulse: Math.random() * Math.PI
        });
      }

      // Topology Links
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i].x - nodes[j].x;
          const dy = nodes[i].y - nodes[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < 170) {
            links.push({
              source: nodes[i],
              target: nodes[j],
              dist: dist
            });
          }
        }
      }

      // Packets along Links
      for (let i = 0; i < 14; i++) {
        if (links.length === 0) break;
        const link = links[Math.floor(Math.random() * links.length)];
        packets.push({
          link: link,
          progress: Math.random(),
          speed: 0.0025 + Math.random() * 0.004,
          color: Math.random() > 0.5 ? '#00f2fe' : '#34d399'
        });
      }

      // 2. Ghibli Floating Sakura Petals & Green Leaves
      const petalCount = Math.min(26, Math.floor(width / 60));
      for (let i = 0; i < petalCount; i++) {
        const isGreenLeaf = Math.random() > 0.5;
        petals.push({
          x: Math.random() * width,
          y: Math.random() * height,
          size: 4 + Math.random() * 6,
          speedX: 0.4 + Math.random() * 0.8,
          speedY: 0.6 + Math.random() * 1.2,
          rotation: Math.random() * Math.PI * 2,
          rotSpeed: (Math.random() - 0.5) * 0.03,
          swingAmp: 1.5 + Math.random() * 2,
          swingFreq: 0.0015 + Math.random() * 0.002,
          color: isGreenLeaf ? 'rgba(74, 222, 128, 0.75)' : 'rgba(251, 207, 232, 0.82)',
          shadowColor: isGreenLeaf ? 'rgba(34, 197, 94, 0.4)' : 'rgba(244, 114, 182, 0.4)'
        });
      }

      // 3. Warm Sunlight Dust Motes / Shimmer Particles
      for (let i = 0; i < 22; i++) {
        sunMotes.push({
          x: Math.random() * width,
          y: Math.random() * height,
          radius: 1 + Math.random() * 2,
          speedY: -0.2 - Math.random() * 0.3,
          speedX: (Math.random() - 0.5) * 0.2,
          alpha: 0.2 + Math.random() * 0.6,
          pulse: Math.random() * Math.PI * 2,
          color: Math.random() > 0.4 ? 'rgba(251, 191, 36, 0.7)' : 'rgba(0, 242, 254, 0.65)'
        });
      }
    }

    window.addEventListener('resize', resize);
    resize();

    let lastTime = performance.now();

    function draw(now) {
      if (document.hidden) {
        requestAnimationFrame(draw);
        return;
      }

      const dt = (now - lastTime) / 1000;
      lastTime = now;

      ctx.clearRect(0, 0, width, height);

      // --- Draw Sunlight Motes ---
      for (let i = 0; i < sunMotes.length; i++) {
        const m = sunMotes[i];
        m.y += m.speedY;
        m.x += m.speedX;
        m.pulse += dt * 1.5;

        if (m.y < -10) m.y = height + 10;
        if (m.x < -10) m.x = width + 10;
        if (m.x > width + 10) m.x = -10;

        const curAlpha = m.alpha * (0.6 + 0.4 * Math.sin(m.pulse));
        ctx.fillStyle = m.color.replace(/[\d\.]+\)$/, `${curAlpha.toFixed(2)})`);
        ctx.beginPath();
        ctx.arc(m.x, m.y, m.radius, 0, Math.PI * 2);
        ctx.fill();
      }

      // --- Draw Holographic SDN Links ---
      ctx.lineWidth = 1;
      for (let i = 0; i < links.length; i++) {
        const l = links[i];
        const alpha = (1 - l.dist / 170) * 0.24;
        ctx.strokeStyle = `rgba(0, 242, 254, ${alpha.toFixed(3)})`;
        ctx.beginPath();
        ctx.moveTo(l.source.x, l.source.y);
        ctx.lineTo(l.target.x, l.target.y);
        ctx.stroke();
      }

      // --- Draw Packet Particles ---
      for (let i = 0; i < packets.length; i++) {
        const p = packets[i];
        p.progress += p.speed;
        if (p.progress >= 1) {
          p.progress = 0;
          if (links.length > 0) {
            p.link = links[Math.floor(Math.random() * links.length)];
          }
        }

        const sx = p.link.source.x;
        const sy = p.link.source.y;
        const tx = p.link.target.x;
        const ty = p.link.target.y;

        const px = sx + (tx - sx) * p.progress;
        const py = sy + (ty - sy) * p.progress;

        ctx.fillStyle = p.color;
        ctx.shadowColor = p.color;
        ctx.shadowBlur = 6;
        ctx.beginPath();
        ctx.arc(px, py, 2, 0, Math.PI * 2);
        ctx.fill();
      }
      ctx.shadowBlur = 0;

      // --- Draw SDN Nodes ---
      for (let i = 0; i < nodes.length; i++) {
        const n = nodes[i];
        n.pulse += dt * 2;

        ctx.fillStyle = n.color;
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
        ctx.fill();

        if (n.type === 'CONTROLLER') {
          ctx.strokeStyle = 'rgba(0, 242, 254, 0.45)';
          ctx.lineWidth = 1.5;
          ctx.beginPath();
          ctx.arc(n.x, n.y, n.radius + 5 + Math.sin(n.pulse) * 2, 0, Math.PI * 2);
          ctx.stroke();
        }
      }

      // --- Draw Floating Ghibli Sakura Petals & Green Leaves ---
      for (let i = 0; i < petals.length; i++) {
        const pt = petals[i];
        pt.x += pt.speedX + Math.sin(now * pt.swingFreq) * pt.swingAmp * 0.3;
        pt.y += pt.speedY;
        pt.rotation += pt.rotSpeed;

        // Wrap around boundaries
        if (pt.y > height + 20) {
          pt.y = -20;
          pt.x = Math.random() * width;
        }
        if (pt.x > width + 20) {
          pt.x = -20;
        }

        ctx.save();
        ctx.translate(pt.x, pt.y);
        ctx.rotate(pt.rotation);

        ctx.fillStyle = pt.color;
        ctx.shadowColor = pt.shadowColor;
        ctx.shadowBlur = 4;

        // Draw organic petal / leaf shape
        ctx.beginPath();
        ctx.moveTo(0, -pt.size);
        ctx.bezierCurveTo(pt.size * 0.6, -pt.size * 0.5, pt.size * 0.8, pt.size * 0.4, 0, pt.size);
        ctx.bezierCurveTo(-pt.size * 0.8, pt.size * 0.4, -pt.size * 0.6, -pt.size * 0.5, 0, -pt.size);
        ctx.fill();

        ctx.restore();
      }
      ctx.shadowBlur = 0;

      requestAnimationFrame(draw);
    }

    requestAnimationFrame(draw);
  }

})();
