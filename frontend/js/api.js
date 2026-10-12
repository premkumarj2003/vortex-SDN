/**
 * VORTEX-SDN Centralized Resilient API Client
 * Handles authentication headers, timeouts, HTTP errors, 401/403 handling, and retries.
 */

const API = {
  baseUrl:(window.location.hostname === "localhost" ||
          window.location.hostname === "127.0.0.1")
    ? window.location.origin
    : "https://wallpapers-field-pace-focused.trycloudflare.com",
  timeoutMs: 12000,

  getToken() {
    return localStorage.getItem("vortex_token") || sessionStorage.getItem("vortex_token");
  },

  setToken(token, remember = true) {
    if (remember) {
      localStorage.setItem("vortex_token", token);
    } else {
      sessionStorage.setItem("vortex_token", token);
    }
  },

  clearToken() {
    localStorage.removeItem("vortex_token");
    sessionStorage.removeItem("vortex_token");
  },

  async request(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;
    const token = this.getToken();

    const headers = {
      "Content-Type": "application/json",
      ...(token ? { "Authorization": `Bearer ${token}` } : {}),
      ...(options.headers || {})
    };

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(url, {
        ...options,
        headers,
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      // Handle 401 Unauthorized on protected endpoints
      if (response.status === 401 && !endpoint.includes("/api/auth/login") && !endpoint.includes("/api/auth/me")) {
        console.warn("[API] Session expired or unauthorized.");
        this.clearToken();
        const path = window.location.pathname;
        const publicPages = ["login", "register", "verify-email", "forgot-password", "reset-password"];
        const isPublic = publicPages.some(p => path.includes(p));
        if (!isPublic) {
          window.location.href = "login.html";
        }
      }

      if (!response.ok) {
        const errJson = await response.json().catch(() => ({}));
        const error = new Error(errJson.message || `HTTP ${response.status}: ${response.statusText}`);
        error.data = errJson;
        error.code = errJson.code;
        error.status = response.status;
        throw error;
      }

      return await response.json();
    } catch (err) {
      clearTimeout(timeoutId);
      if (err.name === "AbortError") {
        throw new Error("Network request timed out.");
      }
      throw err;
    }
  },

  get(endpoint, params = {}) {
    const query = new URLSearchParams(params).toString();
    const url = query ? `${endpoint}?${query}` : endpoint;
    return this.request(url, { method: "GET" });
  },

  post(endpoint, body = {}) {
    return this.request(endpoint, {
      method: "POST",
      body: JSON.stringify(body)
    });
  },

  put(endpoint, body = {}) {
    return this.request(endpoint, {
      method: "PUT",
      body: JSON.stringify(body)
    });
  },

  delete(endpoint) {
    return this.request(endpoint, { method: "DELETE" });
  }
};
