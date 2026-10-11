/**
 * VORTEX-SDN Enterprise NOC AI Assistant Controller
 * Converses with backend AI engine grounded directly in live telemetry and OpenFlow state.
 */

const Chatbot = {
  isOpen: false,
  isMinimized: false,
  isAnalyzing: false,
  sessionId: `sess_${Math.random().toString(36).substring(2, 9)}`,

  init() {
    this.setupListeners();
    this.checkStatus();
  },

  setupListeners() {
    // Launcher click & keydown
    const launcher = document.getElementById("chatbot-launcher");
    if (launcher) {
      launcher.addEventListener("click", () => this.toggle());
      launcher.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          this.toggle();
        }
      });
    }

    // Close button
    const closeBtn = document.getElementById("chatbot-close-btn");
    if (closeBtn) {
      closeBtn.addEventListener("click", () => this.close());
    }

    // Minimize button
    const minimizeBtn = document.getElementById("chatbot-minimize-btn");
    if (minimizeBtn) {
      minimizeBtn.addEventListener("click", () => this.toggleMinimize());
    }

    // Clear chat button
    const clearBtn = document.getElementById("chatbot-clear-btn");
    if (clearBtn) {
      clearBtn.addEventListener("click", () => this.clearChat());
    }

    // Send button and Input
    const sendBtn = document.getElementById("chatbot-send-btn");
    const input = document.getElementById("chatbot-input");

    if (sendBtn && input) {
      sendBtn.addEventListener("click", () => this.sendMessage());
      input.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && !e.shiftKey) {
          e.preventDefault();
          this.sendMessage();
        }
      });
    }

    // Global ESC Key Listener (respects modals priority)
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && this.isOpen) {
        // If search modal or mitigation modal is active, let them handle ESC
        const searchModal = document.getElementById("search-modal");
        const mitModal = document.getElementById("mitigation-modal");
        if (searchModal && searchModal.classList.contains("active")) return;
        if (mitModal && mitModal.classList.contains("active")) return;

        this.close();
      }
    });
  },

  async checkStatus() {
    try {
      const res = await API.get("/api/chat/status");
      this.updateStatusBadge(res.status || "AI ONLINE");
    } catch (err) {
      this.updateStatusBadge("DEGRADED");
    }
  },

  updateStatusBadge(status) {
    const badge = document.getElementById("chatbot-status-badge");
    const textEl = document.getElementById("chatbot-status-text");
    if (!badge || !textEl) return;

    badge.className = "chatbot-status";
    const stUpper = (status || "").toUpperCase();

    if (stUpper.includes("ONLINE")) {
      badge.classList.add("online");
      textEl.textContent = "AI ONLINE";
    } else if (stUpper.includes("ANALYZ")) {
      badge.classList.add("analyzing");
      textEl.textContent = "ANALYZING...";
    } else if (stUpper.includes("DEGRADED") || stUpper.includes("STALE")) {
      badge.classList.add("degraded");
      textEl.textContent = "DEGRADED";
    } else {
      badge.classList.add("offline");
      textEl.textContent = "OFFLINE";
    }
  },

  toggle() {
    if (this.isOpen) {
      if (this.isMinimized) {
        this.isMinimized = false;
        const windowEl = document.getElementById("chatbot-window");
        if (windowEl) windowEl.classList.remove("minimized");
      } else {
        this.close();
      }
    } else {
      this.open();
    }
  },

  open() {
    const windowEl = document.getElementById("chatbot-window");
    if (windowEl) {
      this.isOpen = true;
      this.isMinimized = false;
      windowEl.classList.remove("minimized");
      windowEl.classList.add("open");

      const input = document.getElementById("chatbot-input");
      if (input) {
        setTimeout(() => input.focus(), 150);
      }
    }
  },

  close() {
    const windowEl = document.getElementById("chatbot-window");
    if (windowEl) {
      this.isOpen = false;
      this.isMinimized = false;
      windowEl.classList.remove("open", "minimized");
    }
  },

  toggleMinimize() {
    const windowEl = document.getElementById("chatbot-window");
    if (!windowEl) return;

    this.isMinimized = !this.isMinimized;
    windowEl.classList.toggle("minimized", this.isMinimized);

    const minBtn = document.getElementById("chatbot-minimize-btn");
    if (minBtn) {
      minBtn.title = this.isMinimized ? "Expand chat" : "Minimize chat";
    }
  },

  async clearChat() {
    const body = document.getElementById("chatbot-messages-body");
    if (body) {
      body.innerHTML = `
        <div class="chat-bubble assistant">
          <div class="assistant-msg-header">
            <strong>VORTEX Network Assistant</strong>
            <span class="source-badge">LIVE ENGINE</span>
          </div>
          Conversation history cleared. Ready to assist with new network telemetry, security, and QoS inquiries.
        </div>
      `;
    }

    try {
      await API.post("/api/chat/clear", { session_id: this.sessionId });
    } catch (e) {
      // Non-blocking
    }

    this.resetDefaultSuggestions();
    if (typeof Utils !== "undefined" && Utils.showToast) {
      Utils.showToast("Chat conversation cleared", "info");
    }
  },

  resetDefaultSuggestions() {
    this.renderSuggestions([
      "What is the current network health?",
      "Are there any active threats?",
      "What is the QoS status?",
      "Show top flows",
      "Which devices are currently offline?",
      "What happened recently?"
    ]);
  },

  async sendMessage(customText = null) {
    const input = document.getElementById("chatbot-input");
    const text = customText || (input ? input.value.trim() : "");
    if (!text || this.isAnalyzing) return;

    if (input) input.value = "";

    // If chat was closed or minimized, expand it
    if (!this.isOpen || this.isMinimized) {
      this.open();
    }

    this.appendMessage("user", text);
    this.isAnalyzing = true;
    this.updateStatusBadge("ANALYZING");

    // Typing indicator
    const typingId = this.appendTypingIndicator();

    try {
      const res = await API.post("/api/chat", {
        message: text,
        session_id: this.sessionId
      });

      this.removeTypingIndicator(typingId);
      this.isAnalyzing = false;
      this.updateStatusBadge("AI ONLINE");

      const responseText = res.response || res.answer || "No response received.";
      const source = res.source || "LIVE TELEMETRY";
      this.appendMessage("assistant", responseText, source);

      if (res.suggestions && res.suggestions.length > 0) {
        this.renderSuggestions(res.suggestions);
      }
    } catch (err) {
      this.removeTypingIndicator(typingId);
      this.isAnalyzing = false;
      this.updateStatusBadge("DEGRADED");

      this.appendMessage(
        "assistant",
        "**AI SERVICE UNAVAILABLE**\n\nAI analysis is temporarily unavailable. You can continue monitoring the network normally from the dashboard.",
        "OFFLINE"
      );
    }
  },

  appendMessage(role, text, source = "LIVE TELEMETRY") {
    const body = document.getElementById("chatbot-messages-body");
    if (!body) return;

    const bubble = document.createElement("div");
    bubble.className = `chat-bubble ${role}`;

    if (role === "user") {
      bubble.textContent = text;
    } else {
      const isDemo = (source || "").toUpperCase().includes("DEMO");
      const badgeClass = isDemo ? "source-badge demo" : "source-badge";
      const sourceLabel = isDemo ? "Source: DEMO SIMULATION" : "Source: LIVE TELEMETRY";
      const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

      let formattedHtml = this.formatMarkdown(text);

      bubble.innerHTML = `
        <div class="assistant-msg-header">
          <strong>VORTEX Network Assistant</strong>
          <span class="${badgeClass}">${sourceLabel}</span>
        </div>
        <div class="assistant-msg-content">${formattedHtml}</div>
        <div class="assistant-msg-footer">
          <span>${timeStr}</span>
          <button class="copy-response-btn" onclick="Chatbot.copyResponse(this)" title="Copy response to clipboard" type="button">
            <svg class="icon icon-xs" viewBox="0 0 24 24" style="width:12px; height:12px;"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            <span>Copy</span>
          </button>
        </div>
      `;

      // Store raw text for copying
      bubble.dataset.rawText = text;
    }

    body.appendChild(bubble);
    body.scrollTop = body.scrollHeight;
  },

  formatMarkdown(raw) {
    if (!raw) return "";

    // Check for markdown tables
    if (raw.includes("|") && raw.includes("\n|")) {
      raw = this.formatMarkdownTables(raw);
    }

    // Escape HTML except already converted tables
    let html = raw
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");

    // Restore table tags if table was formatted
    html = html
      .replace(/&lt;div class="chat-table-wrap"&gt;/g, '<div class="chat-table-wrap">')
      .replace(/&lt;\/div&gt;/g, '</div>')
      .replace(/&lt;table class="chat-table"&gt;/g, '<table class="chat-table">')
      .replace(/&lt;\/table&gt;/g, '</table>')
      .replace(/&lt;thead&gt;/g, '<thead>')
      .replace(/&lt;\/thead&gt;/g, '</thead>')
      .replace(/&lt;tbody&gt;/g, '<tbody>')
      .replace(/&lt;\/tbody&gt;/g, '</tbody>')
      .replace(/&lt;tr&gt;/g, '<tr>')
      .replace(/&lt;\/tr&gt;/g, '</tr>')
      .replace(/&lt;th&gt;/g, '<th>')
      .replace(/&lt;\/th&gt;/g, '</th>')
      .replace(/&lt;td&gt;/g, '<td>')
      .replace(/&lt;\/td&gt;/g, '</td>');

    // Bold text **text**
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');

    // Inline code `code`
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

    // Bullet points •
    html = html.replace(/\n• /g, '<br>• ');
    html = html.replace(/\n- /g, '<br>• ');

    // Double and single linebreaks
    html = html.replace(/\n\n/g, '<br><br>');
    html = html.replace(/\n/g, '<br>');

    return html;
  },

  formatMarkdownTables(text) {
    const lines = text.split("\n");
    let inTable = false;
    let tableHtml = [];
    let result = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (line.startsWith("|") && line.endsWith("|")) {
        if (!inTable) {
          inTable = true;
          tableHtml = ['<div class="chat-table-wrap"><table class="chat-table">'];
          // Header row
          const headers = line.split("|").filter((c, idx, arr) => idx > 0 && idx < arr.length - 1);
          tableHtml.push("<thead><tr>" + headers.map(h => `<th>${h.trim()}</th>`).join("") + "</tr></thead><tbody>");
        } else if (line.includes("---")) {
          // Separator row, skip
          continue;
        } else {
          // Data row
          const cells = line.split("|").filter((c, idx, arr) => idx > 0 && idx < arr.length - 1);
          tableHtml.push("<tr>" + cells.map(c => `<td>${c.trim()}</td>`).join("") + "</tr>");
        }
      } else {
        if (inTable) {
          inTable = false;
          tableHtml.push("</tbody></table></div>");
          result.push(tableHtml.join(""));
          tableHtml = [];
        }
        result.push(lines[i]);
      }
    }

    if (inTable) {
      tableHtml.push("</tbody></table></div>");
      result.push(tableHtml.join(""));
    }

    return result.join("\n");
  },

  copyResponse(btn) {
    const bubble = btn.closest(".chat-bubble");
    if (!bubble) return;

    const rawText = bubble.dataset.rawText || bubble.innerText;

    navigator.clipboard.writeText(rawText).then(() => {
      btn.classList.add("copied");
      const span = btn.querySelector("span");
      if (span) span.textContent = "Copied!";

      setTimeout(() => {
        btn.classList.remove("copied");
        if (span) span.textContent = "Copy";
      }, 2000);
    }).catch(() => {
      if (typeof Utils !== "undefined" && Utils.showToast) {
        Utils.showToast("Failed to copy response", "danger");
      }
    });
  },

  appendTypingIndicator() {
    const body = document.getElementById("chatbot-messages-body");
    if (!body) return null;

    const id = `typing_${Date.now()}`;
    const indicator = document.createElement("div");
    indicator.id = id;
    indicator.className = "chat-bubble assistant";
    indicator.innerHTML = `
      <div class="typing-indicator-wrap">
        <span>AI is analyzing network telemetry</span>
        <div class="typing-dots">
          <div class="typing-dot"></div>
          <div class="typing-dot"></div>
          <div class="typing-dot"></div>
        </div>
      </div>
    `;
    body.appendChild(indicator);
    body.scrollTop = body.scrollHeight;
    return id;
  },

  removeTypingIndicator(id) {
    if (!id) return;
    const el = document.getElementById(id);
    if (el) el.remove();
  },

  renderSuggestions(suggestions) {
    const wrap = document.getElementById("chatbot-suggestions-wrap");
    if (!wrap || !suggestions || suggestions.length === 0) return;

    let html = "";
    suggestions.forEach(s => {
      const escaped = s.replace(/'/g, "\\'");
      html += `<button type="button" class="suggestion-chip" onclick="Chatbot.sendMessage('${escaped}')">${s}</button>`;
    });
    wrap.innerHTML = html;
  }
};
