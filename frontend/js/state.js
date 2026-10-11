/**
 * VORTEX-SDN Reactive State Store
 * Holds cached telemetry, topology, security, and QoS state with event dispatching.
 */

const State = {
  // 1. AUTHENTICATION STATE
  auth: {
    isAuthenticated: false,
    token: null,
    user: null,
    version: 0
  },

  // 2. USER PRESENCE STATE (Source of truth: authenticated session)
  userPresence: {
    status: "OFFLINE", // "ONLINE" | "OFFLINE"
    label: "OFFLINE",
    version: 0,
    lastUpdated: null
  },

  // 3. CONTROLLER CONNECTION STATE
  controller: {
    status: "ONLINE", // "ONLINE" | "RECONNECTING" | "DISCONNECTED"
    label: "RYU OF1.3 ONLINE",
    version: 0,
    lastUpdated: null
  },

  // 4. TELEMETRY STATE
  telemetry: {
    status: "LIVE", // "LIVE" | "DEMO" | "SYNCING" | "STALE" | "OFFLINE"
    label: "TELEMETRY LIVE",
    source: "DEMO",
    version: 0,
    lastUpdated: null
  },

  // 5. NETWORK HEALTH STATE
  networkHealth: {
    score: 98,
    status: "HEALTHY",
    securityScore: 95,
    qosScore: 92,
    version: 0,
    lastUpdated: null
  },

  // 6. DATABASE STATUS
  database: {
    status: "ONLINE",
    label: "SQLITE ONLINE",
    version: 0,
    lastUpdated: null
  },

  // 7. AI ENGINE STATUS
  aiEngine: {
    status: "ONLINE",
    label: "AI ONLINE",
    version: 0,
    lastUpdated: null
  },

  // 8. SECURITY ENGINE STATUS
  securityEngine: {
    status: "ONLINE",
    label: "SECURITY ACTIVE",
    version: 0,
    lastUpdated: null
  },

  // 9. QOS ENGINE STATUS
  qosEngine: {
    status: "ONLINE",
    label: "QOS ACTIVE",
    version: 0,
    lastUpdated: null
  },

  summary: null,
  latestFlows: [],
  topology: null,
  security: null,
  qos: null,
  incidents: [],
  notifications: [],
  events: [],
  subscribers: {},
  pollingIntervalMs: 5000,
  isPaused: false,

  subscribe(event, callback) {
    if (!this.subscribers[event]) this.subscribers[event] = [];
    this.subscribers[event].push(callback);
  },

  emit(event, data) {
    if (this.subscribers[event]) {
      this.subscribers[event].forEach(cb => cb(data));
    }
  },

  setAuth(data) {
    const version = (data && data.version !== undefined) ? data.version : (this.auth.version || 0) + 1;
    if (version < (this.auth.version || 0)) return;
    this.auth = { ...this.auth, ...data, version };
    this.emit("auth:updated", this.auth);
  },

  setUserPresence(data) {
    const version = (data && data.version !== undefined) ? data.version : (this.userPresence.version || 0) + 1;
    if (version < (this.userPresence.version || 0)) return;
    this.userPresence = { ...this.userPresence, ...data, version, lastUpdated: Date.now() };
    this.emit("userPresence:updated", this.userPresence);
  },

  setControllerStatus(data) {
    const version = (data && data.version !== undefined) ? data.version : (this.controller.version || 0) + 1;
    if (version < (this.controller.version || 0)) return;
    this.controller = { ...this.controller, ...data, version, lastUpdated: Date.now() };
    this.emit("controller:updated", this.controller);
  },

  setTelemetryStatus(data) {
    const version = (data && data.version !== undefined) ? data.version : (this.telemetry.version || 0) + 1;
    if (version < (this.telemetry.version || 0)) return;
    this.telemetry = { ...this.telemetry, ...data, version, lastUpdated: Date.now() };
    this.emit("telemetry:updated", this.telemetry);
  },

  setNetworkHealth(data) {
    const version = (data && data.version !== undefined) ? data.version : (this.networkHealth.version || 0) + 1;
    if (version < (this.networkHealth.version || 0)) return;
    this.networkHealth = { ...this.networkHealth, ...data, version, lastUpdated: Date.now() };
    this.emit("health:updated", this.networkHealth);
  },

  setDatabaseStatus(data) {
    const version = (data && data.version !== undefined) ? data.version : (this.database.version || 0) + 1;
    if (version < (this.database.version || 0)) return;
    this.database = { ...this.database, ...data, version, lastUpdated: Date.now() };
    this.emit("database:updated", this.database);
  },

  setAiEngineStatus(data) {
    const version = (data && data.version !== undefined) ? data.version : (this.aiEngine.version || 0) + 1;
    if (version < (this.aiEngine.version || 0)) return;
    this.aiEngine = { ...this.aiEngine, ...data, version, lastUpdated: Date.now() };
    this.emit("aiEngine:updated", this.aiEngine);
  },

  setSecurityEngineStatus(data) {
    const version = (data && data.version !== undefined) ? data.version : (this.securityEngine.version || 0) + 1;
    if (version < (this.securityEngine.version || 0)) return;
    this.securityEngine = { ...this.securityEngine, ...data, version, lastUpdated: Date.now() };
    this.emit("securityEngine:updated", this.securityEngine);
  },

  setQosEngineStatus(data) {
    const version = (data && data.version !== undefined) ? data.version : (this.qosEngine.version || 0) + 1;
    if (version < (this.qosEngine.version || 0)) return;
    this.qosEngine = { ...this.qosEngine, ...data, version, lastUpdated: Date.now() };
    this.emit("qosEngine:updated", this.qosEngine);
  },

  setSummary(data) {
    this.summary = data;
    this.emit("summary:updated", data);
  },

  setLatestFlows(flows) {
    this.latestFlows = flows;
    this.emit("flows:updated", flows);
  },

  setTopology(data) {
    this.topology = data;
    this.emit("topology:updated", data);
  },

  setSecurity(data) {
    this.security = data;
    this.emit("security:updated", data);
  },

  setQoS(data) {
    this.qos = data;
    this.emit("qos:updated", data);
  },

  setEvents(events) {
    this.events = events;
    this.emit("events:updated", events);
  },

  addEvent(event) {
    if (!this.events) this.events = [];
    if (event.id && this.events.some(e => e.id === event.id)) return;
    this.events.unshift(event);
    if (this.events.length > 50) this.events.pop();
    this.emit("events:updated", this.events);
  }
};
