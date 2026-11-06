"use strict";

const byId = (identifier) => document.getElementById(identifier);

const ui = {
  gate: byId("gate"),
  gateMessage: byId("gate-message"),
  console: byId("console"),
  setupName: byId("setup-name"),
  requestName: byId("request-name"),
  enrollmentCode: byId("enrollment-code"),
  hostname: byId("hostname"),
  cpuSpark: byId("cpu-spark"),
  cpuValue: byId("cpu-value"),
  memoryMeter: byId("memory-meter"),
  memoryValue: byId("memory-value"),
  loadValue: byId("load-value"),
  uptimeValue: byId("uptime-value"),
  filter: byId("filter"),
  processCount: byId("process-count"),
  tableWrap: byId("table-wrap"),
  rows: byId("process-rows"),
  inspectorTitle: byId("inspector-title"),
  inspectorCommand: byId("inspector-command"),
  inspectorNote: byId("inspector-note"),
  quitButton: byId("quit-button"),
  forceQuitButton: byId("force-quit-button"),
  signalDialog: byId("signal-dialog"),
  signalTitle: byId("signal-title"),
  signalBody: byId("signal-body"),
  signalCommand: byId("signal-command"),
  signalPasskeyHint: byId("signal-passkey-hint"),
  signalMessage: byId("signal-message"),
  signalConfirm: byId("signal-confirm"),
  devicesDialog: byId("devices-dialog"),
  deviceList: byId("device-list"),
  approveCode: byId("approve-code"),
  devicesMessage: byId("devices-message"),
};

const state = {
  freshUntil: 0,
  setupToken: "",
  preparedSignIn: null,
  preparedRegistration: null,
  registrationAuthorization: null,
  enrollment: null,
  enrollmentTimer: null,
  pollTimer: null,
  snapshot: null,
  cpuHistory: [],
  sortKey: "cpu",
  sortDescending: true,
  filterText: "",
  selected: null,
  pendingSignal: null,
  pendingRemoval: null,
};

const preparedLifetimeMs = 4 * 60 * 1000;
const sparkLength = 30;
const sparkGlyphs = "▁▂▃▄▅▆▇█";
const meterLength = 16;

class RequestError extends Error {
  constructor(message, status, code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function api(path, { method = "GET", body } = {}) {
  const response = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: body === undefined ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new RequestError(data.error || `The server answered ${response.status}.`, response.status, data.code || "");
  }
  return data;
}

function decodeBase64Url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0)).buffer;
}

function encodeBase64Url(buffer) {
  let binary = "";
  for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeCreationOptions(options) {
  return {
    ...options,
    challenge: decodeBase64Url(options.challenge),
    user: { ...options.user, id: decodeBase64Url(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map((descriptor) => ({ ...descriptor, id: decodeBase64Url(descriptor.id) })),
  };
}

function decodeRequestOptions(options) {
  return {
    ...options,
    challenge: decodeBase64Url(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((descriptor) => ({ ...descriptor, id: decodeBase64Url(descriptor.id) })),
  };
}

function encodeAttestation(credential) {
  return {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment || undefined,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
      attestationObject: encodeBase64Url(credential.response.attestationObject),
      transports: credential.response.getTransports ? credential.response.getTransports() : [],
    },
  };
}

function encodeAssertion(credential) {
  return {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment || undefined,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
      authenticatorData: encodeBase64Url(credential.response.authenticatorData),
      signature: encodeBase64Url(credential.response.signature),
      userHandle: credential.response.userHandle ? encodeBase64Url(credential.response.userHandle) : undefined,
    },
  };
}

function describeError(error) {
  if (error instanceof DOMException) {
    if (error.name === "NotAllowedError") return "The passkey prompt was cancelled or timed out.";
    if (error.name === "InvalidStateError") return "This device already has a passkey for su.hause.dev, probably synced from another device. Go back and sign in instead.";
    if (error.name === "SecurityError") return "Passkeys only work on https://su.hause.dev.";
    return `Passkey error: ${error.message}`;
  }
  if (error instanceof RequestError) return error.message;
  return "Couldn't reach the server. Check your connection.";
}

function isPrepared(prepared) {
  return prepared && Date.now() - prepared.fetchedAt < preparedLifetimeMs;
}

async function prepareSignIn() {
  if (isPrepared(state.preparedSignIn)) return state.preparedSignIn;
  const response = await api("/api/login/begin", { method: "POST", body: {} });
  state.preparedSignIn = { ...response, fetchedAt: Date.now() };
  return state.preparedSignIn;
}

async function signInWithPasskey() {
  const prepared = isPrepared(state.preparedSignIn) ? state.preparedSignIn : await prepareSignIn();
  state.preparedSignIn = null;
  const credential = await navigator.credentials.get({ publicKey: decodeRequestOptions(prepared.options.publicKey) });
  const session = await api(`/api/login/finish?ceremony=${encodeURIComponent(prepared.ceremony)}`, {
    method: "POST",
    body: encodeAssertion(credential),
  });
  state.freshUntil = session.freshUntil;
}

async function prepareRegistration(authorization) {
  state.registrationAuthorization = authorization;
  const response = await api("/api/register/begin", { method: "POST", body: authorization });
  state.preparedRegistration = { ...response, fetchedAt: Date.now() };
}

async function createPasskey(deviceName) {
  if (!isPrepared(state.preparedRegistration)) await prepareRegistration(state.registrationAuthorization);
  const prepared = state.preparedRegistration;
  state.preparedRegistration = null;
  const credential = await navigator.credentials.create({ publicKey: decodeCreationOptions(prepared.options.publicKey) });
  const query = new URLSearchParams({ ceremony: prepared.ceremony, name: deviceName || "" });
  const session = await api(`/api/register/finish?${query}`, { method: "POST", body: encodeAttestation(credential) });
  state.freshUntil = session.freshUntil;
  state.preparedSignIn = null;
}

function isFresh() {
  return Date.now() < state.freshUntil - 5000;
}

function guessDeviceName() {
  const agent = navigator.userAgent;
  if (/iPhone/.test(agent)) return "iPhone";
  if (/iPad/.test(agent) || (/Macintosh/.test(agent) && navigator.maxTouchPoints > 1)) return "iPad";
  if (/Android/.test(agent)) return /Mobile/.test(agent) ? "Android phone" : "Android tablet";
  if (/Macintosh/.test(agent)) return "Mac";
  if (/Windows/.test(agent)) return "Windows PC";
  if (/Linux/.test(agent)) return "Linux computer";
  return "New device";
}

function setGateMessage(text, tone = "") {
  ui.gateMessage.textContent = text;
  ui.gateMessage.className = `message ${tone}`;
}

function showGate(viewName, message = "") {
  stopPolling();
  ui.console.hidden = true;
  ui.gate.hidden = false;
  for (const section of ui.gate.querySelectorAll("section")) section.hidden = section.id !== `view-${viewName}`;
  setGateMessage(message);
  if (viewName !== "waiting") clearTimeout(state.enrollmentTimer);
  if (viewName === "signin") {
    state.preparedSignIn = null;
    prepareSignIn().catch((error) => setGateMessage(describeError(error)));
  }
  const firstField = ui.gate.querySelector(`#view-${viewName} input`);
  if (firstField) firstField.focus();
}

function showConsole() {
  ui.gate.hidden = true;
  ui.console.hidden = false;
  if (location.hash) history.replaceState(null, "", location.pathname);
  startPolling();
}

async function runGateAction(button, action) {
  button.disabled = true;
  setGateMessage("");
  try {
    await action();
  } catch (error) {
    setGateMessage(describeError(error));
  } finally {
    button.disabled = false;
  }
}

byId("signin-button").addEventListener("click", (event) =>
  runGateAction(event.currentTarget, async () => {
    try {
      await signInWithPasskey();
    } catch (error) {
      prepareSignIn().catch(() => {});
      throw error;
    }
    showConsole();
  }),
);

byId("request-access-link").addEventListener("click", () => {
  ui.requestName.value = ui.requestName.value || guessDeviceName();
  showGate("request");
});

for (const button of document.querySelectorAll("[data-show]")) {
  button.addEventListener("click", () => {
    state.enrollment = null;
    showGate(button.dataset.show);
  });
}

byId("setup-button").addEventListener("click", (event) =>
  runGateAction(event.currentTarget, async () => {
    await createPasskey(ui.setupName.value);
    state.setupToken = "";
    showConsole();
  }),
);

byId("request-button").addEventListener("click", (event) =>
  runGateAction(event.currentTarget, async () => {
    state.enrollment = await api("/api/enrollments", { method: "POST", body: { name: ui.requestName.value } });
    ui.enrollmentCode.textContent = state.enrollment.code;
    showGate("waiting");
    scheduleEnrollmentCheck();
  }),
);

function scheduleEnrollmentCheck() {
  clearTimeout(state.enrollmentTimer);
  state.enrollmentTimer = setTimeout(checkEnrollment, 2000);
}

async function checkEnrollment() {
  const enrollment = state.enrollment;
  if (!enrollment) return;
  try {
    const { status } = await api("/api/enrollments/status", {
      method: "POST",
      body: { id: enrollment.id, secret: enrollment.secret },
    });
    if (state.enrollment !== enrollment) return;
    if (status === "approved") {
      await prepareRegistration({ enrollmentId: enrollment.id, enrollmentSecret: enrollment.secret });
      showGate("approved");
      return;
    }
    if (status === "expired") {
      state.enrollment = null;
      showGate("request", "The code expired before it was approved. Request access again.");
      return;
    }
  } catch (error) {
    setGateMessage(describeError(error));
  }
  scheduleEnrollmentCheck();
}

byId("approved-button").addEventListener("click", (event) =>
  runGateAction(event.currentTarget, async () => {
    await createPasskey("");
    state.enrollment = null;
    showConsole();
  }),
);

byId("signout-button").addEventListener("click", async () => {
  await api("/api/logout", { method: "POST", body: {} }).catch(() => {});
  state.freshUntil = 0;
  showGate("signin");
});

function startPolling() {
  stopPolling();
  refresh();
  state.pollTimer = setInterval(() => {
    if (!document.hidden) refresh();
  }, 2000);
}

function stopPolling() {
  clearInterval(state.pollTimer);
  state.pollTimer = null;
}

function handleSignedOut(error) {
  if (error instanceof RequestError && error.code === "signin") {
    ui.signalDialog.close();
    ui.devicesDialog.close();
    showGate("signin", "Your session ended. Sign in again.");
    return true;
  }
  return false;
}

async function refresh() {
  try {
    const snapshot = await api("/api/processes");
    state.snapshot = snapshot;
    state.cpuHistory.push(snapshot.system.cpu);
    if (state.cpuHistory.length > sparkLength) state.cpuHistory.shift();
    render();
  } catch (error) {
    handleSignedOut(error);
  }
}

const formatters = {
  percent: (value) => value.toFixed(1),
  bytes(value) {
    const units = ["B", "KB", "MB", "GB", "TB"];
    let unitIndex = 0;
    while (value >= 1024 && unitIndex < units.length - 1) {
      value /= 1024;
      unitIndex += 1;
    }
    const digits = unitIndex >= 2 && value < 10 ? 1 : 0;
    return `${value.toFixed(digits)} ${units[unitIndex]}`;
  },
  duration(totalSeconds) {
    const seconds = Math.max(0, Math.floor(totalSeconds));
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    if (minutes > 0) return `${minutes}m`;
    return `${seconds}s`;
  },
};

function renderVitals(system) {
  ui.hostname.textContent = system.hostname || "hause";
  const sparkline = state.cpuHistory
    .map((value) => sparkGlyphs[Math.min(sparkGlyphs.length - 1, Math.floor((value / 100) * sparkGlyphs.length))])
    .join("");
  ui.cpuSpark.textContent = sparkline.padStart(sparkLength, " ");
  ui.cpuValue.textContent = `${formatters.percent(system.cpu)}% of ${system.cores} threads`;

  const usedFraction = system.memoryTotal ? system.memoryUsed / system.memoryTotal : 0;
  const filledCells = Math.round(usedFraction * meterLength);
  const filled = document.createElement("span");
  filled.className = "on";
  filled.textContent = "█".repeat(filledCells);
  const empty = document.createElement("span");
  empty.className = "off";
  empty.textContent = "█".repeat(meterLength - filledCells);
  ui.memoryMeter.replaceChildren(filled, empty);
  ui.memoryValue.textContent = `${formatters.bytes(system.memoryUsed)} of ${formatters.bytes(system.memoryTotal)}`;

  ui.loadValue.textContent = system.load.map((value) => value.toFixed(2)).join("  ");
  ui.uptimeValue.textContent = formatters.duration(system.uptime);
}

function visibleProcesses() {
  const needle = state.filterText.trim().toLowerCase();
  const matches = needle
    ? state.snapshot.processes.filter(
        (process) =>
          process.name.toLowerCase().includes(needle) ||
          process.command.toLowerCase().includes(needle) ||
          process.user.toLowerCase().includes(needle) ||
          String(process.pid) === needle,
      )
    : state.snapshot.processes.slice();
  const key = state.sortKey;
  const direction = state.sortDescending ? -1 : 1;
  matches.sort((left, right) => {
    const leftValue = left[key];
    const rightValue = right[key];
    let comparison = typeof leftValue === "string" ? leftValue.localeCompare(rightValue) : leftValue - rightValue;
    if (key === "startedAt") comparison = -comparison;
    return comparison * direction || left.pid - right.pid;
  });
  return matches;
}

function isSelected(process) {
  return state.selected && state.selected.pid === process.pid && state.selected.startTicks === process.startTicks;
}

function selectedProcess() {
  if (!state.selected || !state.snapshot) return null;
  return state.snapshot.processes.find(isSelected) || null;
}

function cell(text, className, title) {
  const element = document.createElement("td");
  element.textContent = text;
  if (className) element.className = className;
  if (title) element.title = title;
  return element;
}

function renderTable() {
  const processes = visibleProcesses();
  const now = state.snapshot.system.sampledAt;
  const fragment = document.createDocumentFragment();
  for (const process of processes) {
    const row = document.createElement("tr");
    row.dataset.pid = process.pid;
    row.dataset.startTicks = process.startTicks;
    if (isSelected(process)) {
      row.classList.add("selected");
      row.setAttribute("aria-selected", "true");
    }
    if (process.protected) row.classList.add("protected");
    const cpuClass = process.cpu >= 80 ? "numeric hot" : process.cpu >= 20 ? "numeric warm" : "numeric";
    row.append(
      cell(process.name, "name", process.command),
      cell(String(process.pid), "numeric"),
      cell(process.user, "user"),
      cell(formatters.percent(process.cpu), cpuClass),
      cell(formatters.bytes(process.memory), "numeric"),
      cell(String(process.threads), "numeric threads"),
      cell(formatters.duration((now - process.startedAt) / 1000), "started", new Date(process.startedAt).toLocaleString()),
    );
    fragment.append(row);
  }
  ui.rows.replaceChildren(fragment);
  const total = state.snapshot.processes.length;
  ui.processCount.textContent = processes.length === total ? `${total} processes` : `${processes.length} of ${total} processes`;

  for (const header of document.querySelectorAll("th[data-sort]")) {
    if (header.dataset.sort === state.sortKey) header.setAttribute("aria-sort", state.sortDescending ? "descending" : "ascending");
    else header.removeAttribute("aria-sort");
  }
}

function renderInspector() {
  const process = selectedProcess();
  if (!state.selected) {
    ui.inspectorTitle.textContent = "Select a process to quit it.";
    ui.inspectorCommand.textContent = "";
    ui.quitButton.disabled = true;
    ui.forceQuitButton.disabled = true;
    return;
  }
  if (!process) {
    ui.inspectorTitle.textContent = `${state.selected.name} (${state.selected.pid}) has exited.`;
    ui.inspectorCommand.textContent = "";
    ui.quitButton.disabled = true;
    ui.forceQuitButton.disabled = true;
    return;
  }
  ui.inspectorTitle.textContent = `${process.name}, pid ${process.pid}, parent ${process.ppid}, running as ${process.user}`;
  ui.inspectorCommand.textContent = process.command;
  ui.inspectorCommand.title = process.command;
  if (process.protected) {
    ui.inspectorNote.textContent = process.protected;
    ui.inspectorNote.className = "inspector-note blocked";
  } else if (ui.inspectorNote.classList.contains("blocked")) {
    ui.inspectorNote.textContent = "";
    ui.inspectorNote.className = "inspector-note";
  }
  ui.quitButton.disabled = Boolean(process.protected);
  ui.forceQuitButton.disabled = Boolean(process.protected);
}

function render() {
  if (!state.snapshot) return;
  renderVitals(state.snapshot.system);
  renderTable();
  renderInspector();
}

function selectProcess(process) {
  state.selected = process ? { pid: process.pid, startTicks: process.startTicks, name: process.name } : null;
  ui.inspectorNote.textContent = "";
  ui.inspectorNote.className = "inspector-note";
  render();
}

ui.rows.addEventListener("click", (event) => {
  const row = event.target.closest("tr");
  if (!row || !state.snapshot) return;
  const process = state.snapshot.processes.find(
    (candidate) => candidate.pid === Number(row.dataset.pid) && candidate.startTicks === Number(row.dataset.startTicks),
  );
  selectProcess(process);
});

ui.tableWrap.addEventListener("keydown", (event) => {
  if (!state.snapshot || (event.key !== "ArrowDown" && event.key !== "ArrowUp")) return;
  event.preventDefault();
  const processes = visibleProcesses();
  if (processes.length === 0) return;
  const currentIndex = processes.findIndex(isSelected);
  const step = event.key === "ArrowDown" ? 1 : -1;
  const nextIndex = currentIndex === -1 ? 0 : Math.min(processes.length - 1, Math.max(0, currentIndex + step));
  selectProcess(processes[nextIndex]);
  const selectedRow = ui.rows.querySelector("tr.selected");
  if (selectedRow) selectedRow.scrollIntoView({ block: "nearest" });
});

for (const header of document.querySelectorAll("th[data-sort]")) {
  header.querySelector("button").addEventListener("click", () => {
    const key = header.dataset.sort;
    if (state.sortKey === key) state.sortDescending = !state.sortDescending;
    else {
      state.sortKey = key;
      state.sortDescending = !["name", "user", "pid"].includes(key);
    }
    render();
  });
}

ui.filter.addEventListener("input", () => {
  state.filterText = ui.filter.value;
  render();
});

document.addEventListener("keydown", (event) => {
  if (ui.console.hidden || document.querySelector("dialog[open]")) return;
  if (event.key === "/" && document.activeElement !== ui.filter) {
    event.preventDefault();
    ui.filter.focus();
  }
});

const signalCopy = {
  TERM: {
    title: (name) => `Quit ${name}?`,
    body: "Asks the process to exit cleanly. It can save its work first, or ignore the request.",
    action: "Quit",
    done: "Quit sent",
  },
  KILL: {
    title: (name) => `Force quit ${name}?`,
    body: "Stops the process immediately. Anything it hasn't saved is lost.",
    action: "Force quit",
    done: "Force quit sent",
  },
};

function openSignalDialog(signal) {
  const process = selectedProcess();
  if (!process || process.protected) return;
  const copy = signalCopy[signal];
  state.pendingSignal = { signal, pid: process.pid, startTicks: process.startTicks, name: process.name };
  ui.signalTitle.textContent = copy.title(process.name);
  ui.signalBody.textContent = `${copy.body} pid ${process.pid}, running as ${process.user}.`;
  ui.signalCommand.textContent = process.command;
  ui.signalConfirm.textContent = copy.action;
  ui.signalConfirm.disabled = false;
  ui.signalMessage.textContent = "";
  ui.signalPasskeyHint.hidden = isFresh();
  if (!isFresh()) prepareSignIn().catch((error) => (ui.signalMessage.textContent = describeError(error)));
  ui.signalDialog.showModal();
  byId("signal-cancel").focus();
}

async function withFreshPasskey(action) {
  if (!isFresh()) await signInWithPasskey();
  try {
    return await action();
  } catch (error) {
    if (error instanceof RequestError && error.code === "reauth") {
      state.freshUntil = 0;
      prepareSignIn().catch(() => {});
    }
    throw error;
  }
}

ui.quitButton.addEventListener("click", () => openSignalDialog("TERM"));
ui.forceQuitButton.addEventListener("click", () => openSignalDialog("KILL"));
byId("signal-cancel").addEventListener("click", () => ui.signalDialog.close());

ui.signalConfirm.addEventListener("click", async () => {
  const pending = state.pendingSignal;
  if (!pending) return;
  ui.signalConfirm.disabled = true;
  ui.signalMessage.textContent = "";
  try {
    await withFreshPasskey(() =>
      api(`/api/processes/${pending.pid}/signal`, {
        method: "POST",
        body: { signal: pending.signal, startTicks: pending.startTicks },
      }),
    );
    ui.signalDialog.close();
    ui.inspectorNote.textContent = `${signalCopy[pending.signal].done} to ${pending.name} (${pending.pid}).`;
    ui.inspectorNote.className = "inspector-note";
    refresh();
  } catch (error) {
    if (handleSignedOut(error)) return;
    ui.signalMessage.textContent = describeError(error);
    ui.signalPasskeyHint.hidden = isFresh();
    ui.signalConfirm.disabled = false;
  }
});

function setDevicesMessage(text, tone = "") {
  ui.devicesMessage.textContent = text;
  ui.devicesMessage.className = `message ${tone}`;
}

function formatDate(milliseconds) {
  return new Date(milliseconds).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
}

async function loadDevices() {
  const { devices } = await api("/api/devices");
  const items = devices.map((device) => {
    const item = document.createElement("li");
    const details = document.createElement("div");
    const name = document.createElement("p");
    name.className = "device-name";
    name.textContent = device.name;
    if (device.current) {
      const marker = document.createElement("span");
      marker.className = "device-current";
      marker.textContent = "  this device";
      name.append(marker);
    }
    const meta = document.createElement("p");
    meta.className = "device-meta";
    meta.textContent = `Added ${formatDate(device.createdAt)}, last sign-in ${formatDate(device.lastUsedAt)}`;
    details.append(name, meta);
    item.append(details);
    if (devices.length > 1) {
      const removeButton = document.createElement("button");
      removeButton.type = "button";
      removeButton.className = "danger";
      removeButton.textContent = state.pendingRemoval === device.id ? "Confirm remove" : "Remove";
      removeButton.addEventListener("click", () => removeDevice(device, removeButton));
      item.append(removeButton);
    }
    return item;
  });
  ui.deviceList.replaceChildren(...items);
}

async function removeDevice(device, button) {
  if (state.pendingRemoval !== device.id) {
    state.pendingRemoval = device.id;
    button.textContent = "Confirm remove";
    setDevicesMessage(device.current ? "Removing this device signs it out. It will need approval to get back in." : `${device.name} will need approval to sign in again.`);
    return;
  }
  button.disabled = true;
  try {
    const result = await withFreshPasskey(() => api(`/api/devices/${encodeURIComponent(device.id)}`, { method: "DELETE" }));
    state.pendingRemoval = null;
    if (result.signedOut) {
      ui.devicesDialog.close();
      showGate("signin", "This device was removed.");
      return;
    }
    setDevicesMessage(`Removed ${device.name}.`, "ok");
    await loadDevices();
  } catch (error) {
    if (handleSignedOut(error)) return;
    setDevicesMessage(describeError(error));
    button.disabled = false;
  }
}

byId("devices-button").addEventListener("click", async () => {
  state.pendingRemoval = null;
  setDevicesMessage("");
  ui.approveCode.value = "";
  ui.devicesDialog.showModal();
  if (!isFresh()) prepareSignIn().catch(() => {});
  try {
    await loadDevices();
  } catch (error) {
    if (!handleSignedOut(error)) setDevicesMessage(describeError(error));
  }
});

byId("devices-close").addEventListener("click", () => ui.devicesDialog.close());

byId("approve-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const submitButton = event.currentTarget.querySelector("button[type=submit]");
  const code = ui.approveCode.value.trim();
  if (!code) {
    setDevicesMessage("Enter the code shown on the new device.");
    return;
  }
  submitButton.disabled = true;
  setDevicesMessage("");
  try {
    const { name } = await withFreshPasskey(() => api("/api/enrollments/approve", { method: "POST", body: { code } }));
    ui.approveCode.value = "";
    setDevicesMessage(`Approved ${name}. Finish on that device by creating its passkey.`, "ok");
  } catch (error) {
    if (!handleSignedOut(error)) setDevicesMessage(describeError(error));
  } finally {
    submitButton.disabled = false;
  }
});

async function boot() {
  if (!window.PublicKeyCredential) {
    showGate("signin");
    setGateMessage("This browser doesn't support passkeys.");
    return;
  }
  const setupToken = new URLSearchParams(location.hash.slice(1)).get("setup");
  if (setupToken) {
    state.setupToken = setupToken;
    ui.setupName.value = guessDeviceName();
    showGate("setup");
    try {
      await prepareRegistration({ setupToken });
    } catch (error) {
      setGateMessage(describeError(error));
    }
    return;
  }
  try {
    const session = await api("/api/state");
    if (session.signedIn) {
      state.freshUntil = session.freshUntil;
      showConsole();
    } else {
      showGate("signin");
    }
  } catch (error) {
    showGate("signin", describeError(error));
  }
}

boot();
