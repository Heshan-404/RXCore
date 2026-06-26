const slash = String.fromCharCode(47);
const invoke = window.__TAURI__.invoke;

const app = document.createElement("div");
app.style.display = "flex";
app.style.width = "100%";
app.style.height = "100%";
document.body.appendChild(app);

const sidebar = document.createElement("div");
sidebar.className = "sidebar";
app.appendChild(sidebar);

const sidebarTitle = document.createElement("div");
sidebarTitle.className = "sidebar-title";
sidebarTitle.textContent = "Ruve VPN";
sidebar.appendChild(sidebarTitle);

const sidebarMenu = document.createElement("div");
sidebarMenu.className = "sidebar-menu";
sidebar.appendChild(sidebarMenu);

const menuItems = [
  { id: "connection", label: "Connection" },
  { id: "profiles", label: "Profiles" },
  { id: "logs", label: "Logs" }
];

const menuItemElems = {};

const mainContent = document.createElement("div");
mainContent.className = "main-content";
app.appendChild(mainContent);

const tabs = {};

menuItems.forEach((item, index) => {
  const elem = document.createElement("div");
  elem.className = "menu-item" + (index === 0 ? " active" : "");
  elem.textContent = item.label;
  elem.addEventListener("click", () => switchTab(item.id));
  sidebarMenu.appendChild(elem);
  menuItemElems[item.id] = elem;

  const tab = document.createElement("div");
  tab.className = "tab-content" + (index === 0 ? " active" : "");
  tab.id = "tab-" + item.id;
  mainContent.appendChild(tab);
  tabs[item.id] = tab;
});

function switchTab(tabId) {
  Object.keys(tabs).forEach(id => {
    tabs[id].classList.remove("active");
    menuItemElems[id].classList.remove("active");
  });
  tabs[tabId].classList.add("active");
  menuItemElems[tabId].classList.add("active");
}

let configs = [];
let activeConfigId = "";
let isConnected = false;
let isConnecting = false;
let latencyInterval = null;
let logsInterval = null;

const connTab = tabs["connection"];

const connTitle = document.createElement("h2");
connTitle.textContent = "Connection";
connTab.appendChild(connTitle);

const connCard = document.createElement("div");
connCard.className = "card";
connTab.appendChild(connCard);

const statusRow = document.createElement("div");
statusRow.className = "row";
connCard.appendChild(statusRow);

const statusText = document.createElement("span");
statusText.style.fontWeight = "600";
statusText.textContent = "Service Status";
statusRow.appendChild(statusText);

const statusBadge = document.createElement("span");
statusBadge.className = "status-badge disconnected";
statusBadge.textContent = "Disconnected";
statusRow.appendChild(statusBadge);

const configRow = document.createElement("div");
configRow.className = "row";
connCard.appendChild(configRow);

const configText = document.createElement("span");
configText.style.fontWeight = "600";
configText.textContent = "Selected Profile";
configRow.appendChild(configText);

const activeConfigLabel = document.createElement("span");
activeConfigLabel.style.color = "#aaaaaa";
activeConfigLabel.textContent = "None Selected";
configRow.appendChild(activeConfigLabel);

const latencyRow = document.createElement("div");
latencyRow.className = "row";
connCard.appendChild(latencyRow);

const latencyText = document.createElement("span");
latencyText.style.fontWeight = "600";
latencyText.textContent = "Latency";
latencyRow.appendChild(latencyText);

const latencyVal = document.createElement("span");
latencyVal.style.color = "#888888";
latencyVal.textContent = "Offline";
latencyRow.appendChild(latencyVal);

const controlRow = document.createElement("div");
controlRow.className = "row";
controlRow.style.marginTop = "10px";
connCard.appendChild(controlRow);

const toggleBtn = document.createElement("button");
toggleBtn.className = "btn btn-primary";
toggleBtn.style.width = "100%";
toggleBtn.style.padding = "12px";
toggleBtn.textContent = "Start VPN";
controlRow.appendChild(toggleBtn);

const profTab = tabs["profiles"];

const profTitle = document.createElement("h2");
profTitle.textContent = "Profiles";
profTab.appendChild(profTitle);

const importCard = document.createElement("div");
importCard.className = "card";
profTab.appendChild(importCard);

const importTitle = document.createElement("span");
importTitle.style.fontWeight = "600";
importTitle.textContent = "Import Profile";
importCard.appendChild(importTitle);

const vlessInput = document.createElement("textarea");
vlessInput.placeholder = "Paste VLESS share link here (e.g. vless:\x2f\x2fuuid@host:port...)";
importCard.appendChild(vlessInput);

const importBtn = document.createElement("button");
importBtn.className = "btn btn-primary";
importBtn.textContent = "Import from Link";
importCard.appendChild(importBtn);

const manualCard = document.createElement("div");
manualCard.className = "card";
profTab.appendChild(manualCard);

const manualTitle = document.createElement("span");
manualTitle.style.fontWeight = "600";
manualTitle.textContent = "Add Profile Manually";
manualCard.appendChild(manualTitle);

const manualForm = document.createElement("div");
manualForm.style.display = "flex";
manualForm.style.flexDirection = "column";
manualForm.style.gap = "12px";
manualCard.appendChild(manualForm);

const row1 = document.createElement("div");
row1.className = "form-row";
manualForm.appendChild(row1);

const grpName = document.createElement("div");
grpName.className = "form-group";
grpName.innerHTML = "<label>Profile Name<label>";
const inputName = document.createElement("input");
inputName.type = "text";
inputName.placeholder = "My Server";
grpName.appendChild(inputName);
row1.appendChild(grpName);

const grpHost = document.createElement("div");
grpHost.className = "form-group";
grpHost.innerHTML = "<label>Server Host / IP<label>";
const inputHost = document.createElement("input");
inputHost.type = "text";
inputHost.placeholder = "1.2.3.4";
grpHost.appendChild(inputHost);
row1.appendChild(grpHost);

const row2 = document.createElement("div");
row2.className = "form-row";
manualForm.appendChild(row2);

const grpPort = document.createElement("div");
grpPort.className = "form-group";
grpPort.innerHTML = "<label>Port<label>";
const inputPort = document.createElement("input");
inputPort.type = "number";
inputPort.value = "443";
grpPort.appendChild(inputPort);
row2.appendChild(grpPort);

const grpSni = document.createElement("div");
grpSni.className = "form-group";
grpSni.innerHTML = "<label>SNI<label>";
const inputSni = document.createElement("input");
inputSni.type = "text";
inputSni.placeholder = "example.com";
grpSni.appendChild(inputSni);
row2.appendChild(grpSni);

const grpUuid = document.createElement("div");
grpUuid.className = "form-group";
grpUuid.innerHTML = "<label>UUID<label>";
const inputUuid = document.createElement("input");
inputUuid.type = "text";
inputUuid.placeholder = "uuid";
manualForm.appendChild(grpUuid);

const addManualBtn = document.createElement("button");
addManualBtn.className = "btn";
addManualBtn.textContent = "Add Profile";
manualCard.appendChild(addManualBtn);

const listTitle = document.createElement("span");
listTitle.style.fontWeight = "600";
listTitle.style.marginTop = "10px";
listTitle.textContent = "Saved Profiles";
profTab.appendChild(listTitle);

const configListContainer = document.createElement("div");
configListContainer.className = "config-list";
profTab.appendChild(configListContainer);

const logsTab = tabs["logs"];

const logsTitle = document.createElement("h2");
logsTitle.textContent = "Logs";
logsTab.appendChild(logsTitle);

const logCard = document.createElement("div");
logCard.className = "card";
logsTab.appendChild(logCard);

const logsViewer = document.createElement("div");
logsViewer.className = "log-viewer";
logCard.appendChild(logsViewer);

const clearLogsBtn = document.createElement("button");
clearLogsBtn.className = "btn";
clearLogsBtn.textContent = "Clear Logs View";
logCard.appendChild(clearLogsBtn);

async function loadConfigs() {
  try {
    configs = await invoke("get_configs");
    activeConfigId = await invoke("get_active_config_id");
    renderConfigs();
    updateActiveConfigDisplay();
  } catch (err) {
    console.error(err);
  }
}

function renderConfigs() {
  configListContainer.innerHTML = "";
  if (configs.length === 0) {
    const empty = document.createElement("div");
    empty.style.color = "#888888";
    empty.style.fontSize = "13px";
    empty.style.textAlign = "center";
    empty.style.padding = "20px";
    empty.textContent = "No profiles imported. Import a VLESS link or add one manually.";
    configListContainer.appendChild(empty);
    return;
  }

  configs.forEach(c => {
    const item = document.createElement("div");
    item.className = "config-item" + (c.id === activeConfigId ? " active" : "");
    
    const info = document.createElement("div");
    info.className = "config-info";
    item.appendChild(info);

    const radio = document.createElement("input");
    radio.type = "radio";
    radio.name = "active_profile";
    radio.className = "config-radio";
    radio.checked = (c.id === activeConfigId);
    radio.addEventListener("change", () => selectProfile(c.id));
    info.appendChild(radio);

    const details = document.createElement("div");
    details.className = "config-details";
    info.appendChild(details);

    const name = document.createElement("span");
    name.className = "config-name";
    name.textContent = c.name;
    details.appendChild(name);

    const server = document.createElement("span");
    server.className = "config-server";
    server.textContent = c.server + ":" + c.port + " | SNI: " + c.sni;
    details.appendChild(server);

    const delBtn = document.createElement("button");
    delBtn.className = "btn btn-danger";
    delBtn.style.padding = "4px 8px";
    delBtn.style.fontSize = "11px";
    delBtn.textContent = "Delete";
    delBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      deleteProfile(c.id);
    });
    item.appendChild(delBtn);

    item.addEventListener("click", () => {
      selectProfile(c.id);
    });

    configListContainer.appendChild(item);
  });
}

function updateActiveConfigDisplay() {
  const active = configs.find(c => c.id === activeConfigId);
  if (active) {
    activeConfigLabel.textContent = active.name + " (" + active.server + ":" + active.port + ")";
    activeConfigLabel.style.color = "#60cdff";
  } else {
    activeConfigLabel.textContent = "None Selected";
    activeConfigLabel.style.color = "#aaaaaa";
  }
}

async function selectProfile(id) {
  try {
    await invoke("select_config", { id });
    activeConfigId = id;
    renderConfigs();
    updateActiveConfigDisplay();
  } catch (err) {
    alert(err);
  }
}

async function deleteProfile(id) {
  try {
    await invoke("delete_config", { id });
    await loadConfigs();
  } catch (err) {
    alert(err);
  }
}

importBtn.addEventListener("click", async () => {
  const val = vlessInput.value.trim();
  if (!val) return;
  const prefix = "vless:" + slash + slash;
  if (!val.startsWith(prefix)) {
    alert("Invalid config link format. Link must start with vless:\x2f\x2f");
    return;
  }

  try {
    await invoke("import_config_link", { link: val });
    vlessInput.value = "";
    await loadConfigs();
    switchTab("connection");
  } catch (err) {
    alert(err);
  }
});

addManualBtn.addEventListener("click", async () => {
  const name = inputName.value.trim();
  const server = inputHost.value.trim();
  const port = parseInt(inputPort.value.trim());
  const sni = inputSni.value.trim();
  const uuid = inputUuid.value.trim();

  if (!name || !server || isNaN(port) || !uuid) {
    alert("Please fill in all fields.");
    return;
  }

  try {
    await invoke("add_config", {
      name,
      server,
      port,
      uuid,
      sni: sni || server
    });

    inputName.value = "";
    inputHost.value = "";
    inputPort.value = "443";
    inputSni.value = "";
    inputUuid.value = "";

    await loadConfigs();
    switchTab("connection");
  } catch (err) {
    alert(err);
  }
});

async function checkLatency() {
  if (!isConnected) {
    latencyVal.textContent = "Offline";
    latencyVal.style.color = "#888888";
    return;
  }
  try {
    const ms = await invoke("get_latency");
    latencyVal.textContent = ms + " ms";
    if (ms < 150) {
      latencyVal.style.color = "#4ade80";
    } else if (ms < 300) {
      latencyVal.style.color = "#fbbf24";
    } else {
      latencyVal.style.color = "#ff6b6b";
    }
  } catch (err) {
    latencyVal.textContent = "Timeout";
    latencyVal.style.color = "#ff6b6b";
  }
}

async function fetchLogs() {
  try {
    const logs = await invoke("get_logs");
    logsViewer.innerHTML = "";
    logs.forEach(log => {
      const entry = document.createElement("div");
      entry.className = "log-entry " + (log.includes("failed") || log.includes("Error") ? "error" : "system");
      entry.textContent = log;
      logsViewer.appendChild(entry);
    });
    logsViewer.scrollTop = logsViewer.scrollHeight;
  } catch (err) {
    console.error(err);
  }
}

clearLogsBtn.addEventListener("click", () => {
  logsViewer.innerHTML = "";
});

toggleBtn.addEventListener("click", async () => {
  if (isConnecting) return;

  if (!isConnected) {
    if (!activeConfigId) {
      alert("Please select or import a profile first!");
      switchTab("profiles");
      return;
    }

    isConnecting = true;
    statusBadge.className = "status-badge connecting";
    statusBadge.textContent = "Connecting";
    toggleBtn.textContent = "Connecting...";
    toggleBtn.disabled = true;

    try {
      await invoke("toggle_proxy", { connect: true });
      isConnected = true;
      statusBadge.className = "status-badge connected";
      statusBadge.textContent = "Connected";
      toggleBtn.textContent = "Stop Connection";
      toggleBtn.className = "btn btn-danger";
      
      checkLatency();
      latencyInterval = setInterval(checkLatency, 5000);
      
      fetchLogs();
      logsInterval = setInterval(fetchLogs, 1500);
    } catch (err) {
      statusBadge.className = "status-badge error";
      statusBadge.textContent = "Failed";
      toggleBtn.textContent = "Start VPN";
      toggleBtn.className = "btn btn-primary";
      alert("Connection failed: " + err);
    } finally {
      isConnecting = false;
      toggleBtn.disabled = false;
    }
  } else {
    isConnecting = true;
    toggleBtn.disabled = true;

    try {
      await invoke("toggle_proxy", { connect: false });
      isConnected = false;
      statusBadge.className = "status-badge disconnected";
      statusBadge.textContent = "Disconnected";
      toggleBtn.textContent = "Start VPN";
      toggleBtn.className = "btn btn-primary";
      
      if (latencyInterval) clearInterval(latencyInterval);
      if (logsInterval) clearInterval(logsInterval);
      
      latencyVal.textContent = "Offline";
      latencyVal.style.color = "#888888";
    } catch (err) {
      alert("Disconnection failed: " + err);
    } finally {
      isConnecting = false;
      toggleBtn.disabled = false;
    }
  }
});

loadConfigs();
