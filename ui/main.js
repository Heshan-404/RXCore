const slash = String.fromCharCode(47);
const invoke = window.__TAURI__.invoke;

const app = document.createElement("div");
app.style.display = "flex";
app.style.width = "100%";
app.style.height = "100%";
document.body.appendChild(app);

/* ── Sidebar (icon rail) ── */
const sidebar = document.createElement("div");
sidebar.className = "sidebar";
app.appendChild(sidebar);

const sidebarTitle = document.createElement("div");
sidebarTitle.className = "sidebar-title";
sidebar.appendChild(sidebarTitle);

const sidebarMenu = document.createElement("div");
sidebarMenu.className = "sidebar-menu";
sidebar.appendChild(sidebarMenu);

const menuItems = [
  { id: "connection", icon: "\u2302" },
  { id: "profiles",   icon: "\u2630" },
  { id: "logs",       icon: "\u2261" }
];

const menuItemElems = {};

const mainContent = document.createElement("div");
mainContent.className = "main-content";
app.appendChild(mainContent);

const tabs = {};

menuItems.forEach((item, index) => {
  const elem = document.createElement("div");
  elem.className = "menu-item" + (index === 0 ? " active" : "");
  elem.textContent = item.icon;
  elem.title = item.id.charAt(0).toUpperCase() + item.id.slice(1);
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

/* ══════════════════════════════════════════
   CONNECTION TAB
   ══════════════════════════════════════════ */
const connTab = tabs["connection"];

const connHeader = document.createElement("div");
connHeader.className = "tab-header";
connTab.appendChild(connHeader);

const connHeaderTitle = document.createElement("h2");
connHeaderTitle.textContent = "Home";
connHeader.appendChild(connHeaderTitle);

const connHeaderActions = document.createElement("div");
connHeaderActions.className = "header-actions";
connHeader.appendChild(connHeaderActions);

const connBody = document.createElement("div");
connBody.className = "tab-body";
connTab.appendChild(connBody);

/* Status bar */
const statusBar = document.createElement("div");
statusBar.className = "status-bar";
connBody.appendChild(statusBar);

const statusDot = document.createElement("div");
statusDot.className = "status-dot disconnected";
statusBar.appendChild(statusDot);

const statusText = document.createElement("div");
statusText.className = "status-text";
statusText.textContent = "Disconnected";
statusBar.appendChild(statusText);

const latencyVal = document.createElement("div");
latencyVal.className = "status-latency";
latencyVal.textContent = "Offline";
statusBar.appendChild(latencyVal);

/* Profile cards container */
const profileCardsContainer = document.createElement("div");
profileCardsContainer.style.display = "flex";
profileCardsContainer.style.flexDirection = "column";
profileCardsContainer.style.gap = "10px";
connBody.appendChild(profileCardsContainer);

/* FAB */
const fab = document.createElement("button");
fab.className = "fab";
fab.innerHTML = "\u25B6";
fab.title = "Connect VPN";
document.body.appendChild(fab);

/* ══════════════════════════════════════════
   PROFILES TAB
   ══════════════════════════════════════════ */
const profTab = tabs["profiles"];

const profHeader = document.createElement("div");
profHeader.className = "tab-header";
profTab.appendChild(profHeader);

const profHeaderTitle = document.createElement("h2");
profHeaderTitle.textContent = "Profiles";
profHeader.appendChild(profHeaderTitle);

const profBody = document.createElement("div");
profBody.className = "tab-body";
profTab.appendChild(profBody);

/* Import card */
const importCard = document.createElement("div");
importCard.className = "card";
profBody.appendChild(importCard);

const importTitle = document.createElement("span");
importTitle.style.fontWeight = "600";
importTitle.style.color = "#333";
importTitle.textContent = "Import Profile";
importCard.appendChild(importTitle);

const vlessInput = document.createElement("textarea");
vlessInput.placeholder = "Paste VLESS share link here (e.g. vless:" + slash + slash + "uuid@host:port...)";
importCard.appendChild(vlessInput);

const importBtn = document.createElement("button");
importBtn.className = "btn btn-primary";
importBtn.textContent = "Import from Link";
importCard.appendChild(importBtn);

/* Manual add card */
const manualCard = document.createElement("div");
manualCard.className = "card";
profBody.appendChild(manualCard);

const manualTitle = document.createElement("span");
manualTitle.style.fontWeight = "600";
manualTitle.style.color = "#333";
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
grpName.innerHTML = "<label>Profile Name</label>";
const inputName = document.createElement("input");
inputName.type = "text";
inputName.placeholder = "My Server";
grpName.appendChild(inputName);
row1.appendChild(grpName);

const grpHost = document.createElement("div");
grpHost.className = "form-group";
grpHost.innerHTML = "<label>Server Host / IP</label>";
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
grpPort.innerHTML = "<label>Port</label>";
const inputPort = document.createElement("input");
inputPort.type = "number";
inputPort.value = "443";
grpPort.appendChild(inputPort);
row2.appendChild(grpPort);

const grpSni = document.createElement("div");
grpSni.className = "form-group";
grpSni.innerHTML = "<label>SNI</label>";
const inputSni = document.createElement("input");
inputSni.type = "text";
inputSni.placeholder = "example.com";
grpSni.appendChild(inputSni);
row2.appendChild(grpSni);

const grpUuid = document.createElement("div");
grpUuid.className = "form-group";
grpUuid.innerHTML = "<label>UUID</label>";
const inputUuid = document.createElement("input");
inputUuid.type = "text";
inputUuid.placeholder = "uuid";
manualForm.appendChild(grpUuid);

/* Allow Insecure toggle in manual form */
const aiRow = document.createElement("div");
aiRow.className = "toggle-row";
manualForm.appendChild(aiRow);

const aiLabel = document.createElement("span");
aiLabel.className = "toggle-row-label";
aiLabel.textContent = "Allow Insecure";
aiRow.appendChild(aiLabel);

const aiToggle = document.createElement("label");
aiToggle.className = "toggle-switch";
const aiCheck = document.createElement("input");
aiCheck.type = "checkbox";
aiCheck.checked = true;
aiToggle.appendChild(aiCheck);
const aiSlider = document.createElement("span");
aiSlider.className = "toggle-slider";
aiToggle.appendChild(aiSlider);
aiRow.appendChild(aiToggle);

const addManualBtn = document.createElement("button");
addManualBtn.className = "btn btn-primary";
addManualBtn.textContent = "Add Profile";
manualCard.appendChild(addManualBtn);

/* Saved Profiles list */
const listTitle = document.createElement("span");
listTitle.style.fontWeight = "600";
listTitle.style.marginTop = "10px";
listTitle.style.color = "#333";
listTitle.textContent = "Saved Profiles";
profBody.appendChild(listTitle);

const configListContainer = document.createElement("div");
configListContainer.className = "config-list";
profBody.appendChild(configListContainer);

/* ══════════════════════════════════════════
   LOGS TAB
   ══════════════════════════════════════════ */
const logsTab = tabs["logs"];

const logsHeader = document.createElement("div");
logsHeader.className = "tab-header";
logsTab.appendChild(logsHeader);

const logsHeaderTitle = document.createElement("h2");
logsHeaderTitle.textContent = "Logs";
logsHeader.appendChild(logsHeaderTitle);

const logsBody = document.createElement("div");
logsBody.className = "tab-body";
logsTab.appendChild(logsBody);

const logCard = document.createElement("div");
logCard.className = "card";
logCard.style.flex = "1";
logsBody.appendChild(logCard);

const logsViewer = document.createElement("div");
logsViewer.className = "log-viewer";
logCard.appendChild(logsViewer);

const clearLogsBtn = document.createElement("button");
clearLogsBtn.className = "btn";
clearLogsBtn.textContent = "Clear Logs View";
logCard.appendChild(clearLogsBtn);

/* ══════════════════════════════════════════
   EDIT CONFIG DIALOG
   ══════════════════════════════════════════ */
function openEditDialog(cfg) {
  const overlay = document.createElement("div");
  overlay.className = "modal-overlay";

  const dialog = document.createElement("div");
  dialog.className = "modal-dialog";
  dialog.style.position = "relative";
  overlay.appendChild(dialog);

  /* Header */
  const header = document.createElement("div");
  header.className = "modal-header";
  dialog.appendChild(header);

  const headerLeft = document.createElement("div");
  headerLeft.className = "modal-header-left";
  header.appendChild(headerLeft);

  const headerIcon = document.createElement("div");
  headerIcon.className = "modal-header-icon";
  headerIcon.textContent = "M";
  headerLeft.appendChild(headerIcon);

  const headerTitle = document.createElement("h3");
  headerTitle.textContent = "Edit Config (VLess)";
  headerLeft.appendChild(headerTitle);

  const closeBtn = document.createElement("button");
  closeBtn.className = "modal-close-btn";
  closeBtn.innerHTML = "\u00D7";
  closeBtn.addEventListener("click", () => overlay.remove());
  header.appendChild(closeBtn);

  /* Body */
  const body = document.createElement("div");
  body.className = "modal-body";
  dialog.appendChild(body);

  function addField(labelText, value, opts) {
    const grp = document.createElement("div");
    grp.className = "modal-form-group";
    const lbl = document.createElement("label");
    lbl.textContent = labelText;
    grp.appendChild(lbl);
    const inp = document.createElement("input");
    inp.type = opts && opts.type ? opts.type : "text";
    inp.value = value || "";
    if (opts && opts.highlight) inp.className = "highlight";
    if (opts && opts.placeholder) inp.placeholder = opts.placeholder;
    grp.appendChild(inp);
    return { grp: grp, inp: inp };
  }

  const fRemarks = addField("Remarks", cfg.name, { highlight: true });
  body.appendChild(fRemarks.grp);

  const addrRow = document.createElement("div");
  addrRow.className = "modal-form-row";
  body.appendChild(addrRow);

  const fAddr = addField("Address", cfg.server, { highlight: true });
  addrRow.appendChild(fAddr.grp);

  const fPort = addField("Port", String(cfg.port), { type: "number", highlight: true });
  fPort.grp.style.maxWidth = "100px";
  addrRow.appendChild(fPort.grp);

  const fUuid = addField("User ID", cfg.uuid, { highlight: true });
  body.appendChild(fUuid.grp);

  const fSni = addField("SNI", cfg.sni);
  body.appendChild(fSni.grp);

  /* Allow Insecure toggle */
  const toggleRow = document.createElement("div");
  toggleRow.className = "toggle-row";
  body.appendChild(toggleRow);

  const toggleLabel = document.createElement("span");
  toggleLabel.className = "toggle-row-label";
  toggleLabel.textContent = "Allow Insecure";
  toggleRow.appendChild(toggleLabel);

  const toggleSwitch = document.createElement("label");
  toggleSwitch.className = "toggle-switch";
  const toggleInput = document.createElement("input");
  toggleInput.type = "checkbox";
  toggleInput.checked = cfg.allow_insecure !== false;
  toggleSwitch.appendChild(toggleInput);
  const slider = document.createElement("span");
  slider.className = "toggle-slider";
  toggleSwitch.appendChild(slider);
  toggleRow.appendChild(toggleSwitch);

  /* Save FAB */
  const saveFab = document.createElement("button");
  saveFab.className = "modal-fab";
  saveFab.innerHTML = "\u2713";
  saveFab.title = "Save";
  saveFab.addEventListener("click", async () => {
    try {
      await invoke("update_config", {
        id: cfg.id,
        name: fRemarks.inp.value.trim() || cfg.name,
        server: fAddr.inp.value.trim() || cfg.server,
        port: parseInt(fPort.inp.value) || cfg.port,
        uuid: fUuid.inp.value.trim() || cfg.uuid,
        sni: fSni.inp.value.trim() || cfg.sni,
        allowInsecure: toggleInput.checked
      });
      overlay.remove();
      await loadConfigs();
    } catch (err) {
      alert("Save failed: " + err);
    }
  });
  dialog.appendChild(saveFab);

  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) overlay.remove();
  });

  document.body.appendChild(overlay);
}

/* ══════════════════════════════════════════
   DATA / RENDER
   ══════════════════════════════════════════ */
async function loadConfigs() {
  try {
    configs = await invoke("get_configs");
    activeConfigId = await invoke("get_active_config_id");
    renderProfileCards();
    renderConfigs();
  } catch (err) {
    console.error(err);
  }
}

function renderProfileCards() {
  profileCardsContainer.innerHTML = "";
  if (configs.length === 0) {
    const empty = document.createElement("div");
    empty.style.color = "#999";
    empty.style.fontSize = "13px";
    empty.style.textAlign = "center";
    empty.style.padding = "40px 20px";
    empty.textContent = "No profiles yet. Go to Profiles tab to add one.";
    profileCardsContainer.appendChild(empty);
    return;
  }

  configs.forEach(c => {
    const card = document.createElement("div");
    card.className = "profile-card" + (c.id === activeConfigId ? " active" : "");
    card.addEventListener("click", () => selectProfile(c.id));

    const info = document.createElement("div");
    info.className = "profile-card-info";
    card.appendChild(info);

    const name = document.createElement("div");
    name.className = "profile-card-name";
    name.textContent = c.name;
    info.appendChild(name);

    const serverLine = document.createElement("div");
    serverLine.className = "profile-card-server";
    serverLine.textContent = c.server + ":" + c.port;
    info.appendChild(serverLine);

    const proto = document.createElement("div");
    proto.className = "profile-card-proto";
    const tlsType = (c.allow_insecure === false) ? "TLS" : "RLTY";
    proto.textContent = "(VLESS + TCP + " + tlsType + ")";
    info.appendChild(proto);

    const actions = document.createElement("div");
    actions.className = "profile-card-actions";
    card.appendChild(actions);

    /* Edit button */
    const editBtn = document.createElement("button");
    editBtn.className = "profile-action-btn";
    editBtn.innerHTML = "\u270E";
    editBtn.title = "Edit";
    editBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      openEditDialog(c);
    });
    actions.appendChild(editBtn);

    /* Delete button */
    const delBtn = document.createElement("button");
    delBtn.className = "profile-action-btn danger";
    delBtn.innerHTML = "\u2716";
    delBtn.title = "Delete";
    delBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      deleteProfile(c.id);
    });
    actions.appendChild(delBtn);

    profileCardsContainer.appendChild(card);
  });
}

function renderConfigs() {
  configListContainer.innerHTML = "";
  if (configs.length === 0) {
    const empty = document.createElement("div");
    empty.style.color = "#999";
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

    const cname = document.createElement("span");
    cname.className = "config-name";
    cname.textContent = c.name;
    details.appendChild(cname);

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

    item.addEventListener("click", () => selectProfile(c.id));
    configListContainer.appendChild(item);
  });
}

async function selectProfile(id) {
  try {
    await invoke("select_config", { id });
    activeConfigId = id;
    renderProfileCards();
    renderConfigs();
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
    alert("Invalid config link format. Link must start with vless:" + slash + slash);
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
  const allowInsecure = aiCheck.checked;

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
      sni: sni || server,
      allowInsecure: allowInsecure
    });

    inputName.value = "";
    inputHost.value = "";
    inputPort.value = "443";
    inputSni.value = "";
    inputUuid.value = "";
    aiCheck.checked = true;

    await loadConfigs();
    switchTab("connection");
  } catch (err) {
    alert(err);
  }
});

async function checkLatency() {
  if (!isConnected) {
    latencyVal.textContent = "Offline";
    latencyVal.className = "status-latency";
    return;
  }
  try {
    const ms = await invoke("get_latency");
    latencyVal.textContent = ms + " ms";
    if (ms < 150) {
      latencyVal.className = "status-latency good";
    } else if (ms < 300) {
      latencyVal.className = "status-latency ok";
    } else {
      latencyVal.className = "status-latency bad";
    }
  } catch (err) {
    latencyVal.textContent = "Timeout";
    latencyVal.className = "status-latency bad";
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

fab.addEventListener("click", async () => {
  if (isConnecting) return;

  if (!isConnected) {
    if (!activeConfigId) {
      alert("Please select or import a profile first!");
      switchTab("profiles");
      return;
    }

    isConnecting = true;
    statusDot.className = "status-dot connecting";
    statusText.textContent = "Connecting...";
    fab.className = "fab connecting";
    fab.innerHTML = "\u23F3";

    try {
      await invoke("toggle_proxy", { connect: true });
      isConnected = true;
      statusDot.className = "status-dot connected";
      statusText.textContent = "Connected";
      fab.className = "fab connected";
      fab.innerHTML = "\u25A0";
      fab.title = "Disconnect VPN";

      checkLatency();
      latencyInterval = setInterval(checkLatency, 5000);

      fetchLogs();
      logsInterval = setInterval(fetchLogs, 1500);
    } catch (err) {
      statusDot.className = "status-dot error";
      statusText.textContent = "Failed";
      fab.className = "fab";
      fab.innerHTML = "\u25B6";
      fab.title = "Connect VPN";
      alert("Connection failed: " + err);
    } finally {
      isConnecting = false;
    }
  } else {
    isConnecting = true;

    try {
      await invoke("toggle_proxy", { connect: false });
      isConnected = false;
      statusDot.className = "status-dot disconnected";
      statusText.textContent = "Disconnected";
      fab.className = "fab";
      fab.innerHTML = "\u25B6";
      fab.title = "Connect VPN";

      if (latencyInterval) clearInterval(latencyInterval);
      if (logsInterval) clearInterval(logsInterval);

      latencyVal.textContent = "Offline";
      latencyVal.className = "status-latency";
    } catch (err) {
      alert("Disconnection failed: " + err);
    } finally {
      isConnecting = false;
    }
  }
});

loadConfigs();
