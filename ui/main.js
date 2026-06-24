const slash = String.fromCharCode(47);
const invoke = window.__TAURI__.invoke;

const container = document.createElement("div");
container.className = "container";
document.body.appendChild(container);

const header = document.createElement("h1");
header.textContent = "RUVE BYPASS COMPANION";
container.appendChild(header);

const statusBadge = document.createElement("div");
statusBadge.id = "status";
statusBadge.className = "status-badge disconnected";
statusBadge.textContent = "DISCONNECTED";
container.appendChild(statusBadge);

const toggleContainer = document.createElement("div");
toggleContainer.className = "toggle-container";
container.appendChild(toggleContainer);

const toggleLabel = document.createElement("label");
toggleLabel.className = "switch";
toggleContainer.appendChild(toggleLabel);

const toggleInput = document.createElement("input");
toggleInput.type = "checkbox";
toggleInput.id = "connection-toggle";
toggleLabel.appendChild(toggleInput);

const toggleSlider = document.createElement("span");
toggleSlider.className = "slider round";
toggleLabel.appendChild(toggleSlider);

const toggleText = document.createElement("span");
toggleText.className = "toggle-text";
toggleText.id = "toggle-label";
toggleText.textContent = "TOGGLE TO CONNECT";
toggleContainer.appendChild(toggleText);

const latencyContainer = document.createElement("div");
latencyContainer.className = "latency-container";
container.appendChild(latencyContainer);

const latencyLabel = document.createElement("span");
latencyLabel.textContent = "Latency: ";
latencyContainer.appendChild(latencyLabel);

const latencyValue = document.createElement("span");
latencyValue.id = "latency-value";
latencyValue.className = "latency-offline";
latencyValue.textContent = "Offline";
latencyContainer.appendChild(latencyValue);

const logHeader = document.createElement("h2");
logHeader.textContent = "Bypass Logs";
container.appendChild(logHeader);

const logsContainer = document.createElement("div");
logsContainer.id = "logs";
logsContainer.className = "log-viewer";
container.appendChild(logsContainer);

const initialLog = document.createElement("div");
initialLog.className = "log-entry system";
initialLog.textContent = "Engine initialized. Ready to connect.";
logsContainer.appendChild(initialLog);

let isConnected = false;
let latencyInterval = null;
let logsInterval = null;

function addLogEntry(text, type = "system") {
  const entry = document.createElement("div");
  entry.className = "log-entry " + type;
  entry.textContent = "[" + new Date().toLocaleTimeString() + "] " + text;
  logsContainer.appendChild(entry);
  logsContainer.scrollTop = logsContainer.scrollHeight;
}

async function updateLatency() {
  try {
    const ms = await invoke("get_latency");
    latencyValue.textContent = ms + " ms";
    latencyValue.className = "";
    if (ms < 150) {
      latencyValue.classList.add("latency-good");
    } else if (ms < 300) {
      latencyValue.classList.add("latency-medium");
    } else {
      latencyValue.classList.add("latency-bad");
    }
  } catch (err) {
    latencyValue.textContent = "Offline";
    latencyValue.className = "latency-offline";
  }
}

async function updateLogs() {
  try {
    const logs = await invoke("get_logs");
    logsContainer.innerHTML = "";
    logs.forEach(log => {
      const entry = document.createElement("div");
      if (log.includes("Bypassing")) {
        entry.className = "log-entry bypass";
      } else {
        entry.className = "log-entry system";
      }
      entry.textContent = log;
      logsContainer.appendChild(entry);
    });
    logsContainer.scrollTop = logsContainer.scrollHeight;
  } catch (err) {
  }
}

toggleInput.addEventListener("change", async () => {
  const connect = toggleInput.checked;
  isConnected = connect;
  
  if (connect) {
    statusBadge.textContent = "CONNECTING...";
    statusBadge.className = "status-badge connecting";
    toggleText.textContent = "CONNECTING";
    toggleInput.disabled = true;

    try {
      await invoke("toggle_proxy", { connect: true });
      statusBadge.textContent = "CONNECTED";
      statusBadge.className = "status-badge connected";
      toggleText.textContent = "ACTIVE (127.0.0.1:10808)";
      
      await updateLatency();
      latencyInterval = setInterval(updateLatency, 5000);
      logsInterval = setInterval(updateLogs, 1000);
    } catch (err) {
      statusBadge.textContent = "ERROR";
      statusBadge.className = "status-badge error";
      toggleText.textContent = "FAILED";
      toggleInput.checked = false;
      isConnected = false;
      addLogEntry("Failed to connect: " + err, "system");
    } finally {
      toggleInput.disabled = false;
    }
  } else {
    statusBadge.textContent = "DISCONNECTED";
    statusBadge.className = "status-badge disconnected";
    toggleText.textContent = "TOGGLE TO CONNECT";
    
    if (latencyInterval) clearInterval(latencyInterval);
    if (logsInterval) clearInterval(logsInterval);
    
    latencyValue.textContent = "Offline";
    latencyValue.className = "latency-offline";
    
    try {
      await invoke("toggle_proxy", { connect: false });
    } catch (err) {
    }
    
    addLogEntry("Disconnected", "system");
  }
});
