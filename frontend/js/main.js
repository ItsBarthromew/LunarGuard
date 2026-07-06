const cpuStatusElement = document.getElementById("cpu-status");
const memoryStatusElement = document.getElementById("memory-status");
const latencyStatusElement = document.getElementById("latency-status");
const connectionStatusElement = document.getElementById("connection-status");
const healthStatusElement = document.getElementById("health-status");
const logsProcessedStatusElement = document.getElementById("logs-processed-status");
const activeAlertsStatusElement = document.getElementById("active-alerts-status");
const protectedDevicesStatusElement = document.getElementById("protected-devices-status");
const liveLogListElement = document.getElementById("live-log-list");
const logsPageListElement = document.getElementById("logs-page-list");
const alertListElement = document.getElementById("alert-list");
const connectedDevicesListElement = document.getElementById("connected-devices-list");
const logsPauseButtonElement = document.getElementById("logs-pause-btn");
const logsFollowButtonElement = document.getElementById("logs-follow-btn");
const logsRefreshButtonElement = document.getElementById("logs-refresh-btn");
const logsStreamStatusElement = document.getElementById("logs-stream-status");
const navItems = Array.from(document.querySelectorAll(".nav-item[data-view]"));
const appViews = Array.from(document.querySelectorAll(".app-view"));

const MAX_LIVE_LOG_ROWS = 600;
const MAX_ALERT_ROWS = 100;
let logsWebSocket = null;
let logsReconnectTimer = null;
let alertsWebSocket = null;
let alertsReconnectTimer = null;
let logsProcessedDisplayValue = 0;
let logsProcessedAnimationFrame = null;
let logsProcessedAnimationStart = null;
let logsProcessedAnimationFrom = 0;
let logsProcessedAnimationTo = 0;
const LOGS_PROCESSED_ANIMATION_DURATION = 450;
let devicesRefreshCounter = 0;
let logsPaused = false;
const queuedLogs = [];
const MAX_QUEUED_LOGS = 400;
const dismissedAlertSignatures = new Set();
let currentView = "dashboard";
let recentLogsRetryTimer = null;
let recentLogsRetryDelayMs = 1200;
const MAX_RECENT_LOGS_RETRY_DELAY_MS = 10000;
let recentLogsCache = [];

function setActiveView(viewName) {
	currentView = viewName;

	for (const view of appViews) {
		const isVisible = view.dataset.view === viewName;
		view.classList.toggle("is-visible", isVisible);
		view.hidden = !isVisible;
	}

	for (const item of navItems) {
		const isActive = item.dataset.view === viewName;
		item.classList.toggle("is-active", isActive);
		if (isActive) {
			item.setAttribute("aria-current", "page");
		} else {
			item.removeAttribute("aria-current");
		}
	}

	if (viewName === "logs") {
		loadRecentLogs({ quietFailure: false, retryOnFailure: true });
	}
}

function renderLogsPagePlaceholder(message, severity = "info") {
	if (!logsPageListElement) {
		return;
	}

	logsPageListElement.innerHTML = "";
	const placeholder = document.createElement("p");
	placeholder.className = `log-row placeholder ${severity}`;
	placeholder.textContent = message;
	logsPageListElement.append(placeholder);
}

function setLogsConsoleStatus(statusText) {
	if (logsStreamStatusElement) {
		logsStreamStatusElement.textContent = statusText;
	}
}

function clearRecentLogsRetry() {
	if (recentLogsRetryTimer) {
		clearTimeout(recentLogsRetryTimer);
		recentLogsRetryTimer = null;
	}
}

function scheduleRecentLogsRetry() {
	if (recentLogsRetryTimer) {
		return;
	}

	setLogsConsoleStatus("CONNECTING");
	recentLogsRetryTimer = setTimeout(() => {
		recentLogsRetryTimer = null;
		loadRecentLogs({ quietFailure: true, retryOnFailure: true });
	}, recentLogsRetryDelayMs);
	recentLogsRetryDelayMs = Math.min(recentLogsRetryDelayMs * 1.5, MAX_RECENT_LOGS_RETRY_DELAY_MS);
}

function appendLogsPageRow(logEntry) {
	if (!logsPageListElement) {
		return;
	}

	if (logsPageListElement.firstElementChild?.classList.contains("placeholder")) {
		logsPageListElement.innerHTML = "";
	}

	const row = buildLogRow(logEntry);
	logsPageListElement.prepend(row);
	while (logsPageListElement.children.length > 200) {
		logsPageListElement.removeChild(logsPageListElement.lastElementChild);
	}
}

function renderRecentLogs(logs) {
	recentLogsCache = Array.isArray(logs) ? logs.slice() : [];

	if (liveLogListElement) {
		liveLogListElement.replaceChildren();
	}

	if (logsPageListElement) {
		logsPageListElement.replaceChildren();
	}

	if (recentLogsCache.length === 0) {
		renderLogsPagePlaceholder("No recent logs available", "info");
		return;
	}

	for (const logEntry of recentLogsCache) {
		appendLogToViews(logEntry);
	}

	if (liveLogListElement) {
		liveLogListElement.scrollTop = 0;
	}
}

function formatCpuValue(cpuValue) {
	const numericCpu = Number(cpuValue);
	if (!Number.isFinite(numericCpu)) {
		return "--";
	}

	return Math.round(numericCpu).toString();
}

function formatMemoryValue(memoryValue) {
	const numericMemory = Number(memoryValue);
	if (!Number.isFinite(numericMemory)) {
		return "--";
	}

	return numericMemory.toFixed(1);
}

function formatLatencyValue(latencyValue) {
	if (!Number.isFinite(latencyValue) || latencyValue < 0) {
		return "--";
	}

	return Math.round(latencyValue).toString();
}

function formatLogsProcessedValue(value) {
	const numericValue = Number(value);
	if (!Number.isFinite(numericValue)) {
		return "0";
	}

	const absoluteValue = Math.abs(numericValue);
	const units = [
		{ threshold: 1_000_000_000, suffix: "B" },
		{ threshold: 1_000_000, suffix: "M" },
		{ threshold: 1_000, suffix: "k" },
	];

	for (const unit of units) {
		if (absoluteValue >= unit.threshold) {
			const scaledValue = numericValue / unit.threshold;
			const decimalPlaces = Math.abs(scaledValue) >= 100 ? 0 : Math.abs(scaledValue) >= 10 ? 1 : 1;
			const compactValue = scaledValue.toFixed(decimalPlaces).replace(/\.0$/, "");
			return `${compactValue}${unit.suffix}`;
		}
	}

	return Math.round(numericValue).toString();
}

function easeOutCubic(t) {
	return 1 - Math.pow(1 - t, 3);
}

function renderLogsProcessedValue(value) {
	if (!logsProcessedStatusElement) {
		return;
	}

	logsProcessedStatusElement.textContent = formatLogsProcessedValue(value);
}

function animateLogsProcessedCount(targetValue) {
	if (!logsProcessedStatusElement) {
		return;
	}

	const numericTarget = Number(targetValue);
	if (!Number.isFinite(numericTarget)) {
		renderLogsProcessedValue(0);
		return;
	}

	const roundedTarget = Math.max(0, Math.round(numericTarget));
	const currentDisplayed = Number.isFinite(logsProcessedDisplayValue)
		? logsProcessedDisplayValue
		: 0;

	if (roundedTarget === currentDisplayed) {
		renderLogsProcessedValue(roundedTarget);
		return;
	}

	logsProcessedAnimationFrom = currentDisplayed;
	logsProcessedAnimationTo = roundedTarget;
	logsProcessedAnimationStart = performance.now();

	if (logsProcessedAnimationFrame !== null) {
		cancelAnimationFrame(logsProcessedAnimationFrame);
	}

	const tick = (now) => {
		const elapsed = now - logsProcessedAnimationStart;
		const progress = Math.min(elapsed / LOGS_PROCESSED_ANIMATION_DURATION, 1);
		const easedProgress = easeOutCubic(progress);
		logsProcessedDisplayValue = Math.round(
			logsProcessedAnimationFrom + ((logsProcessedAnimationTo - logsProcessedAnimationFrom) * easedProgress)
		);
		renderLogsProcessedValue(logsProcessedDisplayValue);

		if (progress < 1) {
			logsProcessedAnimationFrame = requestAnimationFrame(tick);
			return;
		}

		logsProcessedDisplayValue = logsProcessedAnimationTo;
		renderLogsProcessedValue(logsProcessedDisplayValue);
		logsProcessedAnimationFrame = null;
	};

	logsProcessedAnimationFrame = requestAnimationFrame(tick);
}

function applyThresholdStatusClass(element, value, threshold) {
	element.classList.remove("ok", "warn");
	element.classList.add(value > threshold ? "warn" : "ok");
}

function mapTagClass(tagText) {
	const normalizedTag = String(tagText || "").toUpperCase();
	if (normalizedTag === "[AUTH]") {
		return "auth";
	}
	if (normalizedTag === "[WARN]" || normalizedTag === "[ERROR]") {
		return "warn";
	}
	return "info";
}

function mapAlertSeverityClass(severity) {
	const normalized = String(severity || "INFO").toUpperCase();
	if (normalized === "CRITICAL") {
		return "critical";
	}
	if (normalized === "WARN") {
		return "warn";
	}
	return "info";
}

function buildLogRow(logEntry) {
	const row = document.createElement("p");
	row.className = "log-row";

	const timeSpan = document.createElement("span");
	timeSpan.className = "log-time";
	timeSpan.textContent = logEntry.time || "--:--:--";

	const tagSpan = document.createElement("span");
	tagSpan.className = `tag ${mapTagClass(logEntry.tag)}`;
	tagSpan.textContent = logEntry.tag || "[SYS]";

	row.append(timeSpan, document.createTextNode(" "), tagSpan, document.createTextNode(` ${logEntry.msg || ""}`));
	return row;
}

function appendLiveLog(logEntry) {
	if (!liveLogListElement) {
		return;
	}

	const nearBottom =
		liveLogListElement.scrollTop <= 24;

	const row = buildLogRow(logEntry);
	liveLogListElement.prepend(row);

	while (liveLogListElement.children.length > MAX_LIVE_LOG_ROWS) {
		liveLogListElement.removeChild(liveLogListElement.lastElementChild);
	}

	if (nearBottom) {
		liveLogListElement.scrollTop = 0;
	}
}

function appendLogToViews(logEntry) {
	appendLiveLog(logEntry);
	appendLogsPageRow(logEntry);
}

function rememberRecentLog(logEntry) {
	recentLogsCache.unshift(logEntry);
	while (recentLogsCache.length > MAX_LIVE_LOG_ROWS) {
		recentLogsCache.pop();
	}
}

function setLogsPaused(paused) {
	logsPaused = paused;

	if (logsPauseButtonElement) {
		logsPauseButtonElement.setAttribute("aria-pressed", paused ? "true" : "false");
		logsPauseButtonElement.textContent = paused ? "Resume Live" : "Pause Live";
	}

	if (logsFollowButtonElement) {
		logsFollowButtonElement.setAttribute("aria-pressed", paused ? "false" : "true");
		logsFollowButtonElement.textContent = paused ? "Paused" : "Following Live";
	}

	if (!paused && queuedLogs.length > 0) {
		const buffered = queuedLogs.splice(0, queuedLogs.length);
		for (const logEntry of buffered) {
			appendLogToViews(logEntry);
			rememberRecentLog(logEntry);
		}
	}
}

function buildAlertSignature(alertEntry) {
	return [
		String(alertEntry.event_id || ""),
		String(alertEntry.title || ""),
		String(alertEntry.description || ""),
		String(alertEntry.source || ""),
		String(alertEntry.log_type || ""),
	].join("|");
}

function setupAlertExpansion(summaryElement, cardElement) {
	const toggleExpansion = () => {
		const expanded = cardElement.classList.toggle("expanded");
		cardElement.dataset.expanded = expanded ? "true" : "false";
		summaryElement.setAttribute("aria-expanded", expanded ? "true" : "false");
	};

	summaryElement.addEventListener("click", toggleExpansion);
	summaryElement.addEventListener("keydown", (event) => {
		if (event.key === "Enter" || event.key === " ") {
			event.preventDefault();
			toggleExpansion();
		}
	});
}

function renderAlertsPlaceholder(message, severity = "info") {
	if (!alertListElement) {
		return;
	}

	const placeholder = document.createElement("article");
	placeholder.className = `alert-card ${severity} placeholder`;
	placeholder.innerHTML = `<p class="alert-title ${severity}">${severity.toUpperCase()}</p><p class="alert-desc">${message}</p>`;
	alertListElement.append(placeholder);
}

function ignoreAlertCard(cardElement) {
	if (!alertListElement || !cardElement) {
		return;
	}

	const signature = String(cardElement.dataset.signature || "");
	if (signature) {
		dismissedAlertSignatures.add(signature);
	}

	cardElement.remove();

	if (alertListElement.children.length === 0) {
		renderAlertsPlaceholder("No alerts yet", "info");
	}
}

function buildAlertCard(alertEntry) {
	const card = document.createElement("article");
	const severityClass = mapAlertSeverityClass(alertEntry.severity);
	card.className = `alert-card ${severityClass}`;
	card.dataset.expanded = "false";
	card.dataset.signature = buildAlertSignature(alertEntry);

	const summary = document.createElement("div");
	summary.className = "alert-summary";
	summary.setAttribute("role", "button");
	summary.setAttribute("tabindex", "0");
	summary.setAttribute("aria-expanded", "false");

	const title = document.createElement("p");
	title.className = `alert-title ${severityClass}`;
	title.textContent = `${String(alertEntry.severity || "INFO").toUpperCase()}: ${alertEntry.title || "Alert"}`;

	const meta = document.createElement("p");
	meta.className = "alert-meta";
	meta.textContent = `${alertEntry.time || "--:--:--"} ${alertEntry.log_type || "SYSTEM"}`;

	const desc = document.createElement("p");
	desc.className = "alert-desc";
	desc.textContent = alertEntry.description || "No details";

	const actions = document.createElement("div");
	actions.className = "alert-actions";

	const investigateButton = document.createElement("button");
	investigateButton.type = "button";
	investigateButton.className = "mini-btn blue";
	investigateButton.textContent = "Investigate";
	investigateButton.addEventListener("click", (event) => {
		event.stopPropagation();
		appendLiveLog({
			time: alertEntry.time || "--:--:--",
			tag: "[SYS]",
			msg: `Investigate selected for alert: ${alertEntry.title || "Alert"}`,
		});
	});

	const ignoreButton = document.createElement("button");
	ignoreButton.type = "button";
	ignoreButton.className = "mini-btn red";
	ignoreButton.textContent = "Ignore";
	ignoreButton.addEventListener("click", (event) => {
		event.stopPropagation();
		ignoreAlertCard(card);
	});

	actions.append(investigateButton, ignoreButton);
	summary.append(title, meta, desc);
	setupAlertExpansion(summary, card);

	card.append(summary, actions);
	return card;
}

function clearAlerts() {
	if (!alertListElement) {
		return;
	}

	alertListElement.innerHTML = "";
}

function prependAlert(alertEntry) {
	if (!alertListElement) {
		return;
	}

	const signature = buildAlertSignature(alertEntry);
	if (dismissedAlertSignatures.has(signature)) {
		return;
	}

	if (alertListElement.firstElementChild?.classList.contains("placeholder")) {
		alertListElement.innerHTML = "";
	}

	const card = buildAlertCard(alertEntry);
	alertListElement.prepend(card);

	while (alertListElement.children.length > MAX_ALERT_ROWS) {
		alertListElement.removeChild(alertListElement.lastElementChild);
	}
}

function getDeviceIconSvg(deviceType) {
	if (deviceType === "mobile") {
		return '<svg class="device-icon" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><rect x="6" y="2" width="12" height="20" rx="2"/><circle cx="12" cy="18" r="1.2" fill="#f4f4f4"/></svg>';
	}

	if (deviceType === "router") {
		return '<svg class="device-icon" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M2 12h20v6a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2z"/><path d="M5 11a7 7 0 0 1 14 0" fill="none" stroke="currentColor" stroke-width="2"/><path d="M8 11a4 4 0 0 1 8 0" fill="none" stroke="currentColor" stroke-width="2"/></svg>';
	}

	return '<svg class="device-icon" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><rect x="2" y="4" width="20" height="13" rx="2"/><rect x="9" y="18" width="6" height="2"/></svg>';
}

function buildDeviceItem(device) {
	const item = document.createElement("article");
	item.className = "device-item";

	const state = String(device.state || "Active");
	if (state.toLowerCase() !== "active") {
		item.classList.add("offline");
	}

	const name = String(device.name || device.ip || "Unknown Device");
	const ip = String(device.ip || "--");
	const mac = String(device.mac || "--");
	const deviceType = String(device.type || "host").toLowerCase();

	item.innerHTML = `
		${getDeviceIconSvg(deviceType)}
		<div>
			<p class="device-name">${name.toUpperCase()}</p>
			<p class="device-ip">${ip}</p>
			<p class="device-state">${state} | ${mac}</p>
		</div>
	`;

	return item;
}

async function updateConnectedDevices() {
	if (!connectedDevicesListElement || !protectedDevicesStatusElement) {
		return;
	}

	try {
		devicesRefreshCounter += 1;
		const forceRefresh = devicesRefreshCounter % 3 === 0;
		const devicesData = await fetchConnectedDevices({ refresh: forceRefresh });
		const devices = Array.isArray(devicesData.devices) ? devicesData.devices : [];

		protectedDevicesStatusElement.textContent = String(devices.length);
		connectedDevicesListElement.innerHTML = "";

		if (devices.length === 0) {
			const emptyItem = document.createElement("article");
			emptyItem.className = "device-item offline";
			emptyItem.innerHTML = `
				${getDeviceIconSvg("host")}
				<div>
					<p class="device-name">NO DEVICES FOUND</p>
					<p class="device-ip">Run local network activity to populate ARP cache</p>
					<p class="device-state">Idle</p>
				</div>
			`;
			connectedDevicesListElement.append(emptyItem);
			return;
		}

		for (const device of devices.slice(0, 12)) {
			connectedDevicesListElement.append(buildDeviceItem(device));
		}
	} catch (error) {
		protectedDevicesStatusElement.textContent = "0";
		connectedDevicesListElement.innerHTML = "";

		const errorItem = document.createElement("article");
		errorItem.className = "device-item offline";
		errorItem.innerHTML = `
			${getDeviceIconSvg("host")}
			<div>
				<p class="device-name">DEVICE DISCOVERY UNAVAILABLE</p>
				<p class="device-ip">Unable to query backend network endpoint</p>
				<p class="device-state">Offline</p>
			</div>
		`;
		connectedDevicesListElement.append(errorItem);
	}
}

function appendAlert(alertEntry) {
	if (!alertListElement) {
		return;
	}

	const signature = buildAlertSignature(alertEntry);
	if (dismissedAlertSignatures.has(signature)) {
		return;
	}

	const card = buildAlertCard(alertEntry);
	alertListElement.append(card);
	while (alertListElement.children.length > MAX_ALERT_ROWS) {
		alertListElement.removeChild(alertListElement.lastElementChild);
	}
}

async function loadRecentAlerts() {
	if (!alertListElement) {
		return;
	}

	try {
		const recentData = await fetchRecentAlerts(MAX_ALERT_ROWS);
		clearAlerts();
		const alerts = Array.isArray(recentData.alerts) ? recentData.alerts : [];
		let visibleAlerts = 0;
		for (let index = alerts.length - 1; index >= 0; index -= 1) {
			const beforeCount = alertListElement.children.length;
			appendAlert(alerts[index]);
			if (alertListElement.children.length > beforeCount) {
				visibleAlerts += 1;
			}
		}

		if (visibleAlerts === 0) {
			renderAlertsPlaceholder("No alerts yet", "info");
		}
	} catch (error) {
		clearAlerts();
		renderAlertsPlaceholder("Unable to load recent alerts", "warn");
	}
}

function scheduleAlertsReconnect() {
	if (alertsReconnectTimer) {
		return;
	}

	alertsReconnectTimer = setTimeout(() => {
		alertsReconnectTimer = null;
		connectLiveAlerts();
	}, 2000);
}

async function connectLiveAlerts() {
	if (!alertListElement) {
		return;
	}

	if (alertsWebSocket && (alertsWebSocket.readyState === WebSocket.OPEN || alertsWebSocket.readyState === WebSocket.CONNECTING)) {
		return;
	}

	try {
		const wsInfo = await fetchAlertsWebsocketInfo();
		const websocketUrl = wsInfo.websocket_url;
		if (!websocketUrl) {
			throw new Error("Missing alerts websocket URL");
		}

		alertsWebSocket = new WebSocket(websocketUrl);

		alertsWebSocket.addEventListener("message", (event) => {
			try {
				const alertEntry = JSON.parse(event.data);
				prependAlert(alertEntry);
			} catch (parseError) {
				prependAlert({
					time: "--:--:--",
					severity: "WARN",
					title: "Malformed Alert Payload",
					description: "Received invalid alert payload",
					log_type: "SYSTEM",
				});
			}
		});

		alertsWebSocket.addEventListener("close", () => {
			scheduleAlertsReconnect();
		});

		alertsWebSocket.addEventListener("error", () => {
			if (alertsWebSocket) {
				alertsWebSocket.close();
			}
		});
	} catch (error) {
		await loadRecentAlerts();
		scheduleAlertsReconnect();
	}
}

function clearLiveLogs() {
	if (!liveLogListElement) {
		return;
	}

	liveLogListElement.innerHTML = "";
}

async function loadRecentLogs(options = {}) {
	const quietFailure = options.quietFailure === true;
	const retryOnFailure = options.retryOnFailure !== false;
	if (!liveLogListElement && !logsPageListElement) {
		return;
	}

	try {
		clearRecentLogsRetry();
		recentLogsRetryDelayMs = 1200;
		setLogsConsoleStatus("CONNECTING");
		const recentData = await fetchRecentLogs(MAX_LIVE_LOG_ROWS);
		if (logsRecentCountElement) {
			logsRecentCountElement.textContent = String(Number(recentData.count) || 0);
		}

		const logs = Array.isArray(recentData.logs) ? recentData.logs : [];
		renderRecentLogs(logs);
		setLogsConsoleStatus("LIVE");
	} catch (error) {
		if (!quietFailure) {
			renderLogsPagePlaceholder("Connecting to recent logs...", "info");
		}
		setLogsConsoleStatus("CONNECTING");
		if (retryOnFailure) {
			scheduleRecentLogsRetry();
		}
	}
}

function scheduleLogsReconnect() {
	if (logsReconnectTimer) {
		return;
	}

	logsReconnectTimer = setTimeout(() => {
		logsReconnectTimer = null;
		connectLiveLogs();
	}, 2000);
}

async function connectLiveLogs() {
	if (!liveLogListElement) {
		return;
	}

	if (logsWebSocket && (logsWebSocket.readyState === WebSocket.OPEN || logsWebSocket.readyState === WebSocket.CONNECTING)) {
		return;
	}

	try {
		const wsInfo = await fetchLogsWebsocketInfo();
		const websocketUrl = wsInfo.websocket_url;
		if (!websocketUrl) {
			throw new Error("Missing websocket URL");
		}

		if (logsWebsocketUrlElement) {
			logsWebsocketUrlElement.textContent = websocketUrl;
		}
		setLogsConsoleStatus("LIVE");

		logsWebSocket = new WebSocket(websocketUrl);

		logsWebSocket.addEventListener("message", (event) => {
			try {
				const logEntry = JSON.parse(event.data);

				if (
					logEntry.tag === "[SYS]" &&
					logEntry.msg === "Connected to LunarGuard log stream"
				) {
					return;
				}

				if (logsPaused) {
					queuedLogs.push(logEntry);
					while (queuedLogs.length > MAX_QUEUED_LOGS) {
						queuedLogs.shift();
					}
					return;
				}

				appendLogToViews(logEntry);
				rememberRecentLog(logEntry);
			} catch (parseError) {
				appendLogToViews({
					time: "--:--:--",
					tag: "[WARN]",
					msg: "Received malformed log payload",
				});
			}
		});

		logsWebSocket.addEventListener("close", () => {
			if (logsStreamStatusElement) {
				setLogsConsoleStatus("RECONNECTING");
			}
			scheduleLogsReconnect();
		});

		logsWebSocket.addEventListener("error", () => {
			setLogsConsoleStatus("OFFLINE");
			if (logsWebSocket) {
				logsWebSocket.close();
			}
		});
	} catch (error) {
		await loadRecentLogs({ quietFailure: true, retryOnFailure: true });
		setLogsConsoleStatus("RECENT ONLY");
		scheduleLogsReconnect();
	}
}

if (logsPauseButtonElement) {
	logsPauseButtonElement.addEventListener("click", () => {
		setLogsPaused(!logsPaused);
	});
}

if (logsFollowButtonElement) {
	logsFollowButtonElement.addEventListener("click", () => {
		setLogsPaused(!logsPaused);
	});
}

if (logsRefreshButtonElement) {
	logsRefreshButtonElement.addEventListener("click", async () => {
		await loadRecentLogs({ quietFailure: false, retryOnFailure: true });
	});
}

for (const navItem of navItems) {
	navItem.addEventListener("click", (event) => {
		event.preventDefault();
		setActiveView(navItem.dataset.view || "dashboard");
	});
}

async function updateBottomStatus() {
	if (!cpuStatusElement || !memoryStatusElement || !latencyStatusElement || !connectionStatusElement || !healthStatusElement || !logsProcessedStatusElement || !activeAlertsStatusElement) {
		return;
	}

	const t0 = Date.now();

	try {
		const [cpuData, memoryData, healthData, logsData, alertsData] = await Promise.all([
			fetchCpuStatus(),
			fetchMemoryStatus(t0),
			fetchHealthStatus(),
			fetchLogsProcessedStatus(),
			fetchAlertsStatus(),
		]);

		const t2 = Date.now();
		const numericMemory = Number(memoryData.memory);
		const numericCpu = Number(cpuData.cpu);
		const memoryValue = formatMemoryValue(numericMemory);
		const cpuValue = formatCpuValue(numericCpu);
		const latencyValue = formatLatencyValue(t2 - t0);

		memoryStatusElement.textContent = `MEM: ${memoryValue}%`;
		cpuStatusElement.textContent = `CPU: ${cpuValue}%`;

		if (Number.isFinite(numericMemory)) {
			applyThresholdStatusClass(memoryStatusElement, numericMemory, 80);
		}

		if (Number.isFinite(numericCpu)) {
			applyThresholdStatusClass(cpuStatusElement, numericCpu, 70);
		}

		latencyStatusElement.textContent = `LATENCY: ${latencyValue}MS`;
		animateLogsProcessedCount(logsData.logs_processed);
		activeAlertsStatusElement.textContent = String(Number(alertsData.active_alerts) || 0);
		connectionStatusElement.textContent = "STATUS: ONLINE";
		connectionStatusElement.classList.remove("warn");
		connectionStatusElement.classList.add("ok");

		const healthLabel = typeof healthData.health === "string" ? healthData.health : "--";
		healthStatusElement.textContent = `HEALTH: ${healthLabel}`;
		healthStatusElement.classList.remove("ok", "warn");
		healthStatusElement.classList.add(healthLabel === "POOR" ? "warn" : "ok");
	} catch (error) {
		memoryStatusElement.textContent = "MEM: --%";
		cpuStatusElement.textContent = "CPU: --%";
		memoryStatusElement.classList.remove("ok");
		memoryStatusElement.classList.add("warn");
		cpuStatusElement.classList.remove("ok");
		cpuStatusElement.classList.add("warn");
		latencyStatusElement.textContent = "LATENCY: --MS";
		animateLogsProcessedCount(0);
		activeAlertsStatusElement.textContent = "0";
		connectionStatusElement.textContent = "STATUS: OFFLINE";
		connectionStatusElement.classList.remove("ok");
		connectionStatusElement.classList.add("warn");
		healthStatusElement.textContent = "HEALTH: --";
		healthStatusElement.classList.remove("ok");
		healthStatusElement.classList.add("warn");
	}
}

updateBottomStatus();
setInterval(updateBottomStatus, 1000);

setActiveView("dashboard");
loadRecentLogs({ quietFailure: true, retryOnFailure: true });
connectLiveLogs();
loadRecentAlerts();
connectLiveAlerts();
updateConnectedDevices();
setInterval(updateConnectedDevices, 10000);
