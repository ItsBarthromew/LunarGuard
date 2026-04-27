const cpuStatusElement = document.getElementById("cpu-status");
const memoryStatusElement = document.getElementById("memory-status");
const latencyStatusElement = document.getElementById("latency-status");
const connectionStatusElement = document.getElementById("connection-status");
const healthStatusElement = document.getElementById("health-status");
const logsProcessedStatusElement = document.getElementById("logs-processed-status");
const activeAlertsStatusElement = document.getElementById("active-alerts-status");
const liveLogListElement = document.getElementById("live-log-list");
const alertListElement = document.getElementById("alert-list");

const MAX_LIVE_LOG_ROWS = 18;
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

	const row = buildLogRow(logEntry);
	liveLogListElement.append(row);

	while (liveLogListElement.children.length > MAX_LIVE_LOG_ROWS) {
		liveLogListElement.removeChild(liveLogListElement.firstElementChild);
	}
}

function buildAlertCard(alertEntry) {
	const card = document.createElement("article");
	const severityClass = mapAlertSeverityClass(alertEntry.severity);
	card.className = `alert-card ${severityClass}`;

	const title = document.createElement("p");
	title.className = `alert-title ${severityClass}`;
	title.textContent = `${String(alertEntry.severity || "INFO").toUpperCase()}: ${alertEntry.title || "Alert"}`;

	const meta = document.createElement("p");
	meta.className = "alert-meta";
	meta.textContent = `${alertEntry.time || "--:--:--"} ${alertEntry.log_type || "SYSTEM"}`;

	const desc = document.createElement("p");
	desc.className = "alert-desc";
	desc.textContent = alertEntry.description || "No details";

	card.append(title, meta, desc);
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

	if (alertListElement.firstElementChild?.classList.contains("placeholder")) {
		alertListElement.innerHTML = "";
	}

	const card = buildAlertCard(alertEntry);
	alertListElement.prepend(card);

	while (alertListElement.children.length > MAX_ALERT_ROWS) {
		alertListElement.removeChild(alertListElement.lastElementChild);
	}
}

function appendAlert(alertEntry) {
	if (!alertListElement) {
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
		for (let index = alerts.length - 1; index >= 0; index -= 1) {
			appendAlert(alerts[index]);
		}

		if (alerts.length === 0) {
			const placeholder = document.createElement("article");
			placeholder.className = "alert-card info placeholder";
			placeholder.innerHTML = '<p class="alert-title info">INFO</p><p class="alert-desc">No alerts yet</p>';
			alertListElement.append(placeholder);
		}
	} catch (error) {
		clearAlerts();
		const placeholder = document.createElement("article");
		placeholder.className = "alert-card warn placeholder";
		placeholder.innerHTML = '<p class="alert-title warn">WARN</p><p class="alert-desc">Unable to load recent alerts</p>';
		alertListElement.append(placeholder);
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

async function loadRecentLogs() {
	if (!liveLogListElement) {
		return;
	}

	try {
		const recentData = await fetchRecentLogs(MAX_LIVE_LOG_ROWS);
		clearLiveLogs();
		for (const logEntry of recentData.logs || []) {
			appendLiveLog(logEntry);
		}
	} catch (error) {
		clearLiveLogs();
		appendLiveLog({
			time: "--:--:--",
			tag: "[WARN]",
			msg: "Unable to load recent logs",
		});
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

				appendLiveLog(logEntry);
			} catch (parseError) {
				appendLiveLog({
					time: "--:--:--",
					tag: "[WARN]",
					msg: "Received malformed log payload",
				});
			}
		});

		logsWebSocket.addEventListener("close", () => {
			scheduleLogsReconnect();
		});

		logsWebSocket.addEventListener("error", () => {
			if (logsWebSocket) {
				logsWebSocket.close();
			}
		});
	} catch (error) {
		await loadRecentLogs();
		scheduleLogsReconnect();
	}
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

loadRecentLogs();
connectLiveLogs();
loadRecentAlerts();
connectLiveAlerts();
