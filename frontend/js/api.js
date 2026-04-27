const API_BASE_URL = "http://localhost:8000";

async function fetchCpuStatus() {
	const response = await fetch(`${API_BASE_URL}/status/cpu`, {
		headers: {
			Accept: "application/json",
		},
	});

	if (!response.ok) {
		throw new Error(`CPU status request failed: ${response.status}`);
	}

	return response.json();
}

async function fetchMemoryStatus(t0) {
	const params = new URLSearchParams();
	if (Number.isFinite(t0)) {
		params.set("t0", Math.round(t0).toString());
	}

	const response = await fetch(`${API_BASE_URL}/status/memory?${params.toString()}`, {
		headers: {
			Accept: "application/json",
		},
	});

	if (!response.ok) {
		throw new Error(`Memory status request failed: ${response.status}`);
	}

	return response.json();
}

async function fetchHealthStatus() {
	const response = await fetch(`${API_BASE_URL}/status/health`, {
		headers: {
			Accept: "application/json",
		},
	});

	if (!response.ok) {
		throw new Error(`Health status request failed: ${response.status}`);
	}

	return response.json();
}

async function fetchLogsProcessedStatus() {
	const response = await fetch(`${API_BASE_URL}/status/logs`, {
		headers: {
			Accept: "application/json",
		},
	});

	if (!response.ok) {
		throw new Error(`Logs processed status request failed: ${response.status}`);
	}

	return response.json();
}

async function fetchAlertsStatus() {
	const response = await fetch(`${API_BASE_URL}/status/alerts`, {
		headers: {
			Accept: "application/json",
		},
	});

	if (!response.ok) {
		throw new Error(`Alerts status request failed: ${response.status}`);
	}

	return response.json();
}

async function fetchLogsWebsocketInfo() {
	const response = await fetch(`${API_BASE_URL}/logs/ws-info`, {
		headers: {
			Accept: "application/json",
		},
	});

	if (!response.ok) {
		throw new Error(`Logs websocket info request failed: ${response.status}`);
	}

	return response.json();
}

async function fetchRecentLogs(limit = 20) {
	const params = new URLSearchParams({
		limit: String(limit),
	});

	const response = await fetch(`${API_BASE_URL}/logs/recent?${params.toString()}`, {
		headers: {
			Accept: "application/json",
		},
	});

	if (!response.ok) {
		throw new Error(`Recent logs request failed: ${response.status}`);
	}

	return response.json();
}

async function fetchAlertsWebsocketInfo() {
	const response = await fetch(`${API_BASE_URL}/alerts/ws-info`, {
		headers: {
			Accept: "application/json",
		},
	});

	if (!response.ok) {
		throw new Error(`Alerts websocket info request failed: ${response.status}`);
	}

	return response.json();
}

async function fetchRecentAlerts(limit = 30) {
	const params = new URLSearchParams({
		limit: String(limit),
	});

	const response = await fetch(`${API_BASE_URL}/alerts/recent?${params.toString()}`, {
		headers: {
			Accept: "application/json",
		},
	});

	if (!response.ok) {
		throw new Error(`Recent alerts request failed: ${response.status}`);
	}

	return response.json();
}
