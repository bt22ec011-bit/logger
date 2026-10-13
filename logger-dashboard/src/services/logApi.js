/**
 * Logger backend API client.
 * The base URL comes from VITE_LOGGER_API_URL (see .env.example) —
 * never hard-coded per deployment.
 */
const API_URL =
  (typeof import.meta !== 'undefined' &&
    import.meta.env &&
    import.meta.env.VITE_LOGGER_API_URL) ||
  'http://localhost:4000';

async function request(path, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const res = await fetch(`${API_URL}${path}`, {
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
      ...options,
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(body.message || `HTTP ${res.status}`);
    }
    return body;
  } finally {
    clearTimeout(timer);
  }
}

export function fetchHealth() {
  return request('/api/health');
}

export function fetchLogs(params = {}) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      query.set(key, value);
    }
  });
  const qs = query.toString();
  return request(`/api/logs${qs ? `?${qs}` : ''}`);
}

export function fetchStats() {
  return request('/api/logs/stats');
}

export function fetchLogById(id) {
  return request(`/api/logs/${encodeURIComponent(id)}`);
}

export function postLog(event) {
  return request('/api/logs', {
    method: 'POST',
    body: JSON.stringify(event),
  });
}

export { API_URL };
