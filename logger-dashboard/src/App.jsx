import React, { useCallback, useEffect, useMemo, useState } from 'react';
import SummaryCards from './components/SummaryCards.jsx';
import LogTable from './components/LogTable.jsx';
import LogFilters, { EMPTY_FILTERS } from './components/LogFilters.jsx';
import LogDetails from './components/LogDetails.jsx';
import { fetchHealth, fetchLogs, fetchStats, API_URL } from './services/logApi.js';

export default function App() {
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState(null);
  const [filters, setFilters] = useState({ ...EMPTY_FILTERS });
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [connected, setConnected] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [pagination, setPagination] = useState({ page: 1, pages: 1, total: 0 });

  const load = useCallback(async (page = 1) => {
    setLoading(true);
    setError(null);
    try {
      const params = {
        page,
        page_size: 50,
        severity: filters.severity,
        application: filters.application,
        direction: filters.direction,
        method: filters.method,
        search: filters.search,
      };
      if (filters.start) params.start_time = new Date(filters.start).toISOString();
      if (filters.end) params.end_time = new Date(filters.end).toISOString();

      const [logsRes, statsRes] = await Promise.all([
        fetchLogs(params),
        fetchStats(),
      ]);
      setLogs(logsRes?.data?.logs ?? []);
      setPagination(logsRes?.data?.pagination ?? { page: 1, pages: 1, total: 0 });
      setStats(statsRes?.data ?? null);
      setConnected(true);
    } catch (err) {
      setConnected(false);
      setError(err.message || 'Unable to reach the logger backend.');
    } finally {
      setLoading(false);
    }
  }, [filters]);

  useEffect(() => {
    load(1);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters]);

  useEffect(() => {
    fetchHealth().then(() => setConnected(true)).catch(() => setConnected(false));
    const t = setInterval(() => load(pagination.page), 15000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [load]);

  const applications = useMemo(() => {
    const names = new Set();
    logs.forEach((l) => l.application?.name && names.add(l.application.name));
    return [...names].sort();
  }, [logs]);

  return (
    <div className="app">
      <nav className="topbar">
        <h1>Logger Dashboard</h1>
        <div className="topbar-right">
          <span className={`status-pill ${connected ? 'online' : 'offline'}`}>
            {connected ? '● Connected' : '● Disconnected'}
          </span>
          <button className="btn" onClick={() => load(pagination.page)}
                  disabled={loading}>
            {loading ? 'Refreshing…' : '⟳ Refresh'}
          </button>
          <button className="btn" onClick={() => setShowSettings((v) => !v)}>
            ⚙ Settings
          </button>
        </div>
      </nav>

      {showSettings && (
        <div className="settings-panel">
          <p><strong>Backend API URL:</strong> {API_URL}</p>
          <p>Configure it in <code>.env</code> as
            <code> VITE_LOGGER_API_URL</code>.</p>
          <p>Displayed ports are the configured logical ports
            (frontend / backend). Ephemeral browser ports are never shown.</p>
        </div>
      )}

      <main className="content">
        <SummaryCards stats={stats} loading={loading} />

        <LogFilters filters={filters} applications={applications}
                    onChange={setFilters} />

        {error && (
          <div className="state-banner error-state" role="alert">
            <strong>Cannot reach the logger backend.</strong>{' '}
            {error} — is it running on{' '}
            <a href={API_URL} rel="noreferrer">{API_URL}</a>?
            <button className="btn" onClick={() => load(pagination.page)}>
              Retry
            </button>
          </div>
        )}

        {!error && loading && !logs.length && (
          <div className="state-banner loading-state">Loading logs…</div>
        )}

        {!error && !loading && !logs.length && (
          <div className="state-banner empty-state">
            No log records yet. Start the logging agent and make an API
            call, or POST a structured event to <code>/api/logs</code>.
          </div>
        )}

        {!error && logs.length === 0 && !loading &&
          Object.values(filters).some((v) => v !== '') && (
          <div className="state-banner empty-state">
            No logs match the current filters.
          </div>
        )}

        {logs.length > 0 && (
          <>
            <LogTable logs={logs} selectedId={selected?.log_id}
                      onSelect={setSelected} />
            <div className="pagination">
              <button className="btn" disabled={pagination.page <= 1}
                      onClick={() => load(pagination.page - 1)}>‹ Prev</button>
              <span>
                Page {pagination.page} of {Math.max(pagination.pages, 1)}
                {' '}({pagination.total} logs)
              </span>
              <button className="btn"
                      disabled={pagination.page >= pagination.pages}
                      onClick={() => load(pagination.page + 1)}>Next ›</button>
            </div>
          </>
        )}
      </main>

      {selected && (
        <LogDetails log={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}
