/**
 * Shared display helpers.
 *
 * IMPORTANT: directions and ports shown here always come from the
 * normalized `network` block produced by the logger agent, which only
 * ever contains the CONFIGURED logical ports (e.g. 5173 / 4000).
 * Ephemeral browser source ports are never present in log records and
 * are never rendered here.
 */

export function formatDirection(log) {
  const net = log.network || {};
  if (!net.direction) return 'Unknown';
  // "Frontend -> Backend" becomes "Frontend (5173) → Backend (4000)".
  // Ports shown are ONLY the configured logical ports stored by the agent.
  return net.direction
    .split('->')
    .map((side) => side.trim())
    .map((side, i) => {
      const port = i === 0 ? net.source_port : net.destination_port;
      return port ? `${side} (${port})` : side;
    })
    .join(' → ');
}

export function formatTimestamp(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return String(iso);
    return d.toLocaleString(undefined, {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
  } catch {
    return String(iso);
  }
}

export function severityClass(sev) {
  const s = String(sev || '').toUpperCase();
  if (s === 'ERROR' || s === 'CRITICAL') return 'sev-error';
  if (s === 'WARNING') return 'sev-warning';
  if (s === 'DEBUG') return 'sev-debug';
  return 'sev-info';
}
