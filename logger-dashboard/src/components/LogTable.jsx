import React from 'react';
import { formatDirection, formatTimestamp, severityClass } from '../utils.js';

/**
 * Log table. Columns intentionally exclude anything derived from raw
 * sockets — only configured logical ports are displayed.
 */
export default function LogTable({ logs, selectedId, onSelect }) {
  if (!logs.length) return null;
  return (
    <div className="table-wrap">
      <table className="log-table">
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Severity</th>
            <th>Application</th>
            <th>Direction</th>
            <th>Source port</th>
            <th>Dest. port</th>
            <th>Method</th>
            <th>Endpoint</th>
            <th>Status</th>
            <th>Message</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((log) => {
            const req = log.request || {};
            const net = log.network || {};
            return (
              <tr
                key={log.log_id}
                className={
                  selectedId === log.log_id ? 'row-selected' : ''
                }
                onClick={() => onSelect(log)}
              >
                <td className="cell-time">{formatTimestamp(log.timestamp)}</td>
                <td>
                  <span className={`badge ${severityClass(log.severity)}`}>
                    {log.severity}
                  </span>
                </td>
                <td>{log.application?.name ?? '—'}</td>
                <td className="cell-dir">{formatDirection(log)}</td>
                <td>{net.source_port ?? '—'}</td>
                <td>{net.destination_port ?? '—'}</td>
                <td>{req.method ?? '—'}</td>
                <td className="cell-route">{req.route ?? '—'}</td>
                <td>{req.status_code ?? '—'}</td>
                <td className="cell-msg" title={log.message}>
                  {log.message}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
