import React, { useState } from 'react';
import { formatDirection, severityClass } from '../utils.js';

/** One collapsible section of the details panel. */
function Section({ title, children, open = false }) {
  const [expanded, setExpanded] = useState(open);
  return (
    <div className={`detail-section ${expanded ? 'open' : ''}`}>
      <button
        className="section-toggle"
        onClick={() => setExpanded((v) => !v)}
        aria-expanded={expanded}
      >
        <span>{expanded ? '▾' : '▸'} {title}</span>
      </button>
      {expanded && <div className="section-body">{children}</div>}
    </div>
  );
}

function Field({ label, value }) {
  if (value === undefined || value === null || value === '') return null;
  return (
    <div className="field">
      <span className="field-label">{label}</span>
      <span className="field-value">{String(value)}</span>
    </div>
  );
}

/** Structured key/value rendering — never raw bytes/hex/base64. */
function renderObject(obj, prefix = '') {
  return Object.entries(obj || {}).map(([k, v]) => {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      return <React.Fragment key={key}>{renderObject(v, key)}</React.Fragment>;
    }
    return <Field key={key} label={key} value={v} />;
  });
}

export default function LogDetails({ log, onClose }) {
  const [copied, setCopied] = useState(false);
  if (!log) return null;

  const jsonText = JSON.stringify(log, null, 2);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(jsonText);
    } catch {
      const ta = document.createElement('textarea');
      ta.value = jsonText;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <aside className="details-panel" aria-label="Log details">
      <header className="details-header">
        <h2>Log details</h2>
        <div>
          <button className="btn-copy" onClick={copy}>
            {copied ? 'Copied ✓' : 'Copy JSON'}
          </button>
          <button className="btn-close" onClick={onClose}
                  aria-label="Close details">✕</button>
        </div>
      </header>

      <div className={`badge big ${severityClass(log.severity)}`}>
        {log.severity}
      </div>
      <p className="details-event">{log.event}</p>
      <p className="details-message">{log.message}</p>

      <Section title="General information" open>
        <Field label="Log ID" value={log.log_id} />
        <Field label="Timestamp" value={log.timestamp} />
        <Field label="Event type" value={log.event_type} />
      </Section>

      <Section title="Application">
        <Field label="Name" value={log.application?.name} />
        <Field label="Environment" value={log.application?.environment} />
        <Field label="Version" value={log.application?.version ?? 'Not available'} />
      </Section>

      <Section title="Network direction" open>
        <Field label="Direction" value={formatDirection(log)} />
        <Field label="Source" value={log.network?.source} />
        <Field label="Destination" value={log.network?.destination} />
      </Section>

      <Section title="Request details">
        <Field label="Request ID" value={log.request?.request_id} />
        <Field label="Method" value={log.request?.method} />
        <Field label="Route" value={log.request?.route} />
        <Field label="Status code" value={log.request?.status_code} />
        <Field label="Outcome" value={log.request?.outcome} />
      </Section>

      <Section title="Performance">
        <Field label="Duration (ms)" value={log.performance?.duration_ms} />
        <Field label="Slow request"
               value={log.performance?.slow_request === undefined
                 ? 'Not available' : String(log.performance.slow_request)} />
      </Section>

      <Section title="User">
        {log.user ? renderObject(log.user)
                  : <Field label="User" value="Not available" />}
      </Section>

      <Section title="Error">
        {log.error ? renderObject(log.error)
                   : <Field label="Error" value="None recorded" />}
      </Section>

      <Section title="Context">
        {log.context ? renderObject(log.context)
                     : <Field label="Context" value="Not available" />}
      </Section>

      <Section title="Formatted JSON payload">
        <pre className="json-block">{jsonText}</pre>
      </Section>
    </aside>
  );
}
