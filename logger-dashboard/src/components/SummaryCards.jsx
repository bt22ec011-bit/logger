import React from 'react';

/** Summary cards: totals derived from retrieved log records/stats. */
export default function SummaryCards({ stats, loading }) {
  const cards = [
    { label: 'Total logs', value: stats?.total ?? 0, cls: 'card-total' },
    { label: 'INFO', value: stats?.info ?? 0, cls: 'card-info' },
    { label: 'WARNING', value: stats?.warning ?? 0, cls: 'card-warning' },
    { label: 'ERROR', value: stats?.error ?? 0, cls: 'card-error' },
  ];
  return (
    <section className="summary-cards" aria-label="Log summary">
      {cards.map((c) => (
        <div key={c.label} className={`summary-card ${c.cls}`}>
          <span className="card-value">
            {loading && stats == null ? '…' : c.value}
          </span>
          <span className="card-label">{c.label}</span>
        </div>
      ))}
    </section>
  );
}
