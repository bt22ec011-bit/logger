import React from 'react';

const EMPTY = {
  severity: '', application: '', direction: '', method: '',
  search: '', start: '', end: '',
};

/** Filter bar: severity, application, direction, method, endpoint search,
 *  time range and a clear button. */
export default function LogFilters({ filters, applications, onChange }) {
  const set = (key) => (e) => onChange({ ...filters, [key]: e.target.value });
  const clear = () => onChange({ ...EMPTY });
  const hasActive = Object.values(filters).some((v) => v !== '');

  return (
    <section className="filters" aria-label="Log filters">
      <label>
        Severity
        <select value={filters.severity} onChange={set('severity')}>
          <option value="">All</option>
          <option value="INFO">INFO</option>
          <option value="WARNING">WARNING</option>
          <option value="ERROR">ERROR</option>
          <option value="DEBUG">DEBUG</option>
        </select>
      </label>

      <label>
        Application
        <select value={filters.application} onChange={set('application')}>
          <option value="">All</option>
          {applications.map((name) => (
            <option key={name} value={name}>{name}</option>
          ))}
        </select>
      </label>

      <label>
        Direction
        <select value={filters.direction} onChange={set('direction')}>
          <option value="">All</option>
          <option value={'Frontend -> Backend'}>Frontend → Backend</option>
          <option value={'Backend -> Frontend'}>Backend → Frontend</option>
        </select>
      </label>

      <label>
        Method
        <select value={filters.method} onChange={set('method')}>
          <option value="">All</option>
          {['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].map((m) => (
            <option key={m} value={m}>{m}</option>
          ))}
        </select>
      </label>

      <label>
        Endpoint search
        <input
          type="search"
          placeholder="/api/matches"
          value={filters.search}
          onChange={set('search')}
        />
      </label>

      <label>
        From
        <input type="datetime-local" value={filters.start}
               onChange={set('start')} />
      </label>

      <label>
        To
        <input type="datetime-local" value={filters.end}
               onChange={set('end')} />
      </label>

      <button className="btn-clear" onClick={clear}
              disabled={!hasActive}>
        Clear filters
      </button>
    </section>
  );
}

export { EMPTY as EMPTY_FILTERS };
