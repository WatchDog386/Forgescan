import { useEffect, useState } from "react";
import { health } from "../api.js";
import Icon from "../icons.jsx";
import { ATTACK_TYPES, Badge, Empty, Notice, PageHeader, SEVERITIES, Time, label, useData } from "../ui.jsx";

function Tile({ icon, title, value, note, tone }) {
  return (
    <div className={`card tile ${tone ?? ""}`}>
      <span className="tile-icon"><Icon name={icon} size={20} /></span>
      <div>
        <div className="tile-title">{title}</div>
        <div className="tile-value">{value}</div>
        {note && <div className="tile-note">{note}</div>}
      </div>
    </div>
  );
}

// Horizontal bars, one per category, each labelled with its name and count.
function Bars({ counts, order, kind }) {
  const total = order.reduce((sum, key) => sum + (counts[key] ?? 0), 0);
  const max = Math.max(1, ...order.map((key) => counts[key] ?? 0));
  return (
    <div className="bars" role="table">
      {order.map((key) => {
        const n = counts[key] ?? 0;
        return (
          <div className="bar-row" role="row" key={key} title={`${label(key)}: ${n} alert${n === 1 ? "" : "s"}${total ? ` (${Math.round((n / total) * 100)}%)` : ""}`}>
            <span className="bar-label" role="cell">{kind === "sev" && <i className={`swatch sev-${key}`} />}{label(key)}</span>
            <span className="bar-track"><span className={kind === "sev" ? `bar-fill sev-${key}` : "bar-fill"} style={{ width: `${(n / max) * 100}%` }} /></span>
            <span className="num" role="cell">{n}</span>
          </div>
        );
      })}
    </div>
  );
}

function TopList({ rows, empty }) {
  if (!rows.length) return <Empty>{empty}</Empty>;
  const max = Math.max(...rows.map((r) => r.alerts));
  return (
    <table className="toplist">
      <tbody>
        {rows.map((r) => (
          <tr key={r.address} title={`${r.address}: ${r.alerts} alerts`}>
            <td className="mono">{r.address}</td>
            <td className="share"><span style={{ width: `${(r.alerts / max) * 100}%` }} /></td>
            <td className="right num">{r.alerts}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Event({ event }) {
  if (event.type === "alert") {
    return (
      <li>
        <span className={`dot sev-${event.severity}`} />
        <div className="event-body">
          <div><b>{label(event.attack_type)}</b> from <span className="mono">{event.source_ip}</span>
            {event.target_ip && <> to <span className="mono">{event.target_ip}</span></>}</div>
          <div className="event-meta"><Badge value={event.severity} kind="sev" /> Risk {event.risk_score}
            {event.new_incident && <> · <a href={`#/incidents/${event.incident_id}`}>New incident #{event.incident_id}</a></>}</div>
        </div>
        <span className="event-time"><Time value={event.received} relative /></span>
      </li>
    );
  }
  if (event.type === "response") {
    return (
      <li>
        <span className="dot response" />
        <div className="event-body">
          <div><b>{label(event.action)}</b> <span className="mono">{event.target_ip}</span></div>
          <div className="event-meta"><Badge value={event.status} />{event.detail && <span className="muted"> {event.detail}</span>}</div>
        </div>
        <span className="event-time"><Time value={event.received} relative /></span>
      </li>
    );
  }
  return (
    <li>
      <span className="dot incident" />
      <div className="event-body">
        <div><a href={`#/incidents/${event.incident_id}`}><b>Incident #{event.incident_id}</b></a> changed</div>
        <div className="event-meta">Now <Badge value={event.status} /></div>
      </div>
      <span className="event-time"><Time value={event.received} relative /></span>
    </li>
  );
}

export default function Overview({ version, events, live }) {
  const { data, error } = useData("/stats/summary", version);
  const [system, setSystem] = useState(null);
  useEffect(() => {
    health().then(setSystem).catch(() => setSystem(null));
  }, [version]);

  const dryRun = system?.firewall === "DryRunFirewall";
  const online = data?.sensors.filter((s) => !s.silent).length ?? 0;
  const critical = data?.by_severity.critical ?? 0;

  return (
    <>
      <PageHeader title="Overview" subtitle="What the sensors have seen in the last 24 hours" />
      <Notice error={error} />
      {system && !system.main_model && (
        <Notice error="No detection model is active. In the backend folder run: python -m app.cli bootstrap-model, then restart the backend." />
      )}

      {data && (
        <div className="tiles">
          <Tile icon="alerts" title="Alerts" value={data.alerts_24h} note="last 24 hours" />
          <Tile icon="incidents" title="Open incidents" value={data.open_incidents} note="new or investigating" tone={data.open_incidents ? "tone-warn" : ""} />
          <Tile icon="warning" title="Critical alerts" value={critical} note="last 24 hours" tone={critical ? "tone-critical" : ""} />
          <Tile icon="sensor" title="Sensors online" value={`${online} / ${data.sensors.length}`} note={data.sensors.length ? "sending traffic" : "none registered"}
                tone={data.sensors.length && online < data.sensors.length ? "tone-warn" : ""} />
        </div>
      )}

      {data && (
        <div className="grid three">
          <section className="card">
            <h2>Alerts by severity</h2>
            <Bars counts={data.by_severity} order={[...SEVERITIES].reverse()} kind="sev" />
          </section>
          <section className="card">
            <h2>Alerts by attack type</h2>
            <Bars counts={data.by_attack_type} order={ATTACK_TYPES} kind="atk" />
          </section>
          <section className="card">
            <h2>System</h2>
            <ul className="status-list">
              <li><Icon name="cpu" /><span>Detection model</span><b className="mono">{system?.main_model ?? "none"}</b></li>
              <li><Icon name="graph" /><span>Anomaly model</span><b className="mono">{system?.anomaly_model ?? "none"}</b></li>
              <li><Icon name="firewall" /><span>Firewall</span><b>{system ? (dryRun ? <Badge value="dry_run" /> : "nftables over SSH") : "—"}</b></li>
              <li><Icon name="pulse" /><span>Live events</span><b>{live ? <span className="badge status-applied"><i />Connected</span> : <span className="badge status-dry_run"><i />Reconnecting</span>}</b></li>
            </ul>
          </section>
        </div>
      )}

      <div className="grid wide-left">
        <section className="card feed">
          <div className="card-head">
            <h2>Live events</h2>
            <span className={live ? "live on" : "live"}><i />{live ? "Streaming" : "Reconnecting"}</span>
          </div>
          {events.length ? (
            <ul className="timeline">{events.map((event) => <Event key={event.key} event={event} />)}</ul>
          ) : (
            <Empty>Waiting for events. Send traffic with sensor\simulate_traffic.py and they appear here as they arrive.</Empty>
          )}
        </section>
        <div className="stack">
          <section className="card">
            <h2>Top sources</h2>
            {data && <TopList rows={data.top_sources} empty="No alerts in the last 24 hours." />}
          </section>
          <section className="card">
            <h2>Top targets</h2>
            {data && <TopList rows={data.top_targets} empty="No alerts in the last 24 hours." />}
          </section>
          <section className="card">
            <h2>Sensors</h2>
            {data?.sensors.length ? (
              <ul className="sensor-list">
                {data.sensors.map((s) => (
                  <li key={s.name}>
                    <Icon name="sensor" />
                    <span>{s.name}<small>Last seen <Time value={s.last_seen} relative /></small></span>
                    <span className={s.silent ? "badge status-failed" : "badge status-applied"}><i />{s.silent ? "Silent" : "Online"}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <Empty>No sensors yet. Run: python -m app.cli create-sensor --name lab-sensor</Empty>
            )}
          </section>
        </div>
      </div>
    </>
  );
}
