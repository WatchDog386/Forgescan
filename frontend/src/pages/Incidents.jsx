import { useState } from "react";
import { ATTACK_TYPES, Badge, Empty, INCIDENT_STATES, Notice, PageHeader, Risk, SEVERITIES, Select, Time, label, query, useData } from "../ui.jsx";

export default function Incidents({ version }) {
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [attack, setAttack] = useState("");
  const [source, setSource] = useState("");
  const { data, error } = useData(`/incidents${query({ status_: status, severity, attack_type: attack, source_ip: source.trim(), limit: 200 })}`, version);
  const open = data?.filter((i) => i.status === "new" || i.status === "investigating").length ?? 0;

  return (
    <>
      <PageHeader title="Incidents" subtitle="Alerts grouped by source and attack, for an analyst to work through">
        {data && <span className="count-chip">{open} open · {data.length} shown</span>}
      </PageHeader>
      <Notice error={error} />
      <div className="card flush">
        <div className="toolbar">
          <Select label="Status" value={status} onChange={setStatus} options={INCIDENT_STATES} />
          <Select label="Severity" value={severity} onChange={setSeverity} options={SEVERITIES} />
          <Select label="Attack" value={attack} onChange={setAttack} options={ATTACK_TYPES} />
          <label className="field inline">
            <span>Source address</span>
            <input placeholder="e.g. 192.168.56.10" value={source} onChange={(e) => setSource(e.target.value)} />
          </label>
        </div>
        {data && !data.length ? (
          <Empty>No incidents match these filters.</Empty>
        ) : (
          <div className="scroll">
            <table className="rows">
              <thead>
                <tr><th>Incident</th><th>Severity</th><th>Source</th><th>Attack</th><th>Risk</th><th>Status</th><th className="right">Alerts</th><th>Last alert</th></tr>
              </thead>
              <tbody>
                {data?.map((i) => (
                  <tr key={i.incident_id} onClick={() => (window.location.hash = `#/incidents/${i.incident_id}`)}>
                    <td><a href={`#/incidents/${i.incident_id}`} className="strong-link">#{i.incident_id}</a></td>
                    <td><Badge value={i.severity} kind="sev" /></td>
                    <td className="mono">{i.source_ip}</td>
                    <td>{label(i.attack_type)}</td>
                    <td><Risk score={i.risk_score} /></td>
                    <td><Badge value={i.status} /></td>
                    <td className="right num">{i.alert_count}</td>
                    <td className="muted"><Time value={i.last_alert_at} relative /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}
