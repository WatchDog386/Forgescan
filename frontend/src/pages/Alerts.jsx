import { useState } from "react";
import { ATTACK_TYPES, Badge, Empty, Notice, PageHeader, Risk, SEVERITIES, Select, Time, label, query, useData } from "../ui.jsx";

export default function Alerts({ version }) {
  const [severity, setSeverity] = useState("");
  const [attack, setAttack] = useState("");
  const { data, error } = useData(`/alerts${query({ severity, attack_type: attack, limit: 300 })}`, version);

  return (
    <>
      <PageHeader title="Alerts" subtitle="Every detection the models made, newest first">
        {data && <span className="count-chip">{data.length} shown</span>}
      </PageHeader>
      <Notice error={error} />
      <div className="card flush">
        <div className="toolbar">
          <Select label="Severity" value={severity} onChange={setSeverity} options={SEVERITIES} />
          <Select label="Attack" value={attack} onChange={setAttack} options={ATTACK_TYPES} />
        </div>
        {data && !data.length ? (
          <Empty>No alerts yet. They appear when a sensor sends traffic the models flag.</Empty>
        ) : (
          <div className="scroll">
            <table>
              <thead>
                <tr><th>Time</th><th>Severity</th><th>Source</th><th>Target</th><th>Attack</th><th className="right">Confidence</th><th>Risk</th><th>Incident</th></tr>
              </thead>
              <tbody>
                {data?.map((a) => (
                  <tr key={a.alert_id}>
                    <td className="muted"><Time value={a.created_at} /></td>
                    <td><Badge value={a.severity} kind="sev" /></td>
                    <td className="mono">{a.source_ip}</td>
                    <td className="mono">{a.target_ip ?? <span className="muted">—</span>}</td>
                    <td>{label(a.attack_type)}{a.rule_match && <span className="tag" title="A signature rule also matched">Rule</span>}</td>
                    <td className="right num">{Math.round(a.confidence * 100)}%</td>
                    <td><Risk score={a.risk_score} /></td>
                    <td><a href={`#/incidents/${a.incident_id}`} className="strong-link">#{a.incident_id}</a></td>
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
