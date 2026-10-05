import { useState } from "react";
import { myUserId, patch, post } from "../api.js";
import Icon from "../icons.jsx";
import { Badge, Empty, Notice, Risk, TRANSITIONS, Time, can, label, useData } from "../ui.jsx";

const VERBS = { investigating: "Start investigating", resolved: "Mark resolved", false_positive: "False positive" };

export default function IncidentDetail({ id, user, version }) {
  const { data, error, reload } = useData(`/incidents/${id}`, version);
  const [actionError, setActionError] = useState(null);
  const [done, setDone] = useState(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState("");
  const analyst = can(user, "analyst");

  async function act(work, message) {
    setBusy(true);
    setActionError(null);
    setDone(null);
    try {
      await work();
      setDone(message);
      reload();
      return true;
    } catch (err) {
      setActionError(err.message);
      return false;
    } finally {
      setBusy(false);
    }
  }

  const back = <a href="#/incidents" className="back"><Icon name="back" size={16} />Incidents</a>;
  if (!data) return <>{back}<Notice error={error} /></>;

  const open = data.status === "new" || data.status === "investigating";
  const me = myUserId();
  const mine = data.assigned_to != null && data.assigned_to === me;
  const blocked = data.responses.some((r) => r.action === "block" && r.status === "applied");

  function changeStatus(status) {
    if (status === "false_positive" && !window.confirm("Mark this incident as a false positive? Any block on the source is released, and its traffic is kept as a normal example for training.")) return;
    act(() => patch(`/incidents/${id}`, { status }), `Incident is now ${label(status).toLowerCase()}.`);
  }

  return (
    <>
      {back}
      <header className="page-header incident-head">
        <div>
          <div className="badges"><Badge value={data.severity} kind="sev" /><Badge value={data.status} /></div>
          <h1>{label(data.attack_type)} from <span className="mono">{data.source_ip}</span></h1>
          <p>Incident #{data.incident_id} · opened <Time value={data.opened_at} relative /></p>
        </div>
        {analyst && (
          <div className="page-actions">
            {open && !mine && (
              <button disabled={busy} onClick={() => act(() => patch(`/incidents/${id}`, { take: true }), "You have taken this incident.")}>
                <Icon name="user" size={16} />Take
              </button>
            )}
            {TRANSITIONS[data.status].map((status) => (
              <button key={status} disabled={busy} className={status === "false_positive" ? "ghost" : status === "resolved" ? "primary" : undefined}
                      onClick={() => changeStatus(status)}>
                {status === "resolved" && <Icon name="check" size={16} />}{VERBS[status]}
              </button>
            ))}
            {blocked ? (
              <button disabled={busy} onClick={() => act(() => post("/responses/release", { ip: data.source_ip, incident_id: data.incident_id }), `Released ${data.source_ip}.`)}>
                Release source
              </button>
            ) : (
              open && (
                <button disabled={busy} className="danger" onClick={() => window.confirm(`Block ${data.source_ip}?`) && act(() => post("/responses/block", { ip: data.source_ip, incident_id: data.incident_id }), `Blocked ${data.source_ip}.`)}>
                  <Icon name="blocks" size={16} />Block source
                </button>
              )
            )}
          </div>
        )}
      </header>
      <Notice error={actionError || error} />
      <Notice tone="success">{done}</Notice>

      <div className="grid detail">
        <div className="stack">
          <section className="card flush">
            <div className="card-head pad"><h2>Alerts</h2><span className="muted small">latest {data.alerts.length} of {data.alert_count}</span></div>
            <div className="scroll tall">
              <table>
                <thead><tr><th>Time</th><th>Severity</th><th>Target</th><th className="right">Confidence</th><th>Risk</th></tr></thead>
                <tbody>
                  {[...data.alerts].reverse().map((a) => (
                    <tr key={a.alert_id}>
                      <td className="muted"><Time value={a.created_at} /></td>
                      <td><Badge value={a.severity} kind="sev" /></td>
                      <td className="mono">{a.target_ip ?? <span className="muted">—</span>}</td>
                      <td className="right num">{Math.round(a.confidence * 100)}%</td>
                      <td><Risk score={a.risk_score} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section className="card flush">
            <div className="card-head pad"><h2>Responses</h2></div>
            {data.responses.length ? (
              <div className="scroll">
                <table>
                  <thead><tr><th>Time</th><th>Action</th><th>Address</th><th>Status</th><th>By</th></tr></thead>
                  <tbody>
                    {data.responses.map((r) => (
                      <tr key={r.response_id}>
                        <td className="muted"><Time value={r.created_at} /></td>
                        <td>{label(r.action)}</td>
                        <td className="mono">{r.target_ip}</td>
                        <td><Badge value={r.status} />{r.detail && <div className="muted small">{r.detail}</div>}</td>
                        <td>{r.automatic ? "System" : "Analyst"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : <Empty>No response yet. Critical incidents are answered automatically when automatic response is on.</Empty>}
          </section>
        </div>

        <div className="stack">
          <section className="card">
            <h2>Details</h2>
            <dl className="facts">
              <dt>Risk score</dt><dd><Risk score={data.risk_score} /></dd>
              <dt>Attack</dt><dd>{label(data.attack_type)}</dd>
              <dt>Source</dt><dd className="mono">{data.source_ip}</dd>
              <dt>Alerts</dt><dd className="num">{data.alert_count}</dd>
              <dt>Assigned to</dt><dd>{data.assigned_to == null ? <span className="muted">Nobody</span> : mine ? "You" : `User #${data.assigned_to}`}</dd>
              <dt>Opened</dt><dd><Time value={data.opened_at} /></dd>
              <dt>Last alert</dt><dd><Time value={data.last_alert_at} /></dd>
              <dt>Closed</dt><dd><Time value={data.closed_at} /></dd>
            </dl>
          </section>

          <section className="card">
            <h2>Notes</h2>
            {data.notes.length ? (
              <ul className="notes">
                {data.notes.map((n) => (
                  <li key={n.note_id}>
                    <div className="note-meta"><b>{n.user_id === me ? "You" : `User #${n.user_id}`}</b> · <Time value={n.created_at} relative /></div>
                    <div className="note-body">{n.body}</div>
                  </li>
                ))}
              </ul>
            ) : <Empty>No notes yet.</Empty>}
            {analyst && (
              <form className="note-form" onSubmit={(e) => {
                e.preventDefault();
                act(() => post(`/incidents/${id}/notes`, { body: note }), "Note added.").then((ok) => ok && setNote(""));
              }}>
                <textarea rows={3} maxLength={2000} required placeholder="What did you find?" value={note} onChange={(e) => setNote(e.target.value)} />
                <button disabled={busy || !note.trim()}><Icon name="note" size={16} />Add note</button>
              </form>
            )}
          </section>
        </div>
      </div>
    </>
  );
}
