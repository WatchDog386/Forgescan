import { useEffect, useState } from "react";
import { del, post, put } from "../api.js";
import { Empty, Notice, PageHeader, Time, useData } from "../ui.jsx";

// The settings in backend/app/runtime.py, with their allowed ranges.
const FIELDS = [
  { key: "detection_threshold", name: "Detection threshold", min: 0.5, max: 0.99, step: 0.01, help: "How sure a model must be before it raises an alert." },
  { key: "block_minutes", name: "Block length (minutes)", min: 1, max: 1440, step: 1, help: "How long a block lasts before it expires." },
  { key: "max_active_blocks", name: "Most active blocks", min: 1, max: 500, step: 1, help: "Automatic blocks stop when this many are active." },
  { key: "weight_confidence", name: "Risk weight: confidence", min: 0, max: 1, step: 0.005 },
  { key: "weight_attack", name: "Risk weight: attack type", min: 0, max: 1, step: 0.005 },
  { key: "weight_spread", name: "Risk weight: targets reached", min: 0, max: 1, step: 0.005 },
  { key: "weight_repeat", name: "Risk weight: repeat offender", min: 0, max: 1, step: 0.005 },
];

function Settings() {
  const { data, error, reload } = useData("/settings", 0);
  const [form, setForm] = useState(null);
  const [saveError, setSaveError] = useState(null);
  const [done, setDone] = useState(null);

  useEffect(() => {
    if (data) setForm(data);
  }, [data]);

  if (!form) return <Notice error={error} />;

  async function save(e) {
    e.preventDefault();
    const changed = {};
    for (const [key, value] of Object.entries(form)) {
      const typed = typeof data[key] === "boolean" ? value : Number(value);
      if (typed !== data[key]) changed[key] = typed;
    }
    if (!Object.keys(changed).length) return setDone("Nothing to save.");
    if (changed.auto_response === true && !window.confirm("Switch on automatic response? The system will block the source of critical incidents by itself. Do this only inside the laboratory.")) return;
    setSaveError(null);
    setDone(null);
    try {
      await put("/settings", changed);
      setDone("Settings saved.");
      reload();
    } catch (err) {
      setSaveError(err.message);
    }
  }

  return (
    <form className="card" onSubmit={save}>
      <h2>Detection and response</h2>
      <Notice error={saveError || error} />
      <Notice tone="success">{done}</Notice>
      <label className="toggle">
        <input type="checkbox" checked={form.auto_response} onChange={(e) => setForm({ ...form, auto_response: e.target.checked })} />
        <span>
          <b>Automatic response</b>
          <span className="muted small">Block the source of critical incidents without waiting for an analyst. Keep it off outside the laboratory.</span>
        </span>
      </label>
      <div className="settings">
        {FIELDS.map((f) => (
          <label className="field" key={f.key}>
            <span>{f.name}</span>
            <input type="number" min={f.min} max={f.max} step={f.step} required value={form[f.key]}
                   onChange={(e) => setForm({ ...form, [f.key]: e.target.value })} />
            {f.help && <small className="muted">{f.help}</small>}
          </label>
        ))}
      </div>
      <div className="actions">
        <button className="primary">Save settings</button>
        <button type="button" className="ghost" onClick={() => { setForm(data); setDone(null); setSaveError(null); }}>Undo changes</button>
      </div>
    </form>
  );
}

function Allowlist() {
  const { data, error, reload } = useData("/allowlist", 0);
  const [range, setRange] = useState("");
  const [reason, setReason] = useState("");
  const [actionError, setActionError] = useState(null);

  async function act(work) {
    setActionError(null);
    try {
      await work();
      reload();
      return true;
    } catch (err) {
      setActionError(err.message);
      return false;
    }
  }

  return (
    <section className="card">
      <div className="card-head"><h2>Allowlist</h2><span className="muted small">never blocked</span></div>
      <Notice error={actionError || error} />
      {data?.length ? (
        <table>
          <thead><tr><th>Address or range</th><th>Reason</th><th /></tr></thead>
          <tbody>
            {data.map((e) => (
              <tr key={e.entry_id}>
                <td className="mono">{e.ip_range}</td>
                <td>{e.reason}</td>
                <td className="right">
                  <button className="small ghost" onClick={() => window.confirm(`Remove ${e.ip_range} from the allowlist?`) && act(() => del(`/allowlist/${e.entry_id}`))}>Remove</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : data && <Empty>No trusted addresses yet. Add your gateway and servers so they are never blocked.</Empty>}
      <form className="inline-form" onSubmit={(e) => {
        e.preventDefault();
        act(() => post("/allowlist", { ip_range: range.trim(), reason: reason.trim() })).then((ok) => ok && (setRange(""), setReason("")));
      }}>
        <input required placeholder="192.168.56.1 or 192.168.56.0/28" value={range} onChange={(e) => setRange(e.target.value)} />
        <input required minLength={3} maxLength={200} placeholder="Reason, e.g. lab gateway" value={reason} onChange={(e) => setReason(e.target.value)} />
        <button className="primary">Add</button>
      </form>
    </section>
  );
}

function AuditLog() {
  const { data, error, reload } = useData("/audit?limit=200", 0);
  return (
    <section className="card flush">
      <div className="card-head pad">
        <h2>Audit log <span className="muted small">latest 200</span></h2>
        <button className="small ghost" onClick={reload}>Refresh</button>
      </div>
      <Notice error={error} />
      <div className="scroll tall">
        <table>
          <thead><tr><th>Time</th><th>Action</th><th>User</th><th>Detail</th></tr></thead>
          <tbody>
            {data?.map((r) => (
              <tr key={r.entry_id}>
                <td><Time value={r.logged_at} /></td>
                <td className="mono">{r.action}</td>
                <td>{r.user_id == null ? <span className="muted">System</span> : `#${r.user_id}`}</td>
                <td className="mono small detail">{r.detail ? Object.entries(r.detail).map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : v}`).join("  ") : ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export default function Admin() {
  return (
    <>
      <PageHeader title="Administration" subtitle="Detection settings, trusted addresses and the audit trail" />
      <div className="grid two">
        <Settings />
        <Allowlist />
      </div>
      <AuditLog />
    </>
  );
}
