import { useEffect, useState } from "react";
import { health, post } from "../api.js";
import Icon from "../icons.jsx";
import { Badge, Empty, Notice, PageHeader, Time, can, useData } from "../ui.jsx";

export default function Blocks({ user, version }) {
  const { data, error, reload } = useData("/responses/active", version);
  const [ip, setIp] = useState("");
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState(null);
  const [done, setDone] = useState(null);
  const [dryRun, setDryRun] = useState(false);
  const analyst = can(user, "analyst");

  useEffect(() => {
    health().then((h) => setDryRun(h.firewall === "DryRunFirewall")).catch(() => {});
  }, []);

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

  return (
    <>
      <PageHeader title="Blocks" subtitle="Addresses currently blocked at the firewall, and when each block expires">
        {data && <span className="count-chip">{data.length} active</span>}
      </PageHeader>
      {dryRun && (
        <Notice tone="warn">
          The firewall is in dry-run mode: blocks are recorded but no traffic is stopped. Set FIREWALL_MODE=ssh in .env only inside the laboratory.
        </Notice>
      )}
      <Notice error={actionError || error} />
      <Notice tone="success">{done}</Notice>

      {analyst && (
        <form className="card inline-form block-form" onSubmit={(e) => {
          e.preventDefault();
          const address = ip.trim();
          if (window.confirm(`Block ${address}?`)) act(() => post("/responses/block", { ip: address }), `Blocked ${address}.`).then((ok) => ok && setIp(""));
        }}>
          <label className="field inline">
            <span>Block an address</span>
            <input required placeholder="192.168.56.10" value={ip} onChange={(e) => setIp(e.target.value)} />
          </label>
          <button className="danger" disabled={busy}><Icon name="blocks" size={16} />Block</button>
          <span className="muted small">Addresses outside the monitored network or on the allowlist are refused.</span>
        </form>
      )}

      <div className="card flush">
        {data && !data.length ? (
          <Empty>Nothing is blocked right now.</Empty>
        ) : (
          <div className="scroll">
            <table>
              <thead><tr><th>Address</th><th>Status</th><th>By</th><th>Incident</th><th>Since</th><th>Expires</th>{analyst && <th />}</tr></thead>
              <tbody>
                {data?.map((r) => (
                  <tr key={r.response_id}>
                    <td className="mono strong">{r.target_ip}</td>
                    <td><Badge value={r.status} /></td>
                    <td>{r.automatic ? "System" : "Analyst"}</td>
                    <td>{r.incident_id ? <a href={`#/incidents/${r.incident_id}`}>#{r.incident_id}</a> : <span className="muted">—</span>}</td>
                    <td className="muted"><Time value={r.created_at} relative /></td>
                    <td className="muted"><Time value={r.expires_at} /></td>
                    {analyst && (
                      <td className="right">
                        <button className="small" disabled={busy} onClick={() => act(() => post("/responses/release", { ip: r.target_ip, incident_id: r.incident_id }), `Released ${r.target_ip}.`)}>Release</button>
                      </td>
                    )}
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
