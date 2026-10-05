// Small pieces shared by the screens.
import { useEffect, useState } from "react";
import { get } from "./api.js";

export const ROLES = ["viewer", "analyst", "administrator"];
export const SEVERITIES = ["low", "medium", "high", "critical"];
export const ATTACK_TYPES = ["port_scan", "brute_force", "dos", "anomaly"];
export const INCIDENT_STATES = ["new", "investigating", "resolved", "false_positive"];
// The same moves the backend allows (backend/app/services/incidents.py).
export const TRANSITIONS = { new: ["investigating", "false_positive"], investigating: ["resolved", "false_positive"], resolved: [], false_positive: [] };

const WORDS = {
  port_scan: "Port scan", brute_force: "Brute force", dos: "Denial of service", anomaly: "Anomaly",
  new: "New", investigating: "Investigating", resolved: "Resolved", false_positive: "False positive",
  applied: "Applied", failed: "Failed", refused: "Refused", dry_run: "Dry run", expired: "Expired", reversed: "Reversed",
  block: "Block", release: "Release", notify: "Notify",
  low: "Low", medium: "Medium", high: "High", critical: "Critical",
  viewer: "Viewer", analyst: "Analyst", administrator: "Administrator",
};

export const label = (value) => WORDS[value] ?? String(value ?? "").replace(/_/g, " ");

export const can = (user, minimum) => ROLES.indexOf(user?.role) >= ROLES.indexOf(minimum);

// A pill with a coloured mark; the text stays in the normal ink so it reads in every theme.
export function Badge({ value, kind = "status" }) {
  return <span className={`badge ${kind}-${value}`}><i />{label(value)}</span>;
}

// One clock for every relative time on the page, so "2 min ago" stays true without a timer per row.
const listeners = new Set();
setInterval(() => listeners.forEach((fn) => fn(Date.now())), 30_000);
function useNow() {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    listeners.add(setNow);
    return () => listeners.delete(setNow);
  }, []);
  return now;
}

export function ago(value, now = Date.now()) {
  const seconds = Math.max(0, Math.round((now - new Date(value)) / 1000));
  if (seconds < 45) return "just now";
  if (seconds < 3600) return `${Math.round(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} h ago`;
  return `${Math.round(seconds / 86400)} d ago`;
}

export function Time({ value, relative = false }) {
  const now = useNow();
  if (!value) return <span className="muted">—</span>;
  const date = new Date(value);
  const full = date.toLocaleString();
  if (relative) return <time dateTime={value} title={full}>{ago(value, now)}</time>;
  return <time dateTime={value} title={full}>{date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" })}</time>;
}

export function Risk({ score }) {
  // The same bands as backend/app/engine/risk.py
  const level = score >= 75 ? "critical" : score >= 50 ? "high" : score >= 25 ? "medium" : "low";
  return (
    <span className="risk" title={`Risk ${score} of 100 (${label(level)})`}>
      <span className="risk-bar"><span className={`fill-${level}`} style={{ width: `${score}%` }} /></span>
      <span className="num">{score}</span>
    </span>
  );
}

export function PageHeader({ title, subtitle, children }) {
  return (
    <header className="page-header">
      <div>
        <h1>{title}</h1>
        {subtitle && <p>{subtitle}</p>}
      </div>
      {children && <div className="page-actions">{children}</div>}
    </header>
  );
}

export function Notice({ error, children, tone }) {
  if (!error && !children) return null;
  return <div className={`notice ${error ? "error" : tone ?? ""}`} role={error ? "alert" : "status"}>{error || children}</div>;
}

export function Empty({ children }) {
  return <div className="empty">{children}</div>;
}

export function Select({ label: text, value, onChange, options }) {
  return (
    <label className="field inline">
      <span>{text}</span>
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">All</option>
        {options.map((o) => <option key={o} value={o}>{label(o)}</option>)}
      </select>
    </label>
  );
}

// Loads a backend path, and loads it again whenever `version` changes (a live event arrived).
export function useData(path, version) {
  const [state, setState] = useState({ data: null, error: null, loading: true });
  const [again, setAgain] = useState(0);
  useEffect(() => {
    let current = true;
    setState((s) => ({ ...s, loading: true }));
    get(path)
      .then((data) => current && setState({ data, error: null, loading: false }))
      .catch((error) => current && setState((s) => ({ data: s.data, error: error.message, loading: false })));
    return () => {
      current = false;
    };
  }, [path, version, again]);
  return { ...state, reload: () => setAgain((n) => n + 1) };
}

export function query(params) {
  const filled = Object.entries(params).filter(([, v]) => v !== "" && v != null);
  return filled.length ? `?${new URLSearchParams(filled)}` : "";
}
