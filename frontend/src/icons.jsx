// Line icons drawn on a 24px grid (2px strokes), so they sit evenly beside text.
const PATHS = {
  shield: <path d="M12 3 4.5 6v5.5c0 4.6 3.1 8.4 7.5 9.5 4.4-1.1 7.5-4.9 7.5-9.5V6z" />,
  overview: <><rect x="3.5" y="3.5" width="7" height="8" rx="1.5" /><rect x="13.5" y="3.5" width="7" height="5" rx="1.5" /><rect x="13.5" y="11.5" width="7" height="9" rx="1.5" /><rect x="3.5" y="14.5" width="7" height="6" rx="1.5" /></>,
  incidents: <><path d="M12 3 4.5 6v5.5c0 4.6 3.1 8.4 7.5 9.5 4.4-1.1 7.5-4.9 7.5-9.5V6z" /><path d="M12 8.5v4" /><path d="M12 15.8v.2" /></>,
  alerts: <><path d="M6 16.5V11a6 6 0 0 1 12 0v5.5l1.5 2h-15z" /><path d="M10 21h4" /></>,
  blocks: <><circle cx="12" cy="12" r="8.5" /><path d="m6 6 12 12" /></>,
  admin: <><path d="M4 7h10M18 7h2M4 17h4M12 17h8" /><circle cx="16" cy="7" r="2" /><circle cx="10" cy="17" r="2" /></>,
  sensor: <><rect x="3.5" y="4" width="17" height="6.5" rx="1.5" /><rect x="3.5" y="13.5" width="17" height="6.5" rx="1.5" /><path d="M7 7.2h.01M7 16.8h.01" /></>,
  warning: <><path d="M10.3 4.3 2.8 17.5A2 2 0 0 0 4.5 20.5h15a2 2 0 0 0 1.7-3L13.7 4.3a2 2 0 0 0-3.4 0z" /><path d="M12 9.5v4M12 16.8v.2" /></>,
  pulse: <path d="M3 12h4l2.5-6 5 12 2.5-6h4" />,
  cpu: <><rect x="6" y="6" width="12" height="12" rx="2" /><path d="M9.5 9.5h5v5h-5zM9 2.5v3M15 2.5v3M9 18.5v3M15 18.5v3M2.5 9h3M2.5 15h3M18.5 9h3M18.5 15h3" /></>,
  firewall: <><rect x="3.5" y="4.5" width="17" height="15" rx="1.5" /><path d="M3.5 9.5h17M3.5 14.5h17M9 4.5v5M15 9.5v5M9 14.5v5" /></>,
  sun: <><circle cx="12" cy="12" r="4" /><path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4" /></>,
  moon: <path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z" />,
  system: <><rect x="3" y="4" width="18" height="12" rx="2" /><path d="M8 20h8M12 16v4" /></>,
  logout: <><path d="M14 4h4.5A1.5 1.5 0 0 1 20 5.5v13a1.5 1.5 0 0 1-1.5 1.5H14" /><path d="M10 8l-4 4 4 4M6 12h10" /></>,
  back: <path d="M15 5l-7 7 7 7" />,
  check: <path d="m5 12.5 4.5 4.5L19 7.5" />,
  user: <><circle cx="12" cy="8.5" r="3.5" /><path d="M5 20a7 7 0 0 1 14 0" /></>,
  lock: <><rect x="5" y="10.5" width="14" height="10" rx="2" /><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" /></>,
  key: <><circle cx="8" cy="15" r="4" /><path d="m11 12 8.5-8.5M16.5 6.5l2.5 2.5M14 9l2 2" /></>,
  phone: <><rect x="7" y="2.5" width="10" height="19" rx="2" /><path d="M11 18.5h2" /></>,
  note: <><path d="M5 4.5h14v11l-4.5 4.5H5z" /><path d="M14.5 20v-4.5H19M8.5 9h7M8.5 12.5h4" /></>,
  plus: <path d="M12 5v14M5 12h14" />,
  graph: <><circle cx="6" cy="6" r="2.5" /><circle cx="18" cy="9" r="2.5" /><circle cx="9" cy="18" r="2.5" /><path d="m8.3 7.1 7.4 1.1M7.4 15.7l-1-7.3M10.9 16.4l5.4-5.5" /></>,
};

export default function Icon({ name, size = 18, className }) {
  return (
    <svg className={`icon ${className ?? ""}`} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
         strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {PATHS[name]}
    </svg>
  );
}
