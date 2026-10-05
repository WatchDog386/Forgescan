import { useCallback, useEffect, useState } from "react";
import { getToken, logout, onSignedOut, refresh } from "./api.js";
import { can, label } from "./ui.jsx";
import Icon from "./icons.jsx";
import Login from "./pages/Login.jsx";
import Overview from "./pages/Overview.jsx";
import Incidents from "./pages/Incidents.jsx";
import IncidentDetail from "./pages/IncidentDetail.jsx";
import Alerts from "./pages/Alerts.jsx";
import Blocks from "./pages/Blocks.jsx";
import Admin from "./pages/Admin.jsx";
import Security from "./pages/Security.jsx";
import Splash from "./Splash.jsx";
import { Badge, Wordmark } from "./brand.jsx";

const SESSION_MINUTES = 30; // a session ends after 30 minutes without activity (FR-06)

// Light, dark, or follow the system. Remembered in this browser only.
const THEMES = ["system", "light", "dark"];
function useTheme() {
  const [theme, setTheme] = useState(() => {
    try {
      return THEMES.includes(localStorage.getItem("theme")) ? localStorage.getItem("theme") : "system";
    } catch {
      return "system";
    }
  });
  useEffect(() => {
    if (theme === "system") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", theme);
    try {
      localStorage.setItem("theme", theme);
    } catch {
      // storage blocked; the choice lasts until the page closes
    }
  }, [theme]);
  return [theme, () => setTheme(THEMES[(THEMES.indexOf(theme) + 1) % THEMES.length])];
}

const person = (session) => ({ name: session.name, role: session.role, otp_enabled: session.otp_enabled });

// Screens are addressed by the part of the URL after #, e.g. #/incidents/12.
function useRoute() {
  const read = () => window.location.hash.replace(/^#\/?/, "").split("/");
  const [route, setRoute] = useState(read);
  useEffect(() => {
    const changed = () => setRoute(read());
    window.addEventListener("hashchange", changed);
    return () => window.removeEventListener("hashchange", changed);
  }, []);
  return route;
}

export default function App() {
  const [user, setUser] = useState(undefined); // undefined while checking for a session to continue
  const [booted, setBooted] = useState(false); // the opening splash has finished
  const [notice, setNotice] = useState(null);
  const [live, setLive] = useState(false);
  const [events, setEvents] = useState([]);
  const [version, setVersion] = useState(0); // goes up after live events, so screens load again
  const [page, id] = useRoute();
  const [theme, nextTheme] = useTheme();

  const signOut = useCallback(async (reason = null) => {
    await logout();
    setNotice(reason);
    setUser(null);
    setEvents([]);
  }, []);

  // Continue the session after a page reload, if the refresh cookie is still good.
  useEffect(() => {
    onSignedOut(() => {
      setNotice("Your session has ended. Sign in again.");
      setUser(null);
    });
    refresh()
      .then((session) => setUser(session ? person(session) : null))
      .catch(() => setUser(null));
  }, []);

  // Sign out after 30 minutes without a click or key press.
  useEffect(() => {
    if (!user) return;
    let last = Date.now();
    const active = () => (last = Date.now());
    window.addEventListener("pointerdown", active);
    window.addEventListener("keydown", active);
    const timer = setInterval(() => {
      if (Date.now() - last > SESSION_MINUTES * 60_000) signOut(`You were signed out after ${SESSION_MINUTES} minutes without activity.`);
    }, 30_000);
    return () => {
      window.removeEventListener("pointerdown", active);
      window.removeEventListener("keydown", active);
      clearInterval(timer);
    };
  }, [user, signOut]);

  // Live alerts, incidents and responses over WebSocket, reconnecting if the connection drops.
  useEffect(() => {
    if (!user) return;
    let socket, retry, reload;
    let stopped = false;
    let count = 0;
    const connect = () => {
      const scheme = window.location.protocol === "https:" ? "wss" : "ws";
      socket = new WebSocket(`${scheme}://${window.location.host}/api/v1/ws/events?token=${encodeURIComponent(getToken() ?? "")}`);
      socket.onopen = () => setLive(true);
      socket.onmessage = (message) => {
        const event = { ...JSON.parse(message.data), key: ++count, received: new Date().toISOString() };
        setEvents((list) => [event, ...list].slice(0, 100));
        // A burst of events reloads the open screen once a second at most.
        reload ??= setTimeout(() => {
          reload = null;
          setVersion((v) => v + 1);
        }, 1000);
      };
      socket.onclose = () => {
        setLive(false);
        if (stopped) return;
        retry = setTimeout(async () => {
          try {
            // The access token may have expired; get a fresh one before reconnecting.
            if (!(await refresh())) return signOut("Your session has ended. Sign in again.");
          } catch {
            // the backend is not reachable yet; try again
          }
          if (!stopped) connect();
        }, 3000);
      };
    };
    connect();
    return () => {
      stopped = true;
      clearTimeout(retry);
      clearTimeout(reload);
      socket.close();
    };
  }, [user, signOut]);

  const splash = !booted && <Splash ready={user !== undefined} onDone={() => setBooted(true)} />;
  if (user === undefined) return splash;
  if (!user) {
    return <>{splash}<Login notice={notice} onSignedIn={(session) => { setNotice(null); setUser(person(session)); }} /></>;
  }

  const groups = [
    ["Monitor", [["", "Overview", "overview"], ["alerts", "Alerts", "alerts"]]],
    ["Respond", [["incidents", "Incidents", "incidents"], ["blocks", "Blocks", "blocks"]]],
  ];
  if (can(user, "administrator")) groups.push(["Manage", [["admin", "Administration", "admin"]]]);
  groups.push(["Account", [["security", "Sign-in security", "lock"]]]);
  const current = groups.some(([, items]) => items.some(([path]) => path === page)) ? page : "";

  let screen;
  if (current === "incidents" && id) screen = <IncidentDetail key={id} id={id} user={user} version={version} />;
  else if (current === "incidents") screen = <Incidents version={version} />;
  else if (current === "alerts") screen = <Alerts version={version} />;
  else if (current === "blocks") screen = <Blocks user={user} version={version} />;
  else if (current === "admin") screen = <Admin />;
  else if (current === "security") screen = <Security user={user} onEnabled={() => setUser({ ...user, otp_enabled: true })} />;
  else screen = <Overview version={version} events={events} live={live} />;

  const initials = user.name.split(/\s+/).map((w) => w[0]).slice(0, 2).join("").toUpperCase();

  return (
    <>
    {splash}
    <div className="app">
      <aside className="sidebar">
        <a className="brand" href="#/">
          <Badge size={38} />
          <Wordmark tagline="Network defence" />
        </a>
        <nav>
          {groups.map(([group, items]) => (
            <div className="nav-group" key={group}>
              <span className="nav-label">{group}</span>
              {items.map(([path, name, icon]) => (
                <a key={path} href={`#/${path}`} className={current === path ? "active" : undefined} aria-current={current === path ? "page" : undefined}>
                  <Icon name={icon} />{name}
                </a>
              ))}
            </div>
          ))}
        </nav>
        <div className="sidebar-foot">
          <span className={live ? "live on" : "live"} title={live ? "Receiving live events" : "Live events disconnected; reconnecting"}>
            <i />{live ? "Live" : "Reconnecting"}
          </span>
          <button className="icon-button" onClick={nextTheme} title={`Theme: ${theme} (click to change)`} aria-label={`Theme: ${theme}`}>
            <Icon name={theme === "light" ? "sun" : theme === "dark" ? "moon" : "system"} />
          </button>
          <div className="me">
            <span className="avatar">{initials}</span>
            <span className="me-text">{user.name}<small>{label(user.role)}</small></span>
            <button className="icon-button" onClick={() => signOut()} title="Sign out" aria-label="Sign out"><Icon name="logout" /></button>
          </div>
        </div>
      </aside>
      <main className="content">
        {!user.otp_enabled && current === "" && (
          <div className="notice warn nudge">
            <Icon name="lock" size={16} />
            <span>Two-step sign-in is off: your password alone opens this account.</span>
            <a href="#/security">Set it up</a>
          </div>
        )}
        {screen}
      </main>
    </div>
    </>
  );
}
