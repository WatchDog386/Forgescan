# Dashboard

The React dashboard for AI-NIDR, built with Vite. Needs Node.js 20.19 or newer.

## Run it

Start the backend first (see the main README), then in a second window (cmd or PowerShell):

```
cd frontend
npm install        # first time only
npm run dev
```

Open http://localhost:5173 and sign in with the account made by `python -m app.cli create-user`.
The dashboard also listens on the network: `npm run dev` prints a `Network:` address for each adapter
(for example http://192.168.56.1:5173 on the laboratory network) that other machines can open. The backend
stays on 127.0.0.1; only the dashboard is reachable, and it forwards requests to the backend.

Vite forwards `/api` and `/health` to the backend at http://127.0.0.1:8000, so the browser sees one
address and no CORS settings are needed. To use a backend somewhere else, set `BACKEND_URL` before
`npm run dev`, for example `set BACKEND_URL=http://192.168.56.5:8000` in cmd or
`$env:BACKEND_URL = "http://192.168.56.5:8000"` in PowerShell.

## Screens

| Screen | What it shows | Who can act |
| --- | --- | --- |
| Overview | Alerts in the last 24 hours by severity and attack type, top sources and targets, sensors, the model and firewall in use, and live events | Everyone |
| Incidents | Incidents with filters; each one shows its alerts, responses and notes | Analysts take incidents, change their state, add notes, block or release the source |
| Alerts | The latest alerts with filters | Everyone |
| Blocks | Active blocks | Analysts block an address or release one |
| Administration | Runtime settings (threshold, automatic response, block length, risk weights), the allowlist and the audit log | Administrators only |
| Sign-in security | Turns on two-step sign-in: scan a QR code with an authenticator app and confirm a code | Everyone, for their own account |

Screens reload by themselves when a live event arrives over `WebSocket /api/v1/ws/events`.

## Design

The dashboard carries the **CyberShield** name and shield badge (`src/assets/`, `public/favicon.png`). The
badge sits on a white tile so its blue keeps its colours on dark backgrounds. The wordmark pairs Poppins
Light ("Cyber") with Playfair Display Black ("Shield"), as in the logo.

The app opens with a splash of about ten seconds on white (`src/Splash.jsx`): the shield glows in inside a
turning ring. It ends as Kali Linux's boot screen does, the logo fading out and then the app fading in. A click
or key press skips it.

The sign-in page is a glowing panel on a dark charcoal background, with faint pixel clouds, traces and
brackets drawn in code (`src/pages/Login.jsx`) so it stays sharp at any size.

The console takes its cues from Wiz, a security console often praised for its UI: a light page with a deep navy sidebar, one blue accent, DM Sans for text,
Poppins for headings and JetBrains Mono for addresses. All fonts are bundled through `@fontsource`, so they
work in a laboratory with no internet. The theme follows the system setting; the button at the bottom of
the sidebar switches between system, light and dark. Severity colours were checked for colour-blind
separation in both themes and always appear with a text label. The colour tokens are at the top of
`src/styles.css`.

## Sessions

The access token is kept in memory only. The backend's refresh cookie gives a new one when it expires
and when the page is reloaded. The dashboard signs out after 30 minutes without a click or key press (FR-06).

## Files

```
src/
  api.js           requests to the backend, tokens and refresh
  ui.jsx           shared pieces: badges, times, risk bars, data loading
  App.jsx          sign-in state, navigation and live events
  pages/           one file per screen
  styles.css       light and dark themes follow the system setting
```

`npm run build` writes a production build to `dist/`.
