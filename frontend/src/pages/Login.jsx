import { useEffect, useRef, useState } from "react";
import { login } from "../api.js";
import Icon from "../icons.jsx";

// Faint pixel clouds on either side of the sign-in panel, drawn once per screen size.
function PixelField() {
  const canvas = useRef(null);
  useEffect(() => {
    const draw = () => {
      const c = canvas.current;
      if (!c) return;
      const ratio = window.devicePixelRatio || 1;
      const w = c.clientWidth, h = c.clientHeight;
      c.width = w * ratio;
      c.height = h * ratio;
      const ctx = c.getContext("2d");
      ctx.scale(ratio, ratio);
      let seed = 7;
      const random = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
      const cell = 9, size = 5, gap = Math.min(250, w * 0.2);
      const colours = ["#3b82f6", "#1d4ed8", "#60a5fa", "#64748b"];
      for (let i = 0; i < 1600; i++) {
        const side = random() < 0.5 ? -1 : 1;
        const reach = Math.pow(random(), 1.6) * (w / 2 - gap);
        const x = w / 2 + side * (gap + reach);
        const spread = h * 0.2 * (1 - reach / (w / 2)) + 20;
        const y = h / 2 + (random() + random() + random() - 1.5) * spread;
        ctx.globalAlpha = (1 - reach / (w / 2 - gap)) * (0.15 + random() * 0.5);
        ctx.fillStyle = colours[Math.floor(random() * colours.length)];
        ctx.fillRect(Math.round(x / cell) * cell, Math.round(y / cell) * cell, size, size);
      }
    };
    draw();
    window.addEventListener("resize", draw);
    return () => window.removeEventListener("resize", draw);
  }, []);
  return <canvas ref={canvas} className="gate-pixels" aria-hidden="true" />;
}

// A circuit trace running out from the panel to a glowing node.
function Trace({ corner }) {
  return (
    <svg className={`gate-trace ${corner}`} viewBox="0 0 260 70" aria-hidden="true">
      <path d="M260 58H178L142 18H22" />
      <circle cx="16" cy="18" r="4.5" />
      <circle cx="260" cy="58" r="3" />
    </svg>
  );
}

function Bracket({ low }) {
  return (
    <svg className={low ? "gate-bracket low" : "gate-bracket"} viewBox="0 0 220 16" aria-hidden="true">
      <path d="M8 15 20 3H86M212 15 200 3H134" />
    </svg>
  );
}

export default function Login({ notice, onSignedIn }) {
  const [step, setStep] = useState("password"); // "code" once the password is right and the account has an authenticator
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState(null);
  const [info, setInfo] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onSignedIn(await login(email.trim(), password, step === "code" ? code : undefined));
    } catch (err) {
      if (err.otpRequired) {
        setStep("code");
        setInfo(err.message);
      } else {
        setError(err.message);
        setCode("");
      }
    } finally {
      setBusy(false);
    }
  }

  function startAgain() {
    setStep("password");
    setCode("");
    setPassword("");
    setInfo(null);
    setError(null);
  }

  const message = error || info || notice;

  return (
    <div className="gate">
      <PixelField />
      <div className="gate-center">
        <div className="gate-frame">
          <Trace corner="tl" /><Trace corner="tr" /><Trace corner="bl" /><Trace corner="br" />
          <form className="gate-card" onSubmit={submit}>
            <Bracket />
            <h1>{step === "code" ? "Verify" : "Login"}</h1>

            {message && <p className={error ? "gate-message error" : "gate-message"} role={error ? "alert" : "status"}>{message}</p>}

            {step === "password" ? (
              <>
                <label className="gate-field">
                  <span className="gate-icon"><Icon name="user" size={16} /></span>
                  <input type="email" autoComplete="username" required placeholder="Email address" aria-label="Email address"
                         value={email} onChange={(e) => setEmail(e.target.value)} autoFocus />
                </label>
                <label className="gate-field">
                  <span className="gate-icon"><Icon name="lock" size={16} /></span>
                  <input type="password" autoComplete="current-password" required placeholder="Password" aria-label="Password"
                         value={password} onChange={(e) => setPassword(e.target.value)} />
                </label>
              </>
            ) : (
              <>
                <p className="gate-who"><Icon name="user" size={14} />{email}</p>
                <label className="gate-field">
                  <span className="gate-icon"><Icon name="key" size={16} /></span>
                  <input className="gate-code" inputMode="numeric" autoComplete="one-time-code" pattern="\d{6}" maxLength={6} required
                         placeholder="000000" aria-label="Authenticator code" autoFocus
                         value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} />
                </label>
              </>
            )}

            <button className="gate-button" disabled={busy}>{busy ? "Checking…" : step === "code" ? "Verify and sign in" : "Sign in"}</button>
            {step === "code" && <button type="button" className="gate-link" onClick={startAgain}>Use a different account</button>}
            <Bracket low />

            <details className="gate-help">
              <summary>No account yet?</summary>
              <p>An administrator creates accounts on the server, in the backend folder:</p>
              <pre>python -m app.cli create-user --name "Your Name" --email you@example.com --role analyst --no-otp</pre>
              <p>Sign in with the email and password. You can then turn on two-step sign-in with an authenticator app from your account.</p>
            </details>
          </form>
        </div>
      </div>
    </div>
  );
}
