import { useMemo, useState } from "react";
import qrcode from "qrcode-generator";
import { post } from "../api.js";
import Icon from "../icons.jsx";
import { Notice, PageHeader } from "../ui.jsx";

// The otpauth:// link as a QR code, drawn as one SVG path so it stays sharp at any size.
function QrCode({ text }) {
  const { size, path } = useMemo(() => {
    const qr = qrcode(0, "M");
    qr.addData(text);
    qr.make();
    const n = qr.getModuleCount();
    let d = "";
    for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (qr.isDark(r, c)) d += `M${c + 4} ${r + 4}h1v1h-1z`;
    return { size: n + 8, path: d };
  }, [text]);
  return (
    <svg className="qr" viewBox={`0 0 ${size} ${size}`} role="img" aria-label="QR code for your authenticator app" shapeRendering="crispEdges">
      <rect width={size} height={size} fill="#fff" />
      <path d={path} fill="#0b1a3d" />
    </svg>
  );
}

export default function Security({ user, onEnabled }) {
  const [setup, setSetup] = useState(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function start() {
    setBusy(true);
    setError(null);
    try {
      setSetup(await post("/auth/otp/setup"));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function confirm(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await post("/auth/otp/confirm", { setup_token: setup.setup_token, code });
      setSetup(null);
      onEnabled();
    } catch (err) {
      setError(err.message);
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader title="Sign-in security" subtitle={`Two-step sign-in for ${user.name}`} />
      <Notice error={error} />

      {user.otp_enabled ? (
        <section className="card security-state on">
          <span className="security-icon"><Icon name="check" size={22} /></span>
          <div>
            <h2>Two-step sign-in is on</h2>
            <p>Every sign-in asks for your password and then the 6-digit code from your authenticator app.</p>
            <p className="muted small">Lost your phone? An administrator can switch it off in the backend folder with
              <code> python -m app.cli reset-otp --email &lt;your email&gt;</code>, and you can set it up again here.</p>
          </div>
        </section>
      ) : !setup ? (
        <section className="card security-state">
          <span className="security-icon"><Icon name="lock" size={22} /></span>
          <div>
            <h2>Two-step sign-in is off</h2>
            <p>Right now your password alone opens this account. Add an authenticator app so a stolen password is not enough.</p>
            <button className="primary" disabled={busy} onClick={start}><Icon name="phone" size={16} />Set up an authenticator app</button>
          </div>
        </section>
      ) : (
        <section className="card setup">
          <ol className="setup-steps">
            <li>
              <b>Install an authenticator app</b>
              <span>Google Authenticator or Microsoft Authenticator, free from your phone's app store.</span>
            </li>
            <li>
              <b>Scan this code</b>
              <span>In the app, tap <b>+</b> and choose <b>Scan a QR code</b>.</span>
              <QrCode text={setup.uri} />
              <span className="muted small">Can't scan? Choose <b>Enter a setup key</b> and type:</span>
              <code className="setup-key">{setup.secret.match(/.{1,4}/g).join(" ")}</code>
            </li>
            <li>
              <b>Enter the 6-digit code the app shows</b>
              <form className="inline-form" onSubmit={confirm}>
                <input className="code-input" inputMode="numeric" autoComplete="one-time-code" pattern="\d{6}" maxLength={6} required
                       placeholder="000000" aria-label="Code from the app" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} />
                <button className="primary" disabled={busy || code.length !== 6}>Turn on</button>
                <button type="button" className="ghost" onClick={() => { setSetup(null); setCode(""); setError(null); }}>Cancel</button>
              </form>
              <span className="muted small">Finish within {setup.expires_minutes} minutes. Nothing changes until the code is accepted.</span>
            </li>
          </ol>
        </section>
      )}
    </>
  );
}
