// The CyberShield badge and wordmark. The badge sits on a white tile so the blue shield
// keeps its colours on the navy sidebar and the dark sign-in page.
import mark from "./assets/cybershield-mark.png";

export function Badge({ size = 36 }) {
  return (
    <span className="logo-tile" style={{ width: size, height: size }}>
      <img src={mark} alt="" width={size} height={size} />
    </span>
  );
}

export function Wordmark({ tagline }) {
  return (
    <span className="wordmark">
      <span className="wordmark-name"><span>Cyber</span><b>Shield</b></span>
      {tagline && <small>{tagline}</small>}
    </span>
  );
}
