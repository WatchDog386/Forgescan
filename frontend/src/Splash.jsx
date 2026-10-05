// The opening screen, on white, about ten seconds and no text: the shield glows in inside a turning ring and
// pulses. Then it ends the way Kali Linux's boot screen does: the logo fades out and the app fades in. A click or key press skips the wait. With reduced motion it is brief and still.
import { useEffect, useRef, useState } from "react";
import mark from "./assets/cybershield-mark.png";

const STILL = typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
const SHOW_MS = STILL ? 1500 : 8800; // the logo on screen
const OUT_MS = STILL ? 300 : 1300; // fade to black, then fade into the app (matches .boot.leaving)

export default function Splash({ ready, onDone }) {
  const [shown, setShown] = useState(false);
  const [skipped, setSkipped] = useState(false);
  const [leaving, setLeaving] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => setShown(true), SHOW_MS);
    return () => clearTimeout(timer);
  }, []);

  // A click or key press skips the wait.
  useEffect(() => {
    const skip = () => setSkipped(true);
    window.addEventListener("keydown", skip);
    window.addEventListener("pointerdown", skip);
    return () => {
      window.removeEventListener("keydown", skip);
      window.removeEventListener("pointerdown", skip);
    };
  }, []);

  // Leave once the app knows whether someone is signed in, and the splash has had its time.
  useEffect(() => {
    if (ready && (shown || skipped)) setLeaving(true);
  }, [ready, shown, skipped]);

  const done = useRef(onDone);
  done.current = onDone;
  useEffect(() => {
    if (!leaving) return;
    const timer = setTimeout(() => done.current(), OUT_MS);
    return () => clearTimeout(timer);
  }, [leaving]);

  return (
    <div className={["boot", STILL && "still", leaving && "leaving"].filter(Boolean).join(" ")} role="status" aria-label="CyberShield is starting">
      <div className="boot-stage" aria-hidden="true">
        <div className="boot-ring" />
        <div className="boot-logo">
          <img src={mark} alt="" />
          <span className="boot-shine" style={{ WebkitMaskImage: `url(${mark})`, maskImage: `url(${mark})` }} />
        </div>
      </div>
    </div>
  );
}
