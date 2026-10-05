// The opening sequence, about ten seconds, in the manner of a film's security system:
//   a scan line and HUD corners boot → rings draw themselves and turn, a radar sweeps →
//   an armoured cover over the badge splits open in slow segments while the shield reconstructs in slices →
//   targeting brackets close in and the shield locks with a flash →
//   the name decrypts letter by letter out of scrambled glyphs → the screen fades to black onto the app, as Kali's boot does.
// The only text is the app's name. A click or key press skips; with reduced motion it is brief and still.
import { useEffect, useRef, useState } from "react";
import mark from "./assets/cybershield-mark.png";

const STILL = typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
const SHOW_MS = STILL ? 1500 : 8800;
const OUT_MS = STILL ? 300 : 1300; // logo fades to black, then the dark lifts (matches .boot.leaving)

const NAME = "CyberShield";
const GLYPHS = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789#$%&@<>/\\{}[]=+*";
const DECODE_AT = 5000, LEAD = 600, PER_LETTER = 190; // the name decrypts between 5.0 s and about 7.7 s
const STRIPS = 10; // slices the shield is rebuilt from
const WEDGES = 8; // segments of the cover that opens

// The name, as it decrypts: each letter flickers through random glyphs, then locks to the real one.
function useDecodedName() {
  const [letters, setLetters] = useState(() => NAME.split("").map((ch) => (STILL ? { ch, done: true } : { ch: "", done: false })));
  useEffect(() => {
    if (STILL) return;
    const begin = performance.now();
    const timer = setInterval(() => {
      const t = performance.now() - begin - DECODE_AT;
      if (t < 0) return;
      setLetters(NAME.split("").map((ch, i) => {
        if (t < i * 70) return { ch: "", done: false };
        if (t >= LEAD + i * PER_LETTER) return { ch, done: true };
        return { ch: GLYPHS[Math.floor(Math.random() * GLYPHS.length)], done: false };
      }));
      if (t > LEAD + NAME.length * PER_LETTER) clearInterval(timer);
    }, 45);
    return () => clearInterval(timer);
  }, []);
  return letters;
}

function wedge(k) {
  const r = 80, a0 = (k / WEDGES) * Math.PI * 2 - Math.PI / 2, a1 = ((k + 1) / WEDGES) * Math.PI * 2 - Math.PI / 2, mid = (a0 + a1) / 2;
  const p = (a) => `${(Math.cos(a) * r).toFixed(2)} ${(Math.sin(a) * r).toFixed(2)}`;
  return {
    d: `M0 0 L${p(a0)} A${r} ${r} 0 0 1 ${p(a1)} Z`,
    style: { "--dx": `${(Math.cos(mid) * 95).toFixed(1)}px`, "--dy": `${(Math.sin(mid) * 95).toFixed(1)}px`, "--delay": `${2.6 + k * 0.07}s` },
  };
}

export default function Splash({ ready, onDone }) {
  const [shown, setShown] = useState(false);
  const [skipped, setSkipped] = useState(false);
  const [leaving, setLeaving] = useState(false);
  const letters = useDecodedName();

  useEffect(() => {
    const timer = setTimeout(() => setShown(true), SHOW_MS);
    return () => clearTimeout(timer);
  }, []);

  useEffect(() => {
    const skip = () => setSkipped(true);
    window.addEventListener("keydown", skip);
    window.addEventListener("pointerdown", skip);
    return () => {
      window.removeEventListener("keydown", skip);
      window.removeEventListener("pointerdown", skip);
    };
  }, []);

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
      <div className="boot-scan" aria-hidden="true" />
      {["tl", "tr", "bl", "br"].map((c) => <span key={c} className={`boot-corner ${c}`} aria-hidden="true" />)}

      <div className="boot-scene" aria-hidden="true">
        <div className="boot-hud">
          <div className="boot-radar" />
          <svg className="boot-rings" viewBox="-200 -200 400 400">
            <circle className="ring-draw r1" r="140" pathLength="100" />
            <circle className="ring-draw r2" r="92" pathLength="100" />
            <g className="spin cw slow"><circle className="ring-arcs" r="152" pathLength="100" /></g>
            <g className="spin ccw"><circle className="ring-ticks" r="106" pathLength="360" /></g>
            <g className="spin cw"><circle className="ring-split" r="122" pathLength="100" /></g>
            <g className="crosshair">
              <path d="M-198 0H-160M160 0H198M0 -198V-172M0 172V198" />
              <path className="ticks" d="M-190 -4V4M-180 -4V4M-170 -4V4M190 -4V4M180 -4V4M170 -4V4" />
            </g>
          </svg>

          <div className="boot-shield">
            {Array.from({ length: STRIPS }, (_, i) => (
              <img key={i} src={mark} alt="" style={{
                clipPath: `inset(${(i * 100) / STRIPS}% 0 ${100 - ((i + 1) * 100) / STRIPS}% 0)`,
                "--from": `${(i % 2 ? 1 : -1) * (36 + ((i * 37) % 50))}px`,
                "--delay": `${3 + i * 0.14}s`,
              }} />
            ))}
            <span className="boot-beam" />
          </div>
          <span className="boot-pulse" />

          <svg className="boot-cover" viewBox="-200 -200 400 400">
            {Array.from({ length: WEDGES }, (_, k) => {
              const w = wedge(k);
              return <path key={k} className="wedge" d={w.d} style={w.style} />;
            })}
            <circle className="hub" r="14" />
            <g className="reticle">
              <path d="M-100 -70V-100H-70M70 -100H100V-70M100 70V100H70M-70 100H-100V70" />
            </g>
          </svg>
        </div>

        <div className="boot-name">
          {letters.map((l, i) => (
            <span key={i} className={`slot ${i < 5 ? "light" : "heavy"} ${l.done ? "done" : ""}`}>
              <span className="final">{NAME[i]}</span>
              {!l.done && l.ch && <span className="glyph">{l.ch}</span>}
            </span>
          ))}
        </div>
        <span className="boot-underline" />
      </div>
    </div>
  );
}
