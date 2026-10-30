import { useEffect, useRef, useState } from "react";

// A sphere drawn as thousands of tiny stippled squares: every dot is a node, and the
// bright ones are joined into one attack path. The dither (a dot is kept only when a
// fixed random number for it falls under the light at that point) is what gives the
// grain, and bucketing the dots by colour and opacity keeps a frame to a few dozen
// fill calls instead of ten thousand.

const LIGHT = (() => { const v = [-0.42, -0.68, 0.6]; const m = Math.hypot(v[0], v[1], v[2]); return [v[0] / m, v[1] / m, v[2] / m]; })();

// the seven named nodes sit at fixed points on the shell, as [azimuth, polar]
const NODES = [
  { a: -0.55, p: 1.95, crit: false },
  { a: 0.15, p: 1.45, crit: false },
  { a: 0.85, p: 1.75, crit: false },
  { a: 1.55, p: 1.2, crit: true },
  { a: -1.15, p: 1.3, crit: false },
  { a: -0.35, p: 0.85, crit: false },
  { a: 0.55, p: 2.35, crit: false },
];
const EDGES = [[0, 1], [1, 2], [2, 3], [0, 4], [4, 5], [5, 1], [6, 0], [2, 6]];
const PATH = [4, 0, 1, 2, 3];
const NODE_V = NODES.map(({ a, p }) => [Math.sin(p) * Math.cos(a), Math.cos(p), Math.sin(p) * Math.sin(a)]);

function smooth(a, b, x) {
  const t = Math.min(1, Math.max(0, (x - a) / (b - a)));
  return t * t * (3 - 2 * t);
}

function rgb(hex) {
  const h = hex.replace("#", "");
  return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)];
}

function ramp(from, to, steps) {
  const out = [];
  for (let i = 0; i < steps; i++) {
    const t = steps === 1 ? 0 : i / (steps - 1);
    const c = [0, 1, 2].map((k) => Math.round(from[k] + (to[k] - from[k]) * t));
    out.push("rgb(" + c[0] + "," + c[1] + "," + c[2] + ")");
  }
  return out;
}

// dots go into a colour-by-opacity grid, and each bucket is painted in a single pass
function buckets(colors, alphas) {
  const cells = Array.from({ length: colors * alphas }, () => []);
  return {
    add(c, a, x, y, s) { cells[c * alphas + a].push(x, y, s); },
    flush(ctx, palette) {
      for (let c = 0; c < colors; c++) {
        for (let a = 0; a < alphas; a++) {
          const cell = cells[c * alphas + a];
          if (!cell.length) continue;
          ctx.fillStyle = palette[c];
          ctx.globalAlpha = (a + 1) / alphas;
          for (let i = 0; i < cell.length; i += 3) {
            const s = cell[i + 2];
            ctx.fillRect(cell[i] - s / 2, cell[i + 1] - s / 2, s, s);
          }
          cell.length = 0;
        }
      }
      ctx.globalAlpha = 1;
    },
  };
}

// an even spread over the shell, jittered so the spiral that built it cannot be seen
function shell(count) {
  const p = new Float32Array(count * 5);
  const golden = Math.PI * (3 - Math.sqrt(5));
  let seed = 0x9e3779b9;
  const rnd = () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 4294967296; };
  for (let i = 0; i < count; i++) {
    const y = 1 - (i / (count - 1)) * 2;
    const r = Math.sqrt(Math.max(0, 1 - y * y));
    const th = golden * i + (rnd() - 0.5) * 0.35;
    const k = i * 5;
    p[k] = Math.cos(th) * r;
    p[k + 1] = y + (rnd() - 0.5) * 0.012;
    p[k + 2] = Math.sin(th) * r;
    p[k + 3] = 0.985 + rnd() * 0.03;
    p[k + 4] = rnd();
  }
  return p;
}

export default function StippleOrb({
  accent = "#2dd4bf",
  critical = "#f87171",
  dark = true,
  label = "An organisation drawn as a graph: every dot is a node, and the bright path is one route an attacker can take to a critical asset.",
}) {
  const host = useRef(null);
  const cv = useRef(null);
  const [touched, setTouched] = useState(false);

  useEffect(() => {
    const box = host.current;
    const canvas = cv.current;
    if (!box || !canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const reduced = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)").matches : false;
    const acc = rgb(accent);
    const crit = rgb(critical);
    const base = dark ? [58, 76, 82] : [196, 201, 203];
    // the lit end of the ramp has to move away from the paper: lighter on a dark
    // page, deeper on a pale one, or the brightest dots are the ones that vanish
    const hi = dark
      ? [Math.min(255, acc[0] + 46), Math.min(255, acc[1] + 34), Math.min(255, acc[2] + 34)]
      : [Math.round(acc[0] * 0.62), Math.round(acc[1] * 0.68), Math.round(acc[2] * 0.68)];
    const palette = ramp(base, acc, 14).concat(ramp(acc, hi, 4).slice(1));
    const bin = buckets(palette.length, 5);

    let w = 0, h = 0, dpr = 1, count = 0, pts = shell(6000);

    const measure = () => {
      const r = box.getBoundingClientRect();
      dpr = Math.min(2, window.devicePixelRatio || 1);
      w = Math.max(1, Math.round(r.width));
      h = Math.max(1, Math.round(r.height));
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      canvas.style.width = w + "px";
      canvas.style.height = h + "px";
      const want = Math.round(Math.min(14000, Math.max(4200, (w * h) / 26)));
      if (want !== count) { count = want; pts = shell(count); }
    };
    measure();

    const st = { yaw: 0.6, pitch: -0.22, vel: 0.1, auto: reduced ? 0 : 0.1, drag: false, moved: 0, lx: 0, ly: 0, lt: 0, px: -1e4, py: -1e4, hover: 0, hoverTo: 0, ripples: [] };
    let last = performance.now();
    let raf = 0, running = false;

    // the shared rotate-and-project step, reused by the dots and by the graph overlay
    const v = [0, 0, 0];
    let cy = 1, sy = 0, cp = 1, sp = 0;
    const project = (x, y, z) => {
      const x1 = x * cy + z * sy;
      const z1 = z * cy - x * sy;
      v[0] = x1;
      v[1] = y * cp - z1 * sp;
      v[2] = y * sp + z1 * cp;
    };

    const draw = (now) => {
      const dt = Math.min(0.05, (now - last) / 1000);
      last = now;
      if (!st.drag) { st.vel += (st.auto - st.vel) * Math.min(1, dt * 1.6); st.yaw += st.vel * dt; }
      st.hover += (st.hoverTo - st.hover) * Math.min(1, dt * 6);
      st.ripples = st.ripples.filter((r) => now - r.t < 1600);

      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);

      const R = Math.min(w, h) * 0.43;
      const ox = w / 2, oy = h / 2;
      cy = Math.cos(st.yaw); sy = Math.sin(st.yaw);
      cp = Math.cos(st.pitch); sp = Math.sin(st.pitch);
      const reach = Math.max(70, R * 0.38), reach2 = reach * reach;
      const unitSize = Math.max(1.05, R / 205);

      // the atmosphere behind the shell, offset toward the light
      const gx = ox + LIGHT[0] * R * 0.5, gy = oy + LIGHT[1] * R * 0.5;
      const reachOut = Math.min(w, h) / 2;
      const glow = ctx.createRadialGradient(gx, gy, 0, gx, gy, reachOut);
      glow.addColorStop(0, "rgba(" + acc[0] + "," + acc[1] + "," + acc[2] + "," + (dark ? 0.26 : 0.07) + ")");
      glow.addColorStop(1, "rgba(" + acc[0] + "," + acc[1] + "," + acc[2] + ",0)");
      ctx.fillStyle = glow;
      ctx.beginPath();
      ctx.arc(ox, oy, reachOut, 0, Math.PI * 2);
      ctx.fill();

      // graph nodes, projected once and reused for the edges and the pulse
      const np = NODE_V.map((nv) => { project(nv[0], nv[1], nv[2]); return [ox + v[0] * R, oy + v[1] * R, v[2]]; });

      const arc = (i, j) => {
        const a = NODE_V[i], b = NODE_V[j];
        ctx.beginPath();
        for (let k = 0; k <= 14; k++) {
          const t = k / 14;
          const x = a[0] + (b[0] - a[0]) * t, y = a[1] + (b[1] - a[1]) * t, z = a[2] + (b[2] - a[2]) * t;
          const m = Math.hypot(x, y, z) || 1;
          project(x / m, y / m, z / m);
          const sx = ox + v[0] * R, sy2 = oy + v[1] * R;
          if (k === 0) ctx.moveTo(sx, sy2); else ctx.lineTo(sx, sy2);
        }
        ctx.stroke();
      };

      const paintGraph = (front) => {
        ctx.lineWidth = Math.max(1, R / 240);
        for (let e = 0; e < EDGES.length; e++) {
          const i = EDGES[e][0], j = EDGES[e][1];
          const depth = (np[i][2] + np[j][2]) / 2;
          if ((depth >= 0) !== front) continue;
          const a = front ? 0.28 + depth * 0.3 : 0.1;
          ctx.strokeStyle = "rgba(" + acc[0] + "," + acc[1] + "," + acc[2] + "," + a + ")";
          arc(i, j);
        }
        for (let i = 0; i < np.length; i++) {
          const sx = np[i][0], sy2 = np[i][1], z = np[i][2];
          if ((z >= 0) !== front) continue;
          const c = NODES[i].crit ? crit : hi;
          const rr = unitSize * (NODES[i].crit ? 2.5 : 1.8);
          ctx.globalAlpha = front ? 0.55 + z * 0.45 : 0.14;
          ctx.fillStyle = "rgb(" + c[0] + "," + c[1] + "," + c[2] + ")";
          ctx.beginPath();
          ctx.arc(sx, sy2, rr, 0, Math.PI * 2);
          ctx.fill();
          if (front && NODES[i].crit) {
            const beat = 0.5 + 0.5 * Math.sin(now / 420);
            ctx.globalAlpha = 0.34 * (1 - beat * 0.7);
            ctx.strokeStyle = "rgb(" + c[0] + "," + c[1] + "," + c[2] + ")";
            ctx.lineWidth = Math.max(1, R / 260);
            ctx.beginPath();
            ctx.arc(sx, sy2, rr * (1.9 + beat * 1.6), 0, Math.PI * 2);
            ctx.stroke();
          }
          ctx.globalAlpha = 1;
        }
      };

      paintGraph(false);

      for (let i = 0; i < count; i++) {
        const k = i * 5;
        project(pts[k], pts[k + 1], pts[k + 2]);
        const nx = v[0], ny = v[1], nz = v[2];
        const d = nx * LIGHT[0] + ny * LIGHT[1] + nz * LIGHT[2];
        const up = Math.max(0, d);
        // the bright limb: dots near the silhouette catch the light edge-on
        const rim = Math.pow(1 - Math.abs(nz), 5) * 0.55;
        let lit = 0.12 + 1.15 * up + 0.5 * Math.pow(up, 7) + rim;
        const dens = 0.12 + 0.88 * smooth(-0.5, 0.92, d) + rim * 0.5;
        let vis = (dens - pts[k + 4]) * 5;
        if (vis <= 0.02) continue;
        if (vis > 1) vis = 1;
        if (nz < 0) vis *= 0.06 + 0.18 * (1 + nz);

        const rad = pts[k + 3];
        let x = ox + nx * R * rad, y = oy + ny * R * rad;

        for (let r = 0; r < st.ripples.length; r++) {
          const rp = st.ripples[r];
          const age = (now - rp.t) / 1000;
          const edge = age * R * 1.25;
          const dist = Math.hypot(x - rp.x, y - rp.y);
          const f = Math.exp(-Math.pow((dist - edge) / (R * 0.09), 2)) * (1 - age / 1.6);
          if (f > 0.01 && nz > -0.2) {
            x += nx * f * R * 0.07;
            y += ny * f * R * 0.07;
            lit += f * 0.9;
            vis = Math.min(1, vis + f * 0.6);
          }
        }

        if (st.hover > 0.01 && nz > -0.1) {
          const dx = x - st.px, dy = y - st.py;
          const q = dx * dx + dy * dy;
          if (q < reach2 && q > 0.01) {
            const dd = Math.sqrt(q);
            const fall = 1 - dd / reach;
            const push = fall * fall * st.hover * R * 0.09;
            x += (dx / dd) * push;
            y += (dy / dd) * push;
            lit += fall * st.hover * 0.35;
          }
        }

        const ci = Math.min(palette.length - 1, Math.round(smooth(-0.25, 0.7, lit) * 13 + Math.max(0, lit - 1.05) * 6));
        const ai = Math.min(4, Math.floor(vis * 4.999));
        bin.add(ci, ai, x, y, unitSize * (0.7 + 0.7 * (nz * 0.5 + 0.5)) * (0.8 + pts[k + 4] * 0.4));
      }
      bin.flush(ctx, palette);

      paintGraph(true);

      // one packet walking the attack path, from the foothold to the critical asset
      if (!reduced) {
        const span = PATH.length - 1;
        const t = ((now / 1000) * 0.4) % span;
        const seg = Math.floor(t), lt = t - seg;
        const a = NODE_V[PATH[seg]], b = NODE_V[PATH[seg + 1]];
        const x = a[0] + (b[0] - a[0]) * lt, y = a[1] + (b[1] - a[1]) * lt, z = a[2] + (b[2] - a[2]) * lt;
        const m = Math.hypot(x, y, z) || 1;
        project(x / m, y / m, z / m);
        if (v[2] > -0.1) {
          const sx = ox + v[0] * R, sy2 = oy + v[1] * R;
          const fade = Math.min(1, v[2] + 0.6);
          const g = ctx.createRadialGradient(sx, sy2, 0, sx, sy2, unitSize * 9);
          g.addColorStop(0, "rgba(" + hi[0] + "," + hi[1] + "," + hi[2] + "," + 0.75 * fade + ")");
          g.addColorStop(1, "rgba(" + hi[0] + "," + hi[1] + "," + hi[2] + ",0)");
          ctx.fillStyle = g;
          ctx.beginPath();
          ctx.arc(sx, sy2, unitSize * 9, 0, Math.PI * 2);
          ctx.fill();
          ctx.globalAlpha = 0.9 * fade;
          ctx.fillStyle = "#ffffff";
          ctx.beginPath();
          ctx.arc(sx, sy2, unitSize * 1.5, 0, Math.PI * 2);
          ctx.fill();
          ctx.globalAlpha = 1;
        }
      }
    };

    const loop = (now) => { draw(now); if (running) raf = requestAnimationFrame(loop); };
    const start = () => { if (!running) { running = true; last = performance.now(); raf = requestAnimationFrame(loop); } };
    const stop = () => { running = false; cancelAnimationFrame(raf); };
    const once = () => { if (!running) draw(performance.now()); };

    const at = (e) => { const r = canvas.getBoundingClientRect(); return [e.clientX - r.left, e.clientY - r.top]; };
    const down = (e) => {
      const p = at(e);
      st.drag = true; st.moved = 0; st.lx = p[0]; st.ly = p[1]; st.lt = performance.now();
      try { canvas.setPointerCapture(e.pointerId); } catch { /* capture unavailable */ }
    };
    const move = (e) => {
      const p = at(e);
      st.px = p[0]; st.py = p[1];
      st.hoverTo = e.pointerType === "mouse" || st.drag ? 1 : 0;
      if (st.drag) {
        const t = performance.now(), dx = p[0] - st.lx, dy = p[1] - st.ly;
        st.moved += Math.abs(dx) + Math.abs(dy);
        st.yaw += dx * 0.008;
        st.pitch = Math.max(-1.1, Math.min(1.1, st.pitch + dy * 0.005));
        const span = Math.max(0.008, (t - st.lt) / 1000);
        st.vel = st.vel * 0.6 + ((dx * 0.008) / span) * 0.4;
        st.lx = p[0]; st.ly = p[1]; st.lt = t;
        if (st.moved > 6) setTouched(true);
      }
      once();
    };
    const up = (e) => {
      if (!st.drag) return;
      st.drag = false;
      if (st.moved < 6) { const p = at(e); st.ripples.push({ x: p[0], y: p[1], t: performance.now() }); setTouched(true); }
      if (e.pointerType !== "mouse") st.hoverTo = 0;
      st.vel = Math.max(-4, Math.min(4, st.vel));
      once();
    };
    const leave = () => { st.hoverTo = 0; st.px = -1e4; st.py = -1e4; once(); };

    canvas.addEventListener("pointerdown", down);
    canvas.addEventListener("pointermove", move);
    canvas.addEventListener("pointerup", up);
    canvas.addEventListener("pointercancel", up);
    canvas.addEventListener("pointerleave", leave);

    const ro = new ResizeObserver(() => { measure(); once(); });
    ro.observe(box);

    // only animate while the orb is actually on screen
    const io = new IntersectionObserver((entries) => {
      if (entries[0].isIntersecting) { if (reduced) once(); else start(); } else stop();
    }, { rootMargin: "120px" });
    io.observe(box);

    return () => {
      stop();
      ro.disconnect();
      io.disconnect();
      canvas.removeEventListener("pointerdown", down);
      canvas.removeEventListener("pointermove", move);
      canvas.removeEventListener("pointerup", up);
      canvas.removeEventListener("pointercancel", up);
      canvas.removeEventListener("pointerleave", leave);
    };
  }, [accent, critical, dark]);

  return (
    <div className="lp-orb" ref={host} data-touched={touched || undefined}>
      <canvas ref={cv} role="img" aria-label={label} />
      <span className="lp-orb-hint" aria-hidden="true"><i />Drag to turn the graph</span>
    </div>
  );
}
