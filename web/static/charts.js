"use strict";
// Minimal SVG charts for the "Dados reais" view: bars (+ optional reference line and a
// second series as a line) and a single line with a crosshair. Colors come from the CSS
// tokens --series-1 / --series-2 (validated categorical slots 1 and 2), text from the
// text tokens; every chart has a hover tooltip and re-renders on resize.

const Charts = (() => {
  const NS = "http://www.w3.org/2000/svg";
  const registry = new Map(); // host -> render()
  let tip = null;

  function svgEl(tag, attrs = {}) {
    const node = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
    return node;
  }

  function niceMax(value) {
    if (value <= 0) return 1;
    const exp = Math.pow(10, Math.floor(Math.log10(value)));
    for (const m of [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10]) if (m * exp >= value) return m * exp;
    return 10 * exp;
  }

  function fmt(value) {
    return new Intl.NumberFormat("pt-BR", { maximumFractionDigits: value < 10 ? 1 : 0 }).format(value);
  }

  function showTip(event, html) {
    if (!tip) {
      tip = document.createElement("div");
      tip.className = "viz-tip";
      document.body.append(tip);
    }
    tip.innerHTML = html;
    tip.hidden = false;
    const pad = 12, w = tip.offsetWidth, h = tip.offsetHeight;
    let x = event.clientX + pad, y = event.clientY - h - pad;
    if (x + w > window.innerWidth - 4) x = event.clientX - w - pad;
    if (y < 4) y = event.clientY + pad;
    tip.style.left = `${x}px`;
    tip.style.top = `${y}px`;
  }

  function hideTip() { if (tip) tip.hidden = true; }

  function frame(host, height, yMax, yTitle, ticks = 4) {
    const width = Math.max(260, host.clientWidth || 600);
    const m = { l: 66, r: 12, t: 14, b: 26 };
    const svg = svgEl("svg", { viewBox: `0 0 ${width} ${height}`, width: "100%", height, role: "img" });
    const plot = { x: m.l, y: m.t, w: width - m.l - m.r, h: height - m.t - m.b };
    const y = (v) => plot.y + plot.h - (v / yMax) * plot.h;
    for (let i = 0; i <= ticks; i++) {
      const v = (yMax / ticks) * i, yy = y(v);
      svg.append(svgEl("line", { x1: plot.x, x2: plot.x + plot.w, y1: yy, y2: yy, class: i ? "viz-grid" : "viz-axis" }));
      const label = svgEl("text", { x: plot.x - 6, y: yy + 4, "text-anchor": "end", class: "viz-tick" });
      label.textContent = fmt(v);
      svg.append(label);
    }
    if (yTitle) {
      const t = svgEl("text", { x: 12, y: plot.y + plot.h / 2, class: "viz-tick",
        transform: `rotate(-90 12 ${plot.y + plot.h / 2})`, "text-anchor": "middle" });
      t.textContent = yTitle;
      svg.append(t);
    }
    return { svg, plot, y, width };
  }

  function xLabel(svg, x, yPos, text) {
    const t = svgEl("text", { x, y: yPos, "text-anchor": "middle", class: "viz-tick" });
    t.textContent = text;
    svg.append(t);
  }

  // Rounded top corners (4px), flat on the baseline.
  function barPath(x, top, w, base) {
    const r = Math.min(4, w / 2, Math.max(0, base - top));
    return `M${x},${base} V${top + r} Q${x},${top} ${x + r},${top} H${x + w - r} Q${x + w},${top} ${x + w},${top + r} V${base} Z`;
  }

  function bars(host, o) {
    const render = () => {
      const n = o.values.length;
      const top = Math.max(...o.values, ...(o.line || [0]), o.ref ? o.ref.value : 0);
      const { svg, plot, y } = frame(host, o.height || 230, niceMax(top * 1.05), o.yTitle);
      const band = plot.w / n;
      const gap = n > 60 ? 0 : 2;
      const bw = Math.max(1, band - gap);
      const base = plot.y + plot.h;
      if (o.highlight) {
        const [a, b] = o.highlight;
        svg.append(svgEl("rect", { x: plot.x + a * band, y: plot.y, width: (b - a + 1) * band, height: plot.h,
          class: "viz-window" }));
      }
      o.values.forEach((v, i) => {
        const x = plot.x + i * band + gap / 2;
        const cls = o.emphasis !== undefined && o.emphasis !== null
          ? (i === o.emphasis ? "viz-bar emph" : "viz-bar dim") : "viz-bar";
        svg.append(svgEl("path", { d: barPath(x, y(v), bw, base), class: cls }));
      });
      if (o.line) {
        const pts = o.line.map((v, i) => `${plot.x + (i + 0.5) * band},${y(v)}`).join(" ");
        svg.append(svgEl("polyline", { points: pts, class: "viz-line s2" }));
      }
      if (o.ref) {
        const yy = y(o.ref.value);
        svg.append(svgEl("line", { x1: plot.x, x2: plot.x + plot.w, y1: yy, y2: yy, class: "viz-ref" }));
        const t = svgEl("text", { x: plot.x + plot.w - 4, y: yy - 5, "text-anchor": "end", class: "viz-tick" });
        t.textContent = o.ref.label;
        svg.append(t);
      }
      const every = o.xEvery || Math.ceil(n / 12);
      o.labels.forEach((label, i) => { if (label !== "" && i % every === 0) xLabel(svg, plot.x + (i + 0.5) * band, base + 16, label); });
      // hit targets: the whole band, taller than the bar
      o.values.forEach((_, i) => {
        const hit = svgEl("rect", { x: plot.x + i * band, y: plot.y, width: band, height: plot.h, class: "viz-hit" });
        hit.addEventListener("mousemove", (e) => showTip(e, o.tooltip(i)));
        hit.addEventListener("mouseleave", hideTip);
        if (o.onClick) hit.addEventListener("click", () => o.onClick(i));
        svg.append(hit);
      });
      host.replaceChildren(svg);
    };
    registry.set(host, render);
    render();
  }

  function line(host, o) {
    const render = () => {
      const n = o.values.length;
      const { svg, plot, y } = frame(host, o.height || 200, niceMax(Math.max(...o.values) * 1.05), o.yTitle);
      const x = (i) => plot.x + (n > 1 ? (i / (n - 1)) * plot.w : plot.w / 2);
      if (o.mark !== undefined && o.mark !== null) {
        svg.append(svgEl("line", { x1: x(o.mark), x2: x(o.mark), y1: plot.y, y2: plot.y + plot.h, class: "viz-ref" }));
      }
      svg.append(svgEl("polyline", { points: o.values.map((v, i) => `${x(i)},${y(v)}`).join(" "), class: "viz-line s1" }));
      (o.ticks || []).forEach(({ i, label }) => xLabel(svg, x(i), plot.y + plot.h + 16, label));
      const cross = svgEl("line", { y1: plot.y, y2: plot.y + plot.h, class: "viz-cross", visibility: "hidden" });
      const dot = svgEl("circle", { r: 4, class: "viz-dot", visibility: "hidden" });
      svg.append(cross, dot);
      const hit = svgEl("rect", { x: plot.x, y: plot.y, width: plot.w, height: plot.h, class: "viz-hit" });
      hit.addEventListener("mousemove", (e) => {
        const box = svg.getBoundingClientRect();
        const px = (e.clientX - box.left) * (svg.viewBox.baseVal.width / box.width);
        const i = Math.max(0, Math.min(n - 1, Math.round(((px - plot.x) / plot.w) * (n - 1))));
        cross.setAttribute("x1", x(i)); cross.setAttribute("x2", x(i)); cross.setAttribute("visibility", "visible");
        dot.setAttribute("cx", x(i)); dot.setAttribute("cy", y(o.values[i])); dot.setAttribute("visibility", "visible");
        showTip(e, o.tooltip(i));
      });
      hit.addEventListener("mouseleave", () => { hideTip(); cross.setAttribute("visibility", "hidden"); dot.setAttribute("visibility", "hidden"); });
      if (o.onClick) hit.addEventListener("click", (e) => {
        const box = svg.getBoundingClientRect();
        const px = (e.clientX - box.left) * (svg.viewBox.baseVal.width / box.width);
        o.onClick(Math.max(0, Math.min(n - 1, Math.round(((px - plot.x) / plot.w) * (n - 1)))));
      });
      svg.append(hit);
      host.replaceChildren(svg);
    };
    registry.set(host, render);
    render();
  }

  let resizeTimer = null;
  window.addEventListener("resize", () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => registry.forEach((render, host) => { if (host.isConnected && host.offsetParent) render(); }), 120);
  });

  return { bars, line, rerender: () => registry.forEach((render, host) => { if (host.offsetParent) render(); }) };
})();
