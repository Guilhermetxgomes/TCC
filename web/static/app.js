"use strict";

const $ = (id) => document.getElementById(id);
const SIM_START_SECONDS = 8 * 3600; // simulated clock starts at 08:00:00

const state = {
  graph: null,
  sim: null,            // payload of /api/simulate
  tick: 0,
  playing: false,
  lastFrame: 0,
  searchToken: 0,       // bumped to abort a running search animation
  foundRecordIds: new Set(),
  vertex: { id: null, offset: 0 },
  nodePos: {},
  criminalMarked: false,
};
let cy = null;

// ---------- helpers ----------

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value);
  }
  for (const child of children) node.append(child);
  return node;
}

function clockText(tick) {
  const total = SIM_START_SECONDS + Math.round(tick * (state.sim ? state.sim.tick_seconds : 10));
  const h = String(Math.floor(total / 3600) % 24).padStart(2, "0");
  const m = String(Math.floor(total / 60) % 60).padStart(2, "0");
  const s = String(total % 60).padStart(2, "0");
  return `${h}:${m}:${s}`;
}

function fmtNumber(value) {
  if (value >= 1e6) return new Intl.NumberFormat("pt-BR", { notation: "compact", maximumFractionDigits: 2 }).format(value);
  return new Intl.NumberFormat("pt-BR", { maximumFractionDigits: 0 }).format(value);
}

function fmtDuration(seconds) {
  if (seconds < 1) return `${(seconds * 1000).toFixed(1)} ms`;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  if (seconds < 3600) return `${(seconds / 60).toFixed(1)} min`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)} h`;
  if (seconds < 86400 * 365) return `${(seconds / 86400).toFixed(1)} dias`;
  return `${(seconds / (86400 * 365)).toFixed(1)} anos`;
}

function fmtUsd(value) {
  return new Intl.NumberFormat("pt-BR", { style: "currency", currency: "USD", maximumFractionDigits: value < 1 ? 4 : 0 }).format(value);
}

async function api(path, body) {
  const options = body === undefined ? {} : {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  };
  const response = await fetch(path, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// ---------- graph ----------

function layoutPositions(nodes) {
  const lat0 = nodes.reduce((a, n) => a + n.lat, 0) / nodes.length;
  const kx = Math.cos((lat0 * Math.PI) / 180);
  const xs = nodes.map((n) => n.lon * kx);
  const ys = nodes.map((n) => -n.lat);
  const minX = Math.min(...xs), maxX = Math.max(...xs);
  const minY = Math.min(...ys), maxY = Math.max(...ys);
  const scale = 1000 / Math.max(maxX - minX, maxY - minY);
  const positions = {};
  nodes.forEach((n, i) => {
    positions[n.id] = { x: (xs[i] - minX) * scale, y: (ys[i] - minY) * scale };
  });
  return positions;
}

function buildStyle() {
  return [
    { selector: "node.cam", style: {
      width: 15, height: 15, "background-color": cssVar("--node"), "border-width": 1,
      "border-color": cssVar("--edge"), label: "data(nid)", "font-size": 7, color: cssVar("--text"),
      "text-valign": "center", "text-halign": "center",
    } },
    { selector: "node.cam.visited", style: { "background-color": cssVar("--visited"), "border-width": 2 } },
    { selector: "node.cam.found", style: { "background-color": cssVar("--found"), "border-width": 2 } },
    { selector: "node.cam.crime", style: { "border-color": cssVar("--criminal"), "border-width": 4, width: 21, height: 21 } },
    { selector: "node.cam:selected", style: { "overlay-opacity": 0.12, "border-color": cssVar("--accent"), "border-width": 3 } },
    { selector: "edge", style: {
      width: "mapData(p, 0, 1, 1, 5)", "line-color": cssVar("--edge"), "target-arrow-color": cssVar("--edge"),
      "target-arrow-shape": "triangle", "arrow-scale": 0.6, "curve-style": "bezier", opacity: 0.55,
    } },
    { selector: "edge.probe", style: { "line-color": cssVar("--visited"), "target-arrow-color": cssVar("--visited"), opacity: 1 } },
    { selector: "edge.trail", style: { "line-color": cssVar("--trail"), "target-arrow-color": cssVar("--trail"), width: 5, opacity: 1 } },
    { selector: "edge.trail-other", style: { "line-color": cssVar("--trail"), "target-arrow-color": cssVar("--trail"), width: 2, opacity: 0.45 } },
    { selector: "node.car", style: {
      width: 7, height: 7, "background-color": cssVar("--car"), "border-width": 0, events: "no", "z-index": 20,
    } },
    { selector: "node.car.criminal", style: { "background-color": cssVar("--criminal"), width: 11, height: 11, "z-index": 30 } },
  ];
}

async function initGraph() {
  state.graph = await api("/api/graph");
  state.nodePos = layoutPositions(state.graph.nodes);
  const elements = [
    ...state.graph.nodes.map((n) => ({
      group: "nodes", classes: "cam",
      data: { id: `n${n.id}`, nid: n.id, name: n.name },
      position: state.nodePos[n.id], grabbable: false,
    })),
    ...state.graph.edges.map((e) => ({
      group: "edges", data: { id: `e${e.source}-${e.target}`, source: `n${e.source}`, target: `n${e.target}`, p: e.p },
    })),
  ];
  cy = cytoscape({ container: $("cy"), elements, style: buildStyle(), layout: { name: "preset" }, wheelSensitivity: 0.25 });
  cy.fit(cy.nodes(".cam"), 24);
  window.addEventListener("resize", () => { cy.resize(); cy.fit(cy.nodes(".cam"), 24); });
  cy.on("tap", "node.cam", (event) => showVertex(event.target.data("nid"), 0));
  cy.on("mouseover", "node.cam", (event) => { $("cy").title = event.target.data("name"); });
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => cy.style(buildStyle()));
}

// ---------- simulation + playback ----------

function setRunning(isBusy, button, label) {
  button.disabled = isBusy;
  if (label) button.textContent = label;
}

async function runSimulation() {
  state.searchToken++;
  const button = $("simulate");
  setRunning(true, button, "Gerando…");
  try {
    const sim = await api("/api/simulate", {
      seed: +$("p-seed").value, n_vehicles: +$("p-vehicles").value, ticks: +$("p-ticks").value,
      crime_tick: +$("p-crime").value, puzzle_level: +$("p-n").value,
    });
    loadSimulation(sim);
  } catch (error) {
    $("sim-info").textContent = `Erro: ${error.message}`;
  } finally {
    setRunning(false, button, "Gerar simulação");
  }
}

function loadSimulation(sim) {
  state.sim = sim;
  state.foundRecordIds = new Set();
  state.criminalMarked = false;
  state.vertex = { id: null, offset: 0 };
  $("vertex").hidden = true;
  $("vertex-empty").hidden = false;
  $("result").hidden = true;

  cy.elements("node.car").remove();
  cy.nodes(".cam").removeClass("visited found crime");
  cy.edges().removeClass("probe trail trail-other");
  cy.add(sim.vehicles.map((v) => ({
    group: "nodes", classes: "car", data: { id: `c${v.id}` }, position: { ...state.nodePos[v.events[0][1]] },
    selectable: false, grabbable: false,
  })));
  cy.getElementById(`n${sim.crime.node}`).addClass("crime");
  paintCounts(sim.record_counts);

  const slider = $("slider");
  slider.max = sim.params.ticks;
  slider.disabled = false;
  $("play").disabled = false;
  $("search").disabled = false;
  $("p-crime").max = sim.params.ticks;
  $("sim-info").textContent =
    `${sim.params.records} registros no banco · crime na câmera ${sim.crime.node} às ${clockText(sim.crime.tick)} ` +
    `(run ${sim.run_id})`;
  setTick(Math.max(0, sim.crime.tick - 10));
  updateModeUi();
}

function paintCounts(counts) {
  const values = Object.values(counts);
  if (!values.length) return;
  const max = Math.max(...values);
  const low = cssVar("--node"), high = cssVar("--node-busy");
  cy.nodes(".cam").forEach((node) => {
    const count = counts[node.data("nid")] || 0;
    const ratio = max ? Math.round((count / max) * 100) : 0;
    node.style("background-color", `color-mix(in srgb, ${high} ${ratio}%, ${low})`);
  });
}

function vehiclePosition(events, tick) {
  if (tick <= events[0][0]) return state.nodePos[events[0][1]];
  let low = 0, high = events.length - 1;
  while (low < high) {
    const mid = Math.ceil((low + high) / 2);
    if (events[mid][0] <= tick) low = mid; else high = mid - 1;
  }
  const [t0, n0] = events[low];
  if (low === events.length - 1) return state.nodePos[n0];
  const [t1, n1] = events[low + 1];
  const f = (tick - t0) / (t1 - t0);
  const a = state.nodePos[n0], b = state.nodePos[n1];
  return { x: a.x + (b.x - a.x) * f, y: a.y + (b.y - a.y) * f };
}

function setTick(tick) {
  if (!state.sim) return;
  state.tick = Math.min(Math.max(tick, 0), state.sim.params.ticks);
  $("slider").value = state.tick;
  $("clock").textContent = clockText(state.tick);
  const afterCrime = state.tick >= state.sim.crime.tick;
  cy.batch(() => {
    for (const vehicle of state.sim.vehicles) {
      cy.getElementById(`c${vehicle.id}`).position(vehiclePosition(vehicle.events, state.tick));
    }
    if (afterCrime !== state.criminalMarked) {
      cy.getElementById(`c${state.sim.crime.vehicle_id}`).toggleClass("criminal", afterCrime);
      state.criminalMarked = afterCrime;
    }
  });
}

function frame(now) {
  if (!state.playing) return;
  const dt = (now - state.lastFrame) / 1000;
  state.lastFrame = now;
  setTick(state.tick + dt * +$("speed").value);
  if (state.tick >= state.sim.params.ticks) return pause();
  requestAnimationFrame(frame);
}

function play() {
  if (!state.sim) return;
  if (state.tick >= state.sim.params.ticks) setTick(0);
  state.playing = true;
  state.lastFrame = performance.now();
  $("play").textContent = "Pausar";
  requestAnimationFrame(frame);
}

function pause() {
  state.playing = false;
  $("play").textContent = "Reproduzir";
}

// ---------- search ----------

const MODE_NOTES = {
  fechada: "Placa conhecida: resolve os puzzles do crime e, câmera a câmera, os dos vizinhos mais prováveis até achar o carro.",
  aberta: "Placa desconhecida: decifra TODOS os registros da janela do crime, filtra pelas letras lembradas e segue cada suspeito.",
  bolo: "As câmeras alertam em claro (sem puzzle), mas só para avistamentos depois do aviso: o passado não é coberto.",
};

function updateModeUi() {
  const mode = $("s-mode").value;
  $("mode-note").textContent = MODE_NOTES[mode];
  $("l-hint").hidden = mode !== "aberta";
  $("l-delay").hidden = mode !== "bolo";
}

function resetSearchStyles() {
  cy.nodes(".cam").removeClass("visited found");
  cy.edges().removeClass("probe trail trail-other");
  state.foundRecordIds = new Set();
}

function statRow(label, value, cls = "") {
  return [el("dt", { text: label }), el("dd", { text: value, class: cls })];
}

function renderStats(result, partial) {
  const t = partial || result.totals;
  const rows = [
    ...statRow("câmeras consultadas", String(t.probes)),
    ...statRow("registros decifrados", String(t.records_tested)),
    ...statRow("tentativas de puzzle (real)", fmtNumber(t.attempts)),
    ...statRow("tempo (real)", fmtDuration(t.real_seconds)),
  ];
  if (!partial) {
    const e = result.estimate;
    rows.push(el("div", { class: "sep" }));
    if (result.mode === "bolo") {
      rows.push(...statRow("custo de puzzle", "nenhum"));
      rows.push(...statRow("avistamentos perdidos no atraso", String(result.extra.missed_sightings)));
    } else {
      rows.push(...statRow(`com N = ${fmtNumber(e.realistic_n)}`, ""));
      rows.push(...statRow("tentativas", fmtNumber(e.estimated_attempts)));
      rows.push(...statRow("tempo (1 vCPU)", fmtDuration(e.estimated_seconds)));
      rows.push(...statRow("custo AWS (m7g.xlarge)", fmtUsd(e.estimated_usd)));
    }
    if (result.extra && result.extra.suspects !== undefined) {
      rows.push(...statRow("candidatas na janela", String(result.extra.candidates)));
      rows.push(...statRow("suspeitas (após dica)", `${result.extra.suspects} (seguidas: ${result.extra.suspects_traced})`));
    }
    const truth = result.truth;
    rows.push(...statRow(
      "rastro × trajeto real",
      truth.traced_nodes ? `${truth.matching_nodes}/${truth.traced_nodes} câmeras` : "não achou",
      truth.followed_criminal ? "ok" : "bad",
    ));
  }
  $("stats").replaceChildren(...rows);
}

function stepLabel(step) {
  if (step.kind === "alert") return `alerta · câmera ${step.node} · ${clockText(step.tick)}`;
  if (step.kind === "decrypt_window") {
    return `decifra janela · câmera ${step.node} · ${step.records_tested} regs`;
  }
  const from = step.from_node === null ? "crime" : `${step.from_node}→`;
  const p = step.p === null ? "" : ` (p=${step.p.toFixed(2)})`;
  const outcome = step.found ? "achou" : "não";
  return `${from} câmera ${step.node}${p} · ${step.records_tested}/${step.records_in_window} regs · ${outcome}`;
}

async function runSearch() {
  if (!state.sim) return;
  const token = ++state.searchToken;
  pause();
  resetSearchStyles();
  const button = $("search");
  setRunning(true, button, "Buscando…");
  $("result").hidden = false;
  $("steps").replaceChildren();
  $("stats").replaceChildren();
  try {
    const result = await api("/api/search", {
      run_id: state.sim.run_id, mode: $("s-mode").value, hint_len: +$("s-hint").value,
      bolo_delay_ticks: +$("s-delay").value, max_hops: +$("s-hops").value, realistic_n: +$("s-realistic").value,
    });
    if (token !== state.searchToken) return;
    await animateSearch(result, token);
  } catch (error) {
    $("stats").replaceChildren(...statRow("erro", error.message, "bad"));
  } finally {
    setRunning(false, button, "Disparar busca");
  }
}

async function animateSearch(result, token) {
  const running = { probes: 0, records_tested: 0, attempts: 0, real_seconds: 0 };
  const list = $("steps");
  const delay = result.steps.length > 60 ? 40 : 450;
  let active = null;

  for (const step of result.steps) {
    if (token !== state.searchToken) return;
    if (active) active.classList.remove("active");
    const item = el("li", { class: step.found ? "found active" : "active" }, el("span", { text: stepLabel(step) }));
    list.append(item);
    list.scrollTop = list.scrollHeight;
    active = item;

    running.probes += step.kind === "alert" ? 0 : 1;
    running.records_tested += step.records_tested;
    running.attempts += step.attempts;
    running.real_seconds += step.real_seconds;
    renderStats(result, { ...running });

    cy.getElementById(`n${step.node}`).addClass(step.found ? "found" : "visited");
    if (step.from_node !== null && step.from_node !== undefined) {
      cy.getElementById(`e${step.from_node}-${step.node}`).addClass("probe");
    }
    if (step.record_id) state.foundRecordIds.add(step.record_id);
    if (step.found && step.tick !== null && step.tick !== undefined) setTick(step.tick);
    await sleep(delay);
  }
  if (active) active.classList.remove("active");

  for (const path of result.paths) {
    for (let i = 0; i + 1 < path.nodes.length; i++) {
      const edge = cy.getElementById(`e${path.nodes[i][0]}-${path.nodes[i + 1][0]}`);
      edge.removeClass("probe").addClass(path.is_criminal ? "trail" : "trail-other");
    }
  }
  renderStats(result);
  if (state.vertex.id !== null) showVertex(state.vertex.id, 0);
}

// ---------- vertex (database view) ----------

function shorten(text, size) {
  return text.length > size ? `${text.slice(0, size)}…` : text;
}

function recordRow(row) {
  const crime = state.sim.crime;
  const classes = [];
  if (state.foundRecordIds.has(row.record_id)) classes.push("hit");
  else if (row.camera_id === crime.node && row.tick === crime.tick) classes.push("crime");

  const action = el("td");
  const button = el("button", { type: "button", text: "Decifrar" });
  button.addEventListener("click", async () => {
    button.disabled = true;
    button.textContent = "…";
    try {
      const solved = await api(`/api/record/${row.record_id}/solve`, { run_id: state.sim.run_id });
      action.replaceChildren(el("span", {
        class: "mono", text: `${solved.plate} · ${fmtNumber(solved.attempts)} tent. · ${fmtDuration(solved.elapsed_seconds)}`,
      }));
    } catch (error) {
      button.textContent = "erro";
    }
  });
  action.append(button);

  return el("tr", { class: classes.join(" ") },
    el("td", { text: String(row.record_id) }),
    el("td", { text: clockText(row.tick) }),
    el("td", { text: String(row.n) }),
    el("td", { class: "mono", text: shorten(row.c_prime, 10), title: row.c_prime }),
    el("td", { class: "mono", text: shorten(row.nonce, 8), title: row.nonce }),
    el("td", { class: "mono", text: shorten(row.ciphertext, 14), title: row.ciphertext }),
    action,
  );
}

async function showVertex(nodeId, offset) {
  if (!state.sim) return;
  try {
    const data = await api(`/api/vertex/${nodeId}?run_id=${encodeURIComponent(state.sim.run_id)}&offset=${offset}&limit=100`);
    state.vertex = { id: nodeId, offset };
    $("vertex-empty").hidden = true;
    $("vertex").hidden = false;
    $("v-name").textContent = `Câmera ${data.node.id} · ${data.node.name}`;
    $("v-meta").textContent = `${data.total} registros (mostrando ${offset + 1}–${offset + data.rows.length})`;
    $("v-note").textContent = data.note;
    $("v-rows").replaceChildren(...data.rows.map(recordRow));
    const more = $("v-more");
    more.hidden = offset + data.rows.length >= data.total;
    more.onclick = () => showVertex(nodeId, offset + data.rows.length);
  } catch (error) {
    $("vertex-empty").hidden = false;
    $("vertex-empty").textContent = `Erro: ${error.message}`;
  }
}

// ---------- wiring ----------

$("simulate").addEventListener("click", runSimulation);
$("search").addEventListener("click", runSearch);
$("s-mode").addEventListener("change", updateModeUi);
$("play").addEventListener("click", () => (state.playing ? pause() : play()));
$("slider").addEventListener("input", (event) => { pause(); setTick(+event.target.value); });

initGraph().then(() => {
  updateModeUi();
  return runSimulation();
}).catch((error) => {
  $("sim-info").textContent = `Erro ao carregar o grafo: ${error.message}`;
});
