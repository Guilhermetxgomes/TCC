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
    else if (value === false || value === null || value === undefined) continue;
    else if (value === true) node.setAttribute(key, "");
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
  const years = seconds / (86400 * 365);
  return years < 100 ? `${years.toFixed(1)} anos` : `${fmtNumber(Math.round(years))} anos`;
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
      "source-arrow-color": cssVar("--edge"), "target-arrow-shape": "triangle", "arrow-scale": 0.6,
      "curve-style": "bezier", opacity: 0.55,
    } },
    { selector: "edge[?both]", style: { "source-arrow-shape": "triangle" } },
    { selector: "edge.probe", style: {
      "line-color": cssVar("--visited"), "target-arrow-color": cssVar("--visited"), "source-arrow-color": cssVar("--visited"), opacity: 1,
    } },
    { selector: "edge.trail", style: {
      "line-color": cssVar("--trail"), "target-arrow-color": cssVar("--trail"), "source-arrow-color": cssVar("--trail"), width: 5, opacity: 1,
    } },
    { selector: "edge.trail-other", style: {
      "line-color": cssVar("--trail"), "target-arrow-color": cssVar("--trail"), "source-arrow-color": cssVar("--trail"), width: 2, opacity: 0.45,
    } },
    { selector: "node.car", style: {
      width: 7, height: 7, "background-color": cssVar("--car"), "border-width": 0, events: "no", "z-index": 20,
    } },
    { selector: "node.car.criminal", style: { "background-color": cssVar("--criminal"), width: 11, height: 11, "z-index": 30 } },
  ];
}

// One drawn edge per road: a two-way road (u->v and v->u) becomes a single line with an
// arrow at each end. state.edgeIds maps every direction "u-v" to the element that draws it.
function mergedEdges(edges) {
  const byPair = new Map();
  for (const e of edges) byPair.set(`${e.source}-${e.target}`, e);
  state.edgeIds = {};
  const elements = [];
  for (const e of edges) {
    const key = `${e.source}-${e.target}`;
    if (state.edgeIds[key]) continue;
    const back = e.source !== e.target ? byPair.get(`${e.target}-${e.source}`) : undefined;
    const id = `e${key}`;
    state.edgeIds[key] = id;
    if (back) state.edgeIds[`${e.target}-${e.source}`] = id;
    elements.push({
      group: "edges",
      data: { id, source: `n${e.source}`, target: `n${e.target}`, p: back ? Math.max(e.p, back.p) : e.p, both: Boolean(back) },
    });
  }
  return elements;
}

function edgeOf(from, to) {
  return cy.getElementById(state.edgeIds[`${from}-${to}`] || `e${from}-${to}`);
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
    ...mergedEdges(state.graph.edges),
  ];
  // Wheel zoom off: scrolling over the map scrolls the page instead of zooming the graph.
  // Zoom goes through the buttons; dragging still pans.
  cy = cytoscape({
    container: $("cy"), elements, style: buildStyle(), layout: { name: "preset" },
    userZoomingEnabled: false, boxSelectionEnabled: false, minZoom: 0.2, maxZoom: 6,
  });
  const fit = () => cy.fit(cy.nodes(".cam"), 24);
  fit();
  const zoomBy = (factor) => cy.zoom({
    level: cy.zoom() * factor, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 },
  });
  $("zoom-in").addEventListener("click", () => zoomBy(1.3));
  $("zoom-out").addEventListener("click", () => zoomBy(1 / 1.3));
  $("zoom-fit").addEventListener("click", fit);
  window.addEventListener("resize", () => { cy.resize(); fit(); });
  cy.on("tap", "node.cam", (event) => showVertex(event.target.data("nid"), 0));
  cy.on("mouseover", "node.cam", (event) => { $("cy").title = event.target.data("name"); });
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => cy.style(buildStyle()));
}

// ---------- simulation + playback ----------

function setRunning(isBusy, button, label) {
  button.disabled = isBusy;
  if (label) button.textContent = label;
}

async function runSimulation(drawSeed = false) {
  if (drawSeed && $("p-newseed").checked) $("p-seed").value = 1 + Math.floor(Math.random() * 999999);
  state.searchToken++;
  const button = $("simulate");
  setRunning(true, button, "Gerando…");
  try {
    const sim = await api("/api/simulate", {
      seed: +$("p-seed").value, n_vehicles: +$("p-vehicles").value, ticks: +$("p-ticks").value,
      crime_tick: +$("p-crime").value, puzzle_level: +$("p-n").value, block: $("p-block").checked,
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
  // The server clamps out-of-range inputs: show the values that were actually used.
  const p = sim.params;
  $("p-seed").value = p.seed;
  $("p-vehicles").value = p.n_vehicles;
  $("p-ticks").value = p.ticks;
  $("p-crime").value = p.crime_tick;
  $("p-n").value = p.block_level || p.puzzle_level;
  $("p-block").checked = Boolean(p.block_level);
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
  if (window.onSimulationLoaded) window.onSimulationLoaded(sim);
  document.dispatchEvent(new CustomEvent("simulation-loaded", { detail: sim }));
  $("p-crime").max = sim.params.ticks;
  $("sim-info").textContent =
    `${sim.params.records} registros no banco · crime na câmera ${sim.crime.node} às ${clockText(sim.crime.tick)} ` +
    (sim.params.block_level ? `· um puzzle (N = ${fmtNumber(sim.params.block_level)}) por bloco de 10 min ` : "") +
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
  total: "Acesso excepcional: um quórum do Comitê de Emergência decifra por limiar as chaves de sessão das câmeras e TODOS os registros do dia abrem sem puzzle.",
};

function updateModeUi() {
  const mode = $("s-mode").value;
  $("mode-note").textContent = MODE_NOTES[mode];
  $("l-hint").hidden = mode !== "aberta";
  $("l-delay").hidden = mode !== "bolo";
  $("l-members").hidden = mode !== "total";
  $("l-hops").hidden = mode === "bolo" || mode === "total";
  $("l-until").hidden = mode === "bolo" || mode === "total";
  $("l-budget").hidden = mode === "bolo" || mode === "total";
  $("s-hops").disabled = $("s-until").checked;
}

const STOP_REASONS = {
  max_hops: "limite de câmeras atingido (o carro continua)",
  lost: "sem novos registros: fim da gravação ou rastro perdido",
  denied: "o Servidor recusou a janela seguinte (token vencido ou orçamento esgotado)",
};

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
    ...statRow(`tentativas de puzzle reais (N = ${fmtNumber(state.sim.params.block_level || state.sim.params.puzzle_level)})`, fmtNumber(t.attempts)),
    ...statRow("tempo (real)", fmtDuration(t.real_seconds)),
  ];
  if (t.rejected) rows.push(...statRow("registros rejeitados (assinatura inválida)", String(t.rejected), "bad"));
  if (!partial) {
    const e = result.estimate;
    const g = result.governance;
    if (g) {
      rows.push(el("div", { class: "sep" }));
      rows.push(...statRow("tokens do juiz", g.tokens.map((tk) => `${tk.token_id}`).join(", ") || "nenhum"));
      rows.push(...statRow("entradas no log do Servidor", String(g.log_entries)));
      rows.push(...statRow("decifragens declaradas ao Auditor", String(g.declarations)));
      if (g.denials.length) rows.push(...statRow("pedidos recusados pelo Servidor", String(g.denials.length), "bad"));
      rows.push(...statRow("custo da governança (token + log)", fmtDuration(g.overhead_seconds)));
    }
    rows.push(el("div", { class: "sep" }));
    if (result.mode === "bolo") {
      rows.push(...statRow("custo de puzzle", "nenhum"));
      rows.push(...statRow("avistamentos perdidos no atraso", String(result.extra.missed_sightings)));
    } else if (result.mode === "total") {
      const x = result.extra;
      rows.push(...statRow("custo de puzzle", "nenhum (chave de sessão via quórum)"));
      rows.push(...statRow("deputados que participaram", `${x.members.join(", ")} (limiar ${x.threshold} de ${x.committee_members})`));
      rows.push(...statRow("chaves de sessão abertas", `${x.wraps_opened} (sessão ${x.session})`));
      rows.push(...statRow("decifragens parciais", String(x.partial_decryptions)));
      rows.push(...statRow("tempo do comitê", fmtDuration(x.committee_seconds)));
      rows.push(...statRow("outras placas expostas", String(x.other_plates_exposed), "bad"));
      rows.push(...statRow("avistamentos antes do crime", String(x.sightings_before_crime)));
    } else {
      if (e.blocks_solved) {
        rows.push(...statRow("puzzles de bloco resolvidos", String(e.blocks_solved)));
        rows.push(...statRow(`extrapolado para N = ${fmtNumber(e.realistic_t)} por bloco`, ""));
      } else {
        rows.push(...statRow(`extrapolado para N = ${fmtNumber(e.realistic_n)}`, ""));
      }
      rows.push(...statRow("tentativas, (N+1)/2 por puzzle", fmtNumber(e.estimated_attempts)));
      rows.push(...statRow("tempo (1 núcleo)", fmtDuration(e.estimated_seconds)));
      rows.push(...statRow("custo AWS (1 de 4 vCPUs)", fmtUsd(e.estimated_usd)));
      if (e.mass_city_usd !== undefined) {
        rows.push(el("div", { class: "sep" }));
        rows.push(...statRow("varredura em massa, mesmo N", ""));
        rows.push(...statRow(`toda a base simulada (${fmtNumber(e.mass_sim_records)} regs)`, fmtUsd(e.mass_sim_usd)));
        rows.push(...statRow("cidade inteira, 1 ano*", fmtUsd(e.mass_city_usd), "bad"));
        rows.push(...statRow("tempo da varredura (1 núcleo)", fmtDuration(e.mass_city_seconds)));
        rows.push(el("div", { class: "note muted small", text:
          `* hipótese: 5.000 câmeras × 1.000 veículos/h × 1 ano = ${fmtNumber(e.mass_city_records)} registros` }));
      }
    }
    if (result.extra && result.extra.suspects !== undefined) {
      rows.push(...statRow("candidatas na janela", String(result.extra.candidates)));
      rows.push(...statRow("suspeitas (após dica)", `${result.extra.suspects} (seguidas: ${result.extra.suspects_traced})`));
    }
    const truth = result.truth;
    rows.push(...statRow(
      "avistamentos reais confirmados",
      truth.traced_nodes ? `${truth.matching_nodes}/${truth.traced_nodes}` : "não achou",
      truth.followed_criminal ? "ok" : "bad",
    ));
    if (truth.skipped_sightings) {
      rows.push(...statRow("avistamentos reais pulados", String(truth.skipped_sightings)));
    }
    const criminalPath = result.paths.find((p) => p.is_criminal);
    if (criminalPath && criminalPath.stopped_by) {
      rows.push(...statRow("câmeras seguidas", String(criminalPath.nodes.length - 1)));
      rows.push(...statRow("busca parou", STOP_REASONS[criminalPath.stopped_by]));
    }
  }
  $("stats").replaceChildren(...rows);
}

function stepLabel(step) {
  const label = baseStepLabel(step);
  return step.rejected ? `${label} · ${step.rejected} rejeitado${step.rejected > 1 ? "s" : ""}` : label;
}

function baseStepLabel(step) {
  if (step.kind === "denied") return `recusado · câmera ${step.node} · ${step.reason}`;
  if (step.kind === "alert") return `alerta · câmera ${step.node} · ${clockText(step.tick)}`;
  if (step.kind === "quorum") {
    return `quórum · deputados ${step.members.join(", ")} · ${step.wraps_opened} chaves de sessão`;
  }
  if (step.kind === "open_session") {
    return `abre sessão · câmera ${step.node} · ${step.records_tested} regs${step.found ? " · viu o carro" : ""}`;
  }
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
      bolo_delay_ticks: +$("s-delay").value, max_hops: +$("s-hops").value, until_lost: $("s-until").checked,
      realistic_n: +$("s-realistic").value, members: +$("s-members").value, budget_records: +$("s-budget").value,
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
  const running = { probes: 0, records_tested: 0, attempts: 0, real_seconds: 0, rejected: 0 };
  const list = $("steps");
  // ~12 s for a long search (until-lost can have thousands of steps), 450 ms per step for short ones
  const delay = Math.max(3, Math.min(450, Math.round(12000 / result.steps.length)));
  let active = null;

  for (const step of result.steps) {
    if (token !== state.searchToken) return;
    if (active) active.classList.remove("active");

    running.probes += step.kind === "alert" || step.kind === "quorum" || step.kind === "denied" ? 0 : 1;
    running.records_tested += step.records_tested;
    running.attempts += step.attempts;
    running.real_seconds += step.real_seconds;
    running.rejected += step.rejected || 0;

    // right-hand column: records decrypted so far, to watch the cost grow camera by camera
    const item = el("li", { class: (step.found ? "found active" : "active") + (step.rejected ? " rejected" : "") + (step.kind === "denied" ? " denied" : ""),
        title: step.rejected ? `registro(s) ${step.rejected_ids.join(", ")} rejeitado(s): assinatura inválida` : false },
      el("span", { text: stepLabel(step) }),
      el("span", { class: "mono", text: `Σ ${running.records_tested}`, title: "registros decifrados até aqui" }),
    );
    list.append(item);
    list.scrollTop = list.scrollHeight;
    active = item;
    renderStats(result, { ...running });

    cy.getElementById(`n${step.node}`).addClass(step.found ? "found" : "visited");
    if (step.from_node !== null && step.from_node !== undefined) {
      edgeOf(step.from_node, step.node).addClass("probe");
    }
    if (step.record_id) state.foundRecordIds.add(step.record_id);
    if (step.found && step.tick !== null && step.tick !== undefined) setTick(step.tick);
    await sleep(delay);
  }
  if (active) active.classList.remove("active");

  for (const path of result.paths) {
    for (let i = 0; i + 1 < path.nodes.length; i++) {
      const edge = edgeOf(path.nodes[i][0], path.nodes[i + 1][0]);
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

// "2026-01-01T08:1#0" (10-minute slot, sequence) -> "08:10–08:19"
function blockLabel(label) {
  if (!label) return "—";
  const [slot, seq] = label.split("#");
  if (slot.length !== 15) return label;
  const hh = slot.slice(11, 13), m = slot.slice(14, 15);
  return `${hh}:${m}0–${hh}:${m}9` + (seq && seq !== "0" ? ` (#${seq})` : "");
}

function blockRow(block) {
  return el("tr", {},
    el("td", { text: blockLabel(block.block) }),
    el("td", { text: String(block.records) }),
    el("td", { text: fmtNumber(block.t) }),
    el("td", { class: "mono", text: shorten(block.c_prime, 10), title: block.c_prime }),
    el("td", { class: "mono", text: shorten(block.check_nonce, 8), title: block.check_nonce }),
    el("td", { class: "mono", text: shorten(block.check_tag, 10), title: block.check_tag }),
  );
}

function recordRow(row) {
  const crime = state.sim.crime;
  const classes = [];
  if (row.tampered) classes.push("tampered");
  if (state.foundRecordIds.has(row.record_id)) classes.push("hit");
  else if (row.camera_id === crime.node && row.tick === crime.tick) classes.push("crime");

  const action = el("td");
  const button = el("button", { type: "button", text: "Decifrar" });
  button.addEventListener("click", async () => {
    button.disabled = true;
    button.textContent = "…";
    try {
      const solved = await api(`/api/record/${row.record_id}/solve`, { run_id: state.sim.run_id });
      if (solved.rejected) {
        action.replaceChildren(el("span", { class: "small bad-text", text: `rejeitado: ${solved.reason}` }));
        return;
      }
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
    el("td", { text: blockLabel(row.block), hidden: !state.sim.params.block_level }),
    el("td", { text: String(row.n) }),
    el("td", { class: "mono", text: shorten(row.c_prime, 10), title: row.c_prime }),
    el("td", { class: "mono", text: shorten(row.nonce, 8), title: row.nonce }),
    el("td", { class: "mono", text: shorten(row.ciphertext, 14), title: row.ciphertext }),
    el("td", {
      class: row.signature_ok ? "sig-ok" : "sig-bad", text: row.signature_ok ? "✓" : "✗",
      title: (row.signature_ok ? "assinatura válida: " : "assinatura NÃO confere: ") + (row.signature || "ausente"),
    }),
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
    $("v-block-col").hidden = !state.sim.params.block_level;
    $("v-blocks").hidden = !data.blocks.length;
    $("v-block-rows").replaceChildren(...data.blocks.map(blockRow));
    const more = $("v-more");
    more.hidden = offset + data.rows.length >= data.total;
    more.onclick = () => showVertex(nodeId, offset + data.rows.length);
  } catch (error) {
    $("vertex-empty").hidden = false;
    $("vertex-empty").textContent = `Erro: ${error.message}`;
  }
}

// ---------- views (tabs) ----------

const VIEWS = ["busca", "ataques", "dados", "auditoria"];
const viewHooks = {}; // view name -> function called when the view is shown

function showView(name) {
  if (!VIEWS.includes(name)) name = "busca";
  for (const view of VIEWS) $(`view-${view}`).hidden = view !== name;
  document.querySelectorAll(".tab").forEach((tab) => {
    const active = tab.dataset.view === name;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", String(active));
  });
  if (name === "busca" && cy) { cy.resize(); cy.fit(cy.nodes(".cam"), 24); }
  if (viewHooks[name]) viewHooks[name]();
}

window.addEventListener("hashchange", () => showView(location.hash.slice(1)));

// ---------- wiring ----------

$("simulate").addEventListener("click", () => runSimulation(true));
$("p-seed").addEventListener("input", () => { $("p-newseed").checked = false; });
$("search").addEventListener("click", runSearch);
$("s-mode").addEventListener("change", updateModeUi);
$("s-until").addEventListener("change", updateModeUi);
$("play").addEventListener("click", () => (state.playing ? pause() : play()));
$("slider").addEventListener("input", (event) => { pause(); setTick(+event.target.value); });

showView(location.hash.slice(1));

initGraph().then(() => {
  updateModeUi();
  return runSimulation();
}).catch((error) => {
  $("sim-info").textContent = `Erro ao carregar o grafo: ${error.message}`;
});
