"use strict";
// View 3: real hourly volumes of the São Paulo toll plazas (ARTESP open data). Each plaza
// and direction plays one camera; /api/tolls/search runs a search sized by its real volume.

const MONTHS = ["jan", "fev", "mar", "abr", "mai", "jun", "jul", "ago", "set", "out", "nov", "dez"];
const tollState = { summary: null, camera: null, loaded: false };

function isoDay(start, index) {
  const d = new Date(`${start}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + index);
  return d.toISOString().slice(0, 10);
}

function dayLabel(iso) {
  const [, m, d] = iso.split("-");
  return `${+d} ${MONTHS[+m - 1]}`;
}

function tile(label, value, note) {
  return el("div", { class: "tile" },
    el("span", { class: "tile-value", text: value }),
    el("span", { class: "tile-label", text: label }),
    note ? el("span", { class: "tile-note muted", text: note }) : "");
}

function cameraLabel(c) {
  return `${c.plaza} (${c.direction}) · ${fmtNumber(Math.round(c.mean_per_hour))}/h`;
}

function fillCameras(lot, selectId) {
  const cams = tollState.summary.cameras.filter((c) => c.lot === lot).sort((a, b) => b.total - a.total);
  $("d-camera").replaceChildren(...cams.map((c) => el("option", { value: c.id, text: cameraLabel(c), selected: c.id === selectId })));
}

function selectCamera(id) {
  const cam = tollState.summary.cameras.find((c) => c.id === id);
  if (!cam) return;
  $("d-lot").value = cam.lot;
  fillCameras(cam.lot, id);
  loadCamera();
}

async function loadTolls() {
  if (tollState.loaded) return;
  tollState.loaded = true;
  try {
    const s = await api("/api/tolls/summary");
    tollState.summary = s;
    const n = s.network;
    $("d-source").textContent = `Fonte: ${s.source}; ${dayLabel(s.start)} a ${dayLabel(s.last_day)} de 2026.`;
    $("d-tiles").replaceChildren(
      tile("praças × sentidos", String(n.cameras)),
      tile("passagens no período", fmtNumber(n.total), `≈ ${fmtNumber(n.per_year)} por ano`),
      tile("veículos/h por câmera", `${fmtNumber(Math.round(n.mean_per_camera_hour))} média`,
        `mediana ${fmtNumber(n.quantiles.p50)} · p90 ${fmtNumber(n.quantiles.p90)}`),
      tile("hora mais movimentada", `${fmtNumber(n.max)}/h`, `p99 ${fmtNumber(n.quantiles.p99)}/h`),
      tile("câmeras com média ≥ 1.000/h", String(n.cameras_over_1000), `${n.cameras_under_100} com média < 100/h`),
    );
    const lots = [...new Set(s.cameras.map((c) => c.lot))].sort();
    $("d-lot").replaceChildren(...lots.map((lot) => el("option", { value: lot, text: lot })));
    $("d-day").min = s.start;
    $("d-day").max = s.last_day;
    const busiest = [...s.cameras].sort((a, b) => b.total - a.total)[0];
    renderRanking(busiest.id);
    selectCamera(busiest.id);
    $("d-search").disabled = false;
  } catch (error) {
    tollState.loaded = false;
    $("d-tiles").replaceChildren(el("p", { class: "bad-text small", text: `Erro: ${error.message}` }));
  }
}

function renderRanking(selectedId) {
  const cams = [...tollState.summary.cameras].sort((a, b) => b.mean_per_hour - a.mean_per_hour);
  Charts.bars($("d-chart-rank"), {
    values: cams.map((c) => c.mean_per_hour),
    labels: cams.map((_, i) => (i % 50 === 0 ? `${i + 1}º` : "")),
    xEvery: 1,
    emphasis: cams.findIndex((c) => c.id === selectedId),
    ref: { value: 1000, label: "hipótese: 1.000 veículos/h" },
    yTitle: "veículos/h (média)",
    height: 220,
    tooltip: (i) => `<strong>${cams[i].plaza} (${cams[i].direction})</strong><br>${cams[i].lot}<br>`
      + `${fmtNumber(Math.round(cams[i].mean_per_hour))} veículos/h em média · ${i + 1}º de ${cams.length}`,
    onClick: (i) => selectCamera(cams[i].id),
  });
}

function windowRange() {
  const start = Math.max(0, Math.min(23, +$("d-hour").value));
  const hours = Math.max(1, Math.min(6, +$("d-hours").value));
  return [start, Math.min(23, start + hours - 1)];
}

async function loadCamera() {
  const id = +$("d-camera").value;
  const day = $("d-day").value || "2026-03-10";
  try {
    const data = await api(`/api/tolls/camera/${id}?day=${day}`);
    tollState.camera = data;
    renderRanking(id);
    renderCameraCharts();
  } catch (error) {
    $("d-chart-day").textContent = `Erro: ${error.message}`;
  }
}

function renderCameraCharts() {
  const data = tollState.camera;
  if (!data) return;
  const [a, b] = windowRange();
  const inWindow = data.hourly.slice(a, b + 1).reduce((x, y) => x + y, 0);
  $("d-day-title").textContent = `${data.camera.name}: veículos por hora em ${dayLabel(data.day)} (${fmtNumber(inWindow)} na janela)`;
  Charts.bars($("d-chart-day"), {
    values: data.hourly,
    labels: data.hourly.map((_, h) => `${h}h`),
    xEvery: 2,
    line: data.profile,
    highlight: [a, b],
    yTitle: "veículos/h",
    tooltip: (h) => `<strong>${h}h–${h + 1}h</strong><br>${fmtNumber(data.hourly[h])} veículos no dia<br>`
      + `${fmtNumber(Math.round(data.profile[h]))} em média no período`,
    onClick: (h) => { $("d-hour").value = h; renderCameraCharts(); },
  });
  const ticks = [];
  data.daily.forEach((_, i) => { const iso = isoDay(data.start, i); if (iso.endsWith("-01")) ticks.push({ i, label: MONTHS[+iso.slice(5, 7) - 1] }); });
  const mark = Math.round((Date.parse(`${data.day}T00:00:00Z`) - Date.parse(`${data.start}T00:00:00Z`)) / 86400000);
  $("d-period-title").textContent = `${data.camera.name}: veículos por dia em 2026 (${fmtNumber(data.total)} no período)`;
  Charts.line($("d-chart-period"), {
    values: data.daily, ticks, mark, yTitle: "veículos/dia",
    tooltip: (i) => `<strong>${dayLabel(isoDay(data.start, i))}</strong><br>${fmtNumber(data.daily[i])} veículos`,
    onClick: (i) => { $("d-day").value = isoDay(data.start, i); loadCamera(); },
  });
}

function costRow(label, item, records) {
  return el("tr", {},
    el("td", { text: label }),
    el("td", { text: records }),
    el("td", { text: fmtDuration(item.seconds) }),
    el("td", { text: fmtUsd(item.usd) }),
  );
}

async function runTollSearch() {
  const button = $("d-search");
  setRunning(true, button, "Cifrando e buscando…");
  try {
    const [a] = windowRange();
    const r = await api("/api/tolls/search", {
      camera_id: +$("d-camera").value, day: $("d-day").value, start_hour: a, hours: +$("d-hours").value,
      demo_n: +$("d-demo-n").value, realistic_n: +$("d-realistic").value,
    });
    const m = r.measured, x = r.extrapolated;
    $("d-stats").replaceChildren(
      ...statRow("veículos na janela (n real)", fmtNumber(r.n)),
      ...statRow("registros gerados e assinados", r.scale > 1 ? `${fmtNumber(r.records_generated)} (amostra; custos escalados)` : fmtNumber(r.records_generated)),
      ...statRow("captura (cifrar + assinar)", `${r.capture_us.toFixed(0)} µs por registro`),
      ...statRow("Busca Fechada executada", `${fmtNumber(m.fechada.records)} registros até a placa-alvo (posição ${fmtNumber(r.target_position)}) · ${fmtNumber(m.fechada.attempts)} tent. · ${fmtDuration(m.fechada.seconds)}`),
      ...statRow("Busca Aberta executada", `${fmtNumber(m.aberta.records)} registros · ${fmtNumber(m.aberta.attempts)} tent. · ${fmtDuration(m.aberta.seconds)}`),
      ...statRow("tempo por tentativa medido", `${(r.seconds_per_attempt * 1e6).toFixed(2)} µs`),
      el("div", { class: "sep" }),
      ...statRow(`extrapolado para N = ${fmtNumber(r.realistic_n)}`, ""),
    );
    $("d-costs").replaceChildren(
      costRow("Busca Fechada nesta janela (média)", x.fechada, fmtNumber(Math.round(x.fechada.puzzles))),
      costRow("Busca Aberta nesta janela", x.aberta, fmtNumber(r.n)),
      costRow(`Mesma janela com um puzzle por hora (N_B = ${fmtNumber(r.block_n)})`, x.bloco, `${r.window.hours} bloco(s)`),
      costRow(`Esta praça, jan.–set. inteiro`, x.camera_periodo, fmtNumber(r.camera_period_records)),
      costRow("Toda a rede pedagiada, 1 ano", x.rede_ano, fmtNumber(Math.round(r.network_year_records))),
    );
    $("d-result").hidden = false;
  } catch (error) {
    $("d-note").textContent = `Erro: ${error.message}`;
  } finally {
    setRunning(false, button, "Buscar com volume real");
  }
}

$("d-lot").addEventListener("change", () => { fillCameras($("d-lot").value); loadCamera(); });
$("d-camera").addEventListener("change", loadCamera);
$("d-day").addEventListener("change", loadCamera);
$("d-hour").addEventListener("input", renderCameraCharts);
$("d-hours").addEventListener("input", renderCameraCharts);
$("d-search").addEventListener("click", runTollSearch);
viewHooks.dados = () => { loadTolls(); Charts.rerender(); };
if (!$("view-dados").hidden) loadTolls();
