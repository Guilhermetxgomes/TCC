"use strict";
// View 4: governance -- tokens of the judge, the Servidor's chained log, the public bulletin
// of the Busca Total, the Auditor's reconciliation and attacks on all of it (/api/audit*).

const MODE_NAMES = { aberta: "Aberta", fechada: "Fechada", total: "Total" };
const KIND_NAMES = { release: "liberação", release_wraps: "liberação de chaves", denied: "recusa" };
const AUDIT_NOTES = {
  expired: "Um token de Busca Fechada com validade de um dia é usado uma hora depois de vencer.",
  scope: "Um token de Busca Aberta para a janela do crime é usado em outra câmera e numa janela de uma hora.",
  operator: "O token emitido para o policial PC-0042 é apresentado pelo PC-0099.",
  budget: "Uma Busca Fechada com orçamento pequeno segue o carro até o Servidor recusar a próxima janela.",
  forged: "O portador do token aumenta o orçamento e o prazo, sem a chave do juiz.",
  log_delete: "O operador do Servidor apaga do banco a liberação com mais registros.",
  log_rewrite: "O operador apaga uma liberação e reencadeia e reassina todo o resto do log com a chave do Servidor.",
  misuse: "Com um token válido para a placa do crime, o policial segue outro veículo e declara o que abriu.",
  total_unpublished: "Um pedido de Busca Total com token válido chega ao Comitê sem recibo do boletim público.",
  offlog_dump: "O operador lê todos os registros direto do banco, sem passar pelo portão do Servidor.",
};

const auditState = { data: null };

function shortHash(hash) {
  return hash ? `${hash.slice(0, 10)}…` : "—";
}

function timeOf(iso) {
  return iso ? iso.slice(11, 19) : "—";
}

function tile(value, label, cls = "") {
  return el("div", { class: "tile" },
    el("span", { class: `tile-value ${cls}`, text: value }),
    el("span", { class: "tile-label", text: label }));
}

function renderAudit(data) {
  auditState.data = data;
  const r = data.reconciliation, t = r.totals;
  $("g-tiles").replaceChildren(
    tile(String(t.tokens), "tokens emitidos"),
    tile(fmtNumber(t.released), `registros liberados em ${t.releases} liberações`),
    tile(String(t.denied), "pedidos recusados", t.denied ? "bad-text" : ""),
    tile(`${t.verified}/${t.declared}`, "decifragens conferidas / declaradas"),
    tile(String(t.log_entries), `entradas no log · ${t.checkpoints} checkpoints`),
    tile(String(t.grave), "discrepâncias graves", t.grave ? "bad-text" : "ok-text"),
  );

  const box = el("div", { class: `verdict ${r.ok ? "blocked" : "open"}` },
    el("span", { class: "verdict-tag", text: r.ok ? "✓ reconciliação limpa" : "✗ discrepâncias encontradas" }),
    el("strong", { text: r.ok
      ? "Todo registro liberado tem token válido, e toda decifragem declarada confere."
      : `${t.grave} discrepância(s) grave(s) e ${t.warnings} alerta(s).` }));
  if (r.discrepancies.length) {
    const list = el("ul", { class: "disc" });
    for (const d of r.discrepancies.slice(0, 40)) {
      list.append(el("li", { class: d.severity === "grave" ? "grave" : "atencao",
        text: `${d.severity === "grave" ? "grave" : "atenção"} · ${d.kind}${d.token_id ? ` · ${d.token_id}` : ""}: ${d.detail}` }));
    }
    if (r.discrepancies.length > 40) list.append(el("li", { text: `… e mais ${r.discrepancies.length - 40}` }));
    box.append(list);
  }
  $("g-verdict").className = "verdict-box";
  $("g-verdict").replaceChildren(box);

  $("g-tokens").replaceChildren(...data.tokens.map((tk) => el("tr", {},
    el("td", { class: "mono", text: tk.token_id }),
    el("td", { text: MODE_NAMES[tk.mode] }),
    el("td", { text: tk.operator_id }),
    el("td", { text: tk.scope_text }),
    el("td", { text: `${tk.issued_at.slice(5, 16).replace("T", " ")} → ${tk.expires_at.slice(5, 16).replace("T", " ")}` }),
    el("td", { text: tk.mode === "fechada" ? `${tk.released} / ${tk.scope.budget_records}` : String(tk.released) }),
    el("td", { class: tk.denied ? "bad-text" : "", text: String(tk.denied) }),
    el("td", { class: tk.invalid ? "bad-text" : "", title: "acertos + colaterais (terceiros abertos no caminho)",
      text: tk.mode === "total" ? "— (boletim)" : `${tk.declared} / ${tk.verified}` + (tk.collateral ? ` (${tk.collateral} colat.)` : "") }),
    el("td", { class: tk.flags ? "bad-text" : "ok-text", text: tk.flags ? `${tk.flags}` : "✓" }),
  )));

  const checkpoints = new Set(data.checkpoints.map((c) => c.seq));
  $("g-chain").textContent = data.chain.ok
    ? `Cadeia íntegra: ${data.chain.length} entradas, último hash ${shortHash(data.chain.head)}.`
    : `Cadeia com ${data.chain.problems.length} problema(s).`;
  $("g-chain").className = data.chain.ok ? "ok-text" : "bad-text";
  $("g-log").replaceChildren(...[...data.log].reverse().map((e) => el("tr", {
      class: (e.broken ? "broken" : "") + (e.kind === "denied" ? " denied" : ""),
      title: e.kind === "denied" ? e.detail.reason : (e.detail.record_ids ? `registros ${e.detail.record_ids.join(", ")}` : false) },
    el("td", {}, el("span", { text: String(e.seq) }),
      checkpoints.has(e.seq) ? el("span", { class: "checkpoint-mark", text: "◆", title: "checkpoint do Conselho" }) : ""),
    el("td", { text: timeOf(e.at) }),
    el("td", { text: KIND_NAMES[e.kind] || e.kind }),
    el("td", { class: "mono", text: e.token_id || "—" }),
    el("td", { text: e.operator_id || "—" }),
    el("td", { text: e.camera_id === null ? "—" : String(e.camera_id) }),
    el("td", { text: e.window_start ? (e.window_start.length > 10 ? `${timeOf(e.window_start)}–${timeOf(e.window_end)}` : e.window_start) : "—" }),
    el("td", { text: String(e.records) }),
    el("td", { class: "mono", text: shortHash(e.prev_hash) }),
    el("td", { class: "mono", text: shortHash(e.hash) }),
    el("td", { class: e.broken ? "bad-text" : "ok-text", text: e.broken ? "✗" : "✓" }),
  )));

  $("g-bulletin").replaceChildren(...(data.bulletin.length ? data.bulletin.map((b) => el("tr", { class: b.broken ? "broken" : "" },
    el("td", { text: String(b.seq) }),
    el("td", { text: b.kind === "activation" ? "ativação" : "fechamento" }),
    el("td", { class: "mono", text: b.token_id }),
    el("td", { text: b.kind === "activation"
      ? `${b.detail.sessions ? b.detail.sessions.join(", ") : b.detail.period}; ${b.detail.camera_ids ? `câmeras ${b.detail.camera_ids.join(", ")}` : "todas as câmeras"}; membros ${(b.detail.members || []).join(", ")}; ${b.detail.reason || ""}`
      : `${b.detail.wraps_opened} chaves de sessão, ${fmtNumber(b.detail.records_opened)} registros, ${b.detail.plates_exposed} placas expostas` }),
    el("td", { class: "mono", text: shortHash(b.hash) }),
  )) : [el("tr", {}, el("td", { colspan: 5, class: "muted", text: "Nenhuma Busca Total executada." }))]));

  $("g-operators").replaceChildren(...r.by_operator.map((o) => el("tr", {},
    el("td", { text: o.operator_id }),
    el("td", { text: o.month }),
    el("td", { text: `${o.tokens} (${Object.entries(o.by_mode).map(([m, n]) => `${n} ${MODE_NAMES[m].toLowerCase()}`).join(", ")})` }),
    el("td", { text: fmtNumber(o.released) }),
    el("td", { text: `${o.verified} de ${o.declared}` + (o.collateral ? ` (${o.collateral} de terceiros)` : "") }),
  )));
  $("g-restore").disabled = !data.pending_restore;
}

async function refreshAudit() {
  if (!state.sim) return;
  try {
    renderAudit(await api(`/api/audit?run_id=${encodeURIComponent(state.sim.run_id)}`));
  } catch (error) {
    $("g-note").textContent = `Erro: ${error.message}`;
  }
}

function updateAuditUi() {
  const attack = $("g-attack").value;
  $("lg-budget").hidden = attack !== "budget";
  $("g-note").textContent = AUDIT_NOTES[attack];
}

async function runAuditAttack() {
  if (!state.sim) return;
  const button = $("g-run-one");
  setRunning(true, button, "Executando…");
  try {
    const result = await api("/api/audit/attack", {
      run_id: state.sim.run_id, attack: $("g-attack").value, budget_records: +$("g-budget").value,
      realistic_n: 10_000_000,
    });
    const box = el("div", { class: `verdict ${result.contained ? "blocked" : "open"}` },
      el("span", { class: "verdict-tag", text: result.contained ? "✓ detectado" : "✗ não detectado pela governança" }),
      el("strong", { text: `${result.title}: ${result.headline}` }));
    const list = el("ul", { class: "checks" });
    for (const c of result.checks) {
      list.append(el("li", { class: c.detected ? "hit" : "", text: `${c.label}: ${c.detail}` }));
    }
    box.append(list);
    if (result.reconciliation) {
      box.append(el("p", { class: "small muted", text: `Reconciliação depois do ataque: ${result.reconciliation.grave} discrepância(s) grave(s), ${result.reconciliation.warnings} alerta(s).` }));
    }
    $("g-attack-result").className = "verdict-box";
    $("g-attack-result").replaceChildren(box);
    await refreshAudit();
  } catch (error) {
    $("g-note").textContent = `Erro: ${error.message}`;
  } finally {
    setRunning(false, button, "Executar ataque");
  }
}

async function restoreAudit() {
  try {
    const result = await api("/api/audit/restore", { run_id: state.sim.run_id });
    $("g-note").textContent = result.restored
      ? `${result.restored} alteração(ões) desfeita(s). Recusas e liberações registradas no log permanecem: as tentativas aconteceram.`
      : "Nada a restaurar.";
    await refreshAudit();
  } catch (error) {
    $("g-note").textContent = `Erro: ${error.message}`;
  }
}

document.addEventListener("simulation-loaded", (event) => {
  const sim = event.detail;
  $("g-run").textContent = `Simulação ${sim.run_id}: ${sim.params.records} registros, crime na câmera ${sim.crime.node}.`;
  ["g-run-one", "g-refresh"].forEach((id) => { $(id).disabled = false; });
  $("g-attack-result").className = "verdict-box muted small";
  $("g-attack-result").textContent = "Escolha um ataque.";
  if (!$("view-auditoria").hidden) refreshAudit();
});

viewHooks.auditoria = refreshAudit;
$("g-attack").addEventListener("change", updateAuditUi);
$("g-run-one").addEventListener("click", runAuditAttack);
$("g-restore").addEventListener("click", restoreAudit);
$("g-refresh").addEventListener("click", refreshAudit);
updateAuditUi();
