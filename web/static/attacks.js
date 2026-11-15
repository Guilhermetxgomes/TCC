"use strict";
// View 2: the same attacks against a conventional ALPR backend and against the Nêmesis,
// both holding the captures of the simulation generated in view 1 (/api/attack).

const ATTACK_LABELS = {
  dump: "Vazamento / vigilância em massa",
  track: "Perseguição pela placa",
  move: "Álibi falso (mover registro)",
  forge: "Troca de placa",
};

const ATTACK_NOTES = {
  dump: "Os dois sistemas recebem o mesmo tempo de ataque para ler o máximo de placas.",
  track: "O atacante conhece só a placa de um veículo qualquer (não o do crime), sem saber onde nem quando ele passou.",
  move: "Alvo: o registro do carro do crime na câmera do crime. O operador muda a câmera e o instante da linha.",
  forge: "Alvo: o registro do carro do crime na câmera do crime. O operador troca a placa: no Nêmesis, resolve o puzzle e "
    + "recifra outra placa com a mesma chave K.",
};

const attackState = { summary: new Map() };

function updateAttackUi() {
  const attack = $("a-attack").value;
  const reading = attack === "dump" || attack === "track";
  $("la-budget").hidden = !reading;
  $("la-realistic").hidden = !reading;
  $("la-plate").hidden = attack !== "track";
  $("la-fake").hidden = attack !== "forge";
  $("la-target").hidden = attack !== "move";
  $("la-shift").hidden = attack !== "move";
  $("la-persist").hidden = reading;
  $("a-note").textContent = ATTACK_NOTES[attack];
}

function verdictBox(side, blockedText, openText) {
  const box = el("div", { class: `verdict ${side.blocked ? "blocked" : "open"}` },
    el("span", { class: "verdict-tag", text: side.blocked ? blockedText : openText }),
    el("strong", { text: side.headline }),
  );
  const list = el("ul", {});
  for (const detail of side.details) list.append(el("li", { text: detail }));
  box.append(list);
  return box;
}

function renderAttack(result) {
  $("a-conv").className = "verdict-box";
  $("a-nem").className = "verdict-box";
  $("a-conv").replaceChildren(verdictBox(result.conventional, "ataque bloqueado", "✗ ataque bem-sucedido"));
  $("a-nem").replaceChildren(verdictBox(result.nemesis, "✓ ataque contido", "✗ ataque bem-sucedido"));
  attackState.summary.set(result.attack, result);
  const rows = [...attackState.summary.values()].map((r) => el("tr", {},
    el("td", { text: ATTACK_LABELS[r.attack] }),
    el("td", { class: r.conventional.blocked ? "ok-text" : "bad-text", text: (r.conventional.blocked ? "✓ " : "✗ ") + r.conventional.headline }),
    el("td", { class: r.nemesis.blocked ? "ok-text" : "bad-text", text: (r.nemesis.blocked ? "✓ " : "✗ ") + r.nemesis.headline }),
  ));
  $("a-summary").replaceChildren(...rows);
  $("a-summary-card").hidden = false;
}

async function runAttack(attack, persist) {
  const result = await api("/api/attack", {
    run_id: state.sim.run_id, attack, realistic_n: +$("a-realistic").value, budget_seconds: +$("a-budget").value,
    plate: $("a-plate").value, fake_plate: $("a-fake").value, target_node: +$("a-target").value,
    shift_minutes: +$("a-shift").value, persist,
  });
  renderAttack(result);
  if (result.tamper && result.tamper.persisted) $("a-restore").disabled = false;
  return result;
}

async function runOneAttack() {
  if (!state.sim) return;
  const button = $("a-run-one");
  setRunning(true, button, "Atacando…");
  try {
    await runAttack($("a-attack").value, $("a-persist").checked);
  } catch (error) {
    $("a-note").textContent = `Erro: ${error.message}`;
  } finally {
    setRunning(false, button, "Atacar os dois sistemas");
  }
}

async function runAllAttacks() {
  if (!state.sim) return;
  const button = $("a-run-all");
  setRunning(true, button, "Rodando…");
  try {
    for (const attack of ["dump", "track", "move", "forge"]) {
      $("a-attack").value = attack;
      updateAttackUi();
      // both tampering attacks target the same record: neither is written to the database here
      await runAttack(attack, false);
    }
    $("a-note").textContent = "Os quatro ataques foram executados; as adulterações não foram gravadas no banco.";
  } catch (error) {
    $("a-note").textContent = `Erro: ${error.message}`;
  } finally {
    setRunning(false, button, "Rodar os quatro ataques");
  }
}

async function restoreAttacks() {
  try {
    const result = await api("/api/tamper/restore", { run_id: state.sim.run_id });
    $("a-restore").disabled = true;
    $("a-note").textContent = result.restored.length
      ? `Bancos restaurados (registro ${result.restored.join(", ")} do Nêmesis e a cópia convencional).`
      : "Cópia convencional restaurada; nada a restaurar no Nêmesis.";
  } catch (error) {
    $("a-note").textContent = `Erro: ${error.message}`;
  }
}

window.onSimulationLoaded = (sim) => {
  $("a-run").textContent = `${sim.params.records} registros, crime na câmera ${sim.crime.node} às ${clockText(sim.crime.tick)}`;
  ["a-run-one", "a-run-all"].forEach((id) => { $(id).disabled = false; });
  $("a-restore").disabled = true;
  attackState.summary.clear();
  $("a-summary-card").hidden = true;
  ["a-conv", "a-nem"].forEach((id) => { $(id).className = "verdict-box muted small"; $(id).textContent = "Escolha um ataque."; });
  const nodes = [...state.graph.nodes].sort((a, b) => a.id - b.id).filter((n) => n.id !== sim.crime.node);
  const far = nodes[nodes.length - 1];
  $("a-target").replaceChildren(...nodes.map((n) => el("option", { value: n.id, text: `${n.id} · ${n.name}`, selected: n.id === far.id })));
};

$("a-attack").addEventListener("change", updateAttackUi);
$("a-run-one").addEventListener("click", runOneAttack);
$("a-run-all").addEventListener("click", runAllAttacks);
$("a-restore").addEventListener("click", restoreAttacks);
updateAttackUi();
