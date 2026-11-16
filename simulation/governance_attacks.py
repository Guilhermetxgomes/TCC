"""
Attacks on the Governance layer -- what each control catches, and what none of them does.

Like simulation/tampering.py, every attack returns the checks a verifier runs, in order,
each with whether it detected the abuse:

    {"attack", "title", "contained", "headline", "checks": [{label, detected, detail}], "undo"}

They run against the live simulation (World + Servidor). Refusals the Servidor writes to
its log stay there -- a refused attempt is part of the record. What changes the database
(deleting or rewriting log entries) or adds declarations is returned in `undo`, so the web
app can restore it (restore()).

1. expired     -- a Busca Fechada token used after its deadline            -> the gate refuses
2. scope       -- a Busca Aberta token used on another camera / window       -> the gate refuses
3. operator    -- a token used by an officer it was not issued to            -> the gate refuses
4. budget      -- a Busca Fechada that goes beyond its record budget         -> the gate refuses
5. forged      -- a real token with its budget edited by the holder          -> the gate refuses
6. log_delete  -- the operator deletes a release from the log                -> the chain shows it
7. log_rewrite -- the operator deletes it and rewrites (and re-signs) the tail -> only the checkpoint shows it
8. misuse      -- a token for the criminal's plate used to follow someone else -> only the Auditor sees it
9. total_unpublished -- a Busca Total that is not published in the bulletin -> the members refuse
10. offlog_dump -- the operator copies the database without going through the gate
                -> nothing in the log; only the puzzle cost remains
"""
import time
from dataclasses import replace

from crypto import hashchain
from crypto.puzzle import solve_puzzle
from services.auditor import Auditor
from services.custody import AuthorizationError, CustodyGateway
from services.governance import DEFAULT_OPERATOR
from services.judge import add_seconds
from simulation import costs
from simulation.investigation import DEFAULT_REALISTIC_N, Investigator

ATTACKS = ("expired", "scope", "operator", "budget", "forged", "log_delete", "log_rewrite", "misuse",
           "total_unpublished", "offlog_dump")
OTHER_OPERATOR = "PC-0099"


def _check(label: str, detected: bool, detail: str) -> dict:
    return {"label": label, "detected": detected, "detail": detail}


def _result(attack: str, title: str, checks: list[dict], contained: bool, headline: str, undo=None, **extra) -> dict:
    return {"attack": attack, "title": title, "checks": checks, "contained": contained, "headline": headline,
            "undo": undo, **extra}


def _gateway(world, server, now: str) -> CustodyGateway:
    gov = world.governance
    return CustodyGateway(server, world.run_id, gov.judge.public_key, gov.audit_log(server, world.run_id), lambda: now)


def _try(gateway: CustodyGateway, token, operator: str, camera: int, start: str, end: str):
    try:
        return gateway.release_window(token, operator, camera, start, end), None
    except AuthorizationError as error:
        return None, error


def _crime_window(world, ticks: int = 6):
    crime, clock = world.crime, world.clock
    return clock.iso(max(crime.tick - ticks, 0)), clock.iso(crime.tick + ticks)


def _gate_checks(error, rows, what: str) -> list[dict]:
    if error is None:
        return [_check("Servidor (verificação do token)", False, f"liberou {len(rows)} registro(s) {what}")]
    return [
        _check("Servidor (verificação do token)", True, f"recusou: {error.reason}"),
        _check("Log do Servidor", True, f"a tentativa recusada ficou registrada (entrada {error.entry['seq']}, "
                                        f"operador {error.entry['operator_id']}, token {error.entry['token_id']})"),
    ]


def _reconcile(world, server) -> dict:
    report = Auditor.for_world(world).reconcile(world, server)
    return {"ok": report["ok"], "grave": report["totals"]["grave"], "warnings": report["totals"]["warnings"]}


def _ensure_logged_search(graph, server, world) -> None:
    """Some attacks need releases (and a checkpoint) in the log: run one honest Busca Fechada."""
    if not any(e["kind"] == "release" for e in server.get_audit_log(world.run_id)) or not world.governance.checkpoints:
        Investigator(graph, server, world).busca_fechada()


# -- 1-5: the gate -------------------------------------------------------------------------

def expired(graph, server, world, **_) -> dict:
    gov, crime = world.governance, world.crime
    issued = world.investigation_time()
    token = gov.judge.issue_fechada(DEFAULT_OPERATOR, crime.plate, issued, validity_seconds=86400)
    late = add_seconds(token.expires_at, 3600)
    start, end = _crime_window(world)
    rows, error = _try(_gateway(world, server, late), token, DEFAULT_OPERATOR, crime.node, start, end)
    checks = _gate_checks(error, rows, "com o token vencido")
    return _result("expired", "Token vencido", checks, error is not None,
                   f"token {token.token_id} venceu em {token.expires_at[:16]}; pedido em {late[:16]}")


def scope(graph, server, world, **_) -> dict:
    gov, crime = world.governance, world.crime
    start, end = _crime_window(world)
    token = gov.judge.issue_aberta(DEFAULT_OPERATOR, crime.node, start, end, world.investigation_time())
    other = next(iter(graph.next_probs(crime.node, None)))
    gateway = _gateway(world, server, world.investigation_time())
    rows, error = _try(gateway, token, DEFAULT_OPERATOR, other, start, end)
    checks = _gate_checks(error, rows, f"da câmera {other}")
    wider_end = world.clock.iso(crime.tick + 360)
    rows2, error2 = _try(gateway, token, DEFAULT_OPERATOR, crime.node, start, wider_end)
    checks += [c for c in _gate_checks(error2, rows2, "de uma janela de uma hora") if c["label"].startswith("Servidor")]
    checks[-1]["label"] = "Servidor (janela maior na mesma câmera)"
    return _result("scope", "Fora do escopo da Busca Aberta", checks, error is not None and error2 is not None,
                   f"token {token.token_id} vale para a câmera {crime.node}, {start[11:19]}–{end[11:19]}; pedidos: "
                   f"câmera {other} e a câmera {crime.node} por uma hora")


def operator(graph, server, world, **_) -> dict:
    gov, crime = world.governance, world.crime
    token = gov.judge.issue_fechada(DEFAULT_OPERATOR, crime.plate, world.investigation_time())
    start, end = _crime_window(world)
    rows, error = _try(_gateway(world, server, world.investigation_time()), token, OTHER_OPERATOR,
                       crime.node, start, end)
    return _result("operator", "Token usado por outro operador", _gate_checks(error, rows, f"para {OTHER_OPERATOR}"),
                   error is not None, f"token {token.token_id} emitido para {DEFAULT_OPERATOR}, usado por {OTHER_OPERATOR}")


def budget(graph, server, world, budget_records: int = 3, **_) -> dict:
    investigator = Investigator(graph, server, world, budget_records=budget_records)
    result = investigator.busca_fechada(max_hops=None)
    denied = [s for s in result["steps"] if s["kind"] == "denied"]
    released = sum(s["records_in_window"] for s in result["steps"] if s["kind"] == "probe")
    token = investigator.tokens[0]
    if denied:
        checks = [
            _check("Servidor (orçamento do token)", True, f"liberou {released} de {budget_records} registros e recusou "
                   f"a janela seguinte: {denied[0]['reason']}"),
            _check("Log do Servidor", True, "liberações e recusa registradas; o saldo é contado a partir do próprio log"),
        ]
    else:
        checks = [_check("Servidor (orçamento do token)", False, f"a busca coube no orçamento ({released} registros)")]
    return _result("budget", "Orçamento da Busca Fechada esgotado", checks, bool(denied),
                   f"token {token.token_id} com orçamento de {budget_records} registros; a busca seguiu "
                   f"{len(result['paths'][0]['nodes']) if result['paths'] else 0} câmeras e parou")


def forged(graph, server, world, **_) -> dict:
    gov, crime = world.governance, world.crime
    token = gov.judge.issue_fechada(DEFAULT_OPERATOR, crime.plate, world.investigation_time(), budget_records=10)
    edited = replace(token, scope={**token.scope, "budget_records": 10**9},
                     expires_at=add_seconds(token.expires_at, 365 * 86400))
    start, end = _crime_window(world)
    rows, error = _try(_gateway(world, server, world.investigation_time()), edited, DEFAULT_OPERATOR,
                       crime.node, start, end)
    return _result("forged", "Token adulterado", _gate_checks(error, rows, "com o token adulterado"), error is not None,
                   f"o portador do token {token.token_id} aumentou o orçamento de 10 para 10⁹ registros e o prazo "
                   "em um ano, sem a chave do juiz")


# -- 6-7: the log ------------------------------------------------------------------------

def _target_release(world, server, covered_only: bool):
    last_checkpoint = world.governance.checkpoints[-1]["seq"] if world.governance.checkpoints else 0
    releases = [e for e in server.get_audit_log(world.run_id) if e["kind"] == "release" and e["records"]
                and (not covered_only or e["seq"] <= last_checkpoint)]
    return max(releases, key=lambda e: e["records"]) if releases else None


def log_delete(graph, server, world, **_) -> dict:
    _ensure_logged_search(graph, server, world)
    target = _target_release(world, server, covered_only=False)
    server.delete_audit(world.run_id, [target["seq"]])
    gov = world.governance
    chain = hashchain.verify(server.get_audit_log(world.run_id), (), gov.server_log_public_key)
    covered = bool(gov.checkpoints) and target["seq"] <= gov.checkpoints[-1]["seq"]
    checks = [
        _check("Cadeia de hash", not chain["ok"], "; ".join(f"entrada {p['seq']}: {p['detail']}" for p in chain["problems"])
               or "nenhum problema (era a última entrada)"),
        _check("Checkpoint do Conselho", covered, "a entrada apagada já estava coberta por um checkpoint"
               if covered else "a entrada é posterior ao último checkpoint"),
    ]
    return _result("log_delete", "Apagar uma liberação do log", checks, not chain["ok"],
                   f"o operador apagou a entrada {target['seq']} ({target['records']} registros liberados sob "
                   f"{target['token_id']})", undo={"kind": "reinsert", "entries": [target]},
                   reconciliation=_reconcile(world, server))


def log_rewrite(graph, server, world, **_) -> dict:
    _ensure_logged_search(graph, server, world)
    gov = world.governance
    target = _target_release(world, server, covered_only=True)
    log = server.get_audit_log(world.run_id)
    originals = [e for e in log if e["seq"] >= target["seq"]]
    head = next((e for e in log if e["seq"] == target["seq"] - 1), None)
    rewritten = []
    for entry in originals[1:]:  # drop the target, re-number, re-link and re-sign everything after it
        head = hashchain.link(head, {k: v for k, v in hashchain.content_of(entry).items() if k != "seq"},
                              gov.server_log_key)
        rewritten.append(head)
    server.delete_audit(world.run_id, [e["seq"] for e in originals])
    for entry in rewritten:
        server.append_audit(world.run_id, entry)
    entries = server.get_audit_log(world.run_id)
    # Only problems in the rewritten part count (an earlier attack may still be unrestored).
    tail = lambda report, kinds: [p for p in report["problems"] if p["seq"] >= target["seq"] and p["kind"] in kinds]
    chain = hashchain.verify(entries, (), gov.server_log_public_key)
    with_cp = hashchain.verify(entries, gov.checkpoints, gov.server_log_public_key)
    links = tail(chain, ("seq", "link", "edited"))
    signatures = tail(chain, ("signature",))
    checkpoint = tail(with_cp, ("checkpoint", "truncated"))
    checks = [
        _check("Cadeia de hash", bool(links), "a cauda foi reencadeada: cada entrada aponta para a anterior"
               if not links else "; ".join(p["detail"] for p in links)),
        _check("Assinatura do Servidor", bool(signatures), "o operador tem a chave de assinatura do log e reassinou tudo"),
        _check("Checkpoint do Conselho", bool(checkpoint),
               "; ".join(p["detail"] for p in checkpoint) or "nenhum checkpoint cobre a parte reescrita"),
    ]
    return _result("log_rewrite", "Reescrever o log", checks, bool(checkpoint or links),
                   f"o operador apagou a entrada {target['seq']} e reescreveu e reassinou as {len(rewritten)} seguintes",
                   undo={"kind": "replace_tail", "from_seq": target["seq"], "entries": originals},
                   reconciliation=_reconcile(world, server))


# -- 8: misuse of a token, seen only by the Auditor -------------------------------------

def misuse(graph, server, world, **_) -> dict:
    gov, crime = world.governance, world.crime
    victim = next(v for v in world.vehicles if v.plate != crime.plate and len(v.arrivals) >= 6)
    investigator = Investigator(graph, server, world)
    token = investigator._token_fechada(crime.plate)  # the order names the criminal's plate...
    before = len(gov.declarations)
    tick, node = victim.arrivals[0]
    first = investigator._probe(node, tick, tick, victim.plate)  # ...but the officer follows someone else
    steps, path, _ = investigator._trace(victim.plate, node, tick, 4, victim.plate) if first["found"] else ([], [], None)
    for declaration in gov.declarations[before:]:
        declaration["source"] = "ataque:misuse"
    hits = sum(1 for d in gov.declarations[before:] if d["kind"] == "acerto")
    released = first["records_in_window"] + sum(s.get("records_in_window", 0) for s in steps)
    report = Auditor.for_world(world).reconcile(world, server)
    misuse_flags = [d for d in report["discrepancies"] if d["token_id"] == token.token_id and d["kind"] == "desvio de finalidade"]
    checks = [
        _check("Servidor (verificação do token)", False, f"liberou {released} registros: o token é válido e o Servidor "
               "não vê a placa (só o HMAC)"),
        _check("Auditor (reconciliação)", bool(misuse_flags), f"{len(misuse_flags)} de {hits} acerto(s) declarado(s) com "
               "placa que não é a do token: HMAC(placa) ≠ HMAC do token"),
        _check("Sem declaração (ou tudo como colateral)", False, "o Auditor só veria registros liberados sem nenhum "
               "acerto: alerta, não prova"),
    ]
    return _result("misuse", "Desvio de finalidade do token", checks, bool(misuse_flags),
                   f"token {token.token_id} emitido para a placa do crime, usado para seguir outro veículo por "
                   f"{len(path)} câmeras", undo={"kind": "declarations", "source": "ataque:misuse"},
                   reconciliation={"ok": report["ok"], "grave": report["totals"]["grave"],
                                   "warnings": report["totals"]["warnings"]})


# -- 9: Busca Total without the public trace ----------------------------------------------

def total_unpublished(graph, server, world, **_) -> dict:
    if world.committee is None:
        raise ValueError("simulação sem custódia: a Busca Total não está disponível")
    head_before = server.get_audit_head(world.run_id)
    try:
        Investigator(graph, server, world).busca_total(publish=False)
        refused, reason = False, "o Comitê decifrou sem publicação"
    except PermissionError as error:
        refused, reason = True, str(error)
    head_after = server.get_audit_head(world.run_id)
    released = (head_after or {}).get("seq") != (head_before or {}).get("seq")
    checks = [
        _check("Membros do Comitê", refused, f"recusaram a decifragem parcial: {reason}" if refused else reason),
        _check("Servidor", not released, "nenhum encapsulamento nem registro foi liberado" if not released
               else "encapsulamentos liberados"),
    ]
    return _result("total_unpublished", "Busca Total sem publicação", checks, refused,
                   "o pedido da Busca Total chegou ao Comitê com token válido, mas sem recibo do boletim público")


# -- 10: what governance cannot see --------------------------------------------------------

def offlog_dump(graph, server, world, realistic_n: int = DEFAULT_REALISTIC_N, **_) -> dict:
    head_before = server.get_audit_head(world.run_id)
    before = _reconcile(world, server)
    rows = []
    for camera in sorted(server.count_by_camera(world.run_id)):
        rows += server.get_rows_in_window(world.run_id, camera, "0000", "9999")  # straight from the database
    started, attempts = time.perf_counter(), 0
    sample = rows[:20]
    for row in sample:
        if row["record"].block is None:
            attempts += solve_puzzle(row["record"])["attempts"]
    seconds_per_attempt = (time.perf_counter() - started) / attempts if attempts else 0.0
    estimate = costs.estimate(len(rows), 1, seconds_per_attempt, realistic_n)
    head_after = server.get_audit_head(world.run_id)
    report = _reconcile(world, server)
    unchanged = (head_after or {}).get("seq") == (head_before or {}).get("seq")
    checks = [
        _check("Log do Servidor", not unchanged, f"nenhuma entrada nova: {len(rows)} registros copiados por fora do portão"),
        _check("Auditor (reconciliação)", report["grave"] > before["grave"],
               "nenhuma discrepância nova: a cópia não passou por token nem por log"),
        _check("Custo dos puzzles", True, f"o conteúdo continua cifrado: abrir os {len(rows)} registros com "
               f"N = {realistic_n:.0e} custa ~{estimate['estimated_seconds'] / 3600:,.0f} h de um núcleo "
               f"(US$ {estimate['estimated_usd']:,.2f})"),
    ]
    return _result("offlog_dump", "Cópia do banco por fora do log", checks, True,
                   "governança não vê o que não passa pelo portão; o que sobra é o custo computacional",
                   estimate=estimate, records=len(rows), reconciliation=report)


def run(attack: str, graph, server, world, **params) -> dict:
    if world.governance is None:
        raise ValueError("simulação sem governança")
    if attack not in ATTACKS:
        raise ValueError(f"ataque desconhecido: {attack!r}")
    return globals()[attack](graph, server, world, **params)


def restore(server, world, undo_list: list[dict]) -> int:
    """Undoes what the attacks changed (most recent first). Returns how many undos were applied."""
    gov = world.governance
    for undo in reversed(undo_list):
        if undo["kind"] == "reinsert":
            for entry in undo["entries"]:
                server.append_audit(world.run_id, entry)
        elif undo["kind"] == "replace_tail":
            # Entries logged after the rewrite (and checkpoints of them) are discarded with it.
            current = server.get_audit_log(world.run_id)
            server.delete_audit(world.run_id, [e["seq"] for e in current if e["seq"] >= undo["from_seq"]])
            for entry in undo["entries"]:
                server.append_audit(world.run_id, entry)
            last = undo["entries"][-1]["seq"] if undo["entries"] else undo["from_seq"] - 1
            gov.checkpoints[:] = [c for c in gov.checkpoints if c["seq"] <= last]
        elif undo["kind"] == "declarations":
            gov.declarations[:] = [d for d in gov.declarations if d.get("source") != undo["source"]]
    return len(undo_list)
