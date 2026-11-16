"""
Checks of the Governance layer (tokens, gate, log, bulletin, Auditor), no database needed:

    python -m tests.test_governance

The functions are also collected by pytest, if it is installed.
"""
from dataclasses import replace

from crypto import hashchain
from crypto.tokens import SigningKey, sign_token, verify_token
from services.auditor import Auditor
from services.committee import Scope
from services.custody import AuthorizationError, CustodyGateway
from services.judge import LegalAuthorizer, add_seconds
from simulation.city_graph import CityGraph
from simulation.engine import run_simulation
from simulation.investigation import Investigator
from simulation.memory_server import MemoryServer
from simulation import governance_attacks

NOW = "2026-01-01T10:00:00+00:00"
_WORLD = {}


def world():
    """One small simulation shared by the tests that need data (built once)."""
    if not _WORLD:
        graph, server = CityGraph.load(), MemoryServer()
        _WORLD.update(graph=graph, server=server, world=run_simulation(
            graph, server, "gov", n_vehicles=60, ticks=200, puzzle_level=100, crime_tick=60, seed=2))
    return _WORLD["graph"], _WORLD["server"], _WORLD["world"]


def gateway(w, server, now=None):
    gov = w.governance
    return CustodyGateway(server, w.run_id, gov.judge.public_key, gov.audit_log(server, w.run_id),
                          lambda: now or w.investigation_time())


def denied(call) -> str:
    try:
        call()
    except AuthorizationError as error:
        return error.reason
    raise AssertionError("the gate should have refused")


def test_token_signature_covers_every_field():
    judge = LegalAuthorizer()
    token = judge.issue_fechada("PC-1", "ABC1234", NOW, budget_records=10)
    assert verify_token(token, judge.public_key)
    for changed in (replace(token, operator_id="PC-2"), replace(token, expires_at=add_seconds(token.expires_at, 1)),
                    replace(token, scope={**token.scope, "budget_records": 11}), replace(token, mode="aberta")):
        assert not verify_token(changed, judge.public_key)
    assert not verify_token(sign_token(token, SigningKey()), judge.public_key)  # signed by someone else
    assert "ABC1234" not in str(token.summary())  # the plate only appears as an HMAC


def test_gate_checks_deadline_operator_scope_and_budget():
    _, server, w = world()
    judge, crime, clock = w.governance.judge, w.crime, w.clock
    start, end = clock.iso(crime.tick - 6), clock.iso(crime.tick + 6)
    now = w.investigation_time()

    closed = judge.issue_fechada("PC-1", crime.plate, now, budget_records=10**6)
    assert gateway(w, server).release_window(closed, "PC-1", crime.node, start, end)
    late = add_seconds(closed.expires_at, 1)
    assert "prazo" in denied(lambda: gateway(w, server, late).release_window(closed, "PC-1", crime.node, start, end))
    assert "operador" in denied(lambda: gateway(w, server).release_window(closed, "PC-2", crime.node, start, end))

    opened = judge.issue_aberta("PC-1", crime.node, start, end, now)
    other = next(iter(_WORLD["graph"].next_probs(crime.node, None)))
    assert "escopo" in denied(lambda: gateway(w, server).release_window(opened, "PC-1", other, start, end))
    assert "escopo" in denied(lambda: gateway(w, server).release_window(opened, "PC-1", crime.node, start,
                                                                        clock.iso(crime.tick + 60)))

    small = judge.issue_fechada("PC-1", crime.plate, now, budget_records=1)
    assert "orçamento" in denied(lambda: gateway(w, server).release_window(small, "PC-1", crime.node, start, end))
    log = server.get_audit_log(w.run_id)
    assert sum(1 for e in log if e["kind"] == "denied") >= 5  # every refusal is logged


def test_chain_detects_edit_delete_and_rewrite_with_checkpoints():
    key = SigningKey()
    entries, head = [], None
    for i in range(6):
        head = hashchain.link(head, {"kind": "release", "records": i}, key)
        entries.append(head)
    checkpoints = [{"seq": 4, "hash": entries[3]["hash"], "at": "t"}]
    assert hashchain.verify(entries, checkpoints, key.public_key_bytes)["ok"]

    edited = [dict(e) for e in entries]
    edited[2]["records"] = 99
    assert {"edited"} <= {p["kind"] for p in hashchain.verify(edited)["problems"]}

    deleted = entries[:2] + entries[3:]
    assert {"seq", "link"} <= {p["kind"] for p in hashchain.verify(deleted)["problems"]}

    rewritten, head = entries[:2], entries[1]  # drop entry 3, re-link and re-sign the tail with the same key
    for entry in entries[3:]:
        head = hashchain.link(head, {k: v for k, v in hashchain.content_of(entry).items() if k != "seq"}, key)
        rewritten.append(head)
    assert hashchain.verify(rewritten, (), key.public_key_bytes)["ok"]  # the chain alone does not see it
    assert not hashchain.verify(rewritten, checkpoints, key.public_key_bytes)["ok"]  # the checkpoint does

    truncated = entries[:3]
    assert "truncated" in {p["kind"] for p in hashchain.verify(truncated, checkpoints)["problems"]}


def test_searches_go_through_the_gate_and_reconcile_clean():
    graph, server, w = world()
    closed = Investigator(graph, server, w).busca_fechada()
    opened = Investigator(graph, server, w).busca_aberta(hint_len=3)
    assert closed["truth"]["followed_criminal"] and opened["truth"]["followed_criminal"]
    assert len(closed["governance"]["tokens"]) == 1
    assert len(opened["governance"]["tokens"]) == 1 + opened["extra"]["suspects_traced"]
    released = {i for e in server.get_audit_log(w.run_id) if e["kind"] == "release" for i in e["detail"]["record_ids"]}
    probed = {s["record_id"] for s in closed["steps"] if s.get("found")}
    assert probed <= released  # every record the search opened was released (and logged)
    report = Auditor.for_world(w).reconcile(w, server)
    assert report["ok"], report["discrepancies"]
    assert report["totals"]["verified"] == report["totals"]["declared"] > 0


def test_committee_requires_token_and_bulletin_receipt():
    graph, server, w = world()
    committee, judge = w.committee, w.governance.judge
    crime_time = w.clock.iso(w.crime.tick)
    period, session = crime_time[:7], crime_time[:10]
    wraps = server.get_session_wraps(w.run_id, period, session)
    members = list(range(1, committee.threshold + 1))

    def refused(scope) -> bool:
        try:
            committee.open_session_keys(scope, wraps, members)
        except PermissionError:
            return True
        return False

    token = judge.issue_total("PC-1", period, [session], None, "teste", NOW)
    assert refused(Scope(period=period, sessions=frozenset({session})))  # no token
    assert refused(Scope(period=period, sessions=frozenset({session}), token=token))  # not published
    other = judge.issue_fechada("PC-1", w.crime.plate, NOW)
    receipt = w.governance.bulletin.publish("activation", NOW, other.token_id, {})
    assert refused(Scope(period=period, sessions=frozenset({session}), token=other, receipt=receipt))  # wrong mode
    receipt = w.governance.bulletin.publish("activation", NOW, token.token_id, {})
    assert refused(Scope(period=period, sessions=None, token=token, receipt=receipt))  # wider than the token
    keys = committee.open_session_keys(Scope(period=period, sessions=frozenset({session}), token=token,
                                             receipt=receipt), wraps, members)
    assert len(keys) == len(wraps)


def test_attacks_are_caught_where_expected_and_restore_cleans_up():
    graph, server, w = world()
    expected_contained = {"expired": True, "scope": True, "operator": True, "budget": True, "forged": True,
                          "log_delete": True, "log_rewrite": True, "misuse": True, "total_unpublished": True}
    undo = []
    for attack, contained in expected_contained.items():
        result = governance_attacks.run(attack, graph, server, w)
        assert result["contained"] == contained, (attack, result["checks"])
        if result["undo"]:
            undo.append(result["undo"])
        if attack == "log_rewrite":  # the chain and the signature do not see it; only the checkpoint does
            assert [c["detected"] for c in result["checks"]] == [False, False, True]
    dump = governance_attacks.run("offlog_dump", graph, server, w)
    assert [c["detected"] for c in dump["checks"]] == [False, False, True]  # only the puzzle cost remains
    governance_attacks.restore(server, w, undo)
    report = Auditor.for_world(w).reconcile(w, server)
    assert report["ok"], [d for d in report["discrepancies"] if d["severity"] == "grave"]


if __name__ == "__main__":
    tests = [(name, fn) for name, fn in sorted(globals().items()) if name.startswith("test_") and callable(fn)]
    for name, fn in tests:
        fn()
        print(f"  [ok] {name}")
    print(f"{len(tests)} tests passed")
