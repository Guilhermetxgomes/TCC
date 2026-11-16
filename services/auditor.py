"""
The Auditor (RF09) and the Conselho's retroactive view (RNF03).

The reconciliation crosses three sources that come from three different entities:

- AUTHORIZED: the tokens the judge issued (services/judge.py), with their scope, deadline
  and budget;
- RELEASED:   the Servidor's log (services/audit_log.py): which rows left the Custódia,
  under which token, when and to whom -- checked first as a chain, against the
  checkpoints the Conselho keeps;
- DECLARED:   what the investigators say they decrypted (services/governance.declare),
  each with its puzzle solution k, so the Auditor confirms it with ONE decryption instead
  of a brute force. In a Busca Fechada the Auditor also checks, with the Judiciary's HMAC
  key, that the plate revealed is the one the token named.

Every mismatch is flagged automatically as a discrepancy ("grave") or a warning
("atenção"). The Busca Total is also crossed with the public bulletin (services/bulletin.py).

What it cannot see: rows read from the database without going through the gate (the
operator copying the database leaves no log entry). Against that the only barrier is the
cost of the puzzles -- see simulation/governance_attacks.offlog_dump.
"""
import base64
from datetime import datetime
from typing import Optional

from cryptography.exceptions import InvalidTag

from crypto import hashchain
from crypto.block_crumpling import block_key_from_secret
from crypto.puzzle import open_record
from crypto.signing import verify_record
from crypto.tokens import plate_commitment, verify_token

RELEASE_KINDS = ("release", "release_wraps")


def _dt(instant: str) -> datetime:
    return datetime.fromisoformat(instant)


def _scope_text(token) -> str:
    scope = token.scope
    if token.mode == "aberta":
        return f"câmera {scope['camera_id']}, {scope['start'][11:19]}–{scope['end'][11:19]}"
    if token.mode == "fechada":
        return f"HMAC(placa) {scope['plate_hmac'][:10]}…, até {scope['budget_records']} registros"
    cameras = "todas as câmeras" if scope["camera_ids"] is None else f"câmeras {scope['camera_ids']}"
    sessions = "o mês inteiro" if scope["sessions"] is None else ", ".join(scope["sessions"])
    return f"{scope['period']}: {sessions}; {cameras}"


class Auditor:
    def __init__(self, judge_public_key: bytes, hmac_key: bytes, server_log_public_key: bytes,
                 camera_keys: dict[int, bytes]):
        self.judge_public_key = judge_public_key
        self.hmac_key = hmac_key
        self.server_log_public_key = server_log_public_key
        self.camera_keys = camera_keys

    @classmethod
    def for_world(cls, world) -> "Auditor":
        gov = world.governance
        return cls(gov.judge.public_key, gov.judge.hmac_key_for_auditor(), gov.server_log_public_key,
                   world.camera_keys)

    def reconcile(self, world, server) -> dict:
        gov = world.governance
        return self.run(gov.judge.issued, server.get_audit_log(world.run_id), gov.checkpoints,
                        gov.bulletin.entries(), gov.declarations, server, world.run_id)

    def run(self, tokens: list, log: list[dict], checkpoints: list[dict], bulletin: list[dict],
            declarations: list[dict], server, run_id: str) -> dict:
        discrepancies = []

        def flag(severity: str, kind: str, detail: str, token_id: Optional[str] = None, seq: Optional[int] = None):
            discrepancies.append({"severity": severity, "kind": kind, "detail": detail, "token_id": token_id,
                                  "seq": seq})

        chain = hashchain.verify(log, checkpoints, self.server_log_public_key)
        for problem in chain["problems"]:
            flag("grave", "log adulterado", f"entrada {problem['seq']}: {problem['detail']}", seq=problem["seq"])
        bulletin_chain = hashchain.verify(bulletin)
        for problem in bulletin_chain["problems"]:
            flag("grave", "boletim adulterado", f"entrada {problem['seq']}: {problem['detail']}", seq=problem["seq"])

        by_id = {token.token_id: token for token in tokens}
        stats = {
            token.token_id: {
                **token.summary(), "scope_text": _scope_text(token), "signature_ok": verify_token(token, self.judge_public_key),
                "releases": 0, "released": 0, "denied": 0, "declared": 0, "verified": 0, "invalid": 0,
                "hits": 0, "collateral": 0,
                "record_ids": set(), "activation": False, "closing": None, "flags": 0,
            }
            for token in tokens
        }
        for token_id, stat in stats.items():
            if not stat["signature_ok"]:
                flag("grave", "token inválido", "token do registro sem assinatura válida do juiz", token_id)

        activations = {e["token_id"] for e in bulletin if e["kind"] == "activation"}
        for entry in bulletin:
            if entry["token_id"] not in by_id:
                flag("grave", "ativação sem token", f"boletim {entry['seq']}: token {entry['token_id']} não foi emitido",
                     entry["token_id"], entry["seq"])
            elif entry["kind"] == "activation":
                stats[entry["token_id"]]["activation"] = True
            elif entry["kind"] == "closing":
                stats[entry["token_id"]]["closing"] = entry["detail"]

        # -- RELEASED vs AUTHORIZED ------------------------------------------------------
        unknown_denials = 0
        for entry in log:
            token = by_id.get(entry["token_id"])
            if entry["kind"] == "denied":
                if token is None:
                    unknown_denials += 1
                else:
                    stats[token.token_id]["denied"] += 1
                continue
            if entry["kind"] not in RELEASE_KINDS:
                continue
            seq = entry["seq"]
            if token is None:
                flag("grave", "liberação sem token", f"entrada {seq}: {entry['records']} registro(s) liberados sob o "
                     f"token {entry['token_id']}, que o juiz não emitiu", entry["token_id"], seq)
                continue
            stat = stats[token.token_id]
            if not (_dt(token.issued_at) <= _dt(entry["at"]) < _dt(token.expires_at)):
                flag("grave", "fora do prazo", f"entrada {seq}: liberação em {entry['at'][:16]}, token vale de "
                     f"{token.issued_at[:16]} a {token.expires_at[:16]}", token.token_id, seq)
            if entry["operator_id"] != token.operator_id:
                flag("grave", "operador diferente", f"entrada {seq}: liberado para {entry['operator_id']}, token de "
                     f"{token.operator_id}", token.token_id, seq)
            if entry["mode"] != token.mode:
                flag("grave", "modalidade diferente", f"entrada {seq}: registrada como {entry['mode']}", token.token_id, seq)
            if token.mode == "aberta" and entry["kind"] == "release":
                scope = token.scope
                if (entry["camera_id"] != scope["camera_id"] or _dt(entry["window_start"]) < _dt(scope["start"])
                        or _dt(entry["window_end"]) > _dt(scope["end"])):
                    flag("grave", "fora do escopo", f"entrada {seq}: câmera {entry['camera_id']} "
                         f"{entry['window_start'][11:19]}–{entry['window_end'][11:19]} fora de {_scope_text(token)}",
                         token.token_id, seq)
            if token.mode == "total":
                if not stat["activation"]:
                    flag("grave", "Busca Total sem rastro público", f"entrada {seq}: liberação da Busca Total sem "
                         "ativação publicada no boletim", token.token_id, seq)
                scope = token.scope
                if entry["kind"] == "release" and (
                        (scope["camera_ids"] is not None and entry["camera_id"] not in scope["camera_ids"])
                        or (scope["sessions"] is not None and entry["window_start"] not in scope["sessions"])):
                    flag("grave", "fora do escopo", f"entrada {seq}: câmera {entry['camera_id']} / "
                         f"{entry['window_start']} fora de {_scope_text(token)}", token.token_id, seq)
            if entry["kind"] == "release":
                stat["releases"] += 1
                stat["released"] += entry["records"]
                stat["record_ids"].update(entry["detail"].get("record_ids", []))
                if token.mode == "fechada" and stat["released"] > token.scope["budget_records"]:
                    flag("grave", "orçamento excedido", f"entrada {seq}: {stat['released']} registros liberados, "
                         f"orçamento de {token.scope['budget_records']}", token.token_id, seq)

        # -- DECLARED vs RELEASED and AUTHORIZED -----------------------------------------
        headers = {}
        for declaration in declarations:
            token = by_id.get(declaration["token_id"])
            if token is None:
                flag("grave", "declaração sem token", f"registro {declaration['record_id']} declarado sob o token "
                     f"{declaration['token_id']}, que o juiz não emitiu", declaration["token_id"])
                continue
            stat = stats[token.token_id]
            stat["declared"] += 1
            problem = self._check_declaration(declaration, token, stat, server, run_id, headers)
            if problem is None:
                stat["verified"] += 1
                stat["collateral" if declaration.get("kind") == "colateral" else "hits"] += 1
            else:
                stat["invalid"] += 1
                flag("grave", problem[0], f"registro {declaration['record_id']}: {problem[1]}", token.token_id)

        for token in tokens:
            stat = stats[token.token_id]
            if token.mode == "fechada" and stat["released"] and not stat["hits"]:
                flag("atenção", "liberação sem acerto declarado", f"{stat['released']} registro(s) liberados e nenhum "
                     "acerto declarado: busca sem sucesso ou uso não declarado do token", token.token_id)
            if token.mode == "total" and stat["closing"] is not None:
                opened = stat["closing"].get("records_opened", 0)
                if opened > stat["released"]:
                    flag("grave", "boletim × log", f"o boletim declara {opened} registros abertos, o log mostra "
                         f"{stat['released']} liberados", token.token_id)
            stat["flags"] = sum(1 for d in discrepancies if d["token_id"] == token.token_id)

        # -- the Conselho's view: volume per operator and month (RNF03) -------------------
        by_operator: dict[tuple, dict] = {}
        for token in tokens:
            stat = stats[token.token_id]
            key = (token.operator_id, token.issued_at[:7])
            row = by_operator.setdefault(key, {"operator_id": key[0], "month": key[1], "tokens": 0, "released": 0,
                                               "declared": 0, "verified": 0, "collateral": 0, "by_mode": {}})
            row["tokens"] += 1
            row["released"] += stat["released"]
            row["declared"] += stat["declared"]
            row["verified"] += stat["verified"]
            row["collateral"] += stat["collateral"]
            row["by_mode"][token.mode] = row["by_mode"].get(token.mode, 0) + 1

        token_rows = []
        for stat in stats.values():
            stat = {**stat, "record_ids": len(stat["record_ids"])}
            token_rows.append(stat)
        grave = [d for d in discrepancies if d["severity"] == "grave"]
        return {
            "ok": not grave,
            "chain": chain,
            "bulletin_chain": bulletin_chain,
            "tokens": token_rows,
            "discrepancies": discrepancies,
            "by_operator": sorted(by_operator.values(), key=lambda r: (r["month"], r["operator_id"])),
            "totals": {
                "tokens": len(tokens), "log_entries": len(log),
                "releases": sum(1 for e in log if e["kind"] in RELEASE_KINDS),
                "released": sum(s["released"] for s in stats.values()),
                "denied": sum(1 for e in log if e["kind"] == "denied"),
                "unknown_denials": unknown_denials,
                "declared": len(declarations), "verified": sum(s["verified"] for s in stats.values()),
                "collateral": sum(s["collateral"] for s in stats.values()),
                "grave": len(grave), "warnings": len(discrepancies) - len(grave),
                "checkpoints": len(checkpoints), "bulletin_entries": len(bulletin),
            },
        }

    def _check_declaration(self, declaration, token, stat, server, run_id, headers) -> Optional[tuple[str, str]]:
        """None when the declaration checks; otherwise (kind, detail)."""
        record_id = declaration["record_id"]
        if record_id not in stat["record_ids"]:
            return "decifrado sem liberação", "não foi liberado sob este token (obtido por fora do Servidor?)"
        record = server.get_record_by_id(run_id, record_id)
        if record is None or not verify_record(record, self.camera_keys.get(record.camera_id)):
            return "registro inválido", "não existe mais ou não confere com a assinatura da câmera"
        prefix = b""
        try:
            if record.block is not None:
                key = (record.camera_id, record.block)
                if key not in headers:
                    headers[key] = server.get_block_header(run_id, record.camera_id, record.block)
                prefix = block_key_from_secret(headers[key], declaration["block_k"])
            plate = open_record(record, declaration["k"], prefix)
        except (InvalidTag, TypeError):
            return "solução falsa", "a solução k declarada não abre o registro"
        # A collateral decryption (a third party opened on the way) is real and counted, but only a
        # declared hit has to be the plate the token names.
        if (token.mode == "fechada" and declaration.get("kind", "acerto") == "acerto"
                and plate_commitment(self.hmac_key, plate) != token.scope["plate_hmac"]):
            return "desvio de finalidade", "a placa decifrada não é a placa autorizada no token"
        if token.mode == "aberta":
            scope = token.scope
            if (record.camera_id != scope["camera_id"] or _dt(record.captured_at) < _dt(scope["start"])
                    or _dt(record.captured_at) > _dt(scope["end"])):
                return "fora do escopo", "o registro não pertence à janela autorizada"
        return None


def entry_view(entry: dict, broken: set) -> dict:
    """A log entry as the UI shows it (record ids summarised)."""
    detail = dict(entry["detail"])
    if "record_ids" in detail:
        ids = detail.pop("record_ids")
        detail["record_ids"] = ids[:8] + (["…"] if len(ids) > 8 else [])
    signature = entry.get("signature")
    return {**entry, "detail": detail, "broken": entry["seq"] in broken,
            "signature": (signature[:12] + "…") if signature else None,
            "signature_bytes": len(base64.b64decode(signature)) if signature else 0}
