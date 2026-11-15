import time
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidTag

from crypto import p256, threshold
from crypto.escrow import unwrap_session_key, wrap_context
from entities.session_key_wrap import SessionKeyWrap


class QuorumError(Exception):
    """Fewer members than the threshold agreed to the request."""


@dataclass(frozen=True)
class Scope:
    """
    What one activation of the Busca Total is allowed to open: one period (month) and,
    optionally, only some sessions (days) and/or some cameras of it. Members refuse to
    produce a partial decryption for any wrap outside the scope they approved.
    """
    period: str
    sessions: Optional[frozenset] = None    # None = every session of the period
    camera_ids: Optional[frozenset] = None  # None = every camera
    reason: str = ""

    def covers(self, wrap: SessionKeyWrap) -> bool:
        return (
            wrap.period == self.period
            and (self.sessions is None or wrap.session in self.sessions)
            and (self.camera_ids is None or wrap.camera_id in self.camera_ids)
        )


class CommitteeMember:
    """One representative (e.g. a state deputy). Holds one key share per period."""

    def __init__(self, index: int):
        self.index = index
        self._shares: dict[str, threshold.KeyShare] = {}

    def receive_share(self, period: str, share: threshold.KeyShare) -> None:
        self._shares[period] = share

    def partial_decrypt(self, wrap: SessionKeyWrap, scope: Scope) -> threshold.PartialDecryption:
        if not scope.covers(wrap):
            raise PermissionError(f"wrap of camera {wrap.camera_id} / {wrap.session} is outside the approved scope")
        return threshold.partial_decrypt(self._shares[wrap.period], p256.decode(wrap.r))

    def prove(self, wrap: SessionKeyWrap, partial: threshold.PartialDecryption) -> threshold.ShareProof:
        return threshold.prove_partial(self._shares[wrap.period], p256.decode(wrap.r), partial)


class EmergencyCommittee:
    """
    The Emergency Committee of the Busca Total: n members, any t of which can open the
    session keys the cameras escrowed (crypto/escrow.py) -- by threshold decryption, so
    the period's secret key is never rebuilt and each activation opens only the wraps
    in its scope. Every activation is recorded in `activations`.

    In this prototype all members live in one process and the period keys come from a
    trusted dealer whose secret is discarded at once; in a deployment each member runs
    on its own device and the keys come from a distributed key generation.
    """

    def __init__(self, threshold_t: int = 4, n_members: int = 8):
        self.threshold = threshold_t
        self.members = {index: CommitteeMember(index) for index in range(1, n_members + 1)}
        self._public_keys: dict[str, threshold.PublicKey] = {}
        self.activations: list[dict] = []

    def public_key(self, period: str) -> threshold.PublicKey:
        """Public key of a period (month); cameras encrypt their session keys to it."""
        if period not in self._public_keys:
            public, shares = threshold.deal(self.threshold, len(self.members))
            for share in shares:
                self.members[share.index].receive_share(period, share)
            self._public_keys[period] = public
        return self._public_keys[period]

    def open_session_keys(self, scope: Scope, wraps: list[SessionKeyWrap], member_indexes: list[int],
                          verify_proofs: bool = False) -> dict:
        """
        Threshold-decrypts every wrap in `scope` with the given members and returns
        {(camera_id, session): session_key}.

        The members' answers are checked optimistically: a wrong partial makes the AES-GCM
        tag of the wrap fail, and only then are the Chaum-Pedersen proofs requested to
        find out who misbehaved (verify_proofs=True checks every partial up front).
        """
        present = sorted(set(member_indexes))
        if len(present) < self.threshold:
            raise QuorumError(f"quorum not reached: {len(present)} of the {self.threshold} members required")
        public = self.public_key(scope.period)
        started = time.perf_counter()
        session_keys = {}
        partial_decryptions = 0
        for wrap in wraps:
            if not scope.covers(wrap):
                continue
            r_point = p256.decode(wrap.r)
            partials = [self.members[index].partial_decrypt(wrap, scope) for index in present[: self.threshold]]
            partial_decryptions += len(partials)
            if verify_proofs:
                self._check_proofs(public, wrap, r_point, partials)
            kem_key = threshold.combine(public, r_point, partials, wrap_context(wrap.camera_id, wrap.period, wrap.session))
            try:
                session_keys[(wrap.camera_id, wrap.session)] = unwrap_session_key(wrap, kem_key)
            except InvalidTag:
                self._check_proofs(public, wrap, r_point, partials)
                raise
        self.activations.append({
            "at": time.time(), "period": scope.period, "reason": scope.reason, "members": present[: self.threshold],
            "sessions": sorted({session for _, session in session_keys}),
            "cameras": sorted({camera for camera, _ in session_keys}),
            "wraps_opened": len(session_keys), "partial_decryptions": partial_decryptions,
            "seconds": time.perf_counter() - started,
        })
        return session_keys

    def _check_proofs(self, public, wrap, r_point, partials) -> None:
        cheaters = [
            partial.index for partial in partials
            if not threshold.verify_partial(public, r_point, partial, self.members[partial.index].prove(wrap, partial))
        ]
        if cheaters:
            raise ValueError(f"invalid partial decryption from member(s) {cheaters}")

    # -- baseline, for comparison only --------------------------------------------------

    def reconstruct_period_secret(self, period: str, member_indexes: list[int]) -> int:
        """
        Plain Shamir reconstruction of the period's secret key (the alternative the
        system does NOT use): whoever receives the result can open every wrap of the
        period, of every camera, without the committee ever being asked again.
        """
        present = sorted(set(member_indexes))
        if len(present) < self.threshold:
            raise QuorumError(f"quorum not reached: {len(present)} of the {self.threshold} members required")
        self.public_key(period)
        shares = [self.members[index]._shares[period] for index in present[: self.threshold]]
        return threshold.reconstruct_secret(shares)
