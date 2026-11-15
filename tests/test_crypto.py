"""
Checks of the cryptographic core (no database, no pytest needed):

    python -m tests.test_crypto

The functions are also collected by pytest, if it is installed.
"""
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec

from crypto import p256, threshold
from crypto.block_crumpling import solve_block
from crypto.crumpling import generate_k
from crypto.escrow import BLOCK_LABEL, RECORD_LABEL, CameraEscrow, derive_secret, open_with_session_key
from crypto.puzzle import open_record, solve_puzzle
from crypto.signing import verify_record
from simulation.tampering import forge_attack, move_attack
from services.camera import Camera
from services.committee import EmergencyCommittee, QuorumError, Scope

DAY1 = "2026-01-01T08:00:00+00:00"
DAY2 = "2026-01-02T08:00:00+00:00"


def test_p256_matches_openssl():
    assert p256.is_on_curve(p256.G)
    assert p256.multiply(p256.ORDER, p256.G) is None
    assert p256.add(p256.multiply(p256.ORDER - 1, p256.G), p256.G) is None
    for _ in range(10):
        d, e = (secrets.randbelow(p256.ORDER - 1) + 1 for _ in range(2))
        mine, peer = ec.derive_private_key(d, ec.SECP256R1()), ec.derive_private_key(e, ec.SECP256R1())
        public = mine.public_key().public_numbers()
        assert p256.multiply(d, p256.G) == (public.x, public.y)  # d*G
        peer_public = peer.public_key().public_numbers()
        shared = mine.exchange(ec.ECDH(), peer.public_key())  # x-coordinate of d*(e*G)
        assert p256.multiply(d, (peer_public.x, peer_public.y))[0] == int.from_bytes(shared, "big")
        a, b = p256.multiply(d, p256.G), p256.multiply(e, p256.G)
        assert p256.add(a, b) == p256.multiply(d + e, p256.G)
        assert p256.add(a, a) == p256.multiply(2 * d, p256.G)
        assert p256.decode(p256.encode(a)) == a


def test_threshold_any_quorum_opens_and_fewer_do_not():
    public, shares = threshold.deal(3, 5)
    r_point, key = threshold.encapsulate(public, b"ctx")
    partials = [threshold.partial_decrypt(share, r_point) for share in shares]
    for subset in ([0, 1, 2], [0, 2, 4], [1, 3, 4], [4, 2, 0]):
        assert threshold.combine(public, r_point, [partials[i] for i in subset], b"ctx") == key
    assert threshold.combine(public, r_point, partials[:3], b"other context") != key
    try:
        threshold.combine(public, r_point, partials[:2], b"ctx")
        raise AssertionError("two partials must not be enough for t = 3")
    except ValueError:
        pass
    # Interpolating with only two real shares (as if t were 2) gives an unrelated key.
    weaker = threshold.PublicKey(public.point, 2, public.verification_points)
    assert threshold.combine(weaker, r_point, partials[:2], b"ctx") != key


def test_threshold_proofs_catch_a_wrong_partial():
    public, shares = threshold.deal(2, 3)
    r_point, _ = threshold.encapsulate(public, b"ctx")
    partial = threshold.partial_decrypt(shares[0], r_point)
    proof = threshold.prove_partial(shares[0], r_point, partial)
    assert threshold.verify_partial(public, r_point, partial, proof)
    forged = threshold.PartialDecryption(partial.index, p256.multiply(7, r_point))
    assert not threshold.verify_partial(public, r_point, forged, proof)
    other_member = threshold.PartialDecryption(2, partial.point)
    assert not threshold.verify_partial(public, r_point, other_member, proof)


def test_shamir_reconstruction_gives_the_whole_key():
    public, shares = threshold.deal(4, 8)
    secret = threshold.reconstruct_secret([shares[i] for i in (7, 1, 4, 2)])
    assert p256.multiply(secret, p256.G) == public.point
    r_point, key = threshold.encapsulate(public, b"ctx")
    assert threshold.decapsulate(secret, r_point, b"ctx") == key
    assert p256.multiply(threshold.reconstruct_secret(shares[:3]), p256.G) != public.point


def test_generate_k_range():
    assert all(0 <= generate_k(7) < 7 for _ in range(200))
    assert generate_k(1) == 0


def test_original_scheme_is_unchanged():
    camera = Camera(id=1, location_id=1, puzzle_level=64)
    record = camera.encrypt_plate("ABC1D23")
    assert record.block is None and record.n == 64
    solved = solve_puzzle(record)
    assert solved["plate"] == "ABC1D23"
    sequential = solve_puzzle(record, sequential=True)
    assert sequential["plate"] == "ABC1D23" and sequential["attempts"] <= 64
    assert sequential["k_found"] == solved["k_found"]


def test_escrow_session_key_opens_only_its_session():
    committee = EmergencyCommittee(threshold_t=3, n_members=5)
    camera = Camera(id=7, location_id=7, puzzle_level=128, escrow=CameraEscrow(7, committee.public_key))
    first = [camera.encrypt_plate(f"AAA{i:04d}", DAY1) for i in range(3)]
    second = camera.encrypt_plate("BBB0000", DAY2)
    wraps = camera.drain_session_wraps()
    assert [(w.period, w.session) for w in wraps] == [("2026-01", "2026-01-01"), ("2026-01", "2026-01-02")]
    assert camera.drain_session_wraps() == []

    # the brute-force path is untouched, and finds exactly the k the escrow path derives
    scope = Scope(period="2026-01", sessions=frozenset({"2026-01-01"}))
    keys = committee.open_session_keys(scope, wraps, [5, 1, 3])
    assert list(keys) == [(7, "2026-01-01")]  # the other day stays closed
    key = keys[(7, "2026-01-01")]
    for i, record in enumerate(first):
        assert solve_puzzle(record, sequential=True)["k_found"] == derive_secret(key, RECORD_LABEL, record.c_prime, 128)
        assert open_with_session_key(record, key) == f"AAA{i:04d}"
    try:
        open_with_session_key(second, key)
        raise AssertionError("day 1's session key must not open day 2")
    except InvalidTag:
        pass

    log = committee.activations[-1]
    assert log["members"] == [1, 3, 5] and log["wraps_opened"] == 1 and log["partial_decryptions"] == 3


def test_committee_refuses_without_quorum_or_outside_scope():
    committee = EmergencyCommittee(threshold_t=3, n_members=5)
    camera = Camera(id=7, location_id=7, puzzle_level=16, escrow=CameraEscrow(7, committee.public_key))
    camera.encrypt_plate("AAA0000", DAY1)
    wraps = camera.drain_session_wraps()
    scope = Scope(period="2026-01", camera_ids=frozenset({99}))
    try:
        committee.open_session_keys(Scope(period="2026-01"), wraps, [1, 2, 2])
        raise AssertionError("two distinct members are not a quorum of three")
    except QuorumError:
        pass
    assert committee.open_session_keys(scope, wraps, [1, 2, 3]) == {}
    try:
        committee.members[1].partial_decrypt(wraps[0], scope)
        raise AssertionError("a member must not answer for a wrap outside the approved scope")
    except PermissionError:
        pass
    assert committee.open_session_keys(Scope(period="2026-01"), wraps, [2, 4, 5], verify_proofs=True)


def test_reconstructed_secret_opens_every_session_of_the_period():
    """Why the system does not use plain Shamir reconstruction for the Busca Total."""
    committee = EmergencyCommittee(threshold_t=2, n_members=3)
    camera = Camera(id=7, location_id=7, puzzle_level=16, escrow=CameraEscrow(7, committee.public_key))
    records = [camera.encrypt_plate("AAA0000", DAY1), camera.encrypt_plate("BBB0000", DAY2)]
    wraps = camera.drain_session_wraps()
    secret = committee.reconstruct_period_secret("2026-01", [1, 3])
    from crypto.escrow import unwrap_session_key, wrap_context
    for record, wrap, plate in zip(records, wraps, ("AAA0000", "BBB0000")):
        kem_key = threshold.decapsulate(secret, p256.decode(wrap.r), wrap_context(wrap.camera_id, wrap.period, wrap.session))
        assert open_with_session_key(record, unwrap_session_key(wrap, kem_key)) == plate


def test_block_crumpling():
    camera = Camera(id=3, location_id=3, puzzle_level=1, block_level=300, block_granularity="hour")
    stamps = ["2026-01-01T08:00:00", "2026-01-01T08:59:59", "2026-01-01T09:00:00"]
    records = [camera.encrypt_plate(f"CCC{i:04d}", stamp) for i, stamp in enumerate(stamps)]
    headers = camera.drain_block_headers()
    assert [h.block for h in headers] == ["2026-01-01T08#0", "2026-01-01T09#0"]
    assert [r.block for r in records] == ["2026-01-01T08#0", "2026-01-01T08#0", "2026-01-01T09#0"]
    assert all(h.t == 300 and h.camera_id == 3 for h in headers)

    solved = solve_block(headers[0], sequential=True)
    assert solved["attempts"] <= 300
    assert solve_puzzle(records[0], key_prefix=solved["key"])["plate"] == "CCC0000"
    assert solve_puzzle(records[1], key_prefix=solved["key"])["attempts"] == 1  # n = 1: no record puzzle
    try:
        solve_puzzle(records[2], key_prefix=solved["key"], sequential=True)
        raise AssertionError("the 08h block key must not open a 09h record")
    except ValueError:
        pass


def test_block_cap_and_two_level_puzzle_with_escrow():
    committee = EmergencyCommittee(threshold_t=2, n_members=3)
    camera = Camera(id=4, location_id=4, puzzle_level=32, block_level=200, block_granularity="hour",
                    block_max_records=2, escrow=CameraEscrow(4, committee.public_key))
    records = [camera.encrypt_plate(f"DDD{i:04d}", DAY1) for i in range(5)]
    headers = {h.block: h for h in camera.drain_block_headers()}
    assert [r.block for r in records] == ["2026-01-01T08#0"] * 2 + ["2026-01-01T08#1"] * 2 + ["2026-01-01T08#2"]

    block = solve_block(headers[records[2].block], sequential=True)
    opened = solve_puzzle(records[2], key_prefix=block["key"], sequential=True)
    assert opened["plate"] == "DDD0002" and opened["attempts"] <= 32

    keys = committee.open_session_keys(Scope(period="2026-01"), camera.drain_session_wraps(), [1, 2])
    key = keys[(4, "2026-01-01")]
    assert derive_secret(key, BLOCK_LABEL, headers[records[2].block].c_prime, 200) == block["k_found"]
    for i, record in enumerate(records):
        assert open_with_session_key(record, key, headers[record.block]) == f"DDD{i:04d}"

    try:  # a block must fit inside one escrow session
        Camera(id=5, location_id=5, block_level=10, block_granularity="day",
               escrow=CameraEscrow(5, committee.public_key, session_granularity="hour"))
        raise AssertionError("a daily block cannot be escrowed with hourly sessions")
    except ValueError:
        pass


def test_associated_data_binds_camera_and_instant():
    camera = Camera(id=11, location_id=11, puzzle_level=64)
    record = camera.encrypt_plate("ABC1D23", "2026-01-01T08:10:00+00:00")
    assert record.captured_at == "2026-01-01T08:10:00+00:00"  # generated/kept by the camera
    k = solve_puzzle(record, sequential=True)["k_found"]
    from dataclasses import replace
    for moved in (replace(record, camera_id=40), replace(record, captured_at="2026-01-01T09:00:00+00:00")):
        try:
            open_record(moved, k)
            raise AssertionError("a record moved to another camera or instant must not open")
        except InvalidTag:
            pass
        try:
            solve_puzzle(moved, sequential=True)
            raise AssertionError("no k opens a moved record")
        except ValueError:
            pass
    assert Camera(id=1, location_id=1).encrypt_plate("AAA0000").captured_at is not None  # default: now


def test_signature_catches_moved_and_forged_records():
    camera = Camera(id=11, location_id=11, puzzle_level=64, block_level=50, block_granularity="hour")
    record = camera.encrypt_plate("ABC1D23", DAY1)
    header = camera.drain_block_headers()[0]
    assert verify_record(record, camera.public_key)
    assert not verify_record(record, Camera(id=12, location_id=12).public_key)  # another camera's key

    block = solve_block(header, sequential=True)
    k = solve_puzzle(record, key_prefix=block["key"], sequential=True)["k_found"]

    moved, checks = move_attack(record, k, block["key"], camera.public_key, "ABC1D23", 40, DAY2)
    assert [c["detected"] for c in checks] == [False, True, True]  # without AD it would pass
    assert not verify_record(moved, camera.public_key)

    forged, checks = forge_attack(record, k, block["key"], camera.public_key, "XYZ9Z99")
    assert open_record(forged, k, block["key"]) == "XYZ9Z99"  # AES-GCM alone accepts the forgery
    assert [c["detected"] for c in checks] == [False, True, True]
    assert not verify_record(forged, camera.public_key)


if __name__ == "__main__":
    tests = [(name, fn) for name, fn in sorted(globals().items()) if name.startswith("test_") and callable(fn)]
    for name, fn in tests:
        fn()
        print(f"  [ok] {name}")
    print(f"{len(tests)} tests passed")
