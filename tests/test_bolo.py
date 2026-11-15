"""
Checks of the BOLO blocklist on the camera (no database, no pytest needed):

    python -m tests.test_bolo
"""
from entities.blocklist import Blocklist, BlocklistFull
from services.camera import Camera
from services.police import Police


class Clock:
    def __init__(self, now: float = 1_000_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


def setup(max_entries=None, cameras: int = 3):
    clock = Clock()
    police = Police()
    cams = [
        Camera(id=i, location_id=i, blocklist=Blocklist(clock=clock, max_entries=max_entries), police=police)
        for i in range(cameras)
    ]
    return clock, police, cams


def test_broadcast_reaches_every_camera_and_alerts_in_the_clear():
    _, police, cameras = setup()
    assert police.issue_bolo("ABC1D23", reason="roubo") == 3
    captured = cameras[1].capture_plate("ABC1D23", timestamp="2026-01-01T08:00:00")
    assert captured["alerted"] and captured["record"].ciphertext  # alert AND the usual encrypted record
    assert [(a.camera_id, a.plate, a.reason) for a in police.alerts_received] == [(1, "ABC1D23", "roubo")]
    assert not cameras[1].capture_plate("XYZ9Z99")["alerted"]


def test_entry_expires_with_its_ttl():
    clock, police, cameras = setup()
    police.issue_bolo("ABC1D23", ttl_seconds=3600)
    clock.now += 3599
    assert cameras[0].blocklist.contains("ABC1D23")
    clock.now += 2
    assert not cameras[0].blocklist.contains("ABC1D23") and len(cameras[0].blocklist) == 0
    assert not cameras[0].capture_plate("ABC1D23")["alerted"]


def test_capacity_bounds_how_many_plates_can_be_watched():
    clock, police, cameras = setup(max_entries=50)
    accepted = sum(police.issue_bolo(f"AAA{i:04d}", ttl_seconds=3600) > 0 for i in range(500))
    assert accepted == 50 and all(len(camera.blocklist) == 50 for camera in cameras)
    assert police.issue_bolo("AAA0000", ttl_seconds=3600) == 3  # renewing a listed plate always fits
    try:
        cameras[0].blocklist.add("ZZZ9999")
        raise AssertionError("a full blocklist must refuse a new plate")
    except BlocklistFull:
        pass
    clock.now += 3601  # entries expire: room again
    assert police.issue_bolo("ZZZ9999") == 3


if __name__ == "__main__":
    import contextlib
    import io

    tests = [(name, fn) for name, fn in sorted(globals().items()) if name.startswith("test_") and callable(fn)]
    for name, fn in tests:
        with contextlib.redirect_stdout(io.StringIO()):  # Police.receive_alert prints each alert
            fn()
        print(f"  [ok] {name}")
    print(f"{len(tests)} tests passed")
