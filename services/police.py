from entities.alert import Alert


class Police:
    """
    The police command center in the "bolo_normal" (forward-looking)
    flow. It does two things:

    - Issues BOLOs: broadcasts a new plate as a single push event to every
      registered camera, and each camera adds it to its own local
      blocklist (entities/blocklist.py) right away. Cameras never poll a
      central server to check a plate at capture time -- that would cost
      a network round-trip per capture, which is exactly what this design
      avoids on constrained camera hardware. The broadcast is the only
      network cost, and it is paid once per BOLO, not once per capture.

    - Receives alerts: cameras call back directly, in the clear, the
      moment they spot a plate that matches their local blocklist.
    """

    def __init__(self):
        self.alerts_received: list[Alert] = []
        self._subscribed_cameras = []  # Camera instances (with a blocklist)

    def register_camera(self, camera) -> None:
        """
        A camera subscribes once, when it comes online, to receive future
        BOLO broadcasts. From then on it needs no further contact with
        the police to stay up to date -- broadcasts just arrive.
        """
        self._subscribed_cameras.append(camera)

    def issue_bolo(self, plate: str, reason: str = "", ttl_seconds: float = 24 * 3600) -> None:
        """
        Broadcasts one BOLO plate to every subscribed camera in a single
        event. Each camera stores it in its own local blocklist with the
        given TTL -- this is the "cameras are notified of the blocklist"
        step from preBOLO.md.
        """
        for camera in self._subscribed_cameras:
            camera.blocklist.add(plate, reason=reason, ttl_seconds=ttl_seconds)

    def receive_alert(self, alert: Alert) -> None:
        self.alerts_received.append(alert)
        when = f" at {alert.timestamp}" if alert.timestamp else ""
        reason = f" ({alert.reason})" if alert.reason else ""
        print(
            f"[POLICE] DIRECT ALERT -- camera {alert.camera_id} "
            f"(location {alert.location_id}) saw plate {alert.plate}{reason}{when}."
        )
