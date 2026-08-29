from dataclasses import dataclass

from entities.camera_id import CameraId
from entities.record import Record


@dataclass
class Sighting:
    """
    An encrypted capture at a camera, tied to a discrete time bin.

    Does not carry its own camera_id: that information already lives on
    `record`, and Sighting is just the association between that record and the
    time window it was observed in -- duplicating the field here could drift
    from the actual value inside `record`.
    """
    time_bin: int
    record: Record

    @property
    def camera_id(self) -> CameraId:
        return self.record.camera_id
