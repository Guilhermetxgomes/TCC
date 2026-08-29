from typing import NewType

# Shared identity between CameraNode and Record: both reference the same
# camera, but there is no "is-a" relationship between them -- Record points to
# the camera that produced it (an association/foreign key), it doesn't inherit
# from it. A NewType makes that intent explicit for the type checker without
# forcing a class hierarchy that doesn't exist in the domain.
CameraId = NewType("CameraId", int)
