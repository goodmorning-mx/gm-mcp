from enum import StrEnum


class Permission(StrEnum):
    READ = "read"
    WRITE = "write"
    CONFIRM = "confirm"


class PermissionDenied(PermissionError):
    pass
