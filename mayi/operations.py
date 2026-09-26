from dataclasses import dataclass
from enum import Enum

class Kind(str, Enum):
    EXEC="EXEC"; FILE_READ="FILE_READ"; FILE_WRITE="FILE_WRITE"; FILE_PATCH="FILE_PATCH"; FILE_DELETE="FILE_DELETE"
    FILE_CREATE="FILE_CREATE"; FILE_MOVE="FILE_MOVE"; FILE_CHMOD="FILE_CHMOD"; FILE_CHOWN="FILE_CHOWN"
    DIRECTORY_CREATE="DIRECTORY_CREATE"; SERVICE_STATUS="SERVICE_STATUS"; SERVICE_START="SERVICE_START"
    SERVICE_STOP="SERVICE_STOP"; SERVICE_RESTART="SERVICE_RESTART"; PACKAGE_INSTALL="PACKAGE_INSTALL"
    PACKAGE_REMOVE="PACKAGE_REMOVE"; PACKAGE_UPGRADE="PACKAGE_UPGRADE"

@dataclass(frozen=True)
class Operation:
    kind: Kind
    target: str
    args: tuple[str, ...] = ()
    source: str = ""
    mode: str = ""
    owner: str = ""
    version: str = ""
    expected_base_sha256: str = ""
    expected_result_sha256: str = ""
    patch: tuple[dict[str, str], ...] = ()
    content: str = ""
    def display(self) -> str:
        if self.kind is Kind.EXEC:
            return f"EXEC {self.target} {list(self.args)!r}"
        if self.kind is Kind.FILE_MOVE:
            return f"FILE_MOVE {self.source} {self.target}"
        return f"{self.kind.value} {self.target}"
