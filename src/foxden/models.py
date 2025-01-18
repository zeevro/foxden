import dataclasses
import hashlib
import html.parser
from typing import Any, Self


@dataclasses.dataclass
class Digest:
    alg: str
    digest: str

    def __str__(self) -> str:
        return f'{self.alg}={self.digest}'

    def json(self) -> dict[str, str]:
        return {self.alg: self.digest}

    @classmethod
    def from_str(cls, attr: str) -> Self:
        return cls(*attr.split('=', 1))

    @classmethod
    def from_json(cls, data: dict[str, str]) -> Self:
        return cls(*next(iter(data.items())))

    @classmethod
    def from_bytes(cls, content: bytes, alg: str = 'sha256') -> Self:
        return cls(alg, hashlib.new(alg, content).hexdigest())


@dataclasses.dataclass
class DistFile:
    filename: str
    digest: Digest
    requires_python: str | None = None
    metadata_digest: Digest | None = None
    yanked: bool = False

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return (self.filename, self.digest) == (other.filename, other.digest)

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.filename > other.filename

    def __gte__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.filename >= other.filename

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.filename < other.filename

    def __lte__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.filename <= other.filename
