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

    def html(self) -> str:
        attrs = {'href': f'{self.filename}#{self.digest}'}
        if self.requires_python:
            attrs['data-requires-python'] = html.escape(self.requires_python)
        if self.metadata_digest:
            attrs['data-core-metadata'] = attrs['data-dist-info-metadata'] = str(self.metadata_digest)
        if self.yanked:
            attrs['data-yanked'] = '1'
        attrs_html = ' '.join(f'{k}="{v}"' for k, v in attrs.items())
        return f'<a {attrs_html}>{self.filename}</a>'

    def json(self) -> dict[str, Any]:
        ret = {
            'filename': self.filename,
            'url': self.filename,
            'hashes': self.digest.json(),
        }
        if self.requires_python:
            ret['requires-python'] = self.requires_python
        if self.metadata_digest:
            ret['core-metadata'] = ret['dist-info-metadata'] = self.metadata_digest.json()
        if self.yanked:
            ret['yanked'] = True
        return ret

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Self:
        metadata_hashes = data.get('core-metadata') or data.get('dist-info-metadata')
        return cls(
            data['filename'],
            Digest.from_json(data['hashes']),
            Digest.from_json(metadata_hashes) if metadata_hashes else None,
            data.get('requires-python'),
            data.get('yanked', False),
        )
