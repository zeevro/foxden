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
    def from_attribute(cls, attr: str) -> Self:
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
    file_hash: Digest
    metadata_hash: Digest | None = None
    requires_python: str | None = None
    yanked: bool = False

    def html(self) -> str:
        attrs = {'href': f'{self.filename}#{self.file_hash}'}
        if self.requires_python:
            attrs['data-requires-python'] = html.escape(self.requires_python)
        if self.metadata_hash:
            attrs['data-core-metadata'] = attrs['data-dist-info-metadata'] = str(self.metadata_hash)
        if self.yanked:
            attrs['data-yanked'] = '1'
        attrs_html = ' '.join(f'{k}="{v}"' for k, v in attrs.items())
        return f'<a {attrs_html}>{self.filename}</a>'

    @classmethod
    def from_html(cls, attrs: dict[str, str]) -> Self:
        path, file_hash = attrs['href'].split('#')
        metadata_hash_attr = attrs.get('data-core-metadata') or attrs.get('data-dist-info-metadata')
        return cls(
            path.rstrip('/').rsplit('/', 1)[-1],
            Digest.from_attribute(file_hash),
            Digest.from_attribute(metadata_hash_attr) if metadata_hash_attr else None,
            attrs.get('data-requires-python'),
            'data-yanked' in attrs,
        )

    def json(self) -> dict[str, Any]:
        ret = {
            'filename': self.filename,
            'url': self.filename,
            'hashes': self.file_hash.json(),
        }
        if self.requires_python:
            ret['requires-python'] = self.requires_python
        if self.metadata_hash:
            ret['core-metadata'] = ret['dist-info-metadata'] = self.metadata_hash.json()
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
