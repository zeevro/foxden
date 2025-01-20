from collections.abc import Iterable
from typing import Self

import msgspec
from msgspec import Struct, field

from foxden.models import Digest, DistFile


def _kebab(s: str) -> str:
    return s.replace('_', '-')


class IndexMeta(Struct, kw_only=True, rename=_kebab):
    api_version: str = '1.0'


class IndexBase(Struct, kw_only=True):
    meta: IndexMeta = field(default_factory=IndexMeta)


class Project(Struct):
    name: str


class RootIndex(IndexBase):
    projects: list[Project]


class ProjectFile(Struct, rename=_kebab, omit_defaults=True):
    filename: str
    url: str
    hashes: dict[str, str] = field(default_factory=dict)
    requires_python: str | None = None
    dist_info_metadata: bool | dict[str, str] | None = None
    gpg_sig: bool | None = None
    yanked: bool | None = None

    def distfile(self) -> DistFile:
        return DistFile(
            self.filename,
            Digest.from_json(self.hashes),
            self.requires_python,
            Digest.from_json(self.dist_info_metadata) if isinstance(self.dist_info_metadata, dict) else None,
            bool(self.yanked),
        )

    @classmethod
    def from_distfile(cls, distfile: DistFile, url_prefix: str = '') -> Self:
        return cls(
            distfile.filename,
            f'{url_prefix}{distfile.filename}',
            distfile.digest.json(),
            distfile.requires_python,
            distfile.metadata_digest.json() if distfile.metadata_digest else None,
            None,
            distfile.yanked or None,
        )


class ProjectIndex(IndexBase):
    name: str
    files: list[ProjectFile]


def generate_root_index(projects: Iterable[str]) -> bytes:
    return msgspec.json.encode(RootIndex([Project(p) for p in projects]))


def generate_project_index(project: str, files: Iterable[DistFile], url_prefix: str = '') -> bytes:
    return msgspec.json.encode(ProjectIndex(project, [ProjectFile.from_distfile(f, url_prefix) for f in files]))
