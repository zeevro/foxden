import pathlib
from typing import Protocol

from foxden.models import DistFile


class IndexBackend(Protocol):
    def list_projects(self) -> list[str]: ...

    def files(self, project: str) -> list[DistFile]: ...

    def set_yanked(self, filename: str, yanked: bool = True) -> None: ...


class StaticFilesIndexBackendMixin:
    def __init__(self, dir_path: pathlib.Path) -> None:
        self.dir_path = dir_path
