import pathlib
from typing import Protocol

from foxden.models import DistFile


class IndexBackend(Protocol):
    def list_projects(self) -> list[str]: ...

    def files(self, project: str) -> list[DistFile]: ...

    def new_file(self, project: str, file: DistFile) -> None: ...  # TODO: Is project really needed here?

    def set_yanked(self, project: str, filename: str, yanked: bool = True) -> None: ...


class StaticFilesIndexBackendMixin:
    # TODO: Lock for write operations

    index_filename = 'index.html'

    def __init__(self, dir_path: pathlib.Path) -> None:
        self.dir_path = dir_path

    def index_path(self, project: str = '') -> pathlib.Path:
        return self.dir_path / project / self.index_filename
