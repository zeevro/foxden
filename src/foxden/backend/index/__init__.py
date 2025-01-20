import contextlib
from typing import Any, Protocol

from foxden.models import DistFile
from foxden.types import AnyPath


class IndexBackend(Protocol):
    def list_projects(self) -> list[str]: ...

    def files(self, project: str) -> list[DistFile]: ...

    def new_file(self, project: str, file: DistFile) -> None: ...  # TODO: Is project really needed here?

    def set_yanked(self, project: str, filename: str, yanked: bool = True) -> None: ...


class StaticFilesIndexBackendMixin:
    # TODO: Lock for write operations

    index_filename = 'index.html'

    def __init__(self, dir_path: AnyPath) -> None:
        self.dir_path = dir_path

    def index_path(self, project: str = '') -> AnyPath:
        return self.dir_path / project / self.index_filename


class CombinedIndexBackend(IndexBackend):
    def __init__(self, *backends: IndexBackend) -> None:
        self.backends = backends

    def list_projects(self) -> list[str]:
        return self.backends[0].list_projects()

    def files(self, project: str) -> list[DistFile]:
        return self.backends[0].files(project)

    def new_file(self, project: str, file: DistFile) -> None:
        for backend in self.backends:
            backend.new_file(project, file)

    def set_yanked(self, project: str, filename: str, yanked: bool = True) -> None:
        for backend in self.backends:
            backend.set_yanked(project, filename, yanked)

    def __getattr__(self, name: str) -> Any:
        for backend in self.backends:
            with contextlib.suppress(AttributeError):
                return getattr(backend, name)
        raise AttributeError(f'{type(self).__name__!r} object has no attribute {name!r}')
