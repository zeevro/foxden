from typing import Protocol

from foxden.models import DistFile


class IndexBackend(Protocol):
    def list_projects(self) -> list[str]: ...

    def files(self, project: str) -> list[DistFile]: ...

    def new_file(self, project: str, file: DistFile) -> None: ...  # TODO: Is project really needed here?

    def set_yanked(self, project: str, filename: str, yanked: bool = True) -> None: ...
