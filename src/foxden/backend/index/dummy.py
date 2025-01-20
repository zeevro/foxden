from foxden.backend.index import IndexBackend
from foxden.models import DistFile


class EmptyIndexBackend(IndexBackend):
    def list_projects(self) -> list[str]:
        return []

    def files(self, project: str) -> list[DistFile]:  # noqa: ARG002
        return []

    def new_file(self, project: str, file: DistFile) -> None:
        pass

    def set_yanked(self, project: str, filename: str, yanked: bool = True) -> None:
        raise NotImplementedError
