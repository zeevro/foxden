from collections.abc import Iterable
import contextlib

from foxden.backend.index import IndexBackend
from foxden.models import DistFile
from foxden.types import AnyPath
from foxden.utils import DuplicateValueError, IndexGenerator, insert_sorted_nodup


class FilesIndexBackend(IndexBackend):
    # TODO: Lock for write operations

    _index_filename = 'index.html'
    _index_generator: IndexGenerator

    def __init__(self, dir_path: AnyPath) -> None:
        self.dir_path = dir_path

    def _index_path(self, project: str = '') -> AnyPath:
        return self.dir_path / project / self._index_filename

    def _write_root_index(self, projects: Iterable[str]) -> None:
        self._index_path().write_bytes(self._index_generator.generate_root_index(projects))

    def _write_project_index(self, project: str, files: Iterable[DistFile]) -> None:
        index_path = self._index_path(project)
        content = self._index_generator.generate_project_index(project, files, '../')
        try:
            index_path.write_bytes(content)
        except FileNotFoundError:
            index_path.parent.mkdir(parents=True, exist_ok=True)
            index_path.write_bytes(content)

    def _parse_root_index(self, index_path: AnyPath) -> list[str]:
        raise NotImplementedError

    def _parse_project_index(self, index_path: AnyPath) -> list[DistFile]:
        raise NotImplementedError

    def list_projects(self) -> list[str]:
        try:
            return self._parse_root_index(self._index_path())
        except FileNotFoundError:
            return []

    def files(self, project: str) -> list[DistFile]:
        try:
            return self._parse_project_index(self._index_path(project))
        except FileNotFoundError:
            return []

    def new_file(self, project: str, file: DistFile) -> None:
        files = self.files(project)
        try:
            insert_sorted_nodup(files, file)
        except DuplicateValueError:
            raise FileExistsError(f'{file.filename} already exists') from None
        project_index_path = self._index_path(project)
        project_index_path.parent.mkdir(parents=True, exist_ok=True)
        self._write_project_index(project, files)
        projects = self.list_projects()
        with contextlib.suppress(DuplicateValueError):
            insert_sorted_nodup(projects, project)
            self._write_root_index(projects)

    def set_yanked(self, project: str, filename: str, yanked: bool = True) -> None:
        files = self.files(project)
        for distfile in files:
            if distfile.filename == filename:
                if distfile.yanked != yanked:
                    distfile.yanked = yanked
                    self._write_project_index(project, files)
                return
        raise FileNotFoundError(f'File {filename!r} does not exist')


def combined_files_index_backends(primary_backend: type[FilesIndexBackend], *extra_backends: type[FilesIndexBackend]) -> type[FilesIndexBackend]:
    if not extra_backends:
        return primary_backend

    class CombinedFilesIndexBackend(primary_backend):  # type: ignore[valid-type,misc]
        def __init__(self, dir_path: AnyPath) -> None:
            super().__init__(dir_path)
            self.extra_backends = [cls(dir_path) for cls in extra_backends]

        def new_file(self, project: str, file: DistFile) -> None:
            super().new_file(project, file)
            for backend in self.extra_backends:
                backend.new_file(project, file)

        def set_yanked(self, project: str, filename: str, yanked: bool = True) -> None:
            super().set_yanked(project, filename, yanked)
            for backend in self.extra_backends:
                backend.set_yanked(project, filename, yanked)

    return CombinedFilesIndexBackend
