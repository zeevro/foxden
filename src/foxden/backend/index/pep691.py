import contextlib

import msgspec

from foxden.backend.index import IndexBackend, StaticFilesIndexBackendMixin
from foxden.models import DistFile
from foxden.utils import DuplicateValueError, insert_sorted_nodup
from foxden.utils.pep691 import ProjectIndex, RootIndex, generate_project_index, generate_root_index


class Pep691IndexBackend(IndexBackend, StaticFilesIndexBackendMixin):
    index_filename = 'index.json'

    def list_projects(self) -> list[str]:
        try:
            return [p.name for p in msgspec.json.decode(self.index_path().read_bytes(), type=RootIndex).projects]
        except FileNotFoundError:
            return []

    def files(self, project: str) -> list[DistFile]:
        try:
            return [f.distfile() for f in msgspec.json.decode(self.index_path(project).read_bytes(), type=ProjectIndex).files]
        except FileNotFoundError:
            return []

    def new_file(self, project: str, file: DistFile) -> None:
        project_files = self.files(project)
        try:
            insert_sorted_nodup(project_files, file)
        except DuplicateValueError:
            raise FileExistsError(f'{file.filename} already exists') from None
        self.index_path(project).write_bytes(generate_project_index(project, project_files))
        projects = self.list_projects()
        with contextlib.suppress(DuplicateValueError):
            insert_sorted_nodup(projects, project)
            self.index_path(project).write_bytes(generate_root_index(projects))

    def set_yanked(self, project: str, filename: str, yanked: bool = True) -> None:
        raise NotImplementedError
