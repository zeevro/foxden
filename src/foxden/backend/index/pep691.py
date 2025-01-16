import contextlib
from typing import Literal, overload

import msgspec

from foxden.backend.index import IndexBackend, StaticFilesIndexBackendMixin
from foxden.models import DistFile
from foxden.utils import DuplicateValueError, insert_sorted_nodup
from foxden.utils.pep691 import ProjectIndex, RootIndex, generate_project_index, generate_root_index


class Pep691IndexBackend(IndexBackend, StaticFilesIndexBackendMixin):
    index_filename = 'index.json'

    @overload
    def _list_index(self, project: Literal[''] = '') -> list[str]: ...

    @overload
    def _list_index(self, project: str) -> list[DistFile]: ...

    def _list_index(self, project: str = '') -> list[str] | list[DistFile]:
        buf = self.index_path(project).read_bytes()
        if project:
            return [f.distfile() for f in msgspec.json.decode(buf, type=ProjectIndex).files]
        return [p.name for p in msgspec.json.decode(buf, type=RootIndex).projects]

    list_projects = _list_index
    files = _list_index

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
