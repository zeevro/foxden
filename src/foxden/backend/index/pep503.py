import contextlib
import html.parser
from typing import Literal, overload

from foxden.backend.index import IndexBackend, StaticFilesIndexBackendMixin
from foxden.models import Digest, DistFile
from foxden.utils import DuplicateValueError, insert_sorted_nodup
from foxden.utils.pep503 import generate_project_index, generate_root_index


class IndexParser[T](html.parser.HTMLParser):
    def reset(self) -> None:
        super().reset()
        self.links: list[T] = []

    def _get_link(self, attrs: dict[str, str]) -> T:
        raise NotImplementedError

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == 'a':
            self.links.append(self._get_link({k: v for k, v in attrs if v}))

    @classmethod
    def get_links(cls, html_content: str) -> list[T]:
        self = cls()
        self.feed(html_content)
        self.close()
        return self.links.copy()


class RootIndexParser(IndexParser[str]):
    def _get_link(self, attrs: dict[str, str]) -> str:
        return attrs['href'].removesuffix('/')


class ProjectIndexParser(IndexParser[DistFile]):
    def _get_link(self, attrs: dict[str, str]) -> DistFile:
        path, digest = attrs['href'].split('#', 1)
        metadata_digest = attrs.get('data-core-metadata') or attrs.get('data-dist-info-metadata')
        return DistFile(
            path.rstrip('/').rsplit('/', 1)[-1],
            Digest.from_str(digest),
            attrs.get('data-requires-python'),
            Digest.from_str(metadata_digest) if metadata_digest else None,
            'data-yanked' in attrs,
        )


class Pep503IndexBackend(IndexBackend, StaticFilesIndexBackendMixin):
    @overload
    def _list_index(self, project: Literal[''] = '') -> list[str]: ...

    @overload
    def _list_index(self, project: str) -> list[DistFile]: ...

    def _list_index(self, project: str = '') -> list[str] | list[DistFile]:
        parser = ProjectIndexParser if project else RootIndexParser
        try:
            return parser.get_links(self.index_path(project).read_text())
        except FileNotFoundError:
            return []

    list_projects = _list_index
    files = _list_index

    def new_file(self, project: str, file: DistFile) -> None:
        project_files = self.files(project)
        try:
            insert_sorted_nodup(project_files, file)
        except DuplicateValueError:
            raise FileExistsError(f'{file.filename} already exists') from None
        project_index_path = self.index_path(project)
        project_index_path.parent.mkdir(parents=True, exist_ok=True)
        project_index_path.write_text(generate_project_index(project, project_files))
        projects = self.list_projects()
        with contextlib.suppress(DuplicateValueError):
            insert_sorted_nodup(projects, project)
            self.index_path().write_text(generate_root_index(projects))

    def set_yanked(self, project: str, filename: str, yanked: bool = True) -> None:
        raise NotImplementedError
