import html.parser

from foxden.backend.index.files import FilesIndexBackend
from foxden.models import Digest, DistFile
from foxden.types import AnyPath
from foxden.utils import pep503


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


class Pep503IndexBackend(FilesIndexBackend):
    _index_generator = pep503

    def _parse_root_index(self, index_path: AnyPath) -> list[str]:
        return RootIndexParser.get_links(index_path.read_text())

    def _parse_project_index(self, index_path: AnyPath) -> list[DistFile]:
        return ProjectIndexParser.get_links(index_path.read_text())
