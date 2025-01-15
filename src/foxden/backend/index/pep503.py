import html.parser

from foxden.backend.index import IndexBackend, StaticFilesIndexBackendMixin
from foxden.models import DistFile


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


class PackageIndexParser(IndexParser[DistFile]):
    def _get_link(self, attrs: dict[str, str]) -> DistFile:
        return DistFile.from_html(attrs)


class Pep503IndexBackend(IndexBackend, StaticFilesIndexBackendMixin):
    def list_projects(self) -> list[str]:
        self.dir_path.joinpath('index.html').read_text()

    def files(self, project: str) -> list[DistFile]:
        return super().files(project)

    def set_yanked(self, filename: str, yanked: bool = True) -> None:
        return super().set_yanked(filename, yanked)
