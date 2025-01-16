import argparse
from collections.abc import Iterable
import dataclasses
import email
import hashlib
import html.parser
import json
import logging
import pathlib
import re
import tarfile
from typing import TYPE_CHECKING, Any, Generic, Literal, Self, TypeVar
import zipfile


CANONICALIZE_RE = re.compile(r'[-_.]+')

HTML_TEMPLATE = """<!DOCTYPE html>
<html>
  <head>
    <meta name="pypi:repository-version" content="1.0">
    <title>{title}</title>
  </head>
  <body>
    <h1>{title}</h1>
{content}
</body>
</html>"""

WHEEL_FILENAME_RE = re.compile(r'^(?P<name>[^-]+)-(?P<version>\d[^-]*)-.*\.whl')
SDIST_FILENAME_RE = re.compile(r'^(?P<name>.+)-(?P<version>\d.*)\.(?:tar\.gz|zip)')


logging.basicConfig(level=logging.INFO, style='{', format='{levelname}: {msg}')
logger = logging.getLogger()


@dataclasses.dataclass
class Distribution:
    name: str
    version: str

    def __post_init__(self) -> None:
        self.name = canonicalize_name(self.name)

    @classmethod
    def from_filename(cls, fn: str) -> Self:
        for r in [WHEEL_FILENAME_RE, SDIST_FILENAME_RE]:
            if m := r.match(fn):
                return cls(**m.groupdict())
        raise ValueError('Malformed filename')


@dataclasses.dataclass
class Hash:
    alg: str
    digest: str

    def __str__(self) -> str:
        return f'{self.alg}={self.digest}'

    def json(self) -> dict[str, str]:
        return {self.alg: self.digest}

    @classmethod
    def from_attribute(cls, attr: str) -> Self:
        return cls(*attr.split('=', 1))

    @classmethod
    def from_json(cls, data: dict[str, str]) -> Self:
        return cls(*next(iter(data.items())))

    @classmethod
    def from_bytes(cls, content: bytes, alg: str = 'sha256') -> Self:
        return cls(alg, hashlib.new(alg, content).hexdigest())


@dataclasses.dataclass
class Link:
    filename: str
    file_hash: Hash
    metadata_hash: Hash | None = None
    requires_python: str | None = None
    yanked: bool = False

    def html(self) -> str:
        attrs = {'href': f'{self.filename}#{self.file_hash}'}
        if self.requires_python:
            attrs['data-requires-python'] = html.escape(self.requires_python)
        if self.metadata_hash:
            attrs['data-core-metadata'] = attrs['data-dist-info-metadata'] = str(self.metadata_hash)
        if self.yanked:
            attrs['data-yanked'] = '1'
        attrs_html = ' '.join(f'{k}="{v}"' for k, v in attrs.items())
        return f'<a {attrs_html}>{self.filename}</a>'

    @classmethod
    def from_html(cls, attrs: dict[str, str]) -> Self:
        path, file_hash = attrs['href'].split('#')
        metadata_hash_attr = attrs.get('data-core-metadata') or attrs.get('data-dist-info-metadata')
        return cls(
            path.rstrip('/').rsplit('/', 1)[-1],
            Hash.from_attribute(file_hash),
            Hash.from_attribute(metadata_hash_attr) if metadata_hash_attr else None,
            attrs.get('data-requires-python'),
            'data-yanked' in attrs,
        )

    def json(self) -> dict[str, Any]:
        ret = {
            'filename': self.filename,
            'url': self.filename,
            'hashes': self.file_hash.json(),
        }
        if self.requires_python:
            ret['requires-python'] = self.requires_python
        if self.metadata_hash:
            ret['core-metadata'] = ret['dist-info-metadata'] = self.metadata_hash.json()
        if self.yanked:
            ret['yanked'] = True
        return ret

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Self:
        metadata_hashes = data.get('core-metadata') or data.get('dist-info-metadata')
        return cls(
            data['filename'],
            Hash.from_json(data['hashes']),
            Hash.from_json(metadata_hashes) if metadata_hashes else None,
            data.get('requires-python'),
            data.get('yanked', False),
        )


IndexFormat = Literal['html', 'json']

_T = TypeVar('_T')


class IndexParser(Generic[_T], html.parser.HTMLParser):
    def reset(self) -> None:
        super().reset()
        self.links: list[_T] = []

    def _get_link(self, attrs: dict[str, str]) -> _T:
        raise NotImplementedError

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == 'a':
            self.links.append(self._get_link({k: v for k, v in attrs if v}))

    @classmethod
    def get_links(cls, html_content: str) -> list[_T]:
        self = cls()
        self.feed(html_content)
        self.close()
        return self.links.copy()


class RootIndexParser(IndexParser[str]):
    def _get_link(self, attrs: dict[str, str]) -> str:
        return attrs['href'].rstrip('/')


class PackageIndexParser(IndexParser[Link]):
    def _get_link(self, attrs: dict[str, str]) -> Link:
        return Link.from_html(attrs)


def canonicalize_name(name: str, underscore: bool = False) -> str:
    return CANONICALIZE_RE.sub('_' if underscore else '-', name).lower()


def get_metadata(path: pathlib.Path) -> bytes:
    fn = path.name
    try:
        if fn.endswith('.whl'):
            arch = zipfile.ZipFile(path)
            metadata_path = next(s for s in arch.namelist() if s.endswith('.dist-info/METADATA'))
        elif fn.endswith('.tar.gz'):
            arch = tarfile.open(path)  # noqa: SIM115
            metadata_path = next(s for s in sorted(arch.getnames(), key=lambda x: x.count('/')) if s.endswith('/PKG-INFO'))
        elif fn.endswith('.zip'):
            arch = zipfile.ZipFile(path)
            metadata_path = next(s for s in sorted(arch.namelist(), key=lambda x: x.count('/')) if s.endswith('/PKG-INFO'))
        else:
            raise ValueError(f'Unsupported filename {path.name!r}')
    except StopIteration:
        raise FileNotFoundError('Could not find metadata in archive') from None

    return (arch.extractfile if isinstance(arch, tarfile.TarFile) else arch.open)(metadata_path).read()


def process_file(path: pathlib.Path) -> tuple[str, Link, bytes | None]:
    file_hash = Hash.from_bytes(path.read_bytes())
    try:
        metadata_bytes = get_metadata(path)
        metadata_msg = email.message_from_bytes(metadata_bytes)
        metadata_hash = Hash.from_bytes(metadata_bytes)
        package_name = canonicalize_name(metadata_msg['name'])
        requires_python = metadata_msg['requires-python']
    except Exception:
        logger.exception(f'Could not extract metadata from {path}')
        metadata_bytes = metadata_hash = requires_python = None
        package_name = Distribution.from_filename(path.name).name

    return package_name, Link(path.name, file_hash, metadata_hash, requires_python), metadata_bytes


def generate_root_index(package_names: Iterable[str], fmt: IndexFormat = 'html') -> str:
    if fmt == 'html':
        return HTML_TEMPLATE.format(title='Simple index', content='\n'.join(f'<a href="{s}/">{s}</a><br/>' for s in package_names))
    if fmt == 'json':
        return json.dumps(
            {
                'meta': {'api-version': '1.0'},
                'projects': [{'name': name} for name in package_names],
            }
        )
    raise ValueError(f'Unsupported format: {fmt}')


def generate_project_index(package_name: str, links: Iterable[Link], fmt: IndexFormat = 'html') -> str:
    if fmt == 'html':
        return HTML_TEMPLATE.format(title=f'Links for {package_name}', content='\n'.join(f'{l.html()}<br/>' for l in links))
    if fmt == 'json':
        return json.dumps(
            {
                'meta': {'api-version': '1.0'},
                'name': package_name,
                'files': [l.json() for l in links],
            }
        )
    raise ValueError(f'Unsupported format: {fmt}')


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument('-v', '--verbose', dest='log_level', action='store_const', const=logging.DEBUG)
    p.add_argument('-q', '--quiet', dest='log_level', action='store_const', const=logging.WARNING)
    p.add_argument('-d', '--dest', type=pathlib.Path, default=pathlib.Path())
    p.add_argument('-j', '--json', dest='index_format', action='store_const', const='json', default='html')

    sp = p.add_subparsers(dest='command', required=True)

    p_add = sp.add_parser('add', aliases=['publish', 'upload'])
    p_add.add_argument('-r', '--relative', action='store_true')
    p_add.add_argument('sources', metavar='SOURCE', nargs='+', type=pathlib.Path)

    p_yank = sp.add_parser('yank')
    p_yank.add_argument('-u', '--unyank', action='store_true')
    p_yank.add_argument('package', type=canonicalize_name)
    p_yank.add_argument('version')

    if TYPE_CHECKING:

        class args_base:  # noqa: N801
            log_level: int | None
            dest: pathlib.Path
            index_format: IndexFormat

        class args_add(args_base):  # noqa: N801
            command: Literal['add']
            relative: bool
            sources: list[pathlib.Path]

        class args_yank(args_base):  # noqa: N801
            command: Literal['yank']
            unyank: bool
            package: str
            version: str

        def parse_args() -> args_add | args_yank: ...

        args = parse_args()
    else:
        args = p.parse_args()

    logger.setLevel(logging.INFO if args.log_level is None else args.log_level)

    if args.command == 'add':
        package_links: dict[str, list[Link]] = {}

        sources = (
            file_path
            for root_path in args.sources
            for file_path in (root_path.rglob('*') if root_path.is_dir() else [root_path])
            if not file_path.is_dir() and file_path.name.endswith(('.whl', '.tar.gz', '.zip'))
        )

        for src_path in sources:
            logger.debug(f'Processing {src_path}')
            try:
                package_name, link, metadata_bytes = process_file(src_path)
            except Exception:
                logger.exception(f'Error processing {src_path}')
                continue
            dst_path = args.dest / package_name / src_path.name
            if dst_path.exists():
                logger.warning(f'File already published: {src_path}')
                continue
            dst_path.parent.mkdir(parents=True, exist_ok=True)
            # shutil.copyfile(src_path, dst_path)  # noqa: ERA001
            dst_path.symlink_to(src_path.relative_to(dst_path.parent, walk_up=True) if args.relative else src_path.absolute())
            if metadata_bytes:
                dst_path.with_name(f'{dst_path.name}.metadata').write_bytes(metadata_bytes)
            package_links.setdefault(package_name, []).append(link)

        if not package_links:
            logger.info('No updates needed')
            return

        for package_name, new_links in package_links.items():
            package_index_path = args.dest / package_name / f'index.{args.index_format}'
            logger.debug(f'Writing {package_index_path}')
            old_links = PackageIndexParser.get_links(package_index_path.read_text()) if package_index_path.exists() else []
            package_index_path.write_text(generate_project_index(package_name, [*old_links, *new_links], fmt=args.index_format))

        root_index_path = args.dest / f'index.{args.index_format}'
        if not (root_index_path.exists() and set(RootIndexParser.get_links(root_index_path.read_text())).issuperset(package_links)):
            logger.debug(f'Writing {root_index_path}')
            root_index_path.write_text(generate_root_index(sorted(package_links), fmt=args.index_format))

    elif args.command == 'yank':
        logger.debug(f'Yanking {args.package}=={args.version}')
        package_index_path = args.dest / args.package / f'index.{args.index_format}'
        if not package_index_path.exists():
            logger.error(f'Package {args.package} does not exist')
            raise SystemExit(1)
        links = PackageIndexParser.get_links(package_index_path.read_text())
        yanked_value = not args.unyank
        action_str = 'Yank' if yanked_value else 'Unyank'
        modified = False
        for link in links:
            if Distribution.from_filename(link.filename).version == args.version and link.yanked != yanked_value:
                link.yanked = yanked_value
                logger.info(f'{action_str}ed {link.filename}')
                modified = True
        if not modified:
            logger.error('No updates needed')
            raise SystemExit(1)
        logger.debug(f'Writing {package_index_path}')
        package_index_path.write_text(generate_project_index(args.package, links, fmt=args.index_format))

    logger.info('Done')


if __name__ == '__main__':
    main()
