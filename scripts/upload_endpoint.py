from collections.abc import Mapping, Sequence
import contextlib
import dataclasses
from functools import cached_property
import hashlib
import html
from pprint import pprint
import sqlite3
import tarfile
import threading
from typing import TYPE_CHECKING, Annotated, Any, Literal
import zipfile

from fastapi import Body, Depends, FastAPI, Form, Response, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from packaging.metadata import Metadata
from packaging.utils import canonicalize_name
from pydantic import BaseModel, Field, RootModel, model_validator


_db_lock = threading.Lock()


def _sql(sql: str, parameters: Sequence[Any] | Mapping[str, Any] = ()) -> sqlite3.Cursor:
    with _db_lock:
        db = sqlite3.connect('test.sqlite', autocommit=True)
        return db.execute(sql, parameters)


_sql("""CREATE TABLE IF NOT EXISTS files (
    filename TEXT NOT NULL PRIMARY KEY,
    name TEXT NOT NULL,
    requires_python TEXT,
    digest_alg TEXT NOT NULL,
    digest TEXT NOT NULL,
    metadata_digest_alg TEXT,
    metadata_digest TEXT,
    metadata BLOB,
    content BLOB NOT NULL,
    yanked BOOL
)""")


class UploadRequestBase(BaseModel):
    action: Annotated[Literal['file_upload'], Field(alias=':action')]
    protocol_version: Literal['1']
    content: UploadFile
    filetype: Literal['sdist', 'bdist_wheel']
    metadata_version: str
    name: str
    version: str

    @cached_property
    def metadata_path(self) -> str:
        if self.filetype == 'bdist_wheel':
            name, version, _ = self.content.filename.split('-', 2)
            return f'{name}-{version}.dist-info/METADATA'
        if self.filetype == 'sdist':
            name, version = self.content.filename[:-7].split('-', 1)
            return f'{name}-{version}/PKG-INFO'
        raise ValueError(f'Unsupported filetype: {self.filetype}')

    @cached_property
    def metadata_bytes(self) -> bytes | None:
        if self.filetype == 'bdist_wheel':
            return zipfile.ZipFile(self.content.file).open(self.metadata_path).read()
        if self.filetype == 'sdist':
            with contextlib.suppress(Exception):
                return tarfile.open(fileobj=self.content.file).extractfile(self.metadata_path).read()
        return None

    @cached_property
    def metadata(self) -> Metadata | None:
        if not self.metadata_bytes:
            return None
        return Metadata.from_email(self.metadata_bytes)


class UploadRequestMD5(UploadRequestBase):
    md5_digest: str

    @property
    def digest(self) -> tuple[Literal['md5'], str]:
        return ('md5', self.md5_digest)


class UploadRequestSha256(UploadRequestBase):
    sha256_digest: str

    @property
    def digest(self) -> tuple[Literal['sha256'], str]:
        return ('sha256', self.sha256_digest)


class UploadRequestBlake2(UploadRequestBase):
    blake2_256_digest: str

    @property
    def digest(self) -> tuple[Literal['blake2_256'], str]:
        return ('blake2_256', self.blake2_256_digest)


if TYPE_CHECKING:
    UploadRequest = UploadRequestMD5 | UploadRequestSha256 | UploadRequestBlake2
else:

    class UploadRequest(RootModel[UploadRequestMD5 | UploadRequestSha256 | UploadRequestBlake2]):
        @model_validator(mode='after')
        def fix_root(self) -> UploadRequestMD5 | UploadRequestSha256 | UploadRequestBlake2:
            return self.root


app = FastAPI()
security = HTTPBasic()


@app.get('/_/oidc/audience')
def oidc_audience() -> dict[Literal['audience'], str]:
    return {'audience': 'foxden-upload'}


@app.get('/gh-api/oidc/token')
def gh_oidc_token(audience: str) -> dict[Literal['value'], str]:
    return {'value': f'token_for_{audience}'}


@app.post('/_/oidc/mint-token')
def oidc_mint_token(token: Annotated[str, Body(embed=True)]) -> dict[Literal['token'], str]:
    return {'token': f'mint-token_for_{token}'}


@app.post('/')
def upload(data: Annotated[UploadRequest, Form()], creds: Annotated[HTTPBasicCredentials, Depends(security)]) -> None:
    pprint(creds)
    pprint(data.model_dump())
    print(f'{canonicalize_name(data.name) = }')
    print(f'{type(data) = }')
    print(data.metadata_path)
    if data.metadata_bytes:
        print(f'{len(data.metadata_bytes) = }')
        print(f'{hashlib.sha256(data.metadata_bytes).hexdigest() = }')
    print(data.metadata)
    if data.metadata:
        print(f'{data.metadata.requires_python = !s}')
    digest_alg, digest = data.digest
    if data.metadata_bytes:
        requires_python = str(data.metadata.requires_python)
        metadata_digest_alg = 'sha256'
        metadata_digest = hashlib.sha256(data.metadata_bytes).hexdigest()
    else:
        requires_python = metadata_digest_alg = metadata_digest = None
    data.content.file.seek(0)
    _sql(
        'INSERT INTO files (filename, name, requires_python, digest_alg, digest, metadata_digest_alg, metadata_digest, metadata, content) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        (
            data.content.filename,
            canonicalize_name(data.name),
            requires_python,
            digest_alg,
            digest,
            metadata_digest_alg,
            metadata_digest,
            data.metadata_bytes,
            data.content.file.read(),
        ),
    )


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


@dataclasses.dataclass
class Hash:
    alg: str
    digest: str

    def __str__(self) -> str:
        return f'{self.alg}={self.digest}'

    def json(self) -> dict[str, str]:
        return {self.alg: self.digest}


@dataclasses.dataclass
class Link:
    filename: str
    file_hash: Hash
    metadata_hash: Hash | None = None
    requires_python: str | None = None
    yanked: bool = False

    def html(self) -> str:
        attrs = {'href': f'/files/{self.filename}#{self.file_hash}'}
        if self.requires_python:
            attrs['data-requires-python'] = html.escape(self.requires_python)
        if self.metadata_hash:
            attrs['data-core-metadata'] = attrs['data-dist-info-metadata'] = str(self.metadata_hash)
        if self.yanked:
            attrs['data-yanked'] = '1'
        attrs_html = ' '.join(f'{k}="{v}"' for k, v in attrs.items())
        return f'<a {attrs_html}>{self.filename}</a>'

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


@app.get('/', response_class=HTMLResponse)
def index() -> str:
    package_names = [row[0] for row in _sql('SELECT DISTINCT name FROM files ORDER BY name').fetchall()]
    return HTML_TEMPLATE.format(title='Simple index', content='\n'.join(f'<a href="{s}/">{s}</a><br/>' for s in package_names))


@app.get('/{project}/', response_class=HTMLResponse)
def proj(project: str) -> str:
    links = [
        Link(
            filename,
            Hash(digest_alg, digest),
            Hash(metadata_digest_alg, metadata_digest) if metadata_digest_alg else None,
            requires_python,
            bool(yanked),
        )
        for filename, digest_alg, digest, metadata_digest_alg, metadata_digest, requires_python, yanked in _sql(
            'SELECT filename, digest_alg, digest, metadata_digest_alg, metadata_digest, requires_python, yanked FROM files WHERE name = ?', (project,)
        ).fetchall()
    ]
    return HTML_TEMPLATE.format(title=f'Links for {project}', content='\n'.join(f'{l.html()}<br/>' for l in links))


@app.get('/files/{filename}')
def get_file(filename: str) -> Response:
    if filename.endswith('.metadata'):
        filename = filename[:-9]
        field = 'metadata'
    else:
        field = 'content'
    content = _sql(f'SELECT {field} FROM files WHERE filename = ?', (filename,)).fetchone()[0]  # noqa: S608
    return Response(content)


@app.post('/{project}/{version}/yank')
def yank(project: str, version: str) -> None:
    pass


@app.post('/{project}/{version}/unyank')
def unyank(project: str, version: str) -> None:
    pass
