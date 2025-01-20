import contextlib
from functools import cached_property
import logging
import shutil
import tarfile
from typing import TYPE_CHECKING, Annotated, Literal
import zipfile

from fastapi import Depends, Form, HTTPException, UploadFile
from fastapi.security import HTTPBasicCredentials
import jwt
from packaging.metadata import Metadata
from packaging.utils import canonicalize_name
from pydantic import BaseModel, Field, RootModel, model_validator

from foxden.config import settings
from foxden.models import Digest, DistFile
from foxden.server import app, security


logger = logging.getLogger(__name__)


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
        if not self.content.filename:
            raise ValueError('No filename')
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
                return tarfile.open(fileobj=self.content.file).extractfile(self.metadata_path).read()  # type: ignore[union-attr]
        return None

    @cached_property
    def metadata(self) -> Metadata | None:
        if not self.metadata_bytes:
            return None
        return Metadata.from_email(self.metadata_bytes)


class UploadRequestMD5(UploadRequestBase):
    md5_digest: str

    @property
    def digest(self) -> Digest:
        return Digest('md5', self.md5_digest)


class UploadRequestSha256(UploadRequestBase):
    sha256_digest: str

    @property
    def digest(self) -> Digest:
        return Digest('sha256', self.sha256_digest)


class UploadRequestBlake2(UploadRequestBase):
    blake2_256_digest: str

    @property
    def digest(self) -> Digest:
        return Digest('blake2_256', self.blake2_256_digest)


if TYPE_CHECKING:
    UploadRequest = UploadRequestMD5 | UploadRequestSha256 | UploadRequestBlake2
else:

    class UploadRequest(RootModel[UploadRequestMD5 | UploadRequestSha256 | UploadRequestBlake2]):
        @model_validator(mode='after')
        def fix_root(self) -> UploadRequestMD5 | UploadRequestSha256 | UploadRequestBlake2:
            return self.root


@app.post('/')
def upload(req: Annotated[UploadRequest, Form()], creds: Annotated[HTTPBasicCredentials, Depends(security)]) -> None:
    if creds.username != '__token__':
        raise HTTPException(401)
    try:
        jwt.decode(creds.password, key=settings.jwk, audience=['oidc', 'login'])
    except jwt.InvalidTokenError:
        logger.warning('Token validation failed', exc_info=True)
        raise HTTPException(401) from None

    project = canonicalize_name(req.name)

    if not req.content.filename:
        raise HTTPException(400, 'content filename cannot be empty')

    distfile = DistFile(
        req.content.filename,
        req.digest,
        str(getattr(req.metadata, 'requires_python', '')) or None,
        Digest.from_bytes(req.metadata_bytes) if req.metadata_bytes else None,
    )

    if not settings.storage_path:
        raise NotImplementedError

    for pdf in settings.index_backend.files(project):
        if pdf.filename == distfile.filename:
            if pdf.digest == distfile.digest:
                return
            raise HTTPException(400, f'File already exists ({pdf.filename!r}, with {pdf.digest.alg} hash {pdf.digest.digest}).')

    file_path = settings.storage_path / distfile.filename

    settings.storage_path.mkdir(parents=True, exist_ok=True)
    settings.storage_path.joinpath('.gitignore').write_text('**\n')

    # Write file
    req.content.file.seek(0)
    with file_path.open('wb') as f:
        shutil.copyfileobj(req.content.file, f)

    # Write metadata
    if req.metadata_bytes:
        file_path.with_name(f'{file_path.name}.metadata').write_bytes(req.metadata_bytes)

    settings.index_backend.new_file(project, distfile)
