import contextlib
from functools import cached_property
import logging
import shutil
import tarfile
import time
from typing import TYPE_CHECKING, Annotated, Any, Literal
import uuid
import zipfile

from fastapi import Body, Depends, Form, HTTPException, UploadFile
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import hishel
import httpx
import jwt
import msgspec
from packaging.metadata import Metadata
from packaging.utils import canonicalize_name
from pydantic import BaseModel, Field, RootModel, model_validator
from starlette.status import HTTP_400_BAD_REQUEST, HTTP_403_FORBIDDEN

from foxden.config import settings
from foxden.models import Digest, DistFile
from foxden.server import app


logger = logging.getLogger(__name__)


class HttpxPyJWKClient(jwt.PyJWKClient):
    def __init__(self, client: httpx.Client, uri: str, headers: dict[str, Any] | None = None) -> None:
        super().__init__(uri, cache_keys=False, cache_jwk_set=False, headers=headers)
        self.client = client

    def fetch_data(self) -> Any:
        try:
            response = self.client.get(self.uri, headers=self.headers)
            response.raise_for_status()
            return msgspec.json.decode(response.read())
        except (httpx.HTTPError, TimeoutError, msgspec.DecodeError) as e:
            raise jwt.PyJWKClientConnectionError(f'Fail to fetch data from the url, err: "{e}"') from e


def custom_jwt_verifier(claims: dict[str, Any]) -> bool:  # TODO: Configuration (how?)
    return bool(claims['repository_owner'] == 'perceptionpoint')


@app.get('/_/oidc/audience')
def oidc_audience() -> dict[Literal['audience'], str]:
    return {'audience': settings.oidc_audience}


@app.post('/_/oidc/mint-token')
def oidc_mint_token(token: Annotated[str, Body(embed=True)]) -> dict[Literal['token'], str]:
    issuer = jwt.decode(token, options={'verify_signature': False})['iss']
    if issuer not in settings.oidc_trusted_issuers:
        raise HTTPException(HTTP_403_FORBIDDEN)
    with hishel.CacheClient() as client:
        oidc_config = msgspec.json.decode(client.get(f'{issuer}/.well-known/openid-configuration').read())
        jwks_client = HttpxPyJWKClient(client, oidc_config['jwks_uri'])
        signing_key = jwks_client.get_signing_key_from_jwt(token)
    claims = jwt.decode(token, key=signing_key, audience=settings.oidc_audience)
    if not custom_jwt_verifier(claims):
        raise HTTPException(HTTP_403_FORBIDDEN)
    now = int(time.time())
    mint_token = jwt.encode({'jti': str(uuid.uuid4()), 'aud': 'oidc', 'iat': now, 'nbf': now - 5, 'exp': now + 20}, settings.jwk)
    return {'token': mint_token}


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
def upload(req: Annotated[UploadRequest, Form()], creds: Annotated[HTTPBasicCredentials, Depends(HTTPBasic())]) -> None:
    if creds.username != '__token__':
        raise HTTPException(HTTP_403_FORBIDDEN)
    try:
        jwt.decode(creds.password, key=settings.jwk, audience=['oidc', 'login'])
    except jwt.InvalidTokenError:
        logger.warning('Token validation failed', exc_info=True)
        raise HTTPException(HTTP_403_FORBIDDEN) from None

    project = canonicalize_name(req.name)

    if not req.content.filename:
        raise HTTPException(HTTP_400_BAD_REQUEST, 'content filename cannot be empty')

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
            raise HTTPException(HTTP_400_BAD_REQUEST, f'File already exists ({pdf.filename!r}, with {pdf.digest.alg} hash {pdf.digest.digest}).')

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
