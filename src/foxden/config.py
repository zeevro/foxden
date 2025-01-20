import base64
from collections.abc import Mapping
from functools import cached_property
import os
import secrets
from typing import Any, Literal

import dotenv
import jwt
import msgspec

from foxden.backend.index import CombinedIndexBackend, IndexBackend
from foxden.backend.index.pep503 import Pep503IndexBackend
from foxden.backend.index.pep691 import Pep691IndexBackend
from foxden.types import AnyPath


def env_dec_hook[T](typ: type[T], obj: Any) -> T:
    for validator in getattr(typ, '__get_validators__', lambda: (typ,))():
        obj = validator(obj)  # type: ignore[call-arg]
    return obj  # type: ignore[no-any-return]


def convert_env[T](env: Mapping[str, str | None], typ: type[T]) -> T:
    ret: dict[str, Any] = dict(env)
    for f in getattr(msgspec.inspect.type_info(typ), 'fields', ()):
        if f.encode_name not in ret:
            continue
        if isinstance(f.type, msgspec.inspect.CollectionType):
            ret[f.encode_name] = ret[f.encode_name].split(',')
    return msgspec.convert(ret, typ, strict=False, dec_hook=env_dec_hook)


class Config(msgspec.Struct, rename='upper', dict=True, kw_only=True):
    secret: bytes = msgspec.field(default_factory=secrets.token_bytes)
    oidc_audience: str = 'foxden'
    oidc_trusted_issuers: frozenset[str] = frozenset({'https://token.actions.githubusercontent.com'})
    storage_backend: Literal['files', 'db'] = 'files'
    index_type: Literal['html', 'json', 'both'] = 'html'
    storage_path: AnyPath | None = None
    database_url: str | None = None

    def __post_init__(self) -> None:
        if self.storage_backend == 'files' and self.storage_path is None:
            raise msgspec.ValidationError('Must define STORAGE_PATH when INDEX_BACKEND is "files"')
        if self.storage_backend == 'db' and self.database_url is None:
            raise msgspec.ValidationError('Must define DATABASE_URL when INDEX_BACKEND is "db"')

    @cached_property
    def index_backend(self) -> IndexBackend:
        if self.storage_backend == 'files':
            d = {
                'json': Pep691IndexBackend(self.storage_path),
                'html': Pep503IndexBackend(self.storage_path),
            }
            d['both'] = CombinedIndexBackend(d['json'], d['html'])
            return d[self.index_type]
        if self.storage_backend == 'db':
            raise NotImplementedError
        raise ValueError(f'Invalid index backend {self.storage_backend!r}')

    @cached_property
    def jwk(self) -> jwt.PyJWK:
        return jwt.PyJWK({'kty': 'oct', 'k': base64.urlsafe_b64encode(self.secret).decode()})


dotenv.load_dotenv()

settings = convert_env(os.environ, Config)
