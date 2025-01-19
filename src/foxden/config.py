import base64
from collections.abc import Mapping
from functools import cached_property
import os
import secrets
from typing import Any

import dotenv
import jwt
import msgspec


def convert_env[T](env: Mapping[str, str | None], typ: type[T]) -> T:
    ret: dict[str, Any] = dict(env)
    for f in getattr(msgspec.inspect.type_info(typ), 'fields', ()):
        if f.encode_name not in ret:
            continue
        if isinstance(f.type, msgspec.inspect.CollectionType):
            ret[f.encode_name] = ret[f.encode_name].split(',')
    return msgspec.convert(ret, typ, strict=False)


class Config(msgspec.Struct, rename='upper', dict=True, kw_only=True):
    secret: bytes = msgspec.field(default_factory=secrets.token_bytes)
    oidc_audience: str = 'foxden'
    oidc_trusted_issuers: frozenset[str] = frozenset({'https://token.actions.githubusercontent.com'})

    @cached_property
    def jwk(self) -> jwt.PyJWK:
        return jwt.PyJWK({'kty': 'oct', 'k': base64.urlsafe_b64encode(self.secret).decode()})


settings = convert_env(dotenv.dotenv_values() | os.environ, Config)
