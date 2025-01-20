import logging
import time
from typing import Annotated, Any, Literal
import uuid

from fastapi import Body, HTTPException
import hishel
import httpx
import jwt
import msgspec

from foxden.config import settings
from foxden.server import app


logger = logging.getLogger(__name__)


class HttpxPyJWKClient(jwt.PyJWKClient):
    def __init__(self, client: httpx.Client, uri: str, headers: dict[str, Any] | None = None) -> None:
        super().__init__(uri, cache_keys=False, cache_jwk_set=False, headers=headers)
        self.client = client

    def fetch_data(self) -> Any:  # noqa: ANN401
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
        raise HTTPException(401)
    with hishel.CacheClient() as client:
        oidc_config = msgspec.json.decode(client.get(f'{issuer}/.well-known/openid-configuration').read())
        jwks_client = HttpxPyJWKClient(client, oidc_config['jwks_uri'])
        signing_key = jwks_client.get_signing_key_from_jwt(token)
    claims = jwt.decode(token, key=signing_key, audience=settings.oidc_audience)
    if not custom_jwt_verifier(claims):
        raise HTTPException(401)
    now = int(time.time())
    mint_token = jwt.encode({'jti': str(uuid.uuid4()), 'aud': 'oidc', 'iat': now, 'nbf': now - 5, 'exp': now + 20}, settings.jwk)
    return {'token': mint_token}
