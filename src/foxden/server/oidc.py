import logging
import time
from typing import Annotated, Any, Literal
from urllib.request import urlopen
import uuid

from fastapi import Body, HTTPException
import jwt
import msgspec

from foxden.config import settings
from foxden.server import app


logger = logging.getLogger(__name__)


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
    oidc_config = msgspec.json.decode(urlopen(f'{issuer}/.well-known/openid-configuration').read())  # noqa: S310  # TODO: cache
    jwks_client = jwt.PyJWKClient(oidc_config['jwks_uri'])
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    claims = jwt.decode(token, key=signing_key, audience=settings.oidc_audience)
    if not custom_jwt_verifier(claims):
        raise HTTPException(401)
    now = int(time.time())
    mint_token = jwt.encode({'jti': str(uuid.uuid4()), 'aud': 'oidc', 'iat': now, 'nbf': now - 5, 'exp': now + 20}, settings.jwk)
    return {'token': mint_token}
