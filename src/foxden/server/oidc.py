import base64
import secrets
import time
from typing import Annotated, Any, Literal
from urllib.request import urlopen
import uuid

from fastapi import Body, HTTPException
import jwt
import msgspec

from foxden.server import app


AUDIENCE = 'foxden-upload'  # TODO: Configuration
TOKEN_SIG_KEY = jwt.PyJWK({'kty': 'oct', 'k': base64.urlsafe_b64encode(secrets.token_bytes())})  # TODO: Configuration
TRUSTED_ISSUERS = {'https://token.actions.githubusercontent.com'}  # TODO: Configuration


def custom_jwt_verifier(claims: dict[str, Any]) -> bool:  # TODO: Configuration (how?)
    return claims['repository_owner'] == 'perceptionpoint'


@app.get('/_/oidc/audience')
def oidc_audience() -> dict[Literal['audience'], str]:
    return {'audience': AUDIENCE}


@app.post('/_/oidc/mint-token')
def oidc_mint_token(token: Annotated[str, Body(embed=True)]) -> dict[Literal['token'], str]:
    issuer = jwt.decode(token, options={'verify_signature': False})['iss']
    if issuer not in TRUSTED_ISSUERS:
        raise HTTPException(401)
    oidc_config = msgspec.json.decode(urlopen(f'{issuer}/.well-known/openid-configuration').read())  # noqa: S310  # TODO: cache
    jwks_client = jwt.PyJWKClient(oidc_config['jwks_uri'])
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    claims = jwt.decode(token, key=signing_key, audience=AUDIENCE)
    if not custom_jwt_verifier(claims):
        raise HTTPException(401)
    now = time.time()
    mint_token = jwt.encode({'jti': str(uuid.uuid4()), 'sub': 'upload', 'aud': 'oidc-upload', 'iat': now, 'nbf': now - 5, 'exp': now + 20}, TOKEN_SIG_KEY)
    return {'token': mint_token}


def verify_oidc_token(token: str) -> bool:
    try:
        jwt.decode(token, key=TOKEN_SIG_KEY, audience='oidc-upload', subject='upload')
    except jwt.InvalidTokenError as e:
        print(f'verify_oidc_token: {type(e).__name__}: {e}')
        return False
    return True
