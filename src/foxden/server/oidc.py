from typing import Annotated, Literal
from urllib.request import urlopen

from fastapi import Body
import jwt
import msgspec

from foxden.server import app


@app.get('/_/oidc/audience')
def oidc_audience() -> dict[Literal['audience'], str]:
    return {'audience': 'foxden-upload'}  # TODO: Configuration


@app.get('/gh-api/oidc/token')
def gh_oidc_token(audience: str) -> dict[Literal['value'], str]:
    return {'value': f'token_for_{audience}'}


@app.post('/_/oidc/mint-token')
def oidc_mint_token(token: Annotated[str, Body(embed=True)]) -> dict[Literal['token'], str]:
    # See: https://pyjwt.readthedocs.io/en/stable/usage.html#oidc-login-flow
    unverified_claims = jwt.decode(token, options={'verify_signature': False})
    oidc_config = msgspec.json.decode(urlopen(f'{unverified_claims["iss"]}/.well-known/openid-configuration').read())  # noqa: S310
    jwks_client = jwt.PyJWKClient(oidc_config['jwks_uri'])
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    claims = jwt.decode(token, key=signing_key, audience='foxden-upload')
    return {'token': f'mint-token_for_{token}'}
