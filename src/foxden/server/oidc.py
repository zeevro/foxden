from typing import Annotated, Literal

from fastapi import Body

from foxden.server import app


@app.get('/_/oidc/audience')
def oidc_audience() -> dict[Literal['audience'], str]:
    return {'audience': 'foxden-upload'}


@app.get('/gh-api/oidc/token')
def gh_oidc_token(audience: str) -> dict[Literal['value'], str]:
    return {'value': f'token_for_{audience}'}


@app.post('/_/oidc/mint-token')
def oidc_mint_token(token: Annotated[str, Body(embed=True)]) -> dict[Literal['token'], str]:
    return {'token': f'mint-token_for_{token}'}
