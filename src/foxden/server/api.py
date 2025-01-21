from typing import Annotated

from fastapi import Body, HTTPException
from packaging.utils import canonicalize_name
from starlette.status import HTTP_404_NOT_FOUND

from foxden.config import settings
from foxden.server import app


def _set_yanked(filename: str, yanked: bool) -> None:
    project = canonicalize_name(filename.split('-', 1)[0])
    try:
        settings.index_backend.set_yanked(project, filename, yanked)
    except FileNotFoundError as e:
        raise HTTPException(HTTP_404_NOT_FOUND) from e


@app.post('/_api/yank')
def yank(filename: Annotated[str, Body(embed=True)]) -> None:
    _set_yanked(filename, True)


@app.post('/_api/unyank')
def unyank(filename: Annotated[str, Body(embed=True)]) -> None:
    _set_yanked(filename, False)
