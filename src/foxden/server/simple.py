import contextlib
from typing import Annotated
from urllib.parse import quote_plus

from fastapi import Depends, Header, HTTPException, Query
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles

from foxden.config import settings
from foxden.server import app
from foxden.utils import IndexGenerator, pep503, pep691
from foxden.utils.http import accepted_types


INDEX_MODULE: dict[str, IndexGenerator] = {
    'application/vnd.pypi.simple.v1+json': pep691,
    'application/vnd.pypi.simple.v1+html': pep503,
    'text/html': pep503,
}

DEFAULT_CONTENT_TYPE: str = 'text/html'

DEFAULT_INDEX_MODULE = INDEX_MODULE[DEFAULT_CONTENT_TYPE]

type ReponseParams = tuple[str, IndexGenerator]


def response_params(
    accept_hdr: Annotated[str | None, Header(alias='accept')] = None, format_param: Annotated[str | None, Query(alias='format')] = None
) -> ReponseParams:
    if format_param:
        format_param_quoted = quote_plus(format_param, safe='/')
        if format_param_quoted in INDEX_MODULE:
            return format_param_quoted, INDEX_MODULE[format_param_quoted]
    if accept_hdr:
        for i in accepted_types(accept_hdr):
            t = i.split(';', 1)[0]
            with contextlib.suppress(KeyError):
                return t, INDEX_MODULE[t]
    return DEFAULT_CONTENT_TYPE, DEFAULT_INDEX_MODULE


@app.get('/')
def root_index(response_params: Annotated[ReponseParams, Depends(response_params)]) -> Response:
    content_type, index_module = response_params
    return Response(index_module.generate_root_index(settings.index_backend.list_projects()), media_type=content_type)


@app.get('/{project}/')
def project_index(project: str, response_params: Annotated[ReponseParams, Depends(response_params)]) -> Response:
    content_type, index_module = response_params
    files = settings.index_backend.files(project)
    if not files:
        raise HTTPException(404)
    return Response(index_module.generate_project_index(project, files, '/files/'), media_type=content_type)


if hasattr(settings.index_backend, 'dir_path'):
    app.mount('/files', StaticFiles(directory=settings.index_backend.dir_path, check_dir=False))
else:
    raise NotImplementedError('No DB storage backend!!')  # TODO: Implement
