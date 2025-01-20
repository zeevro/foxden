from collections.abc import Iterable
import contextlib
from typing import Annotated, Literal, Protocol

from fastapi import Header, HTTPException
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles

from foxden.config import settings
from foxden.models import DistFile
from foxden.server import app
from foxden.utils import pep503, pep691
from foxden.utils.http import accepted_types


class IndexResponseModule(Protocol):
    def generate_root_index(self, projects: Iterable[str]) -> bytes | str: ...

    def generate_project_index(self, project: str, files: Iterable[DistFile], url_prefix: str = '') -> bytes | str: ...


def resp_format(accept_hdr: str | None) -> Literal['html', 'json']:
    if accept_hdr:
        with contextlib.suppress(Exception):
            for i in accepted_types(accept_hdr):
                if i.split(';', 1)[0] in 'application/vnd.pypi.simple.v1+json':
                    return 'json'
    return 'html'


RESP_PARAMS: dict[str, tuple[IndexResponseModule, str]] = {
    'json': (pep691, 'application/vnd.pypi.simple.v1+json'),
    'html': (pep503, 'text/html'),
}


@app.get('/')
def root_index(accept: Annotated[str | None, Header()] = None) -> Response:
    mod, content_type = RESP_PARAMS[resp_format(accept)]
    return Response(mod.generate_root_index(settings.index_backend.list_projects()), media_type=content_type)


@app.get('/{project}/')
def project_index(project: str, accept: Annotated[str | None, Header()] = None) -> Response:
    files = settings.index_backend.files(project)
    if not files:
        raise HTTPException(404)
    mod, content_type = RESP_PARAMS[resp_format(accept)]
    return Response(mod.generate_project_index(project, files, '/files/'), media_type=content_type)


if hasattr(settings.index_backend, 'dir_path'):
    app.mount('/files', StaticFiles(directory=settings.index_backend.dir_path, check_dir=False))
else:
    raise NotImplementedError('No DB storage backend!!')  # TODO: Implement
