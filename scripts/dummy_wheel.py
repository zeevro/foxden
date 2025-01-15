from __future__ import annotations

import argparse
import base64
from functools import cached_property
import hashlib
import html
import http.server
import io
import itertools
import json
from operator import itemgetter
from pathlib import Path
import re
import tarfile
import traceback
from typing import Any, ClassVar, NoReturn
import zipfile


MY_PATH = Path(__file__)
MY_NAME = MY_PATH.name
MY_CONTENT = MY_PATH.read_text()

UNDERSCORE = '_'


def _load_pyproject_toml() -> tuple[str, str]:
    pyproject_toml = Path(__file__).parent.joinpath('pyproject.toml').read_text()
    name = re.findall(r'^name = "(.*)"$', pyproject_toml, re.MULTILINE)[0]
    version = re.findall(r'^version = "(.*)"$', pyproject_toml, re.MULTILINE)[0]
    return name, version


def normalize(name: str, repl: str = '-') -> str:
    return re.sub(r'[-_.]+', repl, name).lower()


def urlsafe_b64encode_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('latin1')


def sha256_base64(content: bytes) -> str:
    return f'sha256={urlsafe_b64encode_nopad(hashlib.sha256(content).digest())}'


def sha256_hex(content: bytes) -> str:
    return f'sha256={hashlib.sha256(content).hexdigest()}'


class DummyDistBase:
    filename_suffix: ClassVar[str]
    mime_type: ClassVar[str]

    @classmethod
    def build_backend(cls, output_dir: str, config_settings: dict[str, str | list[str]] | None = None, metadata_directory: str | None = None) -> str:  # noqa: ARG003
        name, version = _load_pyproject_toml()
        self = cls(name, version)
        self.write_file(Path(output_dir))
        return self.filename

    def __init__(self, name: str, version: str) -> None:
        if '-' in version:
            raise ValueError('version must not contain dashes')

        self.name = name
        self.version = version

        self._full_name = f'{normalize(name, UNDERSCORE)}-{version}'

        self.filename = f'{self._full_name}{self.filename_suffix}'

    @cached_property
    def metadata(self) -> str:
        return f'Metadata-Version: 2.3\nName: {normalize(self.name)}\nVersion: {self.version}\n'

    def _generate_file(self) -> bytes:
        raise NotImplementedError

    @cached_property
    def _bytes(self) -> bytes:
        return self._generate_file()

    def write_file(self, output_dir: Path | None = None) -> Path:
        if not output_dir:
            output_dir = Path()
        elif not output_dir.exists():
            output_dir.mkdir(parents=True)
        path = (output_dir or Path()) / self.filename
        path.write_bytes(self._bytes)
        return path

    def get_bytes(self) -> bytes:
        return self._bytes


class DummyWheel(DummyDistBase):
    filename_suffix = '-py3-none-any.whl'
    mime_type = 'application/zip'

    def _generate_file(self) -> bytes:
        dist_info = f'{self._full_name}.dist-info'

        files = {
            f'{dist_info}/METADATA': self.metadata,
            f'{dist_info}/WHEEL': f'Wheel-Version: 1.0\nGenerator: {MY_NAME}\nRoot-Is-Purelib: true\nTag: py3-none-any\n',
        }

        record_path = f'{dist_info}/RECORD'
        record = io.StringIO()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as zf:
            for path, content in files.items():
                zf.writestr(path, content)
                content_bytes = content.encode()
                record.write(f'{path},{sha256_base64(content_bytes)},{len(content_bytes)}\n')
            record.write(f'{record_path},,\n')
            zf.writestr(record_path, record.getvalue())
        return buf.getvalue()


class DummySourceDist(DummyDistBase):
    filename_suffix = '.tar.gz'
    mime_type = 'application/x-gzip'

    def _generate_file(self) -> bytes:
        files = {
            f'{self._full_name}/PKG-INFO': self.metadata,
            f'{self._full_name}/build.py': MY_CONTENT,
            f'{self._full_name}/pyproject.toml': f'[build-system]\nrequires = []\nbuild-backend = "build"\nbackend-path = ["."]\n\n[project]\nname = "{self.name}"\nversion = "{self.version}"\n',
        }

        buf = io.BytesIO()
        with tarfile.open(self.filename, 'w:gz', buf, format=tarfile.PAX_FORMAT) as tf:
            for path, content in files.items():
                content_bytes = content.encode()
                ti = tf.tarinfo(path)
                ti.size = len(content_bytes)
                tf.addfile(ti, io.BytesIO(content_bytes))
        return buf.getvalue()


build_wheel = DummyWheel.build_backend
build_sdist = DummySourceDist.build_backend


class HttpError(Exception):
    def __init__(self, code: int, msg: str | None = None) -> None:
        super().__init__(code, msg)
        self.code = code
        self.msg = msg


class HttpResponse:
    def __init__(self, body: bytes | str | None = None, code: int = 200, **headers: Any) -> None:
        self._body = body
        self.code = code
        self.headers = headers

    @cached_property
    def body(self) -> bytes:
        ret = self._body or b''
        if isinstance(ret, bytes):
            return ret
        return str(ret).encode('utf-8', errors='replace')


def parse_requirements(requirements: str) -> dict[str, list[str]]:
    l = set()
    for r in requirements.splitlines():
        name, version = r.replace(' ', '').split('==')
        l.add((normalize(name), version))
    return {name: [i[1] for i in items] for name, items in itertools.groupby(sorted(l), key=itemgetter(0))}


class MySimpleRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        try:
            resp = self._handle_request()
            if not isinstance(resp, HttpResponse):
                resp = HttpResponse(resp, content_type='text/html; charset=utf-8')
        except Exception as e:  # noqa: BLE001
            if isinstance(e, HttpError):
                code = e.code
                explain = e.msg or ''
            else:
                code = 500
                explain = ''.join(traceback.format_exc())

            resp = HttpResponse(
                self.error_message_format
                % {
                    'code': code,
                    'message': html.escape(http.HTTPStatus(code).phrase, quote=False),
                    'explain': f'<pre>{html.escape(explain)}</pre>',
                },
                code=code,
                content_type=self.error_content_type,
            )

        self.send_response(resp.code)
        for k, v in resp.headers.items():
            self.send_header(k.replace('_', '-').title(), str(v))
        if resp.body:
            self.send_header('Content-Length', str(len(resp.body)))
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(resp.body)

    def do_HEAD(self) -> None:  # noqa: N802
        return self.do_GET()

    def _abort(self, code: int = 400, msg: str | None = None) -> NoReturn:
        self.log_message('Abort: %d %s', code, msg)
        raise HttpError(code, msg)

    def _redirect(self, new_url: str) -> HttpResponse:
        self.log_message('Redirect: %s', new_url)
        return HttpResponse(code=302, location=new_url)

    def _handle_request(self) -> None | bytes | str | HttpResponse:
        path_parts = list(filter(None, self.path.split('/')))
        trailing_slash = self.path.endswith('/')
        for content_type in ('application/vnd.pypi.simple.v1+json', 'application/vnd.pypi.simple.v1+html', 'text/html'):
            if content_type in self.headers['Accept']:
                break

        if not path_parts:
            return self._abort(404)

        section, *path_parts = path_parts

        if section == 'simple' and path_parts:
            if not trailing_slash:
                return self._redirect(f'{self.path}/')

            requirements_raw, *path_parts = path_parts

            try:
                requirements = parse_requirements(base64.urlsafe_b64decode(requirements_raw).decode())
            except Exception:  # noqa: BLE001
                self._abort()

            if not path_parts:
                if 'json' in content_type:
                    return HttpResponse(
                        json.dumps(
                            {
                                'meta': {'api-version': '1.0'},
                                'projects': [{'name': name} for name in requirements],
                            }
                        ).encode(),
                        content_type=content_type,
                    )

                return HttpResponse(
                    '\n'.join(
                        [
                            '<!DOCTYPE html>',
                            '<html><head><meta name="pypi:repository-version" content="1.0"><title>Simple index</title></head>',
                            '<body><h1>Simple index</h1>',
                            *(f'<a href="{name}/">{name}</a><br/>' for name in requirements),
                            '</body></html>',
                        ]
                    ),
                    content_type=content_type,
                )

            if len(path_parts) == 1:
                name = path_parts[0]
                if name != normalize(name):
                    return self._redirect(normalize(name))

                if name not in requirements:
                    self._abort(404)

                dummies: list[DummyDistBase] = [builder(name, version) for version in requirements[name] for builder in [DummyWheel, DummySourceDist]]

                if 'json' in content_type:
                    return HttpResponse(
                        json.dumps(
                            {
                                'meta': {'api-version': '1.0'},
                                'name': name,
                                'files': [
                                    {
                                        'filename': d.filename,
                                        'url': f'/files/{d.filename}',
                                        'hashes': {},
                                        'core-metadata': {'sha256': hashlib.sha256(d.metadata.encode()).hexdigest()},
                                    }
                                    for d in dummies
                                ],
                            }
                        ).encode(),
                        content_type=content_type,
                    )

                return HttpResponse(
                    '\n'.join(
                        [
                            '<!DOCTYPE html>',
                            f'<html><head><meta name="pypi:repository-version" content="1.0"><title>Links for {name}</title></head>'
                            f'<body><h1>Links for {name}</h1>',
                            *(
                                f'<a href="/files/{d.filename}" data-core-metadata="{sha256_hex(d.metadata.encode())}">{d.filename}</a><br/>'
                                for d in dummies
                            ),
                            '</body></html>',
                        ]
                    ),
                    content_type=content_type,
                )

            self._abort(404)

        if section == 'files':
            if len(path_parts) != 1 or trailing_slash:
                self._abort(404)

            filename = path_parts[0]

            metadata = filename.endswith('.metadata')
            if metadata:
                filename = filename[:-9]

            for builder in [DummyWheel, DummySourceDist]:
                if filename.endswith(builder.filename_suffix):
                    break
            else:
                self._abort(404)

            try:
                name, version = filename[: -len(builder.filename_suffix)].split('-')
                d = builder(name, version)
            except ValueError:
                self._abort(msg='Invalid filename')

            if filename != d.filename:
                return self._redirect(f'{d.filename}')

            if metadata:
                return HttpResponse(d.metadata, content_type='text/plain')

            return HttpResponse(d.get_bytes(), content_type=d.mime_type, content_disposition=f'attachment; filename="{d.filename}"')

        if section in {'sdist', 'wheel'} and trailing_slash:
            try:
                name, version = path_parts
            except ValueError:
                self._abort(404)

            builder = DummyWheel if section == 'wheel' else DummySourceDist
            try:
                d = builder(name, version)
            except ValueError as e:
                self._abort(msg=str(e))

            return self._redirect(f'/files/{d.filename}')

        self._abort(404)  # noqa: RET503


def main() -> None:
    p = argparse.ArgumentParser()
    sp = p.add_subparsers(dest='cmd')

    p_srv = sp.add_parser('server', conflict_handler='resolve')
    p_srv.add_argument('-h', '--host', default='')
    p_srv.add_argument('-p', '--port', type=int, default=12345)

    p_build = sp.add_parser('build')
    p_build.add_argument('-s', '--sdist', action='store_true')
    p_build.add_argument('-w', '--wheel', action='store_true')
    p_build.add_argument('-d', '--output-dir', type=Path, default=Path('dist'))
    p_build.add_argument('name')
    p_build.add_argument('version')

    args = p.parse_args()

    if args.cmd == 'server':
        srv = http.server.ThreadingHTTPServer((args.host, args.port), MySimpleRequestHandler)
        srv.serve_forever()
        return

    if args.cmd == 'build':
        builders: list[type[DummyDistBase]] = []
        if args.sdist:
            builders.append(DummySourceDist)
        if args.wheel:
            builders.append(DummyWheel)
        if not builders:
            builders = [DummySourceDist, DummyWheel]
        for builder in builders:
            d = builder(args.name, args.version)
            d.write_file(args.output_dir)
            print(d.filename)  # noqa: T201


if __name__ == '__main__':
    main()
