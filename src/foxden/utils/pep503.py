from collections.abc import Iterable
import html

from foxden.models import DistFile


INDEX_TEMPLATE = """<!DOCTYPE html>
<html>
  <head>
    <meta name="pypi:repository-version" content="1.0">
    <title>{title}</title>
  </head>
  <body>
    <h1>{title}</h1>
{content}
</body>
</html>"""


def _link(distfile: DistFile, prefix: str = '') -> str:
    attrs = {'href': f'{prefix}{distfile.filename}#{distfile.digest}'}
    if distfile.requires_python:
        attrs['data-requires-python'] = html.escape(distfile.requires_python)
    if distfile.metadata_digest:
        attrs['data-core-metadata'] = attrs['data-dist-info-metadata'] = str(distfile.metadata_digest)
    if distfile.yanked:
        attrs['data-yanked'] = '1'
    attrs_html = ' '.join(f'{k}="{v}"' for k, v in attrs.items())
    return f'<a {attrs_html}>{distfile.filename}</a>'


def generate_root_index(projects: Iterable[str]) -> str:
    return INDEX_TEMPLATE.format(title='Simple index', content='\n'.join(f'<a href="{s}/">{s}</a><br/>' for s in projects))


def generate_project_index(project: str, files: Iterable[DistFile], url_prefix: str = '') -> str:
    return INDEX_TEMPLATE.format(title=f'Links for {project}', content='\n'.join(f'{_link(f, url_prefix)}<br/>' for f in files))
