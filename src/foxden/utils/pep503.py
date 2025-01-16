from collections.abc import Iterable

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


def generate_root_index(projects: Iterable[str]) -> str:
    return INDEX_TEMPLATE.format(title='Simple index', content='\n'.join(f'<a href="{s}/">{s}</a><br/>' for s in projects))


def generate_project_index(project: str, files: Iterable[DistFile]) -> str:
    return INDEX_TEMPLATE.format(title=f'Links for {project}', content='\n'.join(f'{l.html()}<br/>' for l in files))
