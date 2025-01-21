import msgspec

from foxden.backend.index.files import FilesIndexBackend
from foxden.models import DistFile
from foxden.types import AnyPath
from foxden.utils import pep691
from foxden.utils.pep691 import ProjectIndex, RootIndex


class Pep691IndexBackend(FilesIndexBackend):
    _index_filename = 'index.json'
    _index_generator = pep691

    def _parse_root_index(self, index_path: AnyPath) -> list[str]:
        return [p.name for p in msgspec.json.decode(index_path.read_bytes(), type=RootIndex).projects]

    def _parse_project_index(self, index_path: AnyPath) -> list[DistFile]:
        return [f.distfile() for f in msgspec.json.decode(index_path.read_bytes(), type=ProjectIndex).files]
