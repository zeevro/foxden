import bisect
from collections.abc import Iterable
from typing import Protocol

from annotated_types import SupportsLt

from foxden.models import DistFile


class DuplicateValueError(ValueError):
    pass


def insert_sorted_nodup[T: SupportsLt](lst: list[T], obj: T) -> None:
    insert_idx = bisect.bisect_left(lst, obj)
    if insert_idx < len(lst) and lst[insert_idx] == obj:
        raise DuplicateValueError(obj)
    lst.insert(insert_idx + 1, obj)


class IndexGenerator(Protocol):
    def generate_root_index(self, projects: Iterable[str]) -> bytes: ...

    def generate_project_index(self, project: str, files: Iterable[DistFile], url_prefix: str = '') -> bytes: ...
