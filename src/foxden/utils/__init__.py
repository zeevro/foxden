import bisect

from annotated_types import SupportsLt


class DuplicateValueError(ValueError):
    pass


def insert_sorted_nodup[T: SupportsLt](lst: list[T], obj: T) -> None:
    insert_idx = bisect.bisect_left(lst, obj)
    if insert_idx < len(lst) and lst[insert_idx] == obj:
        raise DuplicateValueError(obj)
    lst.insert(insert_idx + 1, obj)
