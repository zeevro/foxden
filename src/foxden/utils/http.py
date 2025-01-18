from operator import itemgetter
from typing import Any


def _q(s: str) -> tuple[tuple[Any, ...], str]:
    typ, *pl = s.replace(' ', '').split(';')
    params = dict(p.split('=', 1) for p in pl)
    try:
        q = float(params.pop('q'))
    except (KeyError, ValueError):
        q = 1
    return (q, 2 if typ == '*/*' else int(typ[-2:] == '/*'), len(params)), ';'.join([typ, *(f'{k}={v}' for k, v in params.items())])


def accepted_types(accept_hdr: str) -> list[str]:
    return [typ for q, typ in sorted((_q(i) for i in accept_hdr.split(',')), key=itemgetter(0), reverse=True)]
