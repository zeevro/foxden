from typing import TYPE_CHECKING

import cloudpathlib


if TYPE_CHECKING:
    import pathlib

    AnyPath = pathlib.Path | cloudpathlib.CloudPath
else:
    AnyPath = cloudpathlib.AnyPath
