import os
from typing import List, MutableMapping, Any
import toml

from gatex.formatter.base import BaseFormatter

TOML_SECTIONS_FOR_TAG = ["patten", "content", "style"]

# patten: how this tag look like, how parser find it
# content: how deal with content on this tag
# style: how to render this tag

"""
SINGLE:
\TAG [a=2,b=3]\ asd

NESTED:
\TAG [a=1] {
asd
}

CUSTOM LEAD SINGLE
# asd

CUSTOM LEAD NESTED
[asd]

CONTEXT
[asd](2333)

"""


class TomlParserException(Exception):
    pass


def load(filename: str) -> MutableMapping[str, Any]:
    if not os.path.exists(filename):
        raise TomlParserException("toml file not found: {}".format(filename))
    try:
        return toml.load(filename)
    except Exception as e:
        raise TomlParserException("load toml file failed: {}".format(e))


def cook(toml_dict: dict) -> List[type]:
    objs = []
    for tag, prop in toml_dict.items():
        try:
            obj = type(tag, (BaseFormatter,), dict())
            for prop_name, prop_value in prop.items():
                setattr(obj, prop_name, prop_value)
            objs.append(obj)
        except Exception as e:
            raise TomlParserException("cook toml file failed: {}".format(e))
    return objs
