"""Type hints to support development process."""
from datetime import datetime
from typing import Literal, TypeAlias

__all__ = [
    "JSONValueType",
    "JSONArrayType",
    "JSONObjectType",
    "JSONType",
    "StealerNameType",
]

JSONValueType: TypeAlias = (
    str
    | bytes
    | int
    | float
    | bool
    | datetime
    | None
    | list["JSONValueType"]
    | dict[str, "JSONValueType"]
)
JSONArrayType: TypeAlias = list[JSONValueType]
JSONObjectType: TypeAlias = dict[str, JSONValueType]
JSONType: TypeAlias = JSONObjectType | JSONArrayType

# NOTE: To be extended if more infostealers are handled.
StealerNameType: TypeAlias = Literal[
    "redline", "stealc", "lummac2", "meta", "raccoon", "dcrat"
]
