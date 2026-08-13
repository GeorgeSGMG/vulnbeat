from dataclasses import dataclass
from enum import Enum


class Scope(str, Enum):
    PRODUCTION = "production"
    DEVELOPMENT = "development"


class Ecosystem(str, Enum):
    PYPI = "PyPI"
    NPM = "npm"


@dataclass(frozen=True)
class Component:
    version: str | None
    constraint: str | None
    exact: bool
    scope: Scope
    ecosystem: Ecosystem