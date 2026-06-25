"""The collector contract and a tiny plugin registry.

Adding a new intelligence source is the most common extension. To do so,
subclass ``BaseCollector``, implement ``collect``, and decorate the class
with ``@register``. The pipeline discovers it automatically.
"""
from __future__ import annotations

import abc
import logging
from typing import Dict, Iterable, List, Type

from .schema import Finding
from ..config import Config

log = logging.getLogger("marlong.collector")


class BaseCollector(abc.ABC):
    name: str = "base"
    description: str = ""

    def __init__(self, config: Config):
        self.config = config

    @abc.abstractmethod
    def collect(self, target: str) -> Iterable[Finding]:
        """Yield Findings for a single target."""
        raise NotImplementedError

    def available(self) -> bool:
        """Whether this collector has what it needs (keys etc.) to run."""
        return True


_REGISTRY: Dict[str, Type[BaseCollector]] = {}


def register(cls: Type[BaseCollector]) -> Type[BaseCollector]:
    if not getattr(cls, "name", None) or cls.name == "base":
        raise ValueError(f"Collector {cls!r} must define a unique 'name'")
    _REGISTRY[cls.name] = cls
    return cls


def get_collector(name: str) -> Type[BaseCollector]:
    if name not in _REGISTRY:
        raise KeyError(f"Unknown collector '{name}'. Available: {sorted(_REGISTRY)}")
    return _REGISTRY[name]


def all_collectors() -> List[str]:
    return sorted(_REGISTRY)
