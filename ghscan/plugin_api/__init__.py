"""
ghscan plugin API — base classes and data structures for scanner plugins.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class PluginMeta:
    """Metadata every plugin must declare."""
    name: str
    description: str
    version: str
    author: str = ""
    category: str = ""
    severity: str = "medium"
    tags: List[str] = field(default_factory=list)


@dataclass
class FileRequest:
    """A file path pattern a plugin needs from each repo."""
    path: str
    required: bool = False
    subdirs: List[str] = field(default_factory=list)

    def expand_paths(self) -> List[str]:
        """Expand subdirs into concrete file paths."""
        if not self.subdirs:
            return [self.path]
        paths = []
        for subdir in self.subdirs:
            if subdir:
                paths.append(f"{subdir}/{self.path}")
            else:
                paths.append(self.path)
        return paths


@dataclass
class PluginFinding:
    """One finding produced by a plugin for a single repo."""
    plugin_name: str
    severity: str
    title: str
    score: int
    details: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)


class ScanPlugin(ABC):
    """Base class for all scanner plugins."""

    @abstractmethod
    def metadata(self) -> PluginMeta:
        """Return plugin metadata."""
        ...

    @abstractmethod
    def file_requests(self) -> List[FileRequest]:
        """
        Declare which files this plugin needs from each repo.
        The core fetches them efficiently and passes the contents
        to evaluate(). Files are fetched once even if multiple
        plugins request the same path.
        """
        ...

    def should_scan_repo(self, repo_info: dict, file_tree: Optional[Set[str]]) -> bool:
        """
        Optional fast pre-filter. Return False to skip this repo entirely
        for this plugin. Called before any file contents are fetched.
        Default: return True (scan everything).
        """
        return True

    @abstractmethod
    def evaluate(self, repo_info: dict, files: Dict[str, Optional[str]],
                 file_tree: Optional[Set[str]]) -> List[PluginFinding]:
        """
        Analyze the repo. ``files`` maps requested paths to their text content
        (or None if the file was not found). Return a list of findings
        (empty list = no issues detected).
        """
        ...
