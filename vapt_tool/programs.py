"""Bug bounty program management.

Store and manage your HackerOne / Bugcrowd / Intigriti programs locally
so you can batch-scan all in-scope targets with one command.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_PROGRAMS_PATH = Path("programs.json")


@dataclass
class BountyTable:
    """Severity → bounty range mapping."""
    critical: str = "$1000–$5000"
    high: str = "$500–$2000"
    medium: str = "$100–$500"
    low: str = "$25–$100"
    info: str = "$0"


@dataclass
class Program:
    """A single bug bounty program."""
    name: str
    platform: str = "custom"  # hackerone, bugcrowd, intigriti, custom
    url: str = ""
    status: str = "active"  # invited, accepted, active, paused
    in_scope: list[str] = field(default_factory=list)
    out_scope: list[str] = field(default_factory=list)
    bounty_table: BountyTable = field(default_factory=BountyTable)
    notes: str = ""
    tags: list[str] = field(default_factory=list)

    def estimated_bounty(self, severity: str) -> str:
        """Return estimated bounty range for a severity level."""
        table = self.bounty_table
        severity_lower = severity.lower()
        return getattr(table, severity_lower, "$0")


class ProgramManager:
    """Manage bug bounty programs stored in a local JSON file."""

    def __init__(self, path: Path | str = DEFAULT_PROGRAMS_PATH):
        self.path = Path(path)
        self._programs: list[Program] = []
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            self._programs = []
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self._programs = []
            for item in data:
                bt = item.pop("bounty_table", {})
                bounty = BountyTable(**bt) if bt else BountyTable()
                self._programs.append(Program(bounty_table=bounty, **item))
        except Exception:
            self._programs = []

    def _save(self) -> None:
        data = [asdict(p) for p in self._programs]
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

    def list_programs(self) -> list[Program]:
        return list(self._programs)

    def get_program(self, name: str) -> Program | None:
        for p in self._programs:
            if p.name.lower() == name.lower():
                return p
        return None

    def add_program(self, program: Program) -> None:
        # Replace if exists
        self._programs = [p for p in self._programs if p.name.lower() != program.name.lower()]
        self._programs.append(program)
        self._save()

    def remove_program(self, name: str) -> bool:
        before = len(self._programs)
        self._programs = [p for p in self._programs if p.name.lower() != name.lower()]
        if len(self._programs) < before:
            self._save()
            return True
        return False

    def update_program(self, name: str, **kwargs: Any) -> Program | None:
        program = self.get_program(name)
        if not program:
            return None
        for key, value in kwargs.items():
            if hasattr(program, key):
                setattr(program, key, value)
        self._save()
        return program

    def to_dict_list(self) -> list[dict[str, Any]]:
        return [asdict(p) for p in self._programs]


def create_sample_programs_file(path: Path | str = DEFAULT_PROGRAMS_PATH) -> None:
    """Create a sample programs.json with example entries."""
    manager = ProgramManager(path)
    if manager.list_programs():
        return  # Don't overwrite existing

    samples = [
        Program(
            name="Example Corp",
            platform="hackerone",
            url="https://hackerone.com/example",
            status="active",
            in_scope=["example.com", "api.example.com", "*.example.com"],
            out_scope=["dev.example.com", "staging.example.com"],
            bounty_table=BountyTable(
                critical="$3000–$10000",
                high="$1000–$3000",
                medium="$300–$1000",
                low="$50–$300",
                info="$0",
            ),
            notes="Focus on API endpoints, auth bypass, and IDOR",
            tags=["api", "web"],
        ),
    ]

    for s in samples:
        manager.add_program(s)
