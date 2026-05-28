from __future__ import annotations

import ipaddress
from pathlib import Path


def normalize_target(raw: str) -> str:
    value = raw.strip()
    if not value:
        return value
    for prefix in ("http://", "https://"):
        if value.startswith(prefix):
            value = value[len(prefix):]
    if "/" in value:
        value = value.split("/", 1)[0]
    if ":" in value and value.count(":") == 1 and "." in value:
        host, _, _ = value.partition(":")
        return host.lower()
    return value.lower()


def parse_scope_file(path: Path) -> tuple[set[str], set[str]]:
    include: set[str] = set()
    exclude: set[str] = set()

    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        if text.startswith("!"):
            exclude.add(normalize_target(text[1:]))
        else:
            include.add(normalize_target(text))
    return include, exclude


def is_ip_or_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def in_scope(target: str, include: set[str], exclude: set[str]) -> bool:
    target_n = normalize_target(target)
    if target_n in exclude:
        return False

    if not include:
        return True

    for item in include:
        if item == target_n:
            return True
        if is_ip_or_cidr(item):
            try:
                network = ipaddress.ip_network(item, strict=False)
                ip = ipaddress.ip_address(target_n)
                if ip in network:
                    return True
            except ValueError:
                continue
        if target_n.endswith("." + item):
            return True
    return False
