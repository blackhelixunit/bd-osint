"""Graph export: graph.json + optional Graphviz SVG."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


def build_nodes_edges(relationships: list[dict[str, str]]) -> dict[str, Any]:
    nodes: dict[str, str] = {}

    def add(node: str, kind: str) -> None:
        nodes.setdefault(node, kind)

    for r in relationships:
        add(r["source"], "entity")
        add(r["target"], "entity")
    return {
        "nodes": [{"id": n, "kind": k} for n, k in sorted(nodes.items())],
        "edges": [{"source": r["source"], "relationship": r["relationship"],
                   "target": r["target"]} for r in relationships],
    }


def write_json(relationships: list[dict[str, str]], path: str) -> str:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        json.dump(build_nodes_edges(relationships), fh, indent=2)
    return str(out)


def write_svg(relationships: list[dict[str, str]], path: str) -> str | None:
    """Render SVG via Graphviz if installed; returns None otherwise."""
    if not shutil.which("dot"):
        return None
    graph = build_nodes_edges(relationships)
    lines = ["digraph G {", '  rankdir="LR";',
             '  node [shape=box, style=filled, fillcolor="#1d2a44", fontcolor="white"];']
    for node in graph["nodes"]:
        lines.append(f'  "{node["id"]}";')
    for edge in graph["edges"]:
        lines.append(f'  "{edge["source"]}" -> "{edge["target"]}" [label="{edge["relationship"]}"];')
    lines.append("}")
    dot_path = str(Path(path).with_suffix(".dot"))
    Path(dot_path).write_text("\n".join(lines), encoding="utf-8")
    try:
        subprocess.run(["dot", "-Tsvg", dot_path, "-o", path], check=True, timeout=60)
        return path
    except (subprocess.SubprocessError, OSError):
        return None
