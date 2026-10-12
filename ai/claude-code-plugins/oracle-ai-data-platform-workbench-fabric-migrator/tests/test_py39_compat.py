"""The package stays importable on the Python it advertises.

``pyproject.toml`` says ``requires-python = ">=3.9"`` and lists the 3.9
classifier. A ``str | None`` annotation is evaluated when the ``def`` runs
unless the module starts with ``from __future__ import annotations``; on 3.9
that is a ``TypeError`` at import, before any argument is parsed. The suite
runs on newer interpreters, where nothing notices -- the sibling Informatica
migrator shipped exactly that bug behind the same ``>=3.9``. This walks the
tree with the 3.9 grammar instead of waiting for a 3.9 user to report it.

Per file:
1. it parses with ``ast.parse(..., feature_version=(3, 9))`` -- no ``match``,
   no ``except*``, nothing the 3.9 parser rejects;
2. if any annotation (parameter, return, variable, dataclass field) contains
   ``|``, the module has the future import;
3. nothing relies on 3.10 at runtime where the future import cannot help:
   ``isinstance(x, A | B)`` and ``zip(..., strict=...)``.

Fabric notebook exports (``notebook-content.py``, the real corpora under
``tests/fixtures``) are inputs to the translator, not modules: they carry
``# META`` headers and magics and do not parse under any Python.
"""
import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_PARTS = {"node_modules", "__pycache__", "build", "dist"}
PY39 = (3, 9)


def _python_files():
    for path in sorted(ROOT.rglob("*.py")):
        rel = path.relative_to(ROOT)
        if any(part in SKIP_PARTS or part.startswith(".") for part in rel.parts):
            continue
        if path.name == "notebook-content.py" or rel.parts[:2] == ("tests", "fixtures"):
            continue
        yield path


def _annotations(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = node.args
            extra = [a for a in (args.vararg, args.kwarg) if a is not None]
            for arg in args.posonlyargs + args.args + args.kwonlyargs + extra:
                if arg.annotation is not None:
                    yield arg.annotation
            if node.returns is not None:
                yield node.returns
        elif isinstance(node, ast.AnnAssign):
            yield node.annotation


def _has_union(node):
    return any(isinstance(n, ast.BinOp) and isinstance(n.op, ast.BitOr) for n in ast.walk(node))


def _has_future_annotations(tree):
    return any(
        isinstance(node, ast.ImportFrom)
        and node.module == "__future__"
        and any(alias.name == "annotations" for alias in node.names)
        for node in tree.body
    )


def _problems(path, source):
    rel = path.relative_to(ROOT).as_posix()
    try:
        ast.parse(source, filename=rel, feature_version=PY39)
    except SyntaxError as exc:
        return [f"{rel}:{exc.lineno}: does not parse as Python 3.9 ({exc.msg})"]
    tree = ast.parse(source, filename=rel)
    found = []
    if not _has_future_annotations(tree):
        for ann in _annotations(tree):
            if _has_union(ann):
                found.append(
                    f"{rel}:{ann.lineno}: '|' annotation evaluated at def time; "
                    "add 'from __future__ import annotations'"
                )
                break
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
        if name == "isinstance" and len(node.args) >= 2 and _has_union(node.args[1]):
            found.append(f"{rel}:{node.lineno}: isinstance() with 'A | B' needs a tuple on 3.9")
        if name == "zip" and any(kw.arg == "strict" for kw in node.keywords):
            found.append(f"{rel}:{node.lineno}: zip(strict=) is 3.10+")
    return found


class Py39CompatTests(unittest.TestCase):
    def test_tree_is_python_39_compatible(self):
        files = list(_python_files())
        # The walk itself is the control: a wrong ROOT or an over-eager skip
        # must fail here, not pass by looking at nothing.
        self.assertGreater(len(files), 50, f"walked only {len(files)} files under {ROOT}")
        problems = []
        for path in files:
            problems.extend(_problems(path, path.read_text(encoding="utf-8")))
        self.assertFalse(
            problems,
            f"{len(problems)} Python 3.9 incompatibilities while requires-python is >=3.9:\n  "
            + "\n  ".join(problems),
        )


if __name__ == "__main__":
    unittest.main()
