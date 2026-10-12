"""SEC-AIDP-SAMPLES-005: mandatory sandbox gate at the notebook execution sink.

Covers the Jira acceptance criteria:
- sandbox (catalog, schema, prefix, network posture) must be declared before
  any notebook code runs; undeclared = refuse, fail closed, clear message;
- AST gate refuses environment reads, local file reads, process/network
  imports, destructive dbutils.fs calls, dynamic code execution and writes
  outside the sandbox; dynamic write targets need a reviewed exception;
- runtime assertions on dbutils.fs.rm/mv/cp/put and the safe_io write helpers;
- every refusal / allowed exception is recorded with notebook path, cell
  index, rule and remediation for the migration report.
"""
import json
import os

import nbformat
import pytest

from aidp_compat import notebook_policy as npol
from aidp_compat.notebook import AIDPNotebookUtils, NotebookExit
from aidp_compat.notebook_policy import (
    PolicyViolation,
    SandboxPolicy,
    SandboxUndeclaredError,
)


# ── helpers ────────────────────────────────────────────────────────────
def write_notebook(tmp_path, name, cells):
    nb = nbformat.v4.new_notebook()
    nb.cells = [nbformat.v4.new_code_cell(src) if not src.startswith("#md ")
                else nbformat.v4.new_markdown_cell(src[4:]) for src in cells]
    path = tmp_path / f"{name}.ipynb"
    nbformat.write(nb, str(path))
    return str(path)


def runner(tmp_path):
    return AIDPNotebookUtils(spark=None, workspace_root=str(tmp_path))


class _Writer:
    """Stand-in for DataFrame.write so refused cells can also be executable."""

    def __init__(self):
        self.calls = []

    def mode(self, *_):
        return self

    def format(self, *_):
        return self

    def partitionBy(self, *_):
        return self

    def saveAsTable(self, name, **_):
        self.calls.append(("saveAsTable", name))

    def insertInto(self, name, **_):
        self.calls.append(("insertInto", name))

    def parquet(self, path, **_):
        self.calls.append(("parquet", path))

    def save(self, path=None, **_):
        self.calls.append(("save", path))


class _FakeDF:
    def __init__(self):
        self.write = _Writer()

    def cache(self):
        return self

    def count(self):
        return 0

    def unpersist(self):
        return self

    def coalesce(self, *_):
        return self

    @property
    def rdd(self):
        class _R:
            def getNumPartitions(self):
                return 1
        return _R()


# ── sandbox declaration ────────────────────────────────────────────────
def test_undeclared_sandbox_refuses_before_any_cell_runs(tmp_path):
    path = write_notebook(tmp_path, "child", ["UNDECLARED_MARK = 1"])
    with pytest.raises(SandboxUndeclaredError) as ei:
        runner(tmp_path).run(path)
    msg = str(ei.value)
    assert "no sandbox policy declared" in msg
    for var in ("AIDP_SANDBOX_CATALOG", "AIDP_SANDBOX_SCHEMA", "AIDP_SANDBOX_PREFIX"):
        assert var in msg
    assert isinstance(ei.value, PermissionError)
    assert "UNDECLARED_MARK" not in globals()


def test_partial_declaration_names_the_missing_variable(tmp_path, monkeypatch):
    monkeypatch.setenv("AIDP_SANDBOX_CATALOG", "default")
    monkeypatch.setenv("AIDP_SANDBOX_SCHEMA", "sbx")
    path = write_notebook(tmp_path, "child", ["PARTIAL_MARK = 1"])
    with pytest.raises(SandboxUndeclaredError) as ei:
        runner(tmp_path).run(path)
    assert "AIDP_SANDBOX_PREFIX" in str(ei.value)
    assert "AIDP_SANDBOX_CATALOG" not in str(ei.value).split("Set", 1)[1].split("(")[0]
    assert "PARTIAL_MARK" not in globals()


def test_undeclared_refusal_precedes_missing_notebook_check(tmp_path):
    # Fail closed even for a path that does not exist: the gate runs first.
    with pytest.raises(SandboxUndeclaredError):
        runner(tmp_path).run("does-not-exist")


def test_explicit_policy_object_is_enough(tmp_path):
    policy = SandboxPolicy(catalog="default", schema="sbx", prefix="oci://b@ns/sbx")
    path = write_notebook(tmp_path, "child", ["EXPLICIT_MARK = 41 + 1"])
    assert AIDPNotebookUtils(workspace_root=str(tmp_path), policy=policy).run(path) == "ok"
    assert globals().pop("EXPLICIT_MARK") == 42


def test_set_sandbox_policy_process_wide(tmp_path):
    npol.set_sandbox_policy(SandboxPolicy(catalog="default", schema="sbx", prefix="oci://b@ns/sbx/"))
    path = write_notebook(tmp_path, "child", ["PROCESS_MARK = 1"])
    assert runner(tmp_path).run(path) == "ok"
    assert globals().pop("PROCESS_MARK") == 1
    declared = [e for e in npol.get_policy_log() if e["event"] == "sandbox_declared"]
    assert declared and declared[0]["detail"]["schema"] == "sbx"


def test_sandbox_policy_requires_every_field():
    with pytest.raises(ValueError):
        SandboxPolicy(catalog="default", schema="", prefix="oci://b@ns/x/")


def test_prefix_is_a_directory_boundary():
    p = SandboxPolicy(catalog="default", schema="sbx", prefix="oci://b@ns/sbx")
    assert p.path_in_sandbox("oci://b@ns/sbx/a/b")
    assert p.path_in_sandbox("oci://b@ns/sbx")
    assert not p.path_in_sandbox("oci://b@ns/sbx-prod/a")
    assert not p.path_in_sandbox("oci://other@ns/sbx/a")


def test_table_membership_handles_quoting_and_case():
    p = SandboxPolicy(catalog="Default", schema="SBX", prefix="oci://b@ns/sbx/")
    assert p.table_in_sandbox("default.sbx.t")
    assert p.table_in_sandbox("`default`.`sbx`.`t`")
    assert p.table_in_sandbox("sbx.T")
    assert not p.table_in_sandbox("prod.sbx.t")
    assert not p.table_in_sandbox("other.t")
    assert not p.table_in_sandbox("t")          # 1-part: unknown schema -> outside


# ── AST gate via notebook.run ──────────────────────────────────────────
REFUSED_CELLS = [
    ("import subprocess", "NBP-IMPORT-PROCESS", "subprocess"),
    ("from subprocess import run", "NBP-IMPORT-PROCESS", "subprocess"),
    ("import ctypes", "NBP-IMPORT-PROCESS", "ctypes"),
    ("import pty", "NBP-IMPORT-PROCESS", "pty"),
    ("import socket", "NBP-IMPORT-NETWORK", "socket"),
    ("import requests", "NBP-IMPORT-NETWORK", "requests"),
    ("import urllib.request", "NBP-IMPORT-NETWORK", "urllib"),
    ("import http.client", "NBP-IMPORT-NETWORK", "http.client"),
    ("from http import client", "NBP-IMPORT-NETWORK", "http.client"),
    ("import paramiko", "NBP-IMPORT-NETWORK", "paramiko"),
    ("import os\nTOKEN = os.environ.get('AIDP_TOKEN')", "NBP-OS-ENVIRON", "os.environ"),
    ("import os\nTOKEN = os.getenv('AIDP_TOKEN')", "NBP-OS-ENVIRON", "os.getenv"),
    ("import os\nos.putenv('A', 'b')", "NBP-OS-ENVIRON", "os.putenv"),
    ("from os import environ", "NBP-OS-ENVIRON", "os.environ"),
    ("import os\nos.system('id')", "NBP-OS-PROCESS", "os.system"),
    ("import os\nos.popen('id')", "NBP-OS-PROCESS", "os.popen"),
    ("import os\nos.execvp('id', ['id'])", "NBP-OS-PROCESS", "os.execvp"),
    ("import shutil\nshutil.rmtree('/Volumes/prod')", "NBP-SHUTIL-RMTREE", "shutil.rmtree"),
    ("from shutil import rmtree", "NBP-SHUTIL-RMTREE", "shutil.rmtree"),
    ("eval('1+1')", "NBP-BUILTIN-EXEC", "eval"),
    ("exec('x=1')", "NBP-BUILTIN-EXEC", "exec"),
    ("compile('1', 'f', 'eval')", "NBP-BUILTIN-EXEC", "compile"),
    ("__import__('subprocess')", "NBP-BUILTIN-EXEC", "__import__"),
    ("open('/etc/passwd').read()", "NBP-OPEN-PATH", "/etc/passwd"),
    ("open('/Workspace/.oci/config', 'r')", "NBP-OPEN-PATH", "/Workspace/.oci/config"),
    ("p = dbutils.widgets.get('p')\nopen(p, 'w')", "NBP-OPEN-DYNAMIC", "<dynamic>"),
    ("p = dbutils.widgets.get('p')\nopen(p).read()", "NBP-OPEN-DYNAMIC", "<dynamic>"),
    ("_p = '/etc/passwd'\nopen(_p).read()", "NBP-OPEN-PATH", "/etc/passwd"),             # resolved constant
    ("p = 'a'\np = '/etc/passwd'\nopen(p).read()", "NBP-OPEN-DYNAMIC", "<dynamic>"),       # rebound: unknown
    ("import pathlib\npathlib.Path('/etc/passwd').read_text()", "NBP-OPEN-PATH", "/etc/passwd"),
    ("from pathlib import Path\nP = Path('/Workspace/.oci/config')\nP.read_bytes()", "NBP-OPEN-PATH",
     "/Workspace/.oci/config"),
    ("from pathlib import Path\nPath('/Volumes/prod/x').write_text('a')", "NBP-OPEN-PATH", "/Volumes/prod/x"),
    ("from pathlib import Path\nPath('/Volumes/prod/x').unlink()", "NBP-FS-PATH", "/Volumes/prod/x"),
    ("from pathlib import Path\nPath(dbutils.widgets.get('p')).read_text()", "NBP-OPEN-DYNAMIC", "<dynamic>"),
    ("import os\nos.remove('/Volumes/prod/x')", "NBP-FS-PATH", "/Volumes/prod/x"),
    ("import os\nos.rename('/Volumes/prod/a', '/Volumes/prod/b')", "NBP-FS-PATH", "/Volumes/prod/a"),
    ("import os\nos.makedirs('/Volumes/prod/new', exist_ok=True)", "NBP-FS-PATH", "/Volumes/prod/new"),
    ("import os\nos.remove(dbutils.widgets.get('p'))", "NBP-FS-DYNAMIC", "<dynamic>"),
    ("import shutil\nshutil.move('/Volumes/prod/a', '/Volumes/prod/b')", "NBP-FS-PATH", "/Volumes/prod/a"),
    ("import shutil\nshutil.copy2('/tmp/model.pt', '/Volumes/prod/model.pt')", "NBP-FS-PATH", "/Volumes/prod/model.pt"),
    ("dbutils.fs.rm('oci://b@ns/prod/data', True)", "NBP-DBFS-PATH", "oci://b@ns/prod/data"),
    ("dbutils.fs.rm('dbfs:/mnt/prod/data', recurse=True)", "NBP-DBFS-PATH", "dbfs:/mnt/prod/data"),
    ("dbutils.fs.rm('oci://b@ns/sbx/../prod/data', True)", "NBP-DBFS-PATH", "oci://b@ns/sbx/../prod/data"),
    ("dbutils.fs.mv('oci://b@ns/sbx/a', 'oci://b@ns/prod/a')", "NBP-DBFS-PATH", "oci://b@ns/prod/a"),
    ("dbutils.fs.mv('oci://b@ns/prod/a', 'oci://b@ns/sbx/a')", "NBP-DBFS-PATH", "oci://b@ns/prod/a"),
    ("dbutils.fs.cp('oci://b@ns/prod/a', 'oci://b@ns/prod/b')", "NBP-DBFS-PATH", "oci://b@ns/prod/b"),
    ("dbutils.fs.put('oci://b@ns/prod/x.txt', 'hi', True)", "NBP-DBFS-PATH", "oci://b@ns/prod/x.txt"),
    ("dbutils.fs.mkdirs('oci://b@ns/prod/newdir')", "NBP-DBFS-PATH", "oci://b@ns/prod/newdir"),
    ("_fs = dbutils.fs\n_fs.rm('oci://b@ns/prod/data')", "NBP-DBFS-PATH", "oci://b@ns/prod/data"),   # shim alias
    ("p = dbutils.widgets.get('p')\ndbutils.fs.rm(p, True)", "NBP-DBFS-DYNAMIC", "<dynamic>"),
    ("_p = 'oci://b@ns/prod/data'\ndbutils.fs.rm(_p, True)", "NBP-DBFS-PATH", "oci://b@ns/prod/data"),
    ("df.write.mode('overwrite').saveAsTable('prod.t')", "NBP-TABLE-TARGET", "prod.t"),
    ("df.write.saveAsTable('cat.prod.t')", "NBP-TABLE-TARGET", "cat.prod.t"),
    ("df.write.insertInto('t')", "NBP-TABLE-TARGET", "t"),
    ("df.writeTo('prod.t').createOrReplace()", "NBP-TABLE-TARGET", "prod.t"),
    ("df.writeTo('prod.t').append()", "NBP-TABLE-TARGET", "prod.t"),
    ("df.write.format('delta').option('path', 'oci://b@ns/prod/x').saveAsTable('sbx.t')",
     "NBP-PATH-WRITE", "oci://b@ns/prod/x"),
    ("df.write.options(path='oci://b@ns/prod/x').saveAsTable('sbx.t')", "NBP-PATH-WRITE", "oci://b@ns/prod/x"),
    ("t = dbutils.widgets.get('t')\ndf.write.saveAsTable(t)", "NBP-TABLE-DYNAMIC", "<dynamic>"),
    ("_t = 'prod.t'\ndf.write.saveAsTable(_t)", "NBP-TABLE-TARGET", "prod.t"),
    ("spark.sql('CREATE TABLE prod.t (a INT)')", "NBP-SQL-TARGET", "prod.t"),
    ("spark.sql('CREATE OR REPLACE TABLE cat.prod.t AS SELECT 1')", "NBP-SQL-TARGET", "cat.prod.t"),
    ("spark.sql('INSERT INTO t VALUES (1)')", "NBP-SQL-TARGET", "t"),
    ("spark.sql('INSERT OVERWRITE TABLE prod.t SELECT 1')", "NBP-SQL-TARGET", "prod.t"),
    ("spark.sql('DROP TABLE IF EXISTS prod.t')", "NBP-SQL-TARGET", "prod.t"),
    ("spark.sql('MERGE INTO prod.t USING s ON 1=1 WHEN MATCHED THEN DELETE')", "NBP-SQL-TARGET", "prod.t"),
    ("spark.sql('DELETE FROM prod.t WHERE 1=1')", "NBP-SQL-TARGET", "prod.t"),
    ("spark.sql('CREATE SCHEMA other')", "NBP-SQL-TARGET", "other"),
    ("spark.sql(\"CREATE TABLE sbx.t USING parquet LOCATION 'oci://b@ns/prod/t'\")",
     "NBP-SQL-TARGET", "oci://b@ns/prod/t"),
    ("sql('INSERT INTO prod.t SELECT 1')", "NBP-SQL-TARGET", "prod.t"),
    ("spark.sql('CREATE TABLE sbx.t USING parquet LOCATION \"oci://b@ns/prod/t\"')",
     "NBP-SQL-TARGET", "oci://b@ns/prod/t"),
    ("spark.sql(\"CREATE TABLE sbx.t USING parquet OPTIONS (path 'oci://b@ns/prod/t')\")",
     "NBP-SQL-TARGET", "oci://b@ns/prod/t"),
    ("spark.sql(\"CREATE TABLE sbx.t USING csv OPTIONS (header 'true', 'path' = 'oci://b@ns/prod/t')\")",
     "NBP-SQL-TARGET", "oci://b@ns/prod/t"),
    ("spark.sql(\"CREATE TABLE sbx.t USING parquet LOCATION 'oci://b@ns/sbx/../prod/t'\")",
     "NBP-SQL-TARGET", "oci://b@ns/sbx/../prod/t"),
    ("t = 'x'\nspark.sql(f'INSERT INTO {t} SELECT 1')", "NBP-SQL-DYNAMIC", "<dynamic>"),
    ("t = 'x'\nspark.sql('CREATE TABLE ' + t + ' (a INT)')", "NBP-SQL-DYNAMIC", "<dynamic>"),
    ("_q = 'DROP TABLE prod.customers'\nspark.sql(_q)", "NBP-SQL-TARGET", "prod.customers"),   # resolved constant
    ("q = dbutils.widgets.get('q')\nspark.sql(q)", "NBP-SQL-DYNAMIC", "<dynamic>"),
    ("spark.sql(build_query())", "NBP-SQL-DYNAMIC", "<dynamic>"),
    ("df.write.parquet('oci://b@ns/prod/out')", "NBP-PATH-WRITE", "oci://b@ns/prod/out"),
    ("df.write.format('delta').save('oci://b@ns/prod/out')", "NBP-PATH-WRITE", "oci://b@ns/prod/out"),
    ("df.write.parquet('oci://b@ns/sbx/../prod/out')", "NBP-PATH-WRITE", "oci://b@ns/sbx/../prod/out"),
    ("p = dbutils.widgets.get('p')\ndf.write.mode('append').parquet(p)", "NBP-PATH-WRITE-DYNAMIC", "<dynamic>"),
    # -- indirection: aliases, importlib, builtins, sys.modules, getattr, star import
    ("import os as _o\n_o.environ.get('AIDP_TOKEN')", "NBP-OS-ENVIRON", "os.environ"),
    ("import os as _o\n_o.environ['AIDP_SANDBOX_PREFIX'] = '/'", "NBP-OS-ENVIRON", "os.environ"),
    ("from os import environ as _e", "NBP-OS-ENVIRON", "os.environ"),
    ("from os import *", "NBP-OS-ENVIRON", "os.*"),
    ("import os\nos.fork()", "NBP-OS-PROCESS", "os.fork"),
    ("import asyncio\nasyncio.create_subprocess_shell('id')", "NBP-OS-PROCESS", "asyncio.create_subprocess_shell"),
    ("from asyncio import create_subprocess_exec", "NBP-OS-PROCESS", "asyncio.create_subprocess_exec"),
    ("import multiprocessing", "NBP-IMPORT-PROCESS", "multiprocessing"),
    ("import urllib3", "NBP-IMPORT-NETWORK", "urllib3"),
    ("import httpx", "NBP-IMPORT-NETWORK", "httpx"),
    ("import aiohttp", "NBP-IMPORT-NETWORK", "aiohttp"),
    ("import ftplib", "NBP-IMPORT-NETWORK", "ftplib"),
    ("import smtplib", "NBP-IMPORT-NETWORK", "smtplib"),
    ("import importlib\nimportlib.import_module('subprocess')", "NBP-INDIRECT", "importlib"),
    ("from importlib import import_module", "NBP-INDIRECT", "importlib"),
    ("import builtins\nbuiltins.exec('X=1')", "NBP-INDIRECT", "builtins"),
    ("import sys\nsys.modules['os'].environ['X']", "NBP-INDIRECT", "sys.modules"),
    ("import os\ngetattr(os, 'environ')['X']", "NBP-INDIRECT", "os"),
    ("import os as _o\nvars(_o)['environ']", "NBP-INDIRECT", "os"),
    # -- policy tampering: compat internals, set_sandbox_policy, module attribute assignment
    ("from aidp_compat.notebook_policy import set_sandbox_policy", "NBP-POLICY-TAMPER",
     "aidp_compat.notebook_policy"),
    ("from aidp_compat import SandboxPolicy", "NBP-POLICY-TAMPER", "aidp_compat.SandboxPolicy"),
    ("from aidp_compat import set_sandbox_policy", "NBP-POLICY-TAMPER", "aidp_compat.set_sandbox_policy"),
    ("from aidp_compat import fs", "NBP-POLICY-TAMPER", "aidp_compat.fs"),
    ("from aidp_compat.fs import AIDPFileSystemUtils", "NBP-POLICY-TAMPER", "aidp_compat.fs.AIDPFileSystemUtils"),
    ("from aidp_compat.fs import _get_oci_storage_client", "NBP-POLICY-TAMPER",
     "aidp_compat.fs._get_oci_storage_client"),
    ("import aidp_compat", "NBP-POLICY-TAMPER", "aidp_compat"),
    ("import aidp_compat.fs as _f\n_f.assert_path_in_sandbox = lambda p, **k: p", "NBP-POLICY-TAMPER",
     "aidp_compat.fs"),
    ("import aidp_compat.fs as _f\nsetattr(_f, 'assert_path_in_sandbox', None)", "NBP-POLICY-TAMPER",
     "aidp_compat.fs"),
    ("import os\nos.environ = {}", "NBP-OS-ENVIRON", "os.environ"),
    ("import os as _o\n_o.remove = print", "NBP-POLICY-TAMPER", "os.remove"),
    ("import sys\nsys.modules['os'] = None", "NBP-INDIRECT", "sys.modules"),
    ("dbutils.fs.rm = lambda *a, **k: True", "NBP-POLICY-TAMPER", "dbutils.fs.rm"),
    ("dbutils.fs = None", "NBP-POLICY-TAMPER", "dbutils.fs"),
    ("dbutils.notebook._policy = None", "NBP-POLICY-TAMPER", "dbutils.notebook._policy"),
    ("del dbutils.fs", "NBP-POLICY-TAMPER", "dbutils.fs"),
    ("import builtins as _b\n_b.open = print", "NBP-INDIRECT", "builtins"),
]


@pytest.mark.parametrize("source,rule,target", REFUSED_CELLS, ids=[c[1] + ":" + c[0][:30] for c in REFUSED_CELLS])
def test_refused_cell_is_not_executed_and_is_logged(tmp_path, sandbox_env, source, rule, target):
    path = write_notebook(tmp_path, "child", ["#md header", "SETUP_OK = 1", source + "\nREFUSED_MARK = 1"])
    globals().pop("SETUP_OK", None)
    globals().pop("REFUSED_MARK", None)
    with pytest.raises(PolicyViolation) as ei:
        runner(tmp_path).run(path)
    err = ei.value
    assert isinstance(err, PermissionError)
    assert err.rule_id == rule
    assert err.cell_index == 2
    assert err.notebook_path == path
    assert err.target == target
    assert err.remediation
    msg = str(err)
    assert path in msg and "cell 2" in msg and rule in msg and "Remediation:" in msg
    # Earlier cells ran; the refused cell did not.
    assert globals().pop("SETUP_OK") == 1
    assert "REFUSED_MARK" not in globals()
    refused = [e for e in npol.get_policy_log() if e["event"] == "refused"]
    assert refused, "refusal must be recorded in the policy log"
    entry = refused[0]
    assert entry["notebook_path"] == path
    assert entry["cell_index"] == 2
    assert entry["rule"] == rule
    assert entry["target"] == target
    assert entry["remediation"]


CLEAN_CELLS = [
    "import os\nP = os.path.join('a', 'b')",
    "import json\nJ = json.dumps({'a': 1})",
    "CLEAN_SQL = spark.sql('SELECT * FROM prod.t')",
    "spark.sql('CREATE OR REPLACE TEMP VIEW v AS SELECT 1')",
    "spark.sql('CREATE GLOBAL TEMPORARY VIEW gv AS SELECT 1')",
    "v = 'v'\nspark.sql(f'CREATE OR REPLACE TEMP VIEW {v} AS SELECT 1')",
    "t = 'prod.t'\nspark.sql(f'SELECT count(*) FROM {t}')",
    "spark.sql('CREATE TABLE IF NOT EXISTS default.sbx.t (a INT)')",
    "spark.sql('INSERT INTO `sbx`.`t` VALUES (1)')",
    "spark.sql('CREATE SCHEMA IF NOT EXISTS sbx')",
    "spark.sql(\"CREATE TABLE sbx.t2 USING parquet LOCATION 'oci://b@ns/sbx/t2'\")",
    "df.write.mode('overwrite').saveAsTable('sbx.t')",
    "df.write.saveAsTable('default.sbx.t')",
    "dbutils.fs.rm('oci://b@ns/sbx/tmp/', True)",
    "dbutils.fs.cp('oci://b@ns/prod/src', 'oci://b@ns/sbx/copy')",   # reading prod is fine
    "df.write.parquet('oci://b@ns/sbx/out')",
    "open('relative.txt', 'w').close()",
    "p = 'relative.txt'\nopen(p).read()",
    "spark.sql('SELECT 1')",
    "x = spark.read.json('oci://b@ns/prod/in')",
    "q = 'SELECT count(*) FROM prod.t'\nspark.sql(q)",                       # resolved read statement
    "from aidp_compat import dbutils, translate_path, safe_pickle_dump\nP = translate_path('/dbfs/x')",
    "from aidp_compat.safe_io import safe_pickle_dump",
    "import pandas as pd\npd.options.display.max_rows = 200",              # third-party module options
    "import os\nimport sys as _s\nX = _s.version",
    "import pathlib\nR = pathlib.Path('rel.txt').read_text()",
    "from pathlib import Path\nPath('oci://b@ns/sbx/x').write_text('a')",
    "import os\nos.makedirs('oci://b@ns/sbx/newdir', exist_ok=True)",
    "s = 'a-b'\nt = s.replace('-', '_')",                                   # str.replace is not Path.replace
    "df.write.option('header', 'true').parquet('oci://b@ns/sbx/out')",
    "df.write.format('delta').option('path', 'oci://b@ns/sbx/x').saveAsTable('sbx.t')",
    "df.writeTo('sbx.t').createOrReplace()",
    "spark.sql('CREATE TABLE sbx.t USING parquet LOCATION \"oci://b@ns/sbx/t\"')",
    "dbutils.fs.mkdirs('oci://b@ns/sbx/newdir')",
    "_fs = dbutils.fs\n_fs.rm('oci://b@ns/sbx/tmp/')",
    "self_like = object()\nsetattr(self_like, 'x', 1)",
    "class C:\n    def __init__(self):\n        self.x = 1",
]


@pytest.mark.parametrize("source", CLEAN_CELLS, ids=[c[:40] for c in CLEAN_CELLS])
def test_clean_cell_passes_the_gate(sandbox_env, source):
    assert npol.scan_source(source) == []


def test_clean_notebook_runs_and_returns_exit_value(tmp_path, sandbox_env):
    path = write_notebook(tmp_path, "child", [
        "#md ## heading",
        "%sql SELECT 1",                       # magic: skipped, as before
        "RESULT_A = 40",
        "RESULT_A = RESULT_A + 2",
        "dbutils.notebook.exit(str(RESULT_A))",
    ])
    g = globals()
    g["dbutils"] = type("D", (), {"notebook": runner(tmp_path)})()
    try:
        assert runner(tmp_path).run(path) == "42"
    finally:
        g.pop("dbutils", None)
        g.pop("RESULT_A", None)
    assert [e for e in npol.get_policy_log() if e["event"] == "refused"] == []


def test_allowlisted_rule_is_logged_as_exception_and_executes(tmp_path, sandbox_env, monkeypatch):
    monkeypatch.setenv("AIDP_NOTEBOOK_POLICY_ALLOW", "NBP-TABLE-DYNAMIC")
    path = write_notebook(tmp_path, "child", [
        "TARGET = ''.join(['sbx', '.t'])",      # not statically resolvable -> needs the exception
        "df.write.saveAsTable(TARGET)",
    ])
    globals()["df"] = _FakeDF()
    try:
        assert runner(tmp_path).run(path) == "ok"
        assert globals()["df"].write.calls == [("saveAsTable", "sbx.t")]
    finally:
        globals().pop("df", None)
        globals().pop("TARGET", None)
    log = npol.get_policy_log()
    allowed = [e for e in log if e["event"] == "allowed_exception"]
    assert len(allowed) == 1
    assert allowed[0]["rule"] == "NBP-TABLE-DYNAMIC"
    assert allowed[0]["cell_index"] == 1
    assert allowed[0]["notebook_path"] == path
    assert not [e for e in log if e["event"] == "refused"]


def test_name_bound_once_to_a_literal_is_resolved_across_cells(tmp_path, sandbox_env):
    # No exception needed: the target is a name bound once to a sandbox literal in an earlier cell.
    path = write_notebook(tmp_path, "child", ["TARGET = 'sbx.t'", "df.write.saveAsTable(TARGET)"])
    globals()["df"] = _FakeDF()
    try:
        assert runner(tmp_path).run(path) == "ok"
    finally:
        globals().pop("df", None)
        globals().pop("TARGET", None)
    assert [e for e in npol.get_policy_log() if e["event"] in ("refused", "allowed_exception")] == []
    # ... and a name bound once to a literal OUTSIDE the sandbox is refused as a literal target.
    path = write_notebook(tmp_path, "child2", ["TARGET2 = 'prod.t'", "df.write.saveAsTable(TARGET2)"])
    with pytest.raises(PolicyViolation) as ei:
        runner(tmp_path).run(path)
    assert ei.value.rule_id == "NBP-TABLE-TARGET" and ei.value.target == "prod.t"
    globals().pop("TARGET2", None)


def test_allowlist_does_not_bleed_across_rules(tmp_path, sandbox_env, monkeypatch):
    monkeypatch.setenv("AIDP_NOTEBOOK_POLICY_ALLOW", "NBP-TABLE-DYNAMIC")
    path = write_notebook(tmp_path, "child", ["p = dbutils.widgets.get('p')\ndbutils.fs.rm(p)"])
    with pytest.raises(PolicyViolation) as ei:
        runner(tmp_path).run(path)
    assert ei.value.rule_id == "NBP-DBFS-DYNAMIC"


def test_allow_network_flag_permits_network_imports_only(tmp_path, sandbox_env, monkeypatch):
    monkeypatch.setenv("AIDP_SANDBOX_ALLOW_NETWORK", "1")
    ok = write_notebook(tmp_path, "net", ["import socket\nNET_MARK = socket.AF_INET is not None"])
    assert runner(tmp_path).run(ok) == "ok"
    assert globals().pop("NET_MARK") is True
    bad = write_notebook(tmp_path, "proc", ["import subprocess"])
    with pytest.raises(PolicyViolation) as ei:
        runner(tmp_path).run(bad)
    assert ei.value.rule_id == "NBP-IMPORT-PROCESS"


def test_first_refusal_wins_but_all_violations_are_logged(tmp_path, sandbox_env):
    path = write_notebook(tmp_path, "child", ["import subprocess\nimport socket\nos.environ['X']"])
    with pytest.raises(PolicyViolation) as ei:
        runner(tmp_path).run(path)
    assert ei.value.rule_id == "NBP-IMPORT-PROCESS"
    assert "+2 more" in str(ei.value)
    rules = sorted(e["rule"] for e in npol.get_policy_log() if e["event"] == "refused")
    assert rules == ["NBP-IMPORT-NETWORK", "NBP-IMPORT-PROCESS", "NBP-OS-ENVIRON"]


def test_syntax_error_cell_does_not_execute(tmp_path, sandbox_env):
    path = write_notebook(tmp_path, "child", ["SYNTAX_MARK = (1"])
    with pytest.raises(SyntaxError):
        runner(tmp_path).run(path)
    assert "SYNTAX_MARK" not in globals()


def test_compiled_cells_carry_the_notebook_filename(tmp_path, sandbox_env):
    path = write_notebook(tmp_path, "child", ["raise ValueError('boom')"])
    with pytest.raises(ValueError) as ei:
        runner(tmp_path).run(path)
    tb = ei.value.__traceback__
    filenames = []
    while tb is not None:
        filenames.append(tb.tb_frame.f_code.co_filename)
        tb = tb.tb_next
    assert path in filenames


# ── policy log surfaces ────────────────────────────────────────────────
def test_policy_log_markdown_and_jsonl(tmp_path, sandbox_env, monkeypatch):
    log_file = tmp_path / "policy.jsonl"
    monkeypatch.setenv("AIDP_NOTEBOOK_POLICY_LOG", str(log_file))
    path = write_notebook(tmp_path, "child", ["import subprocess"])
    with pytest.raises(PolicyViolation):
        runner(tmp_path).run(path)
    md = npol.policy_log_markdown()
    assert "| Event | Notebook | Cell | Rule | Target | Remediation |" in md
    assert "NBP-IMPORT-PROCESS" in md and path in md
    entries = [json.loads(line) for line in log_file.read_text(encoding="utf-8").splitlines()]
    # The sandbox identifiers are recorded once (audit), then the refusal.
    assert [e["event"] for e in entries] == ["sandbox_declared", "refused"]
    assert entries[0]["detail"]["schema"] == "sbx" and entries[0]["detail"]["source"] == "environment"
    entry = entries[1]
    assert entry["rule"] == "NBP-IMPORT-PROCESS"
    assert entry["cell_index"] == 0 and entry["notebook_path"] == path
    assert [e["rule"] for e in json.loads(npol.policy_log_json()) if e["event"] == "refused"] == ["NBP-IMPORT-PROCESS"]
    npol.clear_policy_log()
    assert npol.policy_log_markdown() == ""


# ── runtime assertions: dbutils.fs ─────────────────────────────────────
def _fs():
    from aidp_compat.fs import AIDPFileSystemUtils
    return AIDPFileSystemUtils(spark=None)


def test_fs_rm_outside_prefix_is_refused_and_logged(tmp_path, sandbox_env):
    victim = tmp_path / "prod.txt"
    victim.write_text("keep me")
    with pytest.raises(PolicyViolation) as ei:
        _fs().rm(str(victim))
    assert ei.value.rule_id == "NBP-RUNTIME-PATH"
    assert victim.exists()
    entry = [e for e in npol.get_policy_log() if e["event"] == "runtime_refused"][0]
    assert entry["target"] == str(victim) and entry["detail"]["operation"] == "dbutils.fs.rm"


def test_fs_rm_inside_prefix_works(tmp_path, sandbox_env):
    f = tmp_path / "sandbox" / "tmp.txt"
    f.write_text("scratch")
    assert _fs().rm(str(f)) is True
    assert not f.exists()


def test_fs_rm_undeclared_sandbox_is_refused(tmp_path):
    victim = tmp_path / "prod.txt"
    victim.write_text("keep me")
    with pytest.raises(SandboxUndeclaredError):
        _fs().rm(str(victim))
    assert victim.exists()


def test_fs_put_outside_prefix_is_refused(tmp_path, sandbox_env):
    target = tmp_path / "prod-out.txt"
    with pytest.raises(PolicyViolation):
        _fs().put(str(target), "data", True)
    assert not target.exists()
    inside = tmp_path / "sandbox" / "out.txt"
    assert _fs().put(str(inside), "data", True) is True
    assert inside.read_text() == "data"


def test_fs_mv_requires_both_ends_inside(tmp_path, sandbox_env):
    src_out = tmp_path / "prod-src.txt"
    src_out.write_text("x")
    with pytest.raises(PolicyViolation):
        _fs().mv(str(src_out), str(tmp_path / "sandbox" / "dst.txt"))
    assert src_out.exists()
    src_in = tmp_path / "sandbox" / "src.txt"
    src_in.write_text("y")
    with pytest.raises(PolicyViolation):
        _fs().mv(str(src_in), str(tmp_path / "prod-dst.txt"))
    assert src_in.exists()
    assert _fs().mv(str(src_in), str(tmp_path / "sandbox" / "moved.txt")) is True
    assert (tmp_path / "sandbox" / "moved.txt").read_text() == "y"


def test_fs_cp_destination_must_be_inside(tmp_path, sandbox_env):
    src = tmp_path / "prod-src.txt"            # reading from outside is allowed
    src.write_text("z")
    with pytest.raises(PolicyViolation):
        _fs().cp(str(src), str(tmp_path / "prod-copy.txt"))
    assert not (tmp_path / "prod-copy.txt").exists()
    assert _fs().cp(str(src), str(tmp_path / "sandbox" / "copy.txt")) is True
    assert (tmp_path / "sandbox" / "copy.txt").read_text() == "z"


# ── runtime assertions: safe_io write helpers ─────────────────────────
def test_safe_save_as_table_asserts_sandbox_schema(sandbox_env):
    from aidp_compat.safe_io import safe_save_as_table, safe_save_as_table_coalesced
    df = _FakeDF()
    with pytest.raises(PolicyViolation) as ei:
        safe_save_as_table(df, "prod.t")
    assert ei.value.rule_id == "NBP-RUNTIME-TABLE"
    with pytest.raises(PolicyViolation):
        safe_save_as_table_coalesced(df, "default.other.t")
    assert df.write.calls == []
    safe_save_as_table(df, "sbx.t")
    safe_save_as_table_coalesced(df, "default.sbx.t2", mode="append")
    assert df.write.calls == [("saveAsTable", "sbx.t"), ("saveAsTable", "default.sbx.t2")]


def test_safe_write_parquet_asserts_sandbox_prefix(sandbox_env):
    from aidp_compat.safe_io import safe_write_parquet, safe_write_parquet_coalesced
    df = _FakeDF()
    with pytest.raises(PolicyViolation):
        safe_write_parquet(df, "oci://b@ns/prod/out", mode="append")
    with pytest.raises(PolicyViolation):
        safe_write_parquet_coalesced(df, "oci://b@ns/prod/out")
    assert df.write.calls == []
    safe_write_parquet(df, "oci://b@ns/sbx/out", mode="append")
    assert df.write.calls == [("parquet", "oci://b@ns/sbx/out")]


def test_safe_local_writers_assert_sandbox_prefix(tmp_path, sandbox_env, monkeypatch):
    from aidp_compat import safe_io
    monkeypatch.setattr(safe_io, "FUSE_WRITE_DELAY", 0)
    outside = tmp_path / "prod.pkl"
    with pytest.raises(PolicyViolation):
        safe_io.safe_pickle_dump({"a": 1}, str(outside))
    assert not outside.exists()
    inside = tmp_path / "sandbox" / "ok.pkl"
    safe_io.safe_pickle_dump({"a": 1}, str(inside), delay=0)
    assert inside.exists()

    class _PD:
        def __init__(self):
            self.calls = []

        def to_csv(self, p, **_):
            self.calls.append(p)
    pd = _PD()
    with pytest.raises(PolicyViolation):
        safe_io.safe_pandas_to_csv(pd, str(tmp_path / "prod.csv"), delay=0)
    assert pd.calls == [], "refusal must happen before the DataFrame is written"
    # (the inside-prefix happy path of safe_pandas_to_csv needs a POSIX fsync;
    # safe_pickle_dump above covers the allowed case for local writers)


def test_runtime_assertions_fail_closed_without_a_sandbox():
    from aidp_compat.safe_io import safe_save_as_table
    df = _FakeDF()
    with pytest.raises(SandboxUndeclaredError):
        safe_save_as_table(df, "sbx.t")
    assert df.write.calls == []


def test_fs_mkdirs_asserts_sandbox_prefix(tmp_path, sandbox_env):
    outside = tmp_path / "outside-dir"
    with pytest.raises(PolicyViolation) as ei:
        _fs().mkdirs(str(outside))
    assert ei.value.rule_id == "NBP-RUNTIME-PATH"
    assert not outside.exists()
    inside = tmp_path / "sandbox" / "new" / "dir"
    assert _fs().mkdirs(str(inside)) is True
    assert inside.is_dir()


def test_fs_mount_extra_configs_never_reach_the_environment(sandbox_env):
    fs = _fs()
    before = dict(os.environ)
    assert fs.mount("oci://b@ns/data", "/mnt/data", extra_configs={"fs.key": "mount-secret-value"}) is True
    assert dict(os.environ) == before
    assert not any("mount-secret-value" in v for v in os.environ.values())
    assert fs.mounts()[0].source == "oci://b@ns/data"


# ── path canonicalisation: traversal and symlinks ─────────────────────
@pytest.mark.parametrize("path", [
    "oci://b@ns/sbx/../prod/x",
    "oci://b@ns/sbx/a/../../prod/x",
    "oci://b@ns/sbx/..",
    "/Volumes/sbx/../prod/x",
])
def test_parent_segment_is_never_inside_the_sandbox(path):
    p = SandboxPolicy(catalog="default", schema="sbx", prefix="oci://b@ns/sbx/", extra_prefixes=("/Volumes/sbx/",))
    assert not p.path_in_sandbox(path)
    assert p.path_in_sandbox("oci://b@ns/sbx/./a//b")      # canonical form is still under the prefix
    assert p.path_in_sandbox("/Volumes/sbx/a/./b")


def test_local_traversal_is_refused_at_runtime(tmp_path, sandbox_env):
    from aidp_compat import safe_io
    policy = npol.require_policy()
    local_prefix = sandbox_env["local_prefix"]
    assert not policy.path_in_sandbox(local_prefix + ".." + os.sep + "victim.txt")
    assert not policy.path_in_sandbox(local_prefix + ".." + os.sep + ".." + os.sep + "etc")
    escaped = tmp_path / "escaped.pkl"
    with pytest.raises(PolicyViolation) as ei:
        safe_io.safe_pickle_dump({"a": 1}, local_prefix + ".." + os.sep + "escaped.pkl", delay=0)
    assert ei.value.rule_id == "NBP-RUNTIME-PATH" and "parent-directory" in str(ei.value)
    assert not escaped.exists()
    with pytest.raises(PolicyViolation):
        _fs().rm(local_prefix + ".." + os.sep + "victim.txt")


def test_sandbox_prefix_itself_rejects_parent_segments():
    with pytest.raises(ValueError):
        SandboxPolicy(catalog="default", schema="sbx", prefix="oci://b@ns/sbx/../")


@pytest.mark.skipif(os.name != "posix", reason="symlink resolution is enforced on POSIX hosts only")
def test_symlink_inside_prefix_pointing_outside_is_refused(tmp_path, sandbox_env):
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "sandbox" / "link"
    link.symlink_to(outside, target_is_directory=True)
    policy = npol.require_policy()
    assert not policy.path_in_sandbox(str(link / "x.txt"))
    with pytest.raises(PolicyViolation):
        _fs().put(str(link / "x.txt"), "data", True)
    assert not (outside / "x.txt").exists()


# ── one-shot policy: redeclaration, environment mutation, aliases ──────
def test_policy_is_frozen_after_first_resolution(tmp_path, sandbox_env, monkeypatch):
    victim = tmp_path / "prod.txt"
    victim.write_text("keep me")
    first = npol.require_policy()
    # Environment changes after the first resolution are ignored by every assertion.
    monkeypatch.setenv("AIDP_SANDBOX_PREFIX", str(tmp_path) + os.sep)
    monkeypatch.setenv("AIDP_NOTEBOOK_POLICY_ALLOW", "NBP-DBFS-DYNAMIC")
    assert npol.require_policy() == first
    with pytest.raises(PolicyViolation):
        _fs().rm(str(victim))
    assert victim.exists()
    # A redeclaration that widens (or clears) the sandbox is refused and logged.
    wider = SandboxPolicy(catalog="default", schema="sbx", prefix=str(tmp_path) + os.sep)
    with pytest.raises(PolicyViolation) as ei:
        npol.set_sandbox_policy(wider)
    assert ei.value.rule_id == "NBP-POLICY-TAMPER"
    with pytest.raises(PolicyViolation):
        npol.set_sandbox_policy(None)
    assert npol.require_policy() == first
    tamper = [e for e in npol.get_policy_log() if e["rule"] == "NBP-POLICY-TAMPER"]
    assert len(tamper) == 2 and tamper[0]["detail"]["operation"] == "set_sandbox_policy"
    # Redeclaring the identical policy (bootstrap replay) is a no-op.
    npol.set_sandbox_policy(SandboxPolicy.from_env(dict(os.environ, AIDP_SANDBOX_PREFIX="oci://b@ns/sbx/,"
                                                        + sandbox_env["local_prefix"],
                                                        AIDP_NOTEBOOK_POLICY_ALLOW="")))
    assert npol.require_policy() == first


def test_cell_cannot_redeclare_the_sandbox(tmp_path, sandbox_env):
    victim = tmp_path / "prod" / "victim.txt"
    victim.parent.mkdir()
    victim.write_text("keep me")
    prod_prefix = str(tmp_path / "prod") + os.sep
    path = write_notebook(tmp_path, "child", [
        "from aidp_compat.notebook_policy import set_sandbox_policy, SandboxPolicy\n"
        f"set_sandbox_policy(SandboxPolicy('default', 'sbx', {prod_prefix!r}))",
        f"dbutils.fs.rm({str(victim)!r})",
    ])
    with pytest.raises(PolicyViolation) as ei:
        runner(tmp_path).run(path)
    assert ei.value.rule_id == "NBP-POLICY-TAMPER" and ei.value.cell_index == 0
    assert victim.exists()
    # Even if the import were smuggled past the gate, the runtime refuses the redeclaration.
    with pytest.raises(PolicyViolation):
        npol.set_sandbox_policy(SandboxPolicy("default", "sbx", prod_prefix))
    with pytest.raises(PolicyViolation):
        _fs().rm(str(victim))
    assert victim.exists()


def test_cell_cannot_widen_the_sandbox_through_the_environment(tmp_path, sandbox_env):
    victim = tmp_path / "prod" / "victim.txt"
    victim.parent.mkdir()
    victim.write_text("keep me")
    g = globals()
    g["dbutils"] = type("D", (), {"fs": _fs()})()
    try:
        # Aliasing os does not hide the environment write from the gate (cross-cell alias tracking).
        path = write_notebook(tmp_path, "child", [
            "import os as _o",
            f"_o.environ['AIDP_SANDBOX_PREFIX'] = {str(tmp_path) + os.sep!r}",
            f"dbutils.fs.rm({str(victim)!r})",
        ])
        with pytest.raises(PolicyViolation) as ei:
            runner(tmp_path).run(path)
        assert ei.value.rule_id == "NBP-OS-ENVIRON" and ei.value.cell_index == 1
        assert victim.exists()
        # And the frozen snapshot ignores the environment anyway.
        os.environ["AIDP_SANDBOX_PREFIX"] = str(tmp_path) + os.sep
        with pytest.raises(PolicyViolation):
            _fs().rm(str(victim))
        assert victim.exists()
    finally:
        g.pop("dbutils", None)


def test_shim_alias_bound_in_an_earlier_cell_is_gated(tmp_path, sandbox_env):
    victim = tmp_path / "prod.txt"
    victim.write_text("keep me")
    g = globals()
    g["dbutils"] = type("D", (), {"fs": _fs()})()
    try:
        path = write_notebook(tmp_path, "child", ["_fs = dbutils.fs", f"_fs.rm({str(victim)!r})"])
        with pytest.raises(PolicyViolation) as ei:
            runner(tmp_path).run(path)
        assert ei.value.rule_id == "NBP-DBFS-PATH" and ei.value.cell_index == 1
        assert victim.exists()
    finally:
        g.pop("dbutils", None)
        g.pop("_fs", None)


def test_monkeypatching_the_runtime_assertion_is_refused(tmp_path, sandbox_env):
    path = write_notebook(tmp_path, "child", [
        "import aidp_compat.fs as _f",
        "_f.assert_path_in_sandbox = lambda p, **k: p",
    ])
    with pytest.raises(PolicyViolation) as ei:
        runner(tmp_path).run(path)
    assert ei.value.rule_id == "NBP-POLICY-TAMPER" and ei.value.cell_index == 0
    path = write_notebook(tmp_path, "child2", ["dbutils.fs.rm = lambda *a, **k: True"])
    with pytest.raises(PolicyViolation) as ei:
        runner(tmp_path).run(path)
    assert ei.value.rule_id == "NBP-POLICY-TAMPER"


# ══════════════════════════════════════════════════════════════════════
# SEC-AIDP-SAMPLES-005 revalidation: every route to the same capability
# ══════════════════════════════════════════════════════════════════════
# The security reviewer's residual probes, verbatim.
@pytest.mark.parametrize("source,rule,target", [
    ("__builtins__['__import__']('os').system('id')", "NBP-BUILTIN-EXEC", "__import__"),
    ("__builtins__['open']('/etc/passwd').read()", "NBP-OPEN-PATH", "/etc/passwd"),
    ("globals()['__builtins__']['open']('/etc/passwd').read()", "NBP-OPEN-PATH", "/etc/passwd"),
    ("get_ipython().system('id')", "NBP-OS-PROCESS", "get_ipython.system"),
    ("spark._jvm.java.lang.Runtime.getRuntime().exec('id')", "NBP-POLICY-TAMPER", "spark._jvm"),
    ("sc._jvm.java.lang.Runtime.getRuntime().exec('id')", "NBP-POLICY-TAMPER", "sc._jvm"),
])
def test_residual_notebook_policy_bypasses_are_refused(tmp_path, sandbox_env, source, rule, target):
    path = write_notebook(tmp_path, "child", [source + "\nREFUSED_MARK = 1"])
    globals().pop("REFUSED_MARK", None)
    with pytest.raises(PolicyViolation) as ei:
        runner(tmp_path).run(path)
    assert ei.value.rule_id == rule
    assert target in ei.value.target
    assert "REFUSED_MARK" not in globals()


def _assert_refused(tmp_path, cells, rule, target, cell_index=0, stubs=None):
    """Run ``cells`` as a notebook; the cell at ``cell_index`` must be refused
    with exactly ``rule`` / ``target`` before any of its lines (or any later
    cell) executes, and the refusal must be in the policy log with notebook
    path, cell index, rule, target and remediation."""
    g = globals()
    saved = dict(g)
    g.update(stubs or {})
    cells = list(cells)
    cells[cell_index] = cells[cell_index] + "\nREFUSED_MARK = 1"
    cells.append("LATER_MARK = 1")
    path = write_notebook(tmp_path, "child", cells)
    try:
        with pytest.raises(PolicyViolation) as ei:
            runner(tmp_path).run(path)
        err = ei.value
        assert isinstance(err, PermissionError)
        assert (err.rule_id, err.target, err.cell_index) == (rule, target, cell_index)
        assert err.notebook_path == path and err.remediation
        assert "REFUSED_MARK" not in g and "LATER_MARK" not in g
        entries = [e for e in npol.get_policy_log() if e["event"] == "refused" and e["cell_index"] == cell_index]
        assert entries, "refusal must be recorded in the policy log"
        assert (entries[0]["rule"], entries[0]["target"], entries[0]["notebook_path"]) == (rule, target, path)
        assert entries[0]["remediation"]
        return err
    finally:
        # Earlier cells executed in this module's namespace; put it back.
        for k in set(g) - set(saved):
            g.pop(k, None)
        for k, v in saved.items():
            if g.get(k) is not v:
                g[k] = v


# (1) Builtin indirection: the builtins namespace through any door is checked
#     like the direct form, and a key / attribute that is not a literal is refused.
BUILTIN_INDIRECTION_CELLS = [
    ("__builtins__.open('/etc/passwd')", "NBP-OPEN-PATH", "/etc/passwd"),
    ("__builtins__.__dict__['open']('/etc/passwd')", "NBP-OPEN-PATH", "/etc/passwd"),
    ("getattr(__builtins__, 'open')('/etc/passwd')", "NBP-OPEN-PATH", "/etc/passwd"),
    ("globals()['__builtins__']['__import__']('os').system('id')", "NBP-BUILTIN-EXEC", "__import__"),
    ("locals()['__builtins__']['eval']('1')", "NBP-BUILTIN-EXEC", "eval"),
    ("vars()['__builtins__']['compile']('1', 'f', 'eval')", "NBP-BUILTIN-EXEC", "compile"),
    ("getattr(__builtins__, '__import__')('os')", "NBP-BUILTIN-EXEC", "__import__"),
    ("__builtins__['exec']('x=1')", "NBP-BUILTIN-EXEC", "exec"),
    ("g = globals\ng()['__builtins__']['exec']('x=1')", "NBP-BUILTIN-EXEC", "exec"),
    ("vars(__builtins__)['open']('rel.txt')", "NBP-INDIRECT", "__builtins__['open']"),       # relative, still indirect
    ("__builtins__['op' + 'en']('/etc/passwd')", "NBP-INDIRECT", "__builtins__[<dynamic>]"),
    ("k = 'open'\n__builtins__[k]('/etc/passwd')", "NBP-INDIRECT", "__builtins__[<dynamic>]"),
    ("getattr(__builtins__, 'op' + 'en')", "NBP-INDIRECT", "__builtins__"),
    ("import builtins\nbuiltins.open('/etc/passwd')", "NBP-INDIRECT", "builtins"),
    ("print(__builtins__)", "NBP-INDIRECT", "__builtins__"),
    ("d = globals()", "NBP-INDIRECT", "globals()"),
    ("ns = locals()", "NBP-INDIRECT", "locals()"),
    ("for k, v in globals().items():\n    pass", "NBP-INDIRECT", "globals()"),
    ("__builtins__['print'] = lambda *a: None", "NBP-POLICY-TAMPER", "__builtins__"),
    ("globals()['__builtins__'] = {}", "NBP-POLICY-TAMPER", "globals()['__builtins__']"),
    ("globals()['dbutils'] = None", "NBP-POLICY-TAMPER", "globals()['dbutils']"),
    ("list(map(open, ['/etc/passwd']))", "NBP-INDIRECT", "open"),                          # builtin handed around
    ("import functools\nfunctools.partial(open, '/etc/passwd')()", "NBP-INDIRECT", "open"),
    ("f = exec\nf('x=1')", "NBP-BUILTIN-EXEC", "exec"),
    ("o = open\no('/etc/passwd')", "NBP-OPEN-PATH", "/etc/passwd"),
]


@pytest.mark.parametrize("source,rule,target", BUILTIN_INDIRECTION_CELLS,
                         ids=[c[1] + ":" + c[0][:30] for c in BUILTIN_INDIRECTION_CELLS])
def test_builtin_indirection_is_refused(tmp_path, sandbox_env, source, rule, target):
    _assert_refused(tmp_path, [source], rule, target)


# (2) Dynamic attribute / key access on protected roots and import machinery.
DYNAMIC_ACCESS_CELLS = [
    ("import os\ngetattr(os, 'sys' + 'tem')('id')", "NBP-INDIRECT", "os"),
    ("import os\nn = 'system'\ngetattr(os, n)('id')", "NBP-INDIRECT", "os"),
    ("getattr(obj, name)", "NBP-INDIRECT", "getattr(obj, <dynamic>)"),
    ("setattr(obj, key, value)", "NBP-INDIRECT", "setattr(obj, <dynamic>)"),
    ("delattr(obj, 'x' + 'y')", "NBP-INDIRECT", "delattr(obj, <dynamic>)"),
    ("getattr(spark, '_jvm')", "NBP-INDIRECT", "spark"),
    ("import pkgutil", "NBP-INDIRECT", "pkgutil"),
    ("import runpy\nrunpy.run_path('/tmp/x.py')", "NBP-BUILTIN-EXEC", "runpy"),
    ("import code", "NBP-BUILTIN-EXEC", "code"),
    ("import sys\nsys.modules['o' + 's'].system('id')", "NBP-INDIRECT", "sys.modules"),
    ("import zipimport", "NBP-INDIRECT", "zipimport"),
    ("import _io\n_io.open('/etc/passwd')", "NBP-INDIRECT", "_io"),
    ("import importlib.util", "NBP-INDIRECT", "importlib"),
    ("from importlib import import_module as im\nim('os')", "NBP-INDIRECT", "importlib"),
    ("import sys\nsys.settrace(lambda *a: None)", "NBP-INDIRECT", "sys.settrace"),
    ("import sys\nsys.meta_path.insert(0, finder)", "NBP-INDIRECT", "sys.meta_path"),
    ("import inspect\nfr = inspect.currentframe()", "NBP-INDIRECT", "inspect.currentframe"),
    ("import gc\ngc.get_objects()", "NBP-INDIRECT", "gc.get_objects"),
    ("from shutil import *", "NBP-INDIRECT", "shutil.*"),
    ("from pickle import *", "NBP-INDIRECT", "pickle.*"),
]


@pytest.mark.parametrize("source,rule,target", DYNAMIC_ACCESS_CELLS,
                         ids=[c[1] + ":" + c[0][:30] for c in DYNAMIC_ACCESS_CELLS])
def test_dynamic_access_on_protected_roots_is_refused(tmp_path, sandbox_env, source, rule, target):
    _assert_refused(tmp_path, [source], rule, target)


# (3) Dunder / frame introspection chains (attribute ACCESS; dunder definitions stay fine).
DUNDER_ESCAPE_CELLS = [
    ("().__class__.__bases__[0].__subclasses__()", "NBP-DUNDER-ESCAPE", "<expr>.__subclasses__"),
    ("x.__class__.__mro__", "NBP-DUNDER-ESCAPE", "x.__class__.__mro__"),
    ("f.__globals__['__builtins__']", "NBP-DUNDER-ESCAPE", "f.__globals__"),
    ("f.__code__.co_code", "NBP-DUNDER-ESCAPE", "f.__code__"),
    ("obj.__reduce_ex__(2)", "NBP-DUNDER-ESCAPE", "obj.__reduce_ex__"),
    ("e.__traceback__.tb_frame.f_back.f_globals", "NBP-DUNDER-ESCAPE", "e.__traceback__"),
    ("import sys\nsys.exc_info()[2].tb_frame.f_globals", "NBP-DUNDER-ESCAPE", "tb_frame.f_globals"),
    ("type(x).mro()", "NBP-DUNDER-ESCAPE", "type.mro"),
    ("obj.__dict__['secret']", "NBP-DUNDER-ESCAPE", "obj.__dict__"),
    ("getattr(obj, '__subclasses__')()", "NBP-DUNDER-ESCAPE", "obj.__subclasses__"),
    ("getattr(obj, '__globals__')", "NBP-DUNDER-ESCAPE", "obj.__globals__"),
    ("\"{0.__class__.__mro__}\".format(x)", "NBP-DUNDER-ESCAPE", "{0.__class__.__mro__}"),
    ("spark.__dict__", "NBP-DUNDER-ESCAPE", "spark.__dict__"),
    ("fn.__closure__[0].cell_contents", "NBP-DUNDER-ESCAPE", "fn.__closure__"),
    ("obj.__getattribute__('x')", "NBP-DUNDER-ESCAPE", "obj.__getattribute__"),
    ("m.__loader__.exec_module(m)", "NBP-DUNDER-ESCAPE", "m.__loader__"),
    ("m.__spec__.loader", "NBP-DUNDER-ESCAPE", "m.__spec__"),
    ("gen.gi_frame.f_globals", "NBP-DUNDER-ESCAPE", "gen.gi_frame"),
    ("import inspect\ninspect.stack()[1][0].f_globals", "NBP-DUNDER-ESCAPE", "<expr>.f_globals"),
    ("cls.__init_subclass__", "NBP-DUNDER-ESCAPE", "cls.__init_subclass__"),
    ("bound.__self__", "NBP-DUNDER-ESCAPE", "bound.__self__"),
    ("bound.__func__.__globals__", "NBP-DUNDER-ESCAPE", "bound.__func__"),
    ("obj.__reduce__()", "NBP-DUNDER-ESCAPE", "obj.__reduce__"),
    ("x.__class__.__base__", "NBP-DUNDER-ESCAPE", "x.__class__.__base__"),
]


@pytest.mark.parametrize("source,rule,target", DUNDER_ESCAPE_CELLS,
                         ids=[c[1] + ":" + c[0][:30] for c in DUNDER_ESCAPE_CELLS])
def test_dunder_escape_chains_are_refused(tmp_path, sandbox_env, source, rule, target):
    _assert_refused(tmp_path, [source], rule, target)


# (4) IPython: the shell object, its imports, and %magic / !command lines inside a cell body.
IPYTHON_CELLS = [
    ("import IPython", "NBP-IPYTHON-ESCAPE", "IPython"),
    ("from IPython import get_ipython", "NBP-IPYTHON-ESCAPE", "IPython"),
    ("from IPython.core.interactiveshell import InteractiveShell", "NBP-IPYTHON-ESCAPE", "IPython"),
    ("ip = get_ipython()", "NBP-IPYTHON-ESCAPE", "get_ipython"),
    ("get_ipython().getoutput('id')", "NBP-OS-PROCESS", "get_ipython.getoutput"),
    ("get_ipython().run_line_magic('sh', 'id')", "NBP-OS-PROCESS", "get_ipython.run_line_magic"),
    ("get_ipython().run_cell_magic('bash', '', 'id')", "NBP-OS-PROCESS", "get_ipython.run_cell_magic"),
    ("get_ipython().magic('sh id')", "NBP-OS-PROCESS", "get_ipython.magic"),
    ("get_ipython().system_raw('id')", "NBP-OS-PROCESS", "get_ipython.system_raw"),
    ("get_ipython().ev('__import__(\"os\")')", "NBP-IPYTHON-ESCAPE", "get_ipython.ev"),
    ("get_ipython().ex('import os')", "NBP-IPYTHON-ESCAPE", "get_ipython.ex"),
    ("get_ipython().run_cell('import os')", "NBP-IPYTHON-ESCAPE", "get_ipython.run_cell"),
    ("get_ipython().user_ns['dbutils']", "NBP-IPYTHON-ESCAPE", "get_ipython.user_ns"),
    ("InteractiveShell.instance().system('id')", "NBP-IPYTHON-ESCAPE", "InteractiveShell"),
    ("gi = get_ipython\ngi().system('id')", "NBP-OS-PROCESS", "get_ipython.system"),
    ("x = 1\n!id", "NBP-OS-PROCESS", "!id"),
    ("x = 1\n%%bash\nid", "NBP-OS-PROCESS", "%%bash"),
    ("x = 1\n%sh id", "NBP-OS-PROCESS", "%sh"),
    ("x = 1\n%pip install requests", "NBP-OS-PROCESS", "%pip"),
    ("x = 1\n%matplotlib inline", "NBP-IPYTHON-ESCAPE", "%matplotlib"),
    ("x = 1\n%run ./other", "NBP-IPYTHON-ESCAPE", "%run"),
]


@pytest.mark.parametrize("source,rule,target", IPYTHON_CELLS, ids=[c[1] + ":" + c[0][:30] for c in IPYTHON_CELLS])
def test_ipython_escapes_are_refused(tmp_path, sandbox_env, source, rule, target):
    _assert_refused(tmp_path, [source], rule, target)


def test_magic_led_cell_is_skipped_whole_and_logged(tmp_path, sandbox_env):
    # A cell whose FIRST line is a magic is skipped as a unit: no line of it
    # is compiled or executed, and the skip is visible in the policy log.
    path = write_notebook(tmp_path, "child", ["%sh id\nMAGIC_MARK = 1", "!id\nBANG_MARK = 1", "AFTER_MARK = 1"])
    g = globals()
    for k in ("MAGIC_MARK", "BANG_MARK", "AFTER_MARK"):
        g.pop(k, None)
    try:
        assert runner(tmp_path).run(path) == "ok"
        assert "MAGIC_MARK" not in g and "BANG_MARK" not in g
        assert g["AFTER_MARK"] == 1
    finally:
        g.pop("AFTER_MARK", None)
    skipped = [e for e in npol.get_policy_log() if e["event"] == "skipped_magic"]
    assert [(e["cell_index"], e["target"]) for e in skipped] == [(0, "%sh id"), (1, "!id")]
    assert all(e["notebook_path"] == path and e["remediation"] for e in skipped)
    assert [e for e in npol.get_policy_log() if e["event"] == "refused"] == []


# (5) Spark JVM / py4j bridges: private Spark attributes and py4j handles.
JVM_BRIDGE_CELLS = [
    ("spark.sparkContext._jsc.sc()", "NBP-POLICY-TAMPER", "spark.sparkContext._jsc"),
    ("spark._jsparkSession", "NBP-POLICY-TAMPER", "spark._jsparkSession"),
    ("spark._gateway", "NBP-POLICY-TAMPER", "spark._gateway"),
    ("sc._gateway.jvm.java.lang.Runtime", "NBP-POLICY-TAMPER", "sc._gateway"),
    ("spark.sparkContext._gateway", "NBP-POLICY-TAMPER", "spark.sparkContext._gateway"),
    ("spark.sparkContext._conf._jconf", "NBP-POLICY-TAMPER", "spark.sparkContext._conf"),
    ("SparkContext._active_spark_context._jvm", "NBP-POLICY-TAMPER", "SparkContext._active_spark_context"),
    ("SparkSession._instantiatedSession._jvm", "NBP-POLICY-TAMPER", "SparkSession._instantiatedSession"),
    ("SparkSession._activeSession", "NBP-POLICY-TAMPER", "SparkSession._activeSession"),
    ("SparkSession.getActiveSession()._jvm", "NBP-POLICY-TAMPER", "SparkSession.getActiveSession._jvm"),
    ("from pyspark.sql import SparkSession\nSparkSession._instantiatedSession", "NBP-POLICY-TAMPER",
     "pyspark.sql.SparkSession._instantiatedSession"),
    ("df._jdf.sparkSession()", "NBP-POLICY-TAMPER", "df._jdf"),
    ("df.rdd._jrdd", "NBP-POLICY-TAMPER", "df.rdd._jrdd"),
    ("sqlContext._jsqlContext", "NBP-POLICY-TAMPER", "sqlContext._jsqlContext"),
    ("import py4j", "NBP-POLICY-TAMPER", "py4j"),
    ("from py4j.java_gateway import JavaGateway", "NBP-POLICY-TAMPER", "py4j"),
    ("JavaGateway()", "NBP-POLICY-TAMPER", "JavaGateway"),
    ("sp = spark\nsp._jvm", "NBP-POLICY-TAMPER", "spark._jvm"),
    ("ctx = spark.sparkContext\nctx._jvm", "NBP-POLICY-TAMPER", "spark.sparkContext._jvm"),
    ("spark.sparkContext.addPyFile('oci://b@ns/x/evil.zip')", "NBP-BUILTIN-EXEC", "spark.sparkContext.addPyFile"),
    ("sc.addJar('oci://b@ns/x/evil.jar')", "NBP-BUILTIN-EXEC", "sc.addJar"),
    ("spark.udf.registerJavaFunction('f', 'com.x.Evil')", "NBP-POLICY-TAMPER", "spark.udf.registerJavaFunction"),
    ("session = make()\nsession._jvm", "NBP-POLICY-TAMPER", "session._jvm"),
    ("spark._jvm = None", "NBP-POLICY-TAMPER", "spark._jvm"),
]


@pytest.mark.parametrize("source,rule,target", JVM_BRIDGE_CELLS, ids=[c[1] + ":" + c[0][:30] for c in JVM_BRIDGE_CELLS])
def test_jvm_bridges_are_refused(tmp_path, sandbox_env, source, rule, target):
    _assert_refused(tmp_path, [source], rule, target)


# (6) Other process / exec / open routes.
PROCESS_EXEC_CELLS = [
    ("from concurrent.futures import ProcessPoolExecutor", "NBP-IMPORT-PROCESS",
     "concurrent.futures.ProcessPoolExecutor"),
    ("import concurrent.futures\nconcurrent.futures.ProcessPoolExecutor()", "NBP-IMPORT-PROCESS",
     "concurrent.futures.ProcessPoolExecutor"),
    ("from concurrent import futures\nfutures.ProcessPoolExecutor(2)", "NBP-IMPORT-PROCESS",
     "concurrent.futures.ProcessPoolExecutor"),
    ("import concurrent.futures.process", "NBP-IMPORT-PROCESS", "concurrent.futures.process"),
    ("import os\nos.posix_spawn('/bin/sh', ['sh'], {})", "NBP-OS-PROCESS", "os.posix_spawn"),
    ("import os\nos.forkpty()", "NBP-OS-PROCESS", "os.forkpty"),
    # (references only: if a regression ever let these through, the suite must not kill itself)
    ("import os\nkill = os.kill", "NBP-OS-PROCESS", "os.kill"),
    ("import os\nbye = os._exit", "NBP-POLICY-TAMPER", "os._exit"),
    ("import pickle\npickle.loads(b)", "NBP-DESERIALIZE", "pickle.loads"),
    ("import pickle\npickle.load(fh)", "NBP-DESERIALIZE", "pickle.load"),
    ("import pickle\npickle.Unpickler(fh).load()", "NBP-DESERIALIZE", "pickle.Unpickler"),
    ("import marshal\nmarshal.loads(b)", "NBP-DESERIALIZE", "marshal.loads"),
    ("import shelve\nshelve.open(p)", "NBP-DESERIALIZE", "shelve.open"),
    ("import dill\ndill.loads(b)", "NBP-DESERIALIZE", "dill.loads"),
    ("import cloudpickle\ncloudpickle.load(fh)", "NBP-DESERIALIZE", "cloudpickle.load"),
    ("import joblib\njoblib.load('m.pkl')", "NBP-DESERIALIZE", "joblib.load"),
    ("import pandas as pd\npd.read_pickle('x.pkl')", "NBP-DESERIALIZE", "pandas.read_pickle"),
    ("import yaml\nyaml.load(s)", "NBP-DESERIALIZE", "yaml.load"),
    ("import yaml\nyaml.load(s, Loader=yaml.Loader)", "NBP-DESERIALIZE", "yaml.load"),
    ("import yaml\nyaml.unsafe_load(s)", "NBP-DESERIALIZE", "yaml.unsafe_load"),
    ("import yaml\nyaml.full_load(s)", "NBP-DESERIALIZE", "yaml.full_load"),
    ("import torch\ntorch.load('m.pt')", "NBP-DESERIALIZE", "torch.load"),
    ("import torch\ntorch.load('m.pt', weights_only=False)", "NBP-DESERIALIZE", "torch.load"),
    ("import numpy as np\nnp.load('a.npy', allow_pickle=True)", "NBP-DESERIALIZE", "numpy.load(allow_pickle=True)"),
    ("import jsonpickle\njsonpickle.decode(s)", "NBP-DESERIALIZE", "jsonpickle.decode"),
    ("from pickle import loads\nloads(b)", "NBP-DESERIALIZE", "pickle.loads"),
    ("import cffi", "NBP-IMPORT-PROCESS", "cffi"),
    ("import signal", "NBP-IMPORT-PROCESS", "signal"),
    ("import resource", "NBP-IMPORT-PROCESS", "resource"),
    ("import psutil", "NBP-IMPORT-PROCESS", "psutil"),
    ("import pexpect", "NBP-IMPORT-PROCESS", "pexpect"),
    ("import _posixsubprocess", "NBP-IMPORT-PROCESS", "_posixsubprocess"),
    ("import code\ncode.interact()", "NBP-BUILTIN-EXEC", "code"),
    ("import pdb\npdb.set_trace()", "NBP-BUILTIN-EXEC", "pdb"),
    ("breakpoint()", "NBP-BUILTIN-EXEC", "breakpoint"),
    ("import timeit\ntimeit.timeit('__import__(\"os\")')", "NBP-BUILTIN-EXEC", "timeit"),
    ("import cProfile\ncProfile.run('import os')", "NBP-BUILTIN-EXEC", "cProfile"),
    ("import doctest", "NBP-BUILTIN-EXEC", "doctest"),
    ("import webbrowser", "NBP-IMPORT-PROCESS", "webbrowser"),
    ("import antigravity", "NBP-IMPORT-PROCESS", "antigravity"),
    ("import io\nio.open('/etc/passwd')", "NBP-OPEN-PATH", "/etc/passwd"),
    ("import io\nio.FileIO('/etc/passwd')", "NBP-OPEN-PATH", "/etc/passwd"),
    ("import os\nos.open('/etc/passwd', os.O_RDONLY)", "NBP-OPEN-PATH", "/etc/passwd"),
    ("import codecs\ncodecs.open('/etc/passwd', encoding='utf-8')", "NBP-OPEN-PATH", "/etc/passwd"),
    ("import gzip\ngzip.open('/Volumes/prod/x.gz')", "NBP-OPEN-PATH", "/Volumes/prod/x.gz"),
    ("import tarfile\ntarfile.open('/Volumes/prod/x.tar')", "NBP-OPEN-PATH", "/Volumes/prod/x.tar"),
    ("import zipfile\nzipfile.ZipFile('/Workspace/.oci/config')", "NBP-OPEN-PATH", "/Workspace/.oci/config"),
    ("import io\nio.open(p)", "NBP-OPEN-DYNAMIC", "<dynamic>"),
    ("import sqlite3\nsqlite3.connect('/Volumes/prod/x.db')", "NBP-OPEN-PATH", "/Volumes/prod/x.db"),
    ("import linecache\nlinecache.getline('/etc/passwd', 1)", "NBP-OPEN-PATH", "/etc/passwd"),
    ("import os\nos.chdir('/Volumes/prod')", "NBP-FS-PATH", "/Volumes/prod"),
    ("import os\nos.chdir('no-such-dir/..')", "NBP-FS-PATH", "no-such-dir/.."),       # relative: cwd must stay put
    ("import os\nos.chdir(p)", "NBP-FS-DYNAMIC", "<dynamic>"),
    ("import types\ntypes.FunctionType(co, {})", "NBP-BUILTIN-EXEC", "types.FunctionType"),
    ("from types import CodeType", "NBP-BUILTIN-EXEC", "types.CodeType"),
    ("import asyncio\nasyncio.open_connection('h', 80)", "NBP-IMPORT-NETWORK", "asyncio.open_connection"),
    ("import socketserver", "NBP-IMPORT-NETWORK", "socketserver"),
    ("import ssl", "NBP-IMPORT-NETWORK", "ssl"),
]


@pytest.mark.parametrize("source,rule,target", PROCESS_EXEC_CELLS,
                         ids=[c[1] + ":" + c[0][:30] for c in PROCESS_EXEC_CELLS])
def test_other_process_exec_routes_are_refused(tmp_path, sandbox_env, source, rule, target):
    _assert_refused(tmp_path, [source], rule, target)


# (7) Namespace / alias tracking across the cells of one run; a name rebound
#     to something unknown and then used is refused (fail closed).
class _Stub:
    def __init__(self, **kw):
        self.__dict__.update(kw)


ALIAS_TRACKING_CASES = [
    # (cells, rule, target, refused cell index, stub globals for the cells that run)
    (["x = __builtins__", "x['open']('/etc/passwd')"], "NBP-OPEN-PATH", "/etc/passwd", 1, {}),
    (["f = getattr", "f(os, 'system')('id')"], "NBP-INDIRECT", "os", 1, {}),
    (["sp = spark", "sp._jvm"], "NBP-POLICY-TAMPER", "spark._jvm", 1, {"spark": _Stub()}),
    (["ctx = spark.sparkContext", "ctx.addPyFile('oci://b@ns/x/e.zip')"], "NBP-BUILTIN-EXEC",
     "spark.sparkContext.addPyFile", 1, {"spark": _Stub(sparkContext=_Stub())}),
    (["b = __builtins__", "d = b.__dict__", "d['open']('/etc/passwd')"], "NBP-DUNDER-ESCAPE",
     "__builtins__.__dict__", 1, {}),
    (["g = globals", "ns = g()"], "NBP-INDIRECT", "globals()", 1, {}),
    (["gi = get_ipython", "gi().system('id')"], "NBP-OS-PROCESS", "get_ipython.system", 1,
     {"get_ipython": lambda: None}),
    (["ipy = get_ipython()", "ipy.system('id')"], "NBP-IPYTHON-ESCAPE", "get_ipython", 0, {}),
    (["from pickle import loads as unpack", "unpack(blob)"], "NBP-DESERIALIZE", "pickle.loads", 0, {}),
    (["import pickle", "P = pickle", "P.loads(b)"], "NBP-DESERIALIZE", "pickle.loads", 2, {}),
    (["import os as o", "o.popen('id')"], "NBP-OS-PROCESS", "os.popen", 1, {}),
    # rebound to something the gate cannot resolve -> every later use refused
    (["f = getattr", "f = make_getter()", "f(obj, 'x')"], "NBP-INDIRECT", "f", 2,
     {"make_getter": lambda: None}),
    (["sp = spark", "sp = build_session()", "sp.sparkContext.getConf()"], "NBP-INDIRECT", "sp", 2,
     {"spark": _Stub(), "build_session": lambda: None}),
    (["o = open", "o = my_open", "o('rel.txt')"], "NBP-INDIRECT", "o", 2, {"my_open": None}),
    (["import os", "os = fake_os()", "os.path.join('a', 'b')"], "NBP-INDIRECT", "os", 2,
     {"fake_os": lambda: None}),
    (["b = __builtins__", "b = {}", "b['open']"], "NBP-INDIRECT", "b", 2, {}),
]


@pytest.mark.parametrize("cells,rule,target,idx,stubs", ALIAS_TRACKING_CASES,
                         ids=[c[1] + ":" + " | ".join(c[0])[:40] for c in ALIAS_TRACKING_CASES])
def test_aliases_are_followed_across_cells_and_rebinding_fails_closed(tmp_path, sandbox_env, cells, rule,
                                                                        target, idx, stubs):
    _assert_refused(tmp_path, cells, rule, target, cell_index=idx, stubs=stubs)


def test_refused_cell_count_covers_the_revalidation_classes():
    refused = BUILTIN_INDIRECTION_CELLS + DYNAMIC_ACCESS_CELLS + DUNDER_ESCAPE_CELLS + IPYTHON_CELLS \
        + JVM_BRIDGE_CELLS + PROCESS_EXEC_CELLS
    assert len(refused) + len(ALIAS_TRACKING_CASES) >= 40
    for rule in ("NBP-DUNDER-ESCAPE", "NBP-IPYTHON-ESCAPE", "NBP-DESERIALIZE"):
        assert rule in npol.ALL_RULES


# (8) Clean notebooks keep working.
CLEAN_CELLS_2 = [
    "import pandas as pd\nimport numpy as np\ndf = pd.DataFrame({'a': [1]})\nx = np.array([1])",
    "import matplotlib.pyplot as plt\nplt.plot([1, 2])",
    "import plotly.express as px\nfig = px.bar(df, x='a')",
    "pd.options.display.max_columns = 50",
    "df2 = df.alias('d')",
    "x = spark.read.parquet('oci://b@ns/prod/in')",
    "df.write.mode('overwrite').parquet('oci://b@ns/sbx/out')",
    "dbutils.widgets.text('p', '1')\nv = dbutils.widgets.get('p')",
    "dbutils.notebook.exit('ok')",
    "display(df)",
    "s = 'a {}'.format(1)",
    "n = f'{x} rows'",
    "d = {'key': 1}\nv = d['key']",
    "class Model:\n    def __init__(self, n):\n        self.n = n\n    def __repr__(self):\n        return f'Model({self.n})'",
    "class B(A):\n    def __init__(self):\n        super().__init__()",
    "name = type(df).__name__",
    "m = df.__class__.__name__",
    "import yaml\ncfg = yaml.safe_load(s)",
    "import yaml\ncfg = yaml.load(s, Loader=yaml.SafeLoader)",
    "from yaml import load, SafeLoader\ncfg = load(s, Loader=SafeLoader)",
    "import torch\nm = torch.load('m.pt', weights_only=True)",
    "import numpy as np\na = np.load('a.npy')",
    "import pickle\npickle.dump(obj, fh)",
    "from concurrent.futures import ThreadPoolExecutor",
    "import json\nj = json.loads(s)",
    "v = globals()['my_var']",
    "globals()['result'] = 1",
    "import os\np = os.path.join('a', 'b')",
    "import sys\nprint(sys.version)",
    "with open('rel.txt', 'w') as fh:\n    fh.write('x')",
    "import sqlite3\nc = sqlite3.connect(':memory:')",
    "import io\nbuf = io.BytesIO(b'x')",
    "import inspect\nsig = inspect.signature(fn)",
    "row.__fields__",
    "spark.sparkContext.setLogLevel('WARN')",
    "spark.conf.get('spark.sql.shuffle.partitions')",
    "from pyspark.sql import SparkSession, functions as F\nc = F.col('a')",
    "from pyspark.sql.functions import col, lit",
    "import logging\nlog = logging.getLogger(__name__)",
    "setattr(obj, 'x', 1)",
    "y = getattr(df, 'count')()",
    "x = hasattr(df, 'write')",
    "def helper(spark, df):\n    return df.count()",
    "import gc\ngc.collect()",
    "sc = spark.sparkContext\nn = sc.defaultParallelism",
    "import os as o\nimport sys as s\no2 = o\nE = o2.path.sep",
    "try:\n    risky()\nexcept Exception as e:\n    print(str(e))",
    "total = sum(len(x) for x in rows)",
    "pdf = df.toPandas()",
]


@pytest.mark.parametrize("source", CLEAN_CELLS_2, ids=[c[:40] for c in CLEAN_CELLS_2])
def test_clean_cell_passes_the_hardened_gate(sandbox_env, source):
    assert npol.scan_source(source) == []


def test_chdir_inside_the_sandbox_prefix_is_allowed(sandbox_env):
    inside = sandbox_env["local_prefix"] + "work"
    assert npol.scan_source(f"import os\nos.chdir({inside!r})") == []


def test_clean_notebook_with_dunder_definitions_and_aliases_executes(tmp_path, sandbox_env):
    path = write_notebook(tmp_path, "child", [
        "import json\nimport os as _o",
        "class _Acc:\n    def __init__(self):\n        self.items = []\n    def __len__(self):\n"
        "        return len(self.items)\n    def __repr__(self):\n        return 'Acc({})'.format(len(self))",
        "class _Sub(_Acc):\n    def __init__(self):\n        super().__init__()\n        self.items.append(1)",
        "acc = _Sub()\nsetattr(acc, 'tag', 'x')\nkind = type(acc).__name__",
        "globals()['CLEAN_MARK'] = json.dumps({'n': len(acc), 'kind': kind, 'tag': getattr(acc, 'tag'),"
        " 'sep': _o.path.sep})",
    ])
    g = globals()
    for k in ("CLEAN_MARK", "acc", "kind", "_Acc", "_Sub"):
        g.pop(k, None)
    try:
        assert runner(tmp_path).run(path) == "ok"
        assert json.loads(g["CLEAN_MARK"]) == {"n": 1, "kind": "_Sub", "tag": "x", "sep": os.path.sep}
    finally:
        for k in ("CLEAN_MARK", "acc", "kind", "_Acc", "_Sub", "_o"):
            g.pop(k, None)
    assert [e for e in npol.get_policy_log() if e["event"] in ("refused", "allowed_exception")] == []


# ══════════════════════════════════════════════════════════════════════
# SEC-AIDP-SAMPLES-005 round 2: gaps from the static review of edcb186
# ══════════════════════════════════════════════════════════════════════
# (9) Each gap is closed by generalising the rule, not the spelling: posix / nt
#     are os; the indirect (getattr) route consults the same rule table as the
#     direct one; str.format templates are resolved and walked; library readers
#     refuse literal local paths; a dynamic spark.sql statement needs a literal
#     read-keyword head.
ROUND2_GAP_CELLS = [
    # -- (1) posix / nt are the modules os re-exports: every os rule applies
    ("import posix\nposix.system('id')", "NBP-OS-PROCESS", "os.system"),
    ("import posix\nTOKEN = posix.environ.get('AIDP_TOKEN')", "NBP-OS-ENVIRON", "os.environ"),
    ("import posix\nposix.open('/etc/passwd', 0)", "NBP-OPEN-PATH", "/etc/passwd"),
    ("import posix\nposix.remove('/Volumes/prod/x')", "NBP-FS-PATH", "/Volumes/prod/x"),
    ("import posix\nposix.fork()", "NBP-OS-PROCESS", "os.fork"),
    ("import posix\nposix.environ = {}", "NBP-OS-ENVIRON", "os.environ"),
    ("from posix import system", "NBP-OS-PROCESS", "os.system"),
    ("from posix import environ as _e", "NBP-OS-ENVIRON", "os.environ"),
    ("from posix import *", "NBP-OS-ENVIRON", "os.*"),
    ("import posix as p\np.popen('id')", "NBP-OS-PROCESS", "os.popen"),
    ("import nt\nnt.system('id')", "NBP-OS-PROCESS", "os.system"),
    ("import nt as n\nn.environ['X']", "NBP-OS-ENVIRON", "os.environ"),
    # -- (2) the indirect route consults the same rule table as direct access
    ("import asyncio\nasyncio.run(getattr(asyncio, 'create_subprocess_exec')('id'))", "NBP-OS-PROCESS",
     "asyncio.create_subprocess_exec"),
    ("import asyncio\nf = getattr(asyncio, 'create_subprocess_shell')", "NBP-OS-PROCESS",
     "asyncio.create_subprocess_shell"),
    ("import asyncio\nloop = asyncio.get_event_loop()\nloop.subprocess_exec(lambda: None, 'id')", "NBP-OS-PROCESS",
     "loop.subprocess_exec"),
    ("import asyncio\nloop = asyncio.get_event_loop()\ngetattr(loop, 'subprocess_shell')", "NBP-OS-PROCESS",
     "loop.subprocess_shell"),
    ("getattr(spark.sparkContext, 'addPyFile')('oci://b@ns/x/e.zip')", "NBP-BUILTIN-EXEC",
     "spark.sparkContext.addPyFile"),
    ("import os\nfrom os import system as run_cmd\nrun_cmd('id')", "NBP-OS-PROCESS", "os.system"),
    # -- (3) str.format: templates are resolved and every field is walked
    ("t = '{0.__class__.__mro__}'\nt.format(obj)", "NBP-DUNDER-ESCAPE", "{0.__class__.__mro__}"),
    ("'{x.__init__.__globals__[os].environ}'.format_map(dict(x=obj))", "NBP-DUNDER-ESCAPE",
     "{x.__init__.__globals__[os].environ}"),
    ("t = '{x.__init__.__globals__}'\nt.format_map(dict(x=obj))", "NBP-DUNDER-ESCAPE", "{x.__init__.__globals__}"),
    ("str.format('{0.__class__.__mro__}', obj)", "NBP-DUNDER-ESCAPE", "{0.__class__.__mro__}"),
    ("str.format_map('{x.__globals__}', dict(x=f))", "NBP-DUNDER-ESCAPE", "{x.__globals__}"),
    ("import string\nstring.Formatter().format('{0.__subclasses__}', obj)", "NBP-DUNDER-ESCAPE",
     "{0.__subclasses__}"),
    ("import string\nstring.Formatter().vformat('{0.__code__}', (f,), {})", "NBP-DUNDER-ESCAPE", "{0.__code__}"),
    ("import textwrap\ntextwrap.dedent('  {0.__class__.__mro__}').format(obj)", "NBP-DUNDER-ESCAPE",
     "{0.__class__.__mro__}"),
    ("('{0.__class__.' + '__mro__}').format(obj)", "NBP-DUNDER-ESCAPE", "{0.__class__.__mro__}"),
    ("'{0:{1.__class__.__mro__}}'.format(a, b)", "NBP-DUNDER-ESCAPE", "{1.__class__.__mro__}"),   # nested spec
    ("'{0.f_globals}'.format(frame)", "NBP-DUNDER-ESCAPE", "{0.f_globals}"),
    ("tpl = dbutils.widgets.get('tpl')\ntpl.format(obj)", "NBP-DUNDER-ESCAPE", "<dynamic>"),        # fail closed
    ("TEMPLATES['x'].format(row=row)", "NBP-DUNDER-ESCAPE", "<dynamic>"),
    ("tpl = 'a {0}'\ntpl = 'b {0}'\ntpl.format(obj)", "NBP-DUNDER-ESCAPE", "<dynamic>"),            # rebound: unknown
    # -- (4) local file reads through library readers (literal local path outside the prefix)
    ("import pandas as pd\npd.read_csv('/etc/passwd')", "NBP-OPEN-PATH", "/etc/passwd"),
    ("import pandas as pd\npd.read_parquet('~/.oci/config')", "NBP-OPEN-PATH", "~/.oci/config"),
    ("import pandas as pd\npd.read_json(path_or_buf='/Workspace/.oci/config')", "NBP-OPEN-PATH",
     "/Workspace/.oci/config"),
    ("import pandas as pd\npd.read_csv('C:\\\\Users\\\\x\\\\secret.csv')", "NBP-OPEN-PATH", "C:\\Users\\x\\secret.csv"),
    ("from pandas import read_csv\nread_csv('/etc/passwd')", "NBP-OPEN-PATH", "/etc/passwd"),
    ("import pandas as pd\nP = '/etc/passwd'\npd.read_csv(P)", "NBP-OPEN-PATH", "/etc/passwd"),      # resolved constant
    ("spark.read.text('file:///etc/passwd')", "NBP-OPEN-PATH", "file:///etc/passwd"),
    ("spark.read.csv('/dbfs/mnt/prod/x.csv')", "NBP-OPEN-PATH", "/dbfs/mnt/prod/x.csv"),
    ("spark.read.format('csv').load('/Workspace/.oci/config')", "NBP-OPEN-PATH", "/Workspace/.oci/config"),
    ("spark.read.option('path', '/etc/passwd').load()", "NBP-OPEN-PATH", "/etc/passwd"),
    ("spark.read.options(path='/etc/passwd').load()", "NBP-OPEN-PATH", "/etc/passwd"),
    ("spark.read.load(path='/etc/passwd')", "NBP-OPEN-PATH", "/etc/passwd"),
    ("spark.readStream.parquet('/tmp/other/in')", "NBP-OPEN-PATH", "/tmp/other/in"),
    ("rdr = spark.read\nrdr.json('/etc/x.json')", "NBP-OPEN-PATH", "/etc/x.json"),
    ("sc.textFile('/etc/passwd')", "NBP-OPEN-PATH", "/etc/passwd"),
    ("spark.sparkContext.wholeTextFiles('/Volumes/prod/docs')", "NBP-OPEN-PATH", "/Volumes/prod/docs"),
    ("import numpy as np\nnp.loadtxt('/etc/passwd')", "NBP-OPEN-PATH", "/etc/passwd"),
    ("import numpy as np\nnp.load('/Volumes/prod/a.npy')", "NBP-OPEN-PATH", "/Volumes/prod/a.npy"),
    ("import pyarrow.parquet as pq\npq.read_table('/Volumes/prod/x.parquet')", "NBP-OPEN-PATH",
     "/Volumes/prod/x.parquet"),
    ("import polars as pl\npl.scan_csv('/etc/passwd')", "NBP-OPEN-PATH", "/etc/passwd"),
    ("from PIL import Image\nImage.open('/Workspace/.ssh/id_rsa')", "NBP-OPEN-PATH", "/Workspace/.ssh/id_rsa"),
    ("import xml.etree.ElementTree as ET\nET.parse('/etc/x.xml')", "NBP-OPEN-PATH", "/etc/x.xml"),
    ("import h5py\nh5py.File('/Volumes/prod/m.h5', 'r')", "NBP-OPEN-PATH", "/Volumes/prod/m.h5"),
    ("open('~/.oci/config').read()", "NBP-OPEN-PATH", "~/.oci/config"),
    ("open('C:\\\\Users\\\\x\\\\.oci\\\\config').read()", "NBP-OPEN-PATH", "C:\\Users\\x\\.oci\\config"),
    # -- (c) a dynamic spark.sql statement needs a LITERAL read-keyword head
    ("spark.sql(f'{verb} TABLE prod.t')", "NBP-SQL-DYNAMIC", "<dynamic>"),
    ("spark.sql('  ' + q)", "NBP-SQL-DYNAMIC", "<dynamic>"),
    ("spark.sql('/* c */ ' + q)", "NBP-SQL-DYNAMIC", "<dynamic>"),
    ("spark.sql('-- c\\n' + q)", "NBP-SQL-DYNAMIC", "<dynamic>"),
    ("spark.sql(f'USE {db}')", "NBP-SQL-DYNAMIC", "<dynamic>"),
    ("spark.sql(verb + ' TABLE prod.t')", "NBP-SQL-DYNAMIC", "<dynamic>"),
    ("spark.sql('SELECTX ' + q)", "NBP-SQL-DYNAMIC", "<dynamic>"),
]


@pytest.mark.parametrize("source,rule,target", ROUND2_GAP_CELLS,
                         ids=[c[1] + ":" + c[0][:30] for c in ROUND2_GAP_CELLS])
def test_round2_gap_cells_are_refused(tmp_path, sandbox_env, source, rule, target):
    _assert_refused(tmp_path, [source], rule, target)


def test_posix_alias_bound_in_an_earlier_cell_is_followed(sandbox_env):
    # (scanned, not executed: ``posix`` only exists on POSIX hosts)
    ctx = npol.ScanContext()
    assert npol.scan_source("import posix as p", context=ctx) == []
    assert [(v.rule, v.target) for v in npol.scan_source("p.system('id')", context=ctx)] \
        == [("NBP-OS-PROCESS", "os.system")]
    ctx = npol.ScanContext()
    assert npol.scan_source("import nt", context=ctx) == []
    assert [(v.rule, v.target) for v in npol.scan_source("nt.environ['X']", context=ctx)] \
        == [("NBP-OS-ENVIRON", "os.environ")]


def test_format_template_bound_in_an_earlier_cell_is_resolved(tmp_path, sandbox_env):
    _assert_refused(tmp_path, ["TPL = 'kind: {0.__class__.__mro__}'", "TPL.format(obj)"], "NBP-DUNDER-ESCAPE",
                    "{0.__class__.__mro__}", cell_index=1)


# (10) False refusals fixed: legitimate code the gate wrongly refused.
CLEAN_CELLS_3 = [
    # (a) format fields consult _DUNDER_ALLOW
    "'{0.__class__.__name__}'.format(obj)",
    "'{0.__class__}'.format(obj)",
    "'{x[__class__]}'.format(x=d)",                                           # item lookup, not attribute access
    "'{0:>{1}}'.format(a, 8)",
    "msg = 'rows: {n}'\nout = msg.format(n=count)",
    "import textwrap\nmsg = textwrap.dedent('''\n  rows: {n}''').format(n=count)",
    "w = df.write.mode('overwrite')\nw.format('delta').save('oci://b@ns/sbx/x')",
    "fmt = 'delta'\nw = df.write.mode('overwrite')\nw.format(fmt).save('oci://b@ns/sbx/x')",
    "df.write.format(fmt).save('oci://b@ns/sbx/x')",
    "spark.read.format(fmt).load(src)",
    # (b) getattr on a Spark object with a literal public name
    "getattr(spark, 'version')",
    "v = getattr(spark, 'version')",
    "n = getattr(sc, 'defaultParallelism')",
    "getattr(spark.conf, 'get')('spark.app.name')",
    # (c) dynamic read-only SQL with a literal read-keyword head
    "q = 'SELECT * FROM sbx.t WHERE id=' + str(cid)\nspark.sql(q)",
    "for cid in ids:\n    q = 'SELECT * FROM sbx.t WHERE id=' + str(cid)\n    spark.sql(q)",
    "if flag:\n    q = f'SELECT count(*) FROM sbx.t WHERE d={d}'\n    spark.sql(q)",
    "spark.sql('SELECT * FROM sbx.t WHERE id=' + str(cid))",
    "spark.sql(f'WITH c AS (SELECT 1) SELECT * FROM c WHERE x={v}')",
    "spark.sql('SHOW TABLES IN {}'.format(s))",
    "spark.sql('-- filter\\nSELECT 1 FROM {}'.format(s))",
    "spark.sql('/* cols */ DESCRIBE {}'.format(s))",
    "spark.sql('DESC ' + t)",
    "spark.sql('EXPLAIN ' + q)",
    # (4) dynamic, object-storage, catalog and relative reads stay allowed
    "import pandas as pd\npdf = pd.read_csv(src_path)",
    "spark.read.csv(path, header=True)",
    "spark.read.format('parquet').load(src)",
    "import pandas as pd\npdf = pd.read_csv('oci://b@ns/prod/x.csv')",
    "spark.read.parquet('abfss://c@a.dfs.core.windows.net/prod/in')",
    "spark.read.parquet('s3://bucket/prod/in')",
    "spark.read.parquet('oci://b@ns/sbx/in')",
    "spark.read.table('prod.t')",
    "import pandas as pd\npdf = pd.read_csv('data/local.csv')",
    "import pandas as pd\npdf = pd.read_sql('SELECT 1', con)",
    "import numpy as np\na = np.load('a.npy')",
]


@pytest.mark.parametrize("source", CLEAN_CELLS_3, ids=[c[:40] for c in CLEAN_CELLS_3])
def test_round2_false_refusals_pass_the_gate(sandbox_env, source):
    assert npol.scan_source(source) == []


def test_local_reads_inside_the_sandbox_prefix_are_allowed(sandbox_env):
    inside = sandbox_env["local_prefix"] + "in.csv"
    assert npol.scan_source(f"import pandas as pd\npdf = pd.read_csv({inside!r})") == []
    pol = SandboxPolicy(catalog="default", schema="sbx", prefix="oci://b@ns/sbx/", extra_prefixes=("/tmp/sbx/",))
    assert npol.scan_source("spark.read.csv('file:///tmp/sbx/in.csv')", policy=pol) == []
    assert npol.scan_source("spark.read.csv('/tmp/sbx/in.csv')", policy=pol) == []
    assert [v.rule for v in npol.scan_source("spark.read.csv('file:///tmp/other/in.csv')", policy=pol)] \
        == ["NBP-OPEN-PATH"]


def test_unverified_reads_are_allowed_and_recorded(sandbox_env):
    src = ("import pandas as pd\n"
           "pdf = pd.read_csv(src_path)\n"
           "rows = spark.sql('SELECT * FROM sbx.t WHERE id=' + str(cid))")
    assert npol.scan_source(src) == []
    assert npol.enforce_cell_policy(src, notebook_path="nb", cell_index=3) == []
    notes = [e for e in npol.get_policy_log() if e["event"] in npol.POLICY_NOTES]
    assert [(e["event"], e["target"], e["cell_index"], e["notebook_path"]) for e in notes] == [
        ("unverified_read_path", "pandas.read_csv(<dynamic>)", 3, "nb"),
        ("unverified_sql_read", "SELECT * FROM sbx.t WHERE id=", 3, "nb"),
    ]
    assert [e["detail"]["line"] for e in notes] == [2, 3]
    assert all(e["rule"] == "" and e["remediation"] == "" for e in notes)
    assert "unverified_read_path" in npol.policy_log_markdown()
    assert [e for e in npol.get_policy_log() if e["event"] in ("refused", "allowed_exception")] == []


def test_verified_reads_are_not_recorded(sandbox_env):
    npol.enforce_cell_policy("x = spark.read.parquet('oci://b@ns/prod/in')\ny = spark.sql('SELECT 1')",
                             notebook_path="nb", cell_index=0)
    assert [e for e in npol.get_policy_log() if e["event"] in npol.POLICY_NOTES] == []
