"""
AIDP Notebook Policy - mandatory sandbox gate for notebook execution
=====================================================================
Runtime enforcement that sits next to the execution sink in
``aidp_compat.notebook`` (``dbutils.notebook.run``) and the write paths the
compat layer owns (``dbutils.fs.rm/mv/cp/put/mkdirs``, ``safe_io`` writes,
``dbutils.secrets``).

Static analysis elsewhere in the migrator can be bypassed by a missed rule or
a hand-edited notebook; this module makes the boundary hold at the point
where code actually runs.

Two pieces:

1. ``SandboxPolicy`` - WHAT the run is allowed to touch. It must be declared
   before any notebook code executes (fail closed), either from the
   environment::

       AIDP_SANDBOX_CATALOG=default
       AIDP_SANDBOX_SCHEMA=migration_sandbox
       AIDP_SANDBOX_PREFIX=oci://sandbox-bucket@namespace/migration/,/tmp/
       AIDP_SANDBOX_ALLOW_NETWORK=0          # optional, default off

   or programmatically via :func:`set_sandbox_policy`. The declaration is a
   one-shot snapshot: the first policy resolved for the process is frozen,
   later environment changes are ignored by the runtime assertions, and a
   redeclaration with a different policy is refused (``NBP-POLICY-TAMPER``).

2. ``enforce_cell_policy`` - an AST gate applied to every non-magic code cell
   before ``exec``. It refuses (``PolicyViolation``, a ``PermissionError``)
   environment reads, process/network imports, destructive filesystem calls,
   dynamic code execution, access to the policy machinery itself, and writes
   whose target is outside the sandbox. Targets that are plain names bound to
   a string literal earlier in the notebook are resolved; any other
   non-literal target is refused unless the rule id is listed in
   ``AIDP_NOTEBOOK_POLICY_ALLOW`` (a reviewed exception). Import aliases
   (``import os as o``) and shim aliases (``fs = dbutils.fs``) are tracked
   across the cells of one run.

   The gate is deny-by-default for every route to the same capabilities, not
   only the direct spelling: the builtins namespace reached through
   ``__builtins__`` / ``builtins`` / ``globals()`` / ``locals()`` / ``vars()``
   / ``getattr``, dynamic attribute names on protected modules, dunder and
   frame introspection chains (``__subclasses__``, ``__globals__``,
   ``f_globals``, ...), the IPython shell API and ``%``/``!`` lines, the
   Spark JVM / py4j bridge (``spark._jvm``, ``sc._jsc``), deserialisers that
   execute code (``pickle.loads``, ``yaml.load`` without a safe loader),
   process / debugger / profiler modules, and names that were bound to any of
   these and later rebound to something the gate cannot resolve. One rule
   table serves every spelling of a module attribute: the direct chain, an
   alias (``import posix as p`` is ``os``), a ``from m import n`` name and
   ``getattr(m, "literal")``. ``str.format`` templates (literal, bound once,
   or wrapped in ``textwrap.dedent`` / ``.strip()``) are walked field by field
   against the dunder read allowlist. Library readers (``pd.read_csv``,
   ``spark.read.csv``, ``np.load``, ``sc.textFile``, ...) with a literal
   local-filesystem path outside the sandbox are refused like ``open()``.

   Three scope decisions are allowed and recorded in the policy log instead of
   refused: a reader path the gate cannot resolve (``unverified_read_path``;
   reading source data through variables is the normal migration case, and
   object-storage / catalog reads are never path-checked; ``<object>.open(p)``
   on a receiver that is neither the builtin nor a ``Path`` is recorded the
   same way when the receiver is a name the notebook bound, while
   ``open(path_var)`` itself stays refused in every mode and so does
   ``thing.open(p)`` on a receiver the run never bound), a ``spark.sql``
   statement whose literal head is a read keyword (``unverified_sql_read``;
   Spark runs one statement per call, so it cannot become a write) and
   ``DataFrame.pipe(name)`` with a bare name the gate cannot type on a bound,
   non-Spark receiver (``unverified_pipe_callable``; ``RDD.pipe(cmd)``, a
   string-typed argument and a receiver the run never bound are refused).

   Routes are closed as classes, not spellings: a gated module or Spark
   object handed around as a value (``[os][0]``, ``run(os)``, ``return os``,
   ``lambda: os``), a process sink name on a receiver the gate cannot resolve
   (``helper().system``, ``obj.popen``), string-keyed accessors
   (``operator.attrgetter`` / ``methodcaller``, ``functools.reduce(getattr)``,
   ``inspect.getattr_static`` / ``getmembers``), re-rooting at a module named
   mid-chain (``shutil.os.system``, ``pd.io.common.os.environ``), deny-by-default
   deserialisers (the pickle family except the dump side, ``torch.load`` at
   any depth, ``numpy`` ``allow_pickle``, every unsafe yaml loader /
   constructor / hook / subclass), ``globals()[k]`` with a tainted key or a
   dereferenced result, and ``open(*a, **kw)``. A list literal is folded into
   a path only while its name is used for nothing but ``sep.join(name)`` (an
   in-place mutation, alias or helper call makes the join dynamic); loaders
   gated on a keyword fail closed when the switch is positional or hidden in
   ``*args`` / ``**kwargs`` (``np.load(p, None, True)``, ``torch.load(p,
   pickle_module=..)``); the state of a gated module is read-only
   (``yaml.SafeLoader.yaml_constructors[..] = h``, ``.update(..)``,
   ``setattr``; ``sys.path`` and ``torch`` flags excepted); a process sink
   name or a ``_private`` attribute on an imported module the gate has no
   rules for is refused (``mymod.system``, ``mymod._run``); ``site`` / ``pip``
   load code from paths and are refused like ``addPyFile``.

The gate is a static check of the forms listed in SUPPORTED_OPERATIONS.md
section 8; it is not a Python sandbox, and a static gate over a full Python
runtime is a mitigation layer: the platform-level control is the IAM scope of
the cluster the notebook runs on. The runtime assertions
(:func:`assert_path_in_sandbox`, :func:`assert_table_in_sandbox`) are the
enforcement layer for every write that goes through the compat helpers.

Every refusal, allowed exception, unverified read and sandbox declaration is
appended to an in-process policy log (:func:`get_policy_log`) and, when
``AIDP_NOTEBOOK_POLICY_LOG`` names a file, to that JSONL file, so the
migration report can include it.
"""

import ast
import json
import os
import posixpath
import re
import string
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

# ── Environment contract ───────────────────────────────────────────────
ENV_SANDBOX_CATALOG = "AIDP_SANDBOX_CATALOG"
ENV_SANDBOX_SCHEMA = "AIDP_SANDBOX_SCHEMA"
ENV_SANDBOX_PREFIX = "AIDP_SANDBOX_PREFIX"
ENV_SANDBOX_ALLOW_NETWORK = "AIDP_SANDBOX_ALLOW_NETWORK"
ENV_POLICY_ALLOW = "AIDP_NOTEBOOK_POLICY_ALLOW"
ENV_POLICY_LOG = "AIDP_NOTEBOOK_POLICY_LOG"

# ── Rule ids ───────────────────────────────────────────────────────────
RULE_IMPORT_PROCESS = "NBP-IMPORT-PROCESS"      # subprocess / ctypes / pty / multiprocessing
RULE_IMPORT_NETWORK = "NBP-IMPORT-NETWORK"      # socket / requests / urllib / http.client / paramiko / ...
RULE_OS_ENVIRON = "NBP-OS-ENVIRON"              # os.environ / os.getenv / os.putenv / from os import *
RULE_OS_PROCESS = "NBP-OS-PROCESS"              # os.system / os.popen / os.exec* / os.spawn* / os.fork / asyncio subprocess
RULE_SHUTIL_RMTREE = "NBP-SHUTIL-RMTREE"
RULE_BUILTIN_EXEC = "NBP-BUILTIN-EXEC"          # eval / exec / compile / __import__
RULE_INDIRECT = "NBP-INDIRECT"                  # importlib / builtins / sys.modules / getattr(os, ...)
RULE_POLICY_TAMPER = "NBP-POLICY-TAMPER"        # aidp_compat internals, set_sandbox_policy, module attribute assignment
RULE_OPEN_PATH = "NBP-OPEN-PATH"                # open() / pathlib read-write on absolute path outside sandbox
RULE_OPEN_DYNAMIC = "NBP-OPEN-DYNAMIC"          # open() / pathlib read-write with an unresolvable path
RULE_FS_PATH = "NBP-FS-PATH"                    # os.remove/rename/mkdir..., pathlib unlink/rmdir/mkdir..., shutil.move/copy
RULE_FS_DYNAMIC = "NBP-FS-DYNAMIC"
RULE_DBFS_PATH = "NBP-DBFS-PATH"                # dbutils.fs.rm/mv/cp/put/mkdirs literal outside prefix
RULE_DBFS_DYNAMIC = "NBP-DBFS-DYNAMIC"
RULE_TABLE_TARGET = "NBP-TABLE-TARGET"          # saveAsTable / insertInto / writeTo literal outside catalog.schema
RULE_TABLE_DYNAMIC = "NBP-TABLE-DYNAMIC"
RULE_SQL_TARGET = "NBP-SQL-TARGET"              # spark.sql DDL/DML literal outside catalog.schema / prefix
RULE_SQL_DYNAMIC = "NBP-SQL-DYNAMIC"            # spark.sql with an unresolvable statement
RULE_PATH_WRITE = "NBP-PATH-WRITE"              # df.write.parquet/csv/json/orc/text/save/option("path") literal outside prefix
RULE_PATH_WRITE_DYNAMIC = "NBP-PATH-WRITE-DYNAMIC"
RULE_RUNTIME_PATH = "NBP-RUNTIME-PATH"          # compat helper asked to write outside the prefix
RULE_RUNTIME_TABLE = "NBP-RUNTIME-TABLE"        # compat helper asked to write outside catalog.schema
RULE_RUNTIME_SECRET = "NBP-RUNTIME-SECRET"      # dbutils.secrets scope/key outside the planned allowlist
RULE_DUNDER_ESCAPE = "NBP-DUNDER-ESCAPE"        # __subclasses__ / __globals__ / __dict__ / frame attributes (f_globals, tb_frame)
RULE_IPYTHON_ESCAPE = "NBP-IPYTHON-ESCAPE"      # get_ipython / InteractiveShell / IPython imports / %magic lines inside a cell body
RULE_DESERIALIZE = "NBP-DESERIALIZE"            # pickle / marshal / shelve / dill / joblib loads, yaml.load without SafeLoader, torch.load

ALL_RULES = (
    RULE_IMPORT_PROCESS, RULE_IMPORT_NETWORK, RULE_OS_ENVIRON, RULE_OS_PROCESS,
    RULE_SHUTIL_RMTREE, RULE_BUILTIN_EXEC, RULE_INDIRECT, RULE_POLICY_TAMPER,
    RULE_OPEN_PATH, RULE_OPEN_DYNAMIC, RULE_FS_PATH, RULE_FS_DYNAMIC,
    RULE_DBFS_PATH, RULE_DBFS_DYNAMIC, RULE_TABLE_TARGET, RULE_TABLE_DYNAMIC,
    RULE_SQL_TARGET, RULE_SQL_DYNAMIC, RULE_PATH_WRITE, RULE_PATH_WRITE_DYNAMIC,
    RULE_RUNTIME_PATH, RULE_RUNTIME_TABLE, RULE_RUNTIME_SECRET,
    RULE_DUNDER_ESCAPE, RULE_IPYTHON_ESCAPE, RULE_DESERIALIZE,
)

_PROCESS_MODULES = frozenset({
    "subprocess", "ctypes", "pty", "multiprocessing", "cffi", "signal", "resource",
    "webbrowser", "antigravity", "pexpect", "sh", "plumbum", "fabric", "invoke", "psutil",
    "_posixsubprocess", "pydoc",
})
_NETWORK_MODULES = frozenset({
    "socket", "requests", "urllib", "paramiko", "http.client",
    "urllib3", "httpx", "aiohttp", "ftplib", "smtplib", "pycurl", "telnetlib",
    "poplib", "imaplib", "nntplib", "websocket", "websockets", "grpc", "xmlrpc",
    "socketserver", "ssl", "asyncore", "asynchat",
})
_INDIRECT_MODULES = frozenset({"importlib", "builtins", "pkgutil", "zipimport", "imp"})
# gc.collect() is routine notebook hygiene; the object-graph walkers reach every live object.
_GC_INDIRECT_ATTRS = frozenset({"get_objects", "get_referrers", "get_referents"})
# Modules whose purpose is to run code handed to them as a string / docstring / frame.
_EXEC_MODULES = frozenset({"pdb", "bdb", "code", "codeop", "runpy", "doctest", "timeit", "cProfile",
                           "profile", "trace"})
# Modules that load code from a path while processing it: ``site.addsitedir``
# executes every ``.pth`` file in the directory, ``pip`` installs and imports
# arbitrary distributions, ``sitecustomize`` / ``usercustomize`` run on import.
# The same class as ``sc.addPyFile`` / ``addJar``. (``sys.path.insert`` is NOT in
# this class: the migrator itself puts its module mirror on ``sys.path``.)
_CODE_LOAD_MODULES = frozenset({"site", "pip", "ensurepip", "sitecustomize", "usercustomize"})
# ``site`` is a plausible variable name (``site = row["site"]``), so only its
# code-loading attributes are refused when the import is out of view; the
# other code-load modules are refused at any attribute.
_SITE_CODE_LOAD_ATTRS = frozenset({"addsitedir", "addpackage", "execsitecustomize", "execusercustomize"})
_CODE_LOAD_ROOT_REFUSED = _CODE_LOAD_MODULES - frozenset({"site"})
_JVM_BRIDGE_MODULES = frozenset({"py4j"})
_IPYTHON_MODULES = frozenset({"IPython", "ipykernel"})
_OS_ENV_ATTRS = frozenset({"environ", "getenv", "putenv", "unsetenv", "environb", "getenvb"})
_OS_PROCESS_ATTRS = frozenset({"system", "popen", "posix_spawn", "posix_spawnp", "startfile",
                               "fork", "forkpty", "kill", "killpg", "abort"})
_OS_PROCESS_PREFIXES = ("exec", "spawn")
# Process / environment / introspection sinks whose names have no benign
# homonym in notebook code. On a receiver the gate cannot resolve (a call
# result, a subscript, an unknown name) these are refused outright (fail
# closed); ``load`` / ``remove`` / ``mkdir`` / ``open`` are deliberately NOT
# here (``list.remove``, ``Path.mkdir``, ``loader.load`` are everyday code).
_SINK_ATTRS = frozenset({
    "system", "popen", "posix_spawn", "posix_spawnp", "startfile", "fork", "forkpty", "putenv", "unsetenv",
    "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
    "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
    "pipepager", "tempfilepager", "getattr_static", "getmembers",
})
# A plain ``import m`` of a module the gate has no rules for does not vouch
# for its attributes: ``mymod.system(..)`` may be ``os`` re-exported or
# shadowed, so a sink name on such a module is refused too. The stdlib
# homonyms with a documented benign meaning are the only exception.
_SINK_HOMONYMS = frozenset({("platform", "system")})
# Methods that mutate a registry (dict / list) in place. On a chain rooted at
# a gated module (``yaml.SafeLoader.yaml_constructors.update(..)``) they
# rewrite the module's state the gate reasons about and are refused.
_REGISTRY_MUTATORS = frozenset({"update", "setdefault", "pop", "popitem", "clear", "append", "insert", "extend",
                                "__setitem__", "__delitem__", "__ior__", "__iadd__"})
# ``sys.path`` is the one gated-module list notebook code may mutate: the
# migrator itself puts its module mirror on ``sys.path`` (``sys.path.insert``).
_MUTABLE_GATED_CHAINS = frozenset({("sys", "path")})
# ``torch.serialization`` hooks that widen what ``weights_only=True`` may unpickle.
_TORCH_HOOK_ATTRS = frozenset({"add_safe_globals", "safe_globals", "clear_safe_globals"})
# Callees that may take a gated module / Spark object as an argument: the
# call is judged (getattr / setattr / delattr / vars) or cannot hand the
# object back (print, repr, type, isinstance, ...).
_VALUE_SAFE_CALLEES = frozenset({"getattr", "setattr", "delattr", "hasattr", "vars", "dir", "isinstance",
                                 "issubclass", "type", "id", "repr", "str", "print", "help", "callable",
                                 "display"})
# String-keyed attribute accessors: judged like getattr with a literal name.
_ATTR_ACCESSOR_CALLS = frozenset({("operator", "attrgetter"), ("operator", "methodcaller")})
_ATTR_RESOLVING_NAMES = frozenset({"getattr", "setattr", "delattr", "vars"})
# RDD-producing steps: ``.pipe(cmd)`` on such a chain runs a shell command on the executors.
_RDD_CHAIN_ATTRS = frozenset({"parallelize", "rdd", "emptyRDD", "textFile", "wholeTextFiles", "binaryFiles",
                              "binaryRecords", "sequenceFile", "hadoopFile", "newAPIHadoopFile", "pickleFile"})
# The platform modules ``os`` re-exports: ``posix.system`` is ``os.system``. An
# import of either is tracked as an alias of ``os`` so every os rule applies.
_OS_EQUIVALENT_MODULES = frozenset({"posix", "nt"})
_ASYNCIO_PROCESS_ATTRS = frozenset({"create_subprocess_shell", "create_subprocess_exec", "subprocess"})
# The same capability on an event-loop object (``loop.subprocess_exec``); the
# loop has no module root to key on, so the method names are refused anywhere.
_ASYNCIO_LOOP_PROCESS_ATTRS = frozenset({"subprocess_exec", "subprocess_shell"})
_ASYNCIO_NETWORK_ATTRS = frozenset({"open_connection", "start_server", "create_connection",
                                    "open_unix_connection", "start_unix_server", "create_datagram_endpoint"})
_SYS_INDIRECT_ATTRS = frozenset({"modules", "settrace", "setprofile", "addaudithook", "call_tracing",
                                 "meta_path", "path_hooks", "path_importer_cache"})
_INSPECT_FRAME_ATTRS = frozenset({"currentframe", "stack", "trace", "getouterframes", "getinnerframes"})
_TYPES_EXEC_ATTRS = frozenset({"FunctionType", "CodeType", "LambdaType"})
# ``concurrent.futures.ThreadPoolExecutor`` is fine; the process pool forks workers.
_PROCESS_POOL_NAMES = frozenset({"ProcessPoolExecutor"})
# Stdlib primitives equivalent to builtin open(): (module, callable) -> first argument is the path.
_IO_OPEN_CALLS = frozenset({
    ("io", "open"), ("io", "FileIO"), ("io", "open_code"), ("os", "open"), ("codecs", "open"),
    ("gzip", "open"), ("gzip", "GzipFile"), ("bz2", "open"), ("bz2", "BZ2File"),
    ("lzma", "open"), ("lzma", "LZMAFile"), ("tarfile", "open"), ("tarfile", "TarFile"),
    ("zipfile", "ZipFile"), ("tokenize", "open"), ("fileinput", "input"), ("fileinput", "FileInput"),
    ("sqlite3", "connect"), ("dbm", "open"), ("linecache", "getline"), ("linecache", "getlines"),
})
_IO_MODULES = frozenset(m for m, _ in _IO_OPEN_CALLS)
# Deserialisers that construct arbitrary objects (and therefore run code) from bytes.
# The gate refuses the *load* side only; pickle.dump / safe_io.safe_pickle_dump stay allowed.
_PICKLE_MODULES = frozenset({"pickle", "_pickle", "cPickle", "dill", "cloudpickle"})
# The pickle family is deny-by-default: only the dump side is allowed.
_PICKLE_DUMP_ALLOW = frozenset({"dump", "dumps", "Pickler", "HIGHEST_PROTOCOL", "DEFAULT_PROTOCOL",
                                "PickleError", "PicklingError", "UnpicklingError", "PickleBuffer"})
_DESERIALIZE_ATTRS = {
    "marshal": frozenset({"load", "loads"}),
    "shelve": frozenset({"open", "Shelf", "DbfilenameShelf", "BsdDbShelf"}),
    "joblib": frozenset({"load"}),
    "jsonpickle": frozenset({"decode", "loads"}),
}
# yaml: refused outright at any depth. ``load`` / ``load_all`` are judged at the
# call (``Loader=`` must resolve to a safe loader; ``load_all`` is refused).
_YAML_REFUSED_ATTRS = frozenset({"unsafe_load", "unsafe_load_all", "full_load", "full_load_all", "load_all",
                                 "Loader", "UnsafeLoader", "FullLoader", "Constructor", "FullConstructor",
                                 "UnsafeConstructor", "loader", "constructor", "add_constructor",
                                 "add_multi_constructor"})
_YAML_REFUSED_PREFIXES = ("Full", "Unsafe")
# ``add_constructor`` on any receiver registers code that runs while parsing.
_YAML_HOOK_ATTRS = frozenset({"add_constructor", "add_multi_constructor"})
_DESERIALIZE_MODULES = _PICKLE_MODULES | frozenset(_DESERIALIZE_ATTRS) | frozenset({"torch", "yaml"})
_YAML_SAFE_LOADERS = frozenset({"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"})
# Star imports that would bind the gated API under unqualified names the scanner cannot see.
_STAR_IMPORT_REFUSED = frozenset({"sys", "shutil", "inspect", "types", "asyncio", "concurrent"}) \
    | _IO_MODULES | _DESERIALIZE_MODULES | _INDIRECT_MODULES | _EXEC_MODULES | _CODE_LOAD_MODULES
_OS_FS_ATTRS = frozenset({"remove", "unlink", "rmdir", "removedirs", "rename", "renames", "replace",
                          "truncate", "mkdir", "makedirs", "link", "symlink"})
_OS_FS_TWO_ARG = frozenset({"rename", "renames", "replace", "link", "symlink"})
_SHUTIL_FS_ATTRS = frozenset({"move", "copy", "copy2", "copyfile", "copytree"})
_PATHLIB_IO_ATTRS = frozenset({"read_text", "read_bytes", "write_text", "write_bytes"})
_PATHLIB_FS_ATTRS = frozenset({"unlink", "rmdir", "mkdir", "touch", "symlink_to", "hardlink_to"})
_PATHLIB_RESOLVED_ONLY_ATTRS = frozenset({"open", "rename", "replace"})   # too generic without a Path receiver
_DYNAMIC_BUILTINS = frozenset({"eval", "exec", "compile", "__import__", "breakpoint"})
_INTROSPECT_BUILTINS = frozenset({"getattr", "vars"})
_MUTATE_BUILTINS = frozenset({"setattr", "delattr"})
_NAMESPACE_BUILTINS = frozenset({"globals", "locals", "vars"})    # no-arg call = the frame namespace
_BUILTINS_NAMESPACE_ROOTS = frozenset({"__builtins__", "builtins"})
# Builtins the gate reasons about. Reaching one of them through the builtins
# namespace, an alias or a bare reference (``map(open, ...)``) is checked
# exactly like the direct call, or refused when it cannot be checked.
_DANGEROUS_BUILTINS = _DYNAMIC_BUILTINS | _INTROSPECT_BUILTINS | _MUTATE_BUILTINS | _NAMESPACE_BUILTINS \
    | frozenset({"open"})
# Dunder attributes notebook code may read. Everything else (``__subclasses__``,
# ``__globals__``, ``__dict__``, ``__code__``, ``__reduce__``, ...) is an
# introspection chain out of the sandbox. Dunder *definitions* in class
# bodies are untouched: this list governs attribute access only.
_DUNDER_ALLOW = frozenset({
    "__name__", "__doc__", "__version__", "__class__", "__module__", "__qualname__", "__all__",
    "__annotations__", "__slots__", "__fields__", "__array__",
    "__init__", "__repr__", "__str__", "__len__", "__iter__", "__next__", "__getitem__", "__setitem__",
    "__delitem__", "__contains__", "__eq__", "__ne__", "__lt__", "__le__", "__gt__", "__ge__", "__hash__",
    "__bool__", "__enter__", "__exit__", "__add__", "__radd__", "__sub__", "__rsub__", "__mul__", "__rmul__",
    "__matmul__", "__truediv__", "__floordiv__", "__mod__", "__pow__", "__neg__", "__pos__", "__abs__",
    "__and__", "__or__", "__xor__", "__invert__", "__lshift__", "__rshift__", "__round__", "__format__",
})
# Non-dunder attributes that walk frames, tracebacks, generators or code objects.
_FRAME_ATTRS = frozenset({
    "f_globals", "f_locals", "f_builtins", "f_back", "f_code", "f_trace", "tb_frame", "tb_next",
    "gi_frame", "gi_code", "gi_yieldfrom", "cr_frame", "cr_code", "ag_frame", "ag_code",
    "co_code", "co_consts", "co_names", "func_globals", "func_code", "im_func", "im_self", "mro",
})
# Spark session / context objects and the private py4j handles that lead to the JVM.
_SPARK_ROOTS = frozenset({"spark", "sc", "sqlContext", "sqlCtx", "SparkSession", "SparkContext",
                          "SQLContext", "HiveContext", "pyspark"})
_JVM_BRIDGE_ATTRS = frozenset({
    "_jvm", "_gateway", "_jsc", "_jsparkSession", "_jvm_gateway", "_jconf", "_jdf", "_jrdd", "_jc",
    "_jwrite", "_jreader", "_jspark", "_jsqlContext", "_jcatalog", "_sc", "_gateway_client", "_java_gateway",
})
_SPARK_CODE_LOAD_ATTRS = frozenset({"addPyFile", "addJar", "addArchive"})
_SPARK_JVM_UDF_ATTRS = frozenset({"registerJavaFunction", "registerJavaUDAF"})
_PY4J_NAMES = frozenset({"JavaGateway", "GatewayClient", "GatewayParameters", "java_import", "JavaObject"})
_IPYTHON_NAMES = frozenset({"get_ipython", "InteractiveShell", "TerminalInteractiveShell", "ZMQInteractiveShell"})
# get_ipython().<attr>: shell / magic execution is reported as process execution,
# every other use of the shell object as an IPython escape.
_IPYTHON_SHELL_ATTRS = frozenset({"system", "system_raw", "system_piped", "getoutput",
                                  "run_line_magic", "run_cell_magic", "magic"})
_SHELL_MAGICS = frozenset({"sh", "bash", "sx", "system", "script", "pip", "conda", "cmd", "powershell",
                           "perl", "ruby", "scala", "r", "fs", "env", "set_env", "killbgscripts"})
_MAGIC_LINE_RE = re.compile(r"^\s*(%%?|!)\s*([A-Za-z_][\w.]*)?")
_DBFS_WRITE_METHODS = frozenset({"rm", "mv", "cp", "put", "mkdirs"})
_TABLE_WRITE_METHODS = frozenset({"saveAsTable", "insertInto", "writeTo"})
_PATH_WRITE_METHODS = frozenset({"parquet", "csv", "json", "orc", "text", "save"})
_WRITER_OPTION_METHODS = frozenset({"option", "options"})
_SQL_METHODS = frozenset({"sql"})
# Local file READS through library readers. A LITERAL local-filesystem path
# outside the sandbox prefix is refused (NBP-OPEN-PATH, like open()); a path
# the gate cannot resolve is allowed (reading source data through variables is
# the normal migration case) and recorded as ``unverified_read_path``.
# Object-storage URIs (oci://, abfss://, s3://, ...) and catalog tables are
# not local paths: reading source data is the point of a migration and the
# cluster's IAM scope is the control there.
_DATAFRAME_LIB_ROOTS = frozenset({"pandas", "polars", "modin", "dask", "cudf", "geopandas", "xarray", "pyarrow",
                                  "vaex", "datatable"})
_DATAFRAME_READ_PREFIXES = ("read_", "scan_", "open_")
_DATAFRAME_NON_PATH_READERS = frozenset({"read_sql", "read_sql_query", "read_sql_table", "read_clipboard", "read_gbq"})
_LIB_READER_CALLS = frozenset({
    ("numpy", "loadtxt"), ("numpy", "genfromtxt"), ("numpy", "fromfile"), ("numpy", "load"), ("numpy", "memmap"),
    ("pyarrow", "memory_map"), ("pyarrow", "OSFile"), ("pyarrow", "input_stream"),
    ("pyarrow", "parquet", "ParquetFile"), ("pyarrow", "parquet", "ParquetDataset"), ("pyarrow", "dataset", "dataset"),
    ("PIL", "Image", "open"), ("cv2", "imread"), ("h5py", "File"), ("scipy", "io", "loadmat"),
    ("xml", "etree", "ElementTree", "parse"), ("openpyxl", "load_workbook"), ("xlrd", "open_workbook"),
    ("imageio", "imread"), ("tifffile", "imread"), ("netCDF4", "Dataset"), ("rasterio", "open"), ("zarr", "open"),
    ("librosa", "load"), ("soundfile", "read"),
})
_SPARK_READER_CHAIN = frozenset({"read", "readStream"})
_SPARK_IO_CHAIN = _SPARK_READER_CHAIN | frozenset({"write", "writeStream", "writeTo"})
_SPARK_PATH_READ_METHODS = frozenset({"parquet", "csv", "json", "orc", "text", "load", "textFile", "xml", "avro"})
_SC_PATH_READ_METHODS = frozenset({"textFile", "wholeTextFiles", "binaryFiles", "binaryRecords", "sequenceFile",
                                   "hadoopFile", "newAPIHadoopFile", "pickleFile"})
_READER_PATH_KWARGS = ("path", "paths", "filepath_or_buffer", "path_or_buf", "io", "source", "file", "filename",
                       "fname", "name", "filename_or_obj", "fp")
# str.format templates: methods that return the receiver's text unchanged in
# shape, and the stdlib helpers that do, so ``textwrap.dedent("...").format(x)``
# is checked as the literal.
_STR_PRESERVING_METHODS = frozenset({"strip", "lstrip", "rstrip", "upper", "lower", "title", "capitalize",
                                     "swapcase", "expandtabs", "casefold"})
_STR_PRESERVING_CALLS = frozenset({("textwrap", "dedent"), ("inspect", "cleandoc")})
# Informational policy-log events (not refusals, not rule ids).
NOTE_UNVERIFIED_READ_PATH = "unverified_read_path"      # library reader with a path the gate cannot resolve
NOTE_UNVERIFIED_SQL_READ = "unverified_sql_read"        # spark.sql read statement with run-time fragments
NOTE_UNVERIFIED_PIPE = "unverified_pipe_callable"       # <non-Spark>.pipe(name) with a name the gate cannot type
POLICY_NOTES = (NOTE_UNVERIFIED_READ_PATH, NOTE_UNVERIFIED_SQL_READ, NOTE_UNVERIFIED_PIPE)

# Names whose attributes notebook code must not rebind or introspect: the
# interpreter and the compat shims the sandbox is built from.
_PROTECTED_ROOTS = frozenset({"os", "sys", "builtins", "__builtins__", "importlib", "shutil", "aidp_compat",
                              "dbutils", "spark", "sc", "get_ipython", "io", "pathlib", "inspect", "types", "gc"})
# Modules the gate reasons about: a name bound to one of them (``import os``,
# ``from pickle import loads``, ``import sys as s``) is "tainted" for the run.
# While it stays resolvable the alias is followed; once rebound to something
# the gate cannot resolve, every later use of the name is refused (fail closed).
_WATCHED_MODULES = _PROCESS_MODULES | _NETWORK_MODULES | _INDIRECT_MODULES | _EXEC_MODULES | _JVM_BRIDGE_MODULES \
    | _IPYTHON_MODULES | _IO_MODULES | _DESERIALIZE_MODULES | _PROTECTED_ROOTS | _OS_EQUIVALENT_MODULES \
    | _CODE_LOAD_MODULES \
    | frozenset({"asyncio", "concurrent", "yaml", "aidp_compat", "operator", "functools"})
# A chain segment that names one of these after any root re-roots the chain
# there (``shutil.os.system``, ``pd.io.common.os.environ``, ``self.spark._jvm``):
# the module rules apply from that segment on. Modules whose names are common
# attribute names with no module rules of their own (``signal``, ``code``,
# ``trace``, ``profile``, ``resource``, ``types``, ...) are left out.
_REROOT_NAMES = frozenset({
    "os", "posix", "nt", "sys", "shutil", "subprocess", "importlib", "builtins", "__builtins__", "ctypes",
    "socket", "asyncio", "operator", "inspect", "functools", "pydoc", "io", "pathlib", "gc", "marshal", "shelve",
    "yaml", "torch", "aidp_compat", "dbutils", "get_ipython",
}) | _PICKLE_MODULES | frozenset({"joblib", "jsonpickle"}) | (_SPARK_ROOTS - frozenset({"pyspark"}))
# Process modules whose name is not a plausible variable name: an attribute
# chain rooted there is refused even when the import is out of view.
_PROCESS_ROOT_REFUSED = _PROCESS_MODULES - frozenset({"signal", "resource", "sh", "invoke", "fabric", "plumbum",
                                                      "antigravity"})
# Names that must not be handed around as a value (list / dict / tuple element,
# argument, default, return value, lambda body, conditional, walrus, ...): a
# gated module, a protected root or a Spark object. The tolerated positions
# are the root of an attribute chain the gate judges, the whole right-hand
# side of a plain name assignment (tainted) and the object argument of the
# introspection builtins (judged).
_VALUE_GUARDED = _WATCHED_MODULES | _SPARK_ROOTS | _PROTECTED_ROOTS
# Single names that may be aliased (``sp = spark``, ``f = getattr``, ``b = __builtins__``)
# and that taint the alias for the rest of the run.
_ALIASABLE_SINGLETONS = _PROTECTED_ROOTS | _SPARK_ROOTS | _DANGEROUS_BUILTINS | _PY4J_NAMES | _IPYTHON_NAMES \
    | _PROCESS_POOL_NAMES | _WATCHED_MODULES
_COMPAT_INTERNAL_MODULES = frozenset({"notebook_policy", "fs", "safe_io", "secrets", "notebook",
                                      "dbutils_shim", "credentials"})
_COMPAT_PROTECTED_NAMES = frozenset({
    "SandboxPolicy", "set_sandbox_policy", "clear_policy_log", "require_policy", "current_policy",
    "assert_path_in_sandbox", "assert_table_in_sandbox", "enforce_cell_policy", "scan_source",
    "AIDPNotebookUtils", "AIDPFileSystemUtils", "AIDPSecretsUtils",
}) | _COMPAT_INTERNAL_MODULES

# SQL statements that create, replace, mutate or drop a table/schema. The
# first capture group is the object name (optionally backtick-quoted parts).
_SQL_IDENT = r"((?:`[^`]+`|[A-Za-z_][\w$]*)(?:\s*\.\s*(?:`[^`]+`|[A-Za-z_][\w$]*)){0,2})"
_SQL_WRITE_RE = re.compile(
    r"^\s*(?:"
    r"CREATE\s+(?:OR\s+REPLACE\s+)?(?:EXTERNAL\s+)?(?:TABLE|VIEW|SCHEMA|DATABASE)(?:\s+IF\s+NOT\s+EXISTS)?"
    r"|INSERT\s+(?:INTO|OVERWRITE)(?:\s+TABLE)?"
    r"|DROP\s+(?:TABLE|VIEW|SCHEMA|DATABASE)(?:\s+IF\s+EXISTS)?"
    r"|ALTER\s+(?:TABLE|VIEW|SCHEMA|DATABASE)"
    r"|TRUNCATE\s+TABLE"
    r"|MERGE\s+INTO"
    r"|DELETE\s+FROM"
    r"|UPDATE"
    r")\s+" + _SQL_IDENT,
    re.IGNORECASE | re.DOTALL,
)
_SQL_WRITE_VERB_RE = re.compile(
    r"^\s*(?:CREATE|INSERT|DROP|ALTER|TRUNCATE|MERGE|DELETE|UPDATE)\b",
    re.IGNORECASE,
)
# Session-scoped objects are not catalog writes: CREATE [OR REPLACE] [GLOBAL] TEMP[ORARY] VIEW.
_SQL_TEMP_VIEW_RE = re.compile(
    r"^\s*CREATE\s+(?:OR\s+REPLACE\s+)?(?:GLOBAL\s+)?TEMP(?:ORARY)?\s+VIEW\b", re.IGNORECASE
)
# Spark executes one statement per spark.sql() call, so a statement whose
# literal head is a read keyword cannot become a write whatever the run-time
# tail contains. Dynamic statements with any other head are refused.
_SQL_READ_HEAD_RE = re.compile(r"^\s*(?:SELECT|WITH|SHOW|DESCRIBE|DESC|EXPLAIN)\b", re.IGNORECASE)


def _is_sql_write_verb(text: str) -> bool:
    if _SQL_TEMP_VIEW_RE.match(text):
        return False
    return bool(_SQL_WRITE_VERB_RE.match(text))


# LOCATION 'x' / LOCATION "x" and OPTIONS (path 'x') / OPTIONS ('path' = "x")
_SQL_LOCATION_RE = re.compile(r"\bLOCATION\s+(['\"])(.+?)\1", re.IGNORECASE | re.DOTALL)
_SQL_OPTIONS_PATH_RE = re.compile(
    r"\bOPTIONS\s*\((?:[^()]*?[\s,(])?['\"`]?path['\"`]?\s*=?\s*(['\"])(.+?)\1", re.IGNORECASE | re.DOTALL
)
_SQL_SCHEMA_STMT_RE = re.compile(
    r"^\s*(?:CREATE|DROP|ALTER)\s+(?:OR\s+REPLACE\s+)?(?:SCHEMA|DATABASE)\b", re.IGNORECASE
)
_SQL_COMMENT_RE = re.compile(r"--[^\n]*|/\*.*?\*/", re.DOTALL)
_URI_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*)://([^/\\]*)([/\\].*)?$", re.DOTALL)
_SEGMENT_SPLIT_RE = re.compile(r"[\\/]+")
# Host-absolute forms regardless of the host this module runs on: a Windows
# drive (``C:\``, ``C:/``), a UNC path (``\\server\share``) and a ``file:`` URI.
_WINDOWS_PATH_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\)")
_FILE_URI_RE = re.compile(r"^file:/+", re.IGNORECASE)
# ``{0.attr[key].attr}``: the attribute / index steps after the argument name.
_FORMAT_FIELD_STEP_RE = re.compile(r"\.([^.\[]*)|\[([^\]]*)\]")


# ── Errors ─────────────────────────────────────────────────────────────
class NotebookPolicyError(PermissionError):
    """Base class for every refusal raised by the notebook policy."""

    def __init__(self, message: str, *, notebook_path: str = "", cell_index: Optional[int] = None,
                 rule_id: str = "", target: str = "", remediation: str = ""):
        super().__init__(message)
        self.notebook_path = notebook_path
        self.cell_index = cell_index
        self.rule_id = rule_id
        self.target = target
        self.remediation = remediation


class SandboxUndeclaredError(NotebookPolicyError):
    """No sandbox policy has been declared; nothing may execute."""


class PolicyViolation(NotebookPolicyError):
    """A notebook cell or compat helper tried to leave the sandbox."""


# ── Path canonicalisation ──────────────────────────────────────────────
def _has_parent_segment(path: str) -> bool:
    return any(seg == ".." for seg in _SEGMENT_SPLIT_RE.split(path))


def _norm_path(path: str) -> Optional[str]:
    """Comparison form of ``path``; ``None`` when it contains a ``..`` segment.

    URIs (``scheme://authority/object``) get a posix-normalised object path,
    POSIX-absolute paths (the cluster's ``/Volumes``, ``/tmp``) are
    normalised as POSIX even on a Windows host, host paths use the host rules.
    A trailing separator is preserved so prefixes stay directory boundaries.
    """
    p = path.strip()
    if not p or _has_parent_segment(p):
        return None
    trailing = p.endswith(("/", "\\"))
    m = _URI_RE.match(p)
    if m:
        scheme, authority, obj = m.groups()
        obj = posixpath.normpath((obj or "/").replace("\\", "/"))
        normed = f"{scheme.lower()}://{authority}{obj}"
    elif p.startswith("/"):
        normed = posixpath.normpath(p.replace("\\", "/"))
    else:
        normed = os.path.normcase(os.path.normpath(p))
    if trailing and not normed.endswith(("/", "\\")):
        normed += "/" if (m or p.startswith("/")) else os.sep
    return normed


def _norm_prefix(prefix: str) -> str:
    p = prefix.strip()
    if not p:
        return p
    if _has_parent_segment(p):
        raise ValueError(f"sandbox prefix must not contain a '..' segment: {prefix}")
    # Treat a prefix as a directory boundary so "oci://b@ns/sandbox" does not
    # also admit "oci://b@ns/sandbox-prod/...". A local staging prefix may
    # already end in the host separator.
    return p if p.endswith(("/", "\\")) else p + "/"


def _under_prefix(norm_path: str, prefix: str) -> bool:
    norm_pref = _norm_path(prefix)
    if not norm_pref:
        return False
    return norm_path == norm_pref.rstrip("/\\") or norm_path.startswith(norm_pref)


def _real_under_prefix(path: str, prefix: str) -> bool:
    """POSIX: follow symlinks so a link inside the prefix cannot point outside.

    ``realpath`` resolves the existing components of a not-yet-created path.
    Skipped on Windows, where ``realpath`` may expand short names on one side
    only and the cluster paths this module guards are POSIX anyway.
    """
    if os.name != "posix" or "://" in path:
        return True
    real = os.path.realpath(path)
    real_pref = os.path.realpath(prefix.rstrip("/"))
    return real == real_pref or real.startswith(real_pref + "/")


def _strip_quotes(part: str) -> str:
    part = part.strip()
    if len(part) >= 2 and part[0] == part[-1] and part[0] in "`\"'":
        part = part[1:-1]
    return part.strip()


def _split_table_name(name: str) -> List[str]:
    """Split ``cat.sch.tbl`` into parts, honouring backtick-quoted parts."""
    parts: List[str] = []
    buf = ""
    quoted = False
    for ch in name.strip():
        if ch == "`":
            quoted = not quoted
            continue
        if ch == "." and not quoted:
            parts.append(buf.strip())
            buf = ""
            continue
        buf += ch
    parts.append(buf.strip())
    return [p for p in parts if p]


@dataclass(frozen=True)
class SandboxPolicy:
    """Boundary a migration run is allowed to write inside of.

    Args:
        catalog: Sandbox catalog (AIDP uses ``default`` uniformly).
        schema: Sandbox schema inside ``catalog``.
        prefix: Object-storage prefix every path write must sit under
            (``oci://bucket@namespace/path/``). Additional prefixes, for
            example the FUSE ``/Volumes/default/default/dbfs/`` staging area
            or ``/tmp/``, can be supplied via ``extra_prefixes`` or as a comma
            list in ``AIDP_SANDBOX_PREFIX``.
        allow_network: Permit network-capable imports (``requests``,
            ``socket``, ``urllib``, ``http.client``, ``paramiko``, ...).
            Process/FFI imports stay refused regardless.
        allowed_rules: Rule ids that are a reviewed exception for this run
            (``AIDP_NOTEBOOK_POLICY_ALLOW``). A matching violation is logged
            as ``allowed_exception`` instead of refused.
        extra_prefixes: Additional path prefixes considered inside the sandbox.

    No prefix may contain a ``..`` segment, and no path containing one is ever
    inside the sandbox.
    """

    catalog: str
    schema: str
    prefix: str
    allow_network: bool = False
    allowed_rules: Tuple[str, ...] = ()
    extra_prefixes: Tuple[str, ...] = ()

    def __post_init__(self):
        missing = [n for n, v in (("catalog", self.catalog), ("schema", self.schema),
                                  ("prefix", self.prefix)) if not (v or "").strip()]
        if missing:
            raise ValueError(f"SandboxPolicy requires non-empty {', '.join(missing)}")
        object.__setattr__(self, "catalog", self.catalog.strip().strip("`").lower())
        object.__setattr__(self, "schema", self.schema.strip().strip("`").lower())
        object.__setattr__(self, "prefix", _norm_prefix(self.prefix))
        object.__setattr__(self, "extra_prefixes",
                           tuple(_norm_prefix(p) for p in self.extra_prefixes if p.strip()))
        object.__setattr__(self, "allowed_rules",
                           tuple(sorted({r.strip() for r in self.allowed_rules if r.strip()})))

    # -- construction -------------------------------------------------
    @classmethod
    def from_env(cls, environ: Optional[Dict[str, str]] = None) -> "SandboxPolicy":
        """Build the policy from ``AIDP_SANDBOX_*``; raise if undeclared."""
        env = os.environ if environ is None else environ
        catalog = env.get(ENV_SANDBOX_CATALOG, "").strip()
        schema = env.get(ENV_SANDBOX_SCHEMA, "").strip()
        prefixes = [p.strip() for p in env.get(ENV_SANDBOX_PREFIX, "").split(",") if p.strip()]
        missing = [name for name, val in ((ENV_SANDBOX_CATALOG, catalog),
                                          (ENV_SANDBOX_SCHEMA, schema),
                                          (ENV_SANDBOX_PREFIX, prefixes)) if not val]
        if missing:
            raise SandboxUndeclaredError(
                "Notebook execution refused: no sandbox policy declared. Set "
                + ", ".join(missing)
                + " (or call aidp_compat.notebook_policy.set_sandbox_policy(...)) "
                "before running notebooks. The migration tool's cluster bootstrap "
                "declares these automatically; a scheduled job must declare them "
                "in its environment.",
                rule_id="NBP-SANDBOX-UNDECLARED",
                remediation="Declare AIDP_SANDBOX_CATALOG, AIDP_SANDBOX_SCHEMA and "
                            "AIDP_SANDBOX_PREFIX for the run.",
            )
        allow_network = env.get(ENV_SANDBOX_ALLOW_NETWORK, "").strip().lower() in ("1", "true", "yes")
        allowed = tuple(r.strip() for r in env.get(ENV_POLICY_ALLOW, "").split(",") if r.strip())
        return cls(catalog=catalog, schema=schema, prefix=prefixes[0],
                   allow_network=allow_network, allowed_rules=allowed,
                   extra_prefixes=tuple(prefixes[1:]))

    # -- membership ---------------------------------------------------
    @property
    def prefixes(self) -> Tuple[str, ...]:
        return (self.prefix,) + self.extra_prefixes

    def path_in_sandbox(self, path: str) -> bool:
        """True when ``path`` is a sandbox prefix or sits under one.

        The path is canonicalised first (``//``, ``/./``); a ``..`` segment
        anywhere makes it outside, and on POSIX a symlink inside the prefix
        pointing outside is outside as well.
        """
        if not isinstance(path, str) or not path.strip():
            return False
        normed = _norm_path(path)
        if normed is None:
            return False
        for pref in self.prefixes:
            if _under_prefix(normed, pref):
                return _real_under_prefix(path.strip(), pref)
        return False

    def table_in_sandbox(self, name: str) -> bool:
        """True when a 2- or 3-part table name resolves to ``catalog.schema``.

        A 1-part name depends on the session's current database, which the
        policy cannot see; it is treated as outside (fail closed).
        """
        if not isinstance(name, str):
            return False
        parts = [p.lower() for p in _split_table_name(name)]
        if len(parts) == 3:
            return parts[0] == self.catalog and parts[1] == self.schema
        if len(parts) == 2:
            return parts[0] == self.schema
        return False

    def schema_in_sandbox(self, name: str) -> bool:
        """True when a schema reference (``cat.sch`` or ``sch``) is the sandbox schema."""
        parts = [p.lower() for p in _split_table_name(name or "")]
        if len(parts) == 2:
            return parts[0] == self.catalog and parts[1] == self.schema
        if len(parts) == 1:
            return parts[0] == self.schema
        return False

    def is_allowed_exception(self, rule_id: str) -> bool:
        return rule_id in self.allowed_rules

    def describe(self) -> Dict[str, Any]:
        return {
            "catalog": self.catalog,
            "schema": self.schema,
            "prefix": self.prefix,
            "extra_prefixes": list(self.extra_prefixes),
            "allow_network": self.allow_network,
            "allowed_rules": list(self.allowed_rules),
        }


# ── Policy registry: one-shot snapshot for the process ─────────────────
_frozen_policy: Optional[SandboxPolicy] = None
_lock = threading.Lock()


def set_sandbox_policy(policy: Optional[SandboxPolicy]) -> None:
    """Declare the policy for this process.

    The first declaration (explicit, or implicit through the first
    :func:`require_policy` that resolves ``AIDP_SANDBOX_*``) is frozen. A
    later call with the same policy is a no-op (bootstrap replay); a call
    with a different policy, or with ``None`` once something is declared,
    is refused as ``NBP-POLICY-TAMPER`` so notebook code cannot widen or
    clear the sandbox it runs under.
    """
    global _frozen_policy
    with _lock:
        frozen = _frozen_policy
        if frozen is None:
            if policy is None:
                return
            _frozen_policy = policy
        elif policy == frozen:
            return
    if frozen is not None:
        _refuse_tamper("set_sandbox_policy",
                       "<cleared>" if policy is None else policy.prefix,
                       "the sandbox is frozen for the process once declared")
    _record("sandbox_declared", rule="", target=policy.prefix,
            detail=dict(policy.describe(), source="explicit"))


def current_policy() -> Optional[SandboxPolicy]:
    """Return the declared policy, or ``None`` when nothing is declared."""
    try:
        return require_policy()
    except SandboxUndeclaredError:
        return None


def require_policy() -> SandboxPolicy:
    """Return the frozen policy, resolving (and freezing) it from the
    environment on first use; raise :class:`SandboxUndeclaredError` if none."""
    global _frozen_policy
    pol = _frozen_policy
    if pol is not None:
        return pol
    pol = SandboxPolicy.from_env()
    with _lock:
        if _frozen_policy is None:
            _frozen_policy = pol
            declared = True
        else:
            pol = _frozen_policy
            declared = False
    if declared:
        _record("sandbox_declared", rule="", target=pol.prefix,
                detail=dict(pol.describe(), source="environment"))
    return pol


def _reset_policy_state() -> None:
    """Forget the frozen policy. Test fixtures only; notebook code cannot
    reach this (``aidp_compat.notebook_policy`` imports are refused)."""
    global _frozen_policy
    with _lock:
        _frozen_policy = None


def _refuse_tamper(operation: str, target: str, why: str) -> None:
    remediation = ("The sandbox is declared once per run by the migration bootstrap "
                   "(AIDP_SANDBOX_*); widen it there after review, not from notebook code.")
    _record("runtime_refused", rule=RULE_POLICY_TAMPER, target=target, remediation=remediation,
            detail={"operation": operation, "why": why})
    raise PolicyViolation(
        f"{operation}: refused, {why} (target: {target}). Remediation: {remediation}",
        rule_id=RULE_POLICY_TAMPER, target=target, remediation=remediation,
    )


# ── Policy log ─────────────────────────────────────────────────────────
_policy_log: List[Dict[str, Any]] = []


def _record(event: str, *, rule: str, target: str, notebook_path: str = "",
            cell_index: Optional[int] = None, remediation: str = "",
            detail: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    entry: Dict[str, Any] = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": event,
        "notebook_path": notebook_path,
        "cell_index": cell_index,
        "rule": rule,
        "target": target,
        "remediation": remediation,
    }
    if detail:
        entry["detail"] = detail
    with _lock:
        _policy_log.append(entry)
    log_file = os.environ.get(ENV_POLICY_LOG, "").strip()
    if log_file:
        try:
            with open(log_file, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")
        except OSError:
            pass  # the in-process log is authoritative; the file is best effort
    return entry


def get_policy_log() -> List[Dict[str, Any]]:
    """Copy of every refusal / allowed exception / declaration so far."""
    with _lock:
        return [dict(e) for e in _policy_log]


def clear_policy_log() -> None:
    with _lock:
        _policy_log.clear()


def policy_log_json() -> str:
    return json.dumps(get_policy_log(), sort_keys=True)


def policy_log_markdown(entries: Optional[Iterable[Dict[str, Any]]] = None) -> str:
    """Render the policy log as a Markdown table for the migration report."""
    rows = list(get_policy_log() if entries is None else entries)
    if not rows:
        return ""
    out = ["| Event | Notebook | Cell | Rule | Target | Remediation |",
           "|---|---|---|---|---|---|"]
    for e in rows:
        cell = "" if e.get("cell_index") is None else str(e.get("cell_index"))
        out.append("| {event} | `{nb}` | {cell} | {rule} | `{target}` | {rem} |".format(
            event=e.get("event", ""),
            nb=e.get("notebook_path", "") or "-",
            cell=cell,
            rule=e.get("rule", "") or "-",
            target=str(e.get("target", "")).replace("|", "\\|") or "-",
            rem=str(e.get("remediation", "")).replace("|", "\\|") or "-",
        ))
    return "\n".join(out) + "\n"


# ── AST gate ───────────────────────────────────────────────────────────
@dataclass
class Violation:
    rule: str
    detail: str
    target: str = ""
    lineno: int = 0
    remediation: str = ""


@dataclass
class ScanContext:
    """Alias and constant state carried across the cells of one notebook run.

    ``aliases`` maps a name to the dotted chain it stands for (``o`` ->
    ``("os",)`` after ``import os as o``; ``fs`` -> ``("dbutils", "fs")``
    after ``fs = dbutils.fs``). ``constants`` maps a name bound exactly once
    to the string-valued node it was bound to (``None`` = rebound, unknown).
    ``identities`` are names bound by a plain ``import name`` of a watched
    module; ``tainted`` are names that were ever bound to a watched module,
    protected root, Spark object or dangerous builtin. A tainted name that is
    neither an alias nor an identity any more (rebound to something the gate
    cannot resolve) is refused wherever it is used.
    """

    aliases: Dict[str, Tuple[str, ...]] = field(default_factory=dict)
    constants: Dict[str, Optional[ast.AST]] = field(default_factory=dict)
    identities: Set[str] = field(default_factory=set)
    tainted: Set[str] = field(default_factory=set)
    # Names bound by ``import m`` of a module the gate has no rules for
    # (``platform``, ``numpy``): a receiver the gate counts as resolved.
    imported: Set[str] = field(default_factory=set)
    # Names bound by ``def`` in any cell (a callable ``.pipe()`` argument).
    functions: Set[str] = field(default_factory=set)
    # Names bound once to an RDD-producing chain (``rdd = sc.parallelize(..)``).
    rdd_names: Set[str] = field(default_factory=set)
    # Every name bound anywhere in the run (assignment, import, def, parameter,
    # loop / with / except target). A receiver the run never bound is a name
    # the gate cannot account for (``thing.open(p)``, ``thing.pipe(fn)``).
    bound: Set[str] = field(default_factory=set)
    # Resolved roots of the imported modules the gate has no rules for
    # (``import helpers as h`` -> ``helpers``): their ``_private`` attributes
    # are refused like those of a gated module.
    modules: Set[str] = field(default_factory=set)

    def forget(self, name: str) -> None:
        """``name`` is (re)bound in the current cell: drop what it stood for."""
        self.bound.add(name)
        self.aliases.pop(name, None)
        self.identities.discard(name)
        self.imported.discard(name)
        self.functions.discard(name)
        self.rdd_names.discard(name)
        self.constants[name] = None

    def is_bound(self, name: str) -> bool:
        return name in self.bound or name in self.aliases or name in self.identities or name in self.imported

    def is_unresolved_taint(self, name: str) -> bool:
        return name in self.tainted and name not in self.aliases and name not in self.identities

    def resolve(self, chain: Sequence[str]) -> List[str]:
        if chain and chain[0] in self.aliases:
            return list(self.aliases[chain[0]]) + list(chain[1:])
        return list(chain)


def _literal_str(node: Optional[ast.AST]) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _joined_literal_head(node: ast.AST) -> Optional[str]:
    """Leading literal text of an f-string / ``"lit" + x`` concatenation."""
    if isinstance(node, ast.JoinedStr):
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                return part.value
            return ""
        return ""
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _joined_literal_head(node.left) if not isinstance(node.left, ast.Constant) \
            else _literal_str(node.left)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
            and node.func.attr == "format":
        return _literal_str(node.func.value)
    return None


def _is_stringish(node: ast.AST) -> bool:
    return _literal_str(node) is not None or _joined_literal_head(node) is not None


def _is_str_sequence(node: ast.AST) -> bool:
    """``["/etc", "passwd"]`` / ``("a", "b")``: a literal sequence of strings (``sep.join(parts)`` folds)."""
    return isinstance(node, (ast.List, ast.Tuple)) and bool(node.elts) \
        and all(_literal_str(e) is not None for e in node.elts)


def _attr_chain(node: ast.AST) -> List[str]:
    """``a.b.c`` -> ["a", "b", "c"]; calls in the chain are skipped (``df.write.mode(..).parquet``)."""
    parts: List[str] = []
    cur = node
    while True:
        if isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        elif isinstance(cur, ast.Call):
            cur = cur.func
        elif isinstance(cur, ast.Name):
            parts.append(cur.id)
            break
        else:
            break
    parts.reverse()
    return parts


def _pure_chain(node: ast.AST) -> Optional[List[str]]:
    """``a.b.c`` -> ["a", "b", "c"]; ``None`` when the chain contains a call or subscript."""
    parts: List[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if not isinstance(cur, ast.Name):
        return None
    parts.append(cur.id)
    parts.reverse()
    return parts


def _module_root(name: str) -> str:
    return name.split(".", 1)[0]


def _is_dunder(name: str) -> bool:
    return len(name) > 4 and name.startswith("__") and name.endswith("__")


def _magic_violation(source: str) -> Optional["Violation"]:
    """Violation for the first ``%magic`` / ``%%cell-magic`` / ``!command``
    line in a cell body that does not parse as Python, or ``None``.

    Such a cell can never be ``exec``'d (the line is a ``SyntaxError``), so
    this only turns the error into a logged refusal. A continuation line that
    merely starts with the ``%`` operator inside a cell that is *already*
    broken is reported the same way; it would not have run either.
    """
    for lineno, line in enumerate(source.split("\n"), start=1):
        m = _MAGIC_LINE_RE.match(line)
        if not m:
            continue
        marker, word = m.group(1), (m.group(2) or "")
        if marker == "!":
            target = "!" + (word or "<command>")
            return Violation(rule=RULE_OS_PROCESS, lineno=lineno, target=target,
                             detail=f"shell escape line {target!r} inside a code cell",
                             remediation=_REM_PROC)
        target = marker + word
        if word.split(".", 1)[0] in _SHELL_MAGICS:
            return Violation(rule=RULE_OS_PROCESS, lineno=lineno, target=target,
                             detail=f"shell / package magic {target!r} inside a code cell",
                             remediation=_REM_PROC)
        return Violation(rule=RULE_IPYTHON_ESCAPE, lineno=lineno, target=target,
                         detail=f"IPython magic {target!r} inside a code cell",
                         remediation=_REM_IPYTHON)
    return None


def _is_abs_path(path: str) -> bool:
    """POSIX-absolute, home-relative (``~``), URI (``scheme://``) or host-absolute path.

    Notebooks run on Linux clusters, so a leading ``/`` is absolute even when
    this module is imported on Windows (where ``os.path.isabs`` disagrees);
    Windows drive / UNC forms are absolute even when checked on Linux.
    """
    return path.startswith(("/", "~")) or "://" in path or bool(_WINDOWS_PATH_RE.match(path)) \
        or os.path.isabs(path)


def _is_local_path(path: str) -> bool:
    """A literal that names the cluster's local filesystem: POSIX-absolute
    (``/etc``, ``/dbfs``, ``/Workspace``, ``/tmp``, ``/Volumes``), ``~``, a
    Windows drive / UNC path or a ``file:`` URI. Object-storage URIs
    (``oci://``, ``abfss://``, ``s3://``, ...) and relative paths are not."""
    p = path.strip()
    return p.startswith(("/", "~")) or bool(_WINDOWS_PATH_RE.match(p)) or bool(_FILE_URI_RE.match(p))


def _local_path_for_check(path: str) -> str:
    """``file:///tmp/x`` -> ``/tmp/x`` so the sandbox-prefix comparison sees the path."""
    p = path.strip()
    m = _FILE_URI_RE.match(p)
    return "/" + p[m.end():] if m else p


def _format_field_escape(template: str) -> Optional[str]:
    """First ``str.format`` replacement field of ``template`` that walks a
    refused dunder / frame attribute (``{0.__class__.__mro__}``), with its
    braces, or ``None``. Honours ``_DUNDER_ALLOW``; index steps (``[key]``)
    are item lookups, not attribute access. Nested fields inside a format
    spec are formatted with the same arguments and are walked too.
    """
    try:
        parsed = list(string.Formatter().parse(template))
    except ValueError:
        return None   # str.format raises the same error before evaluating anything
    for _literal, field_name, format_spec, _conversion in parsed:
        if field_name is None:
            continue
        steps_from = len(field_name)
        for i, ch in enumerate(field_name):
            if ch in ".[":
                steps_from = i
                break
        for m in _FORMAT_FIELD_STEP_RE.finditer(field_name, steps_from):
            attr = m.group(1)
            if attr is not None and ((_is_dunder(attr) and attr not in _DUNDER_ALLOW) or attr in _FRAME_ATTRS):
                return "{" + field_name + "}"
        if format_spec and "{" in format_spec:
            nested = _format_field_escape(format_spec)
            if nested is not None:
                return nested
    return None


def _import_chain(module_name: str) -> Tuple[str, ...]:
    """Dotted import name as a chain, with ``posix`` / ``nt`` canonicalised to ``os``."""
    parts = module_name.split(".")
    if parts and parts[0] in _OS_EQUIVALENT_MODULES:
        parts[0] = "os"
    return tuple(parts)


def _module_level_statements(tree: ast.Module) -> Iterable[ast.stmt]:
    """Statements that run in the cell's own namespace: the top level and the
    bodies of compound statements that do not open a scope (``for`` /
    ``while`` / ``if`` / ``with`` / ``try``). Function and class bodies are
    not descended into: a binding there is a different name."""
    stack: List[ast.stmt] = list(reversed(tree.body))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        children: List[ast.stmt] = []
        for attr in ("body", "orelse", "finalbody"):
            children.extend(getattr(node, attr, None) or [])
        for handler in getattr(node, "handlers", None) or []:
            children.extend(handler.body)
        stack.extend(reversed(children))


def _is_prohibited_module(name: str, policy: SandboxPolicy) -> Optional[Tuple[str, str]]:
    root = _module_root(name)
    if root in _PROCESS_MODULES or name.startswith("concurrent.futures.process"):
        return RULE_IMPORT_PROCESS, root if root in _PROCESS_MODULES else "concurrent.futures.process"
    if root in _INDIRECT_MODULES:
        return RULE_INDIRECT, root
    if root in _EXEC_MODULES or root in _CODE_LOAD_MODULES:
        return RULE_BUILTIN_EXEC, root
    if root in _JVM_BRIDGE_MODULES:
        return RULE_POLICY_TAMPER, root
    if root in _IPYTHON_MODULES:
        return RULE_IPYTHON_ESCAPE, root
    if root in _NETWORK_MODULES or name in _NETWORK_MODULES:
        if policy.allow_network:
            return None
        return RULE_IMPORT_NETWORK, root if root in _NETWORK_MODULES else name
    if root.startswith("_") and root != "__future__":
        # Private interpreter modules (_io, _pickle, _posixsubprocess, _ctypes, ...)
        # are the unguarded twins of the public ones above.
        return RULE_INDIRECT, root
    return None


def _first_arg(call: ast.Call, kw: Sequence[str]) -> Optional[ast.AST]:
    if call.args:
        return call.args[0]
    for k in call.keywords:
        if k.arg in kw:
            return k.value
    return None


def _sql_write_target(sql: str) -> Tuple[Optional[str], bool, List[str]]:
    """Return (object name or None, is_schema_statement, storage paths).

    ``object name`` is None when the statement is not a write/DDL statement.
    ``storage paths`` are every ``LOCATION`` and ``OPTIONS (path ...)`` value.
    """
    text = _SQL_COMMENT_RE.sub(" ", sql).strip()
    if not text or not _is_sql_write_verb(text):
        return None, False, []
    m = _SQL_WRITE_RE.match(text)
    locations = [mm.group(2) for mm in _SQL_LOCATION_RE.finditer(text)]
    locations += [mm.group(2) for mm in _SQL_OPTIONS_PATH_RE.finditer(text)]
    if not m:
        if _SQL_WRITE_VERB_RE.match(text):
            # A write verb we recognise but could not parse a target for.
            return "", False, locations
        return None, False, locations
    return m.group(1), bool(_SQL_SCHEMA_STMT_RE.match(text)), locations


_REM_ENV = "Pass values through dbutils.widgets / job parameters instead of reading the process environment."
_REM_PROC = "Shell/process execution is not available inside the sandbox."
_REM_TAMPER = ("The policy, the compat shims and the interpreter modules are read-only for notebook code; "
               "change the sandbox through AIDP_SANDBOX_* / AIDP_NOTEBOOK_POLICY_ALLOW after review.")
_REM_INDIRECT = ("Indirect access to the interpreter (importlib, builtins / __builtins__, globals() / locals() / "
                 "vars(), sys.modules, getattr with a dynamic name, frames, a rebound alias) is refused; "
                 "import the module you need directly and call it by name so the gate can see it.")
_REM_DUNDER = ("Dunder and frame introspection chains (__subclasses__, __globals__, __dict__, __code__, f_globals, "
               "tb_frame, ...) are refused; use the public API of the object.")
_REM_FORMAT = ("Write the format template as a literal in the notebook (or a name bound once to one): a template "
               "built at run time can address attributes of the formatted objects (__class__.__mro__, "
               "__globals__, ...), so an unresolvable template with run-time arguments is refused.")
_REM_READ_PATH = ("Read source data from object storage (oci://...), a catalog table, a relative path or a path under "
                  "the sandbox prefix; a literal local-filesystem path outside it is refused.")
_REM_IPYTHON = ("The IPython shell API (get_ipython, InteractiveShell, %magics, !commands) is not available inside "
                "the sandbox; express the step in plain Python or dbutils.")
_REM_JVM = ("The Spark JVM / py4j bridge (spark._jvm, sc._jsc, df._jdf, py4j) and private Spark attributes are "
            "not available inside the sandbox; use the public PySpark API or dbutils.fs.")
_REM_DESERIALIZE = ("Deserialising bytes with pickle / marshal / shelve / dill / joblib / jsonpickle, yaml.load without "
                    "SafeLoader or torch.load without weights_only=True executes code; use a data format "
                    "(parquet, json, yaml.safe_load, weights_only=True) or list NBP-DESERIALIZE in "
                    "AIDP_NOTEBOOK_POLICY_ALLOW after review.")
_REM_VALUE = ("A gated module, interpreter root or Spark object may only be the root of an attribute chain, the "
              "whole right-hand side of a plain name assignment or the object argument of getattr / setattr / "
              "vars; handing it around as a value (list / dict element, argument, default, return value, lambda, "
              "conditional, walrus, with-item, loop iterable) hides the chain from the gate and is refused.")
_REM_SINK = ("A process / environment / introspection method name on an object the gate cannot resolve is "
             "refused; call it on the module directly so the gate can judge it, or rename your own method.")
_REM_PIPE = ("RDD.pipe(cmd) runs a shell command on the executors and is not available inside the sandbox; "
             "DataFrame.pipe(func) is fine when the argument is a function, not a string.")
_REM_CODE_LOAD = "Dependencies are installed as cluster libraries; do not load code from paths at run time."
_REM_PRIVATE = ("Private (_name) attributes of an imported module are not its public API and may re-export the "
                "interpreter modules the gate refuses; use the module's public API.")
_REM_MUTATE = ("The state of a gated module (a deserialiser's constructor registry, an interpreter table, a Spark "
               "object) is read-only for notebook code; configure it through the public API or the run's "
               "AIDP_* settings after review.")
_REM_LOADER_ARGS = ("Pass the loader's safety switch as a literal keyword the gate can see (allow_pickle=False, "
                    "weights_only=True, Loader=yaml.SafeLoader) instead of positionally or through *args / **kwargs.")
_REM_RECEIVER = ("The receiver of this call was never bound in the notebook, so the gate cannot tell what it is; "
                 "bind it in the notebook (import the library, assign the object) so the call can be judged.")


class _PolicyScanner(ast.NodeVisitor):
    def __init__(self, policy: SandboxPolicy, context: Optional[ScanContext] = None):
        self.policy = policy
        self.ctx = context if context is not None else ScanContext()
        self.violations: List[Violation] = []
        # Informational entries (``rule`` holds the POLICY_NOTES event name):
        # allowed operations the gate could not verify, for the policy log.
        self.notes: List[Violation] = []
        self._seen: set = set()
        # Node ids a more specific check has already judged (``__builtins__['open'](..)``
        # is reported as open(), not additionally as namespace access).
        self._consumed: Set[int] = set()
        # Name nodes that are the callee of a direct call (``open(p)`` vs ``map(open, ps)``).
        self._call_funcs: Set[int] = set()
        # Parent of every node in the cell (``prepare``), for position checks.
        self._parents: Dict[int, ast.AST] = {}

    def _add(self, rule: str, node: ast.AST, detail: str, target: str = "", remediation: str = ""):
        lineno = getattr(node, "lineno", 0)
        key = (rule, lineno, target)
        if key in self._seen:
            # os.environ.get(...) visits both the Call and the inner Attribute;
            # report the line once.
            return
        self._seen.add(key)
        self.violations.append(Violation(rule=rule, detail=detail, target=target,
                                         lineno=lineno, remediation=remediation))

    def _note(self, event: str, node: ast.AST, detail: str, target: str = "") -> None:
        lineno = getattr(node, "lineno", 0)
        key = (event, lineno, target)
        if key in self._seen:
            return
        self._seen.add(key)
        self.notes.append(Violation(rule=event, detail=detail, target=target, lineno=lineno))

    # -- pre-pass: bindings, aliases, constants -------------------------
    def prepare(self, tree: ast.Module) -> None:
        """Record what this cell binds so later checks can resolve names.

        A name bound more than once (anywhere in the cell) is unknown; a
        top-level ``name = <string literal / f-string / concat>`` bound once
        is a constant; ``import m as a`` / ``from m import n as a`` /
        ``a = dbutils.fs`` are aliases.
        """
        bound: Dict[str, int] = {}

        def bind(name: str) -> None:
            bound[name] = bound.get(name, 0) + 1

        def taint_assignment(targets: Sequence[ast.AST], value: Optional[ast.AST]) -> None:
            # ``x = spark`` / ``f = getattr`` / ``b = __builtins__`` / ``o = os``: the
            # target name now stands for a protected object, wherever it goes next.
            if value is None:
                return
            chain = _pure_chain(value)
            if chain is None or self.ctx.resolve(chain)[0] not in _ALIASABLE_SINGLETONS:
                return
            for t in targets:
                for elt in (t.elts if isinstance(t, (ast.Tuple, ast.List)) else [t]):
                    if isinstance(elt, ast.Name):
                        self.ctx.tainted.add(elt.id)

        defined: Set[str] = set()
        # Names read in any position other than the operand of ``sep.join(name)``:
        # a list literal bound to such a name may have been mutated in place
        # (``p[0] = ..``, ``p.append(..)``, ``p.insert(..)``, ``mutate(p)``,
        # ``q = p; q[0] = ..``), so it is no longer the literal it was bound to.
        loaded_elsewhere: Set[str] = set()
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                self._parents[id(child)] = node
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                bind(node.id)
            elif isinstance(node, ast.Name) and not self._is_join_operand(node):
                loaded_elsewhere.add(node.id)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                bind(node.name)
                if not isinstance(node, ast.ClassDef):
                    defined.add(node.name)
            elif isinstance(node, ast.arg):
                bind(node.arg)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or _module_root(alias.name)
                    bind(local)
                    if _module_root(alias.name) in _WATCHED_MODULES:
                        self.ctx.tainted.add(local)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name != "*":
                        bind(alias.asname or alias.name)
                        root = _module_root(node.module or "")
                        if root in _WATCHED_MODULES and root != "aidp_compat":
                            # (compat helpers keep their own names; _check_compat_import governs them)
                            self.ctx.tainted.add(alias.asname or alias.name)
            elif isinstance(node, ast.ExceptHandler) and node.name:
                bind(node.name)
            elif isinstance(node, ast.Global):
                for n in node.names:
                    bind(n)
            elif isinstance(node, ast.Assign):
                taint_assignment(node.targets, node.value)
            elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
                taint_assignment([node.target], node.value)
        for name in bound:
            self.ctx.forget(name)
        self.ctx.functions.update(n for n in defined if bound.get(n, 0) == 1)
        for node in _module_level_statements(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or _module_root(alias.name)
                    if bound.get(local, 0) != 1:
                        continue
                    chain = _import_chain(alias.name)
                    if chain[0] not in _WATCHED_MODULES:
                        self.ctx.imported.add(local)            # import platform / import pandas as pd
                        self.ctx.modules.add(chain[0])
                    if alias.asname:
                        self.ctx.aliases[local] = chain
                    elif chain[0] != local:
                        self.ctx.aliases[local] = chain[:1]      # import posix -> an alias of os
                    else:
                        self.ctx.identities.add(local)
            elif isinstance(node, ast.ImportFrom) and node.module:
                if _module_root(node.module) == "aidp_compat":
                    continue  # helpers keep their own names (dbutils, translate_path, safe_*)
                if _import_chain(node.module)[0] not in _WATCHED_MODULES:
                    self.ctx.modules.add(_import_chain(node.module)[0])
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    local = alias.asname or alias.name
                    if bound.get(local, 0) == 1:
                        self.ctx.aliases[local] = _import_chain(node.module) + (alias.name,)
            elif isinstance(node, ast.Assign) and len(node.targets) == 1 \
                    and isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
                if bound.get(name, 0) != 1:
                    continue
                chain = _pure_chain(node.value)
                if chain is not None and (len(chain) >= 2 or self.ctx.resolve(chain)[0] in _ALIASABLE_SINGLETONS):
                    resolved = tuple(self.ctx.resolve(chain))
                    self.ctx.aliases[name] = resolved
                    if resolved[0] in _ALIASABLE_SINGLETONS:
                        self.ctx.tainted.add(name)
                    if isinstance(node.value, ast.Name):
                        # ``f = open`` is followed as an alias; the bare reference
                        # on the right-hand side is not also a loose builtin.
                        self._consumed.add(id(node.value))
                elif _is_stringish(node.value) or self._path_ctor_arg(node.value) is not None \
                        or _is_str_sequence(node.value) or self._fold_literal(node.value) is not None:
                    # a literal, f-string / concat, Path("x"), ["a", "b"], "/".join([..]) or os.path.join(..)
                    self.ctx.constants[name] = node.value
                if isinstance(node.value, ast.Call):
                    vchain = self._chain(node.value.func)
                    if vchain and (vchain[0] in _SPARK_ROOTS or any(p in _RDD_CHAIN_ATTRS for p in vchain)):
                        self.ctx.rdd_names.add(name)         # rdd = sc.parallelize(..).map(..)
        for name in loaded_elsewhere:
            # A mutable literal is folded only while its name is used for nothing
            # but ``sep.join(name)``; any other use (this or an earlier cell's
            # binding) may have changed it, and the stale literal must not be
            # what the sandbox check sees (fail closed: the join is then dynamic).
            if isinstance(self.ctx.constants.get(name), (ast.List, ast.Set, ast.Dict)):
                self.ctx.constants[name] = None

    def _is_join_operand(self, node: ast.Name) -> bool:
        """``sep.join(node)``: the one read of a list literal that cannot mutate it."""
        parent = self._parents.get(id(node))
        return isinstance(parent, ast.Call) and isinstance(parent.func, ast.Attribute) \
            and parent.func.attr == "join" and len(parent.args) == 1 and parent.args[0] is node

    def _resolve_value(self, node: Optional[ast.AST]) -> Optional[ast.AST]:
        """Follow a plain name to the string node it was bound to, if known."""
        if isinstance(node, ast.Name):
            return self.ctx.constants.get(node.id)
        return node

    def _resolve_literal(self, node: Optional[ast.AST]) -> Optional[str]:
        """Literal text behind ``node``: a constant, a name bound once, ``Path("x")``,
        ``"a" + "b"``, ``"/".join(["a", "b"])`` or ``os.path.join("a", "b")`` over literals."""
        node = self._resolve_value(node)
        if node is None:
            return None
        arg = self._path_ctor_arg(node)
        if arg is not None:
            node = self._resolve_value(arg)
        return self._fold_literal(node)

    def _chain(self, node: ast.AST) -> List[str]:
        return self.ctx.resolve(_attr_chain(node))

    def _path_ctor_arg(self, node: ast.AST) -> Optional[ast.AST]:
        """``Path("x")`` / ``pathlib.Path("x")`` -> the path argument node."""
        if isinstance(node, ast.Call):
            chain = self._chain(node.func)
            if chain and chain[-1] in ("Path", "PurePath", "PosixPath") and \
                    (len(chain) == 1 or chain[0] == "pathlib"):
                return _first_arg(node, ()) if node.args else None
        return None

    def _is_protected_root(self, chain: Sequence[str]) -> bool:
        """Interpreter / compat / shim roots (after alias resolution)."""
        return bool(chain) and chain[0] in _PROTECTED_ROOTS

    # -- indirection: builtins namespace, getattr routes, chain rules ----
    def _call_name(self, func: ast.AST) -> Optional[str]:
        """Single name a call target stands for after alias resolution (``g`` -> ``globals``)."""
        if isinstance(func, ast.Name):
            resolved = self.ctx.resolve([func.id])
            return resolved[0] if len(resolved) == 1 else None
        return None

    def _is_namespace_call(self, node: ast.AST) -> bool:
        """``globals()`` / ``locals()`` / ``vars()`` without arguments: the frame namespace."""
        return isinstance(node, ast.Call) and not node.args and not node.keywords \
            and self._call_name(node.func) in _NAMESPACE_BUILTINS

    def _is_builtins_namespace(self, node: ast.AST) -> bool:
        """True when ``node`` evaluates to the builtins module or its dict.

        ``__builtins__``, ``builtins`` (also through an alias),
        ``globals()["__builtins__"]`` / ``locals()[..]`` / ``vars()[..]``,
        ``<ns>.__dict__``, ``vars(<ns>)`` and ``getattr(<ns>, "__dict__")``.
        """
        if isinstance(node, ast.Name):
            return self.ctx.resolve([node.id])[0] in _BUILTINS_NAMESPACE_ROOTS
        if isinstance(node, ast.Attribute):
            return node.attr == "__dict__" and self._is_builtins_namespace(node.value)
        if isinstance(node, ast.Subscript):
            return _literal_str(node.slice) == "__builtins__" and self._is_namespace_call(node.value)
        if isinstance(node, ast.Call):
            fn = self._call_name(node.func)
            if fn == "vars" and len(node.args) == 1:
                return self._is_builtins_namespace(node.args[0])
            if fn == "getattr" and len(node.args) >= 2 and _literal_str(node.args[1]) == "__dict__":
                return self._is_builtins_namespace(node.args[0])
        return False

    def _route_nodes(self, node: ast.AST) -> List[ast.AST]:
        """Nodes that make up a builtins-namespace route (to mark as consumed)."""
        out: List[ast.AST] = []
        cur: Optional[ast.AST] = node
        while cur is not None:
            out.append(cur)
            if isinstance(cur, (ast.Subscript, ast.Attribute)):
                cur = cur.value
            elif isinstance(cur, ast.Call):
                out.append(cur.func)
                cur = cur.args[0] if cur.args else None
            else:
                break
        return out

    def _consume(self, nodes: Iterable[ast.AST]) -> None:
        for n in nodes:
            self._consumed.add(id(n))

    def _consume_base(self, func: ast.AST) -> None:
        """Mark the calls and the root name under an attribute chain as judged."""
        cur = func
        while True:
            if isinstance(cur, ast.Attribute):
                cur = cur.value
            elif isinstance(cur, ast.Call):
                self._consumed.add(id(cur))
                cur = cur.func
            elif isinstance(cur, ast.Name):
                self._consumed.add(id(cur))
                return
            else:
                return

    def _indirect_route(self, func: ast.AST) -> Optional[Tuple[List[str], str, List[ast.AST], bool]]:
        """Resolve a call target reached through the builtins namespace or ``getattr``.

        Returns ``(chain, route text, nodes to consume, via_builtins)``:
        ``__builtins__["open"]`` -> ``(["open"], ...)``; ``getattr(os, "system")``
        -> ``(["os", "system"], ...)``. ``chain`` is empty when the name is not
        a literal. ``None`` when ``func`` is an ordinary name or attribute.
        """
        if isinstance(func, ast.Subscript) and self._is_builtins_namespace(func.value):
            key = _literal_str(func.slice)
            text = "__builtins__[<dynamic>]" if key is None else f"__builtins__[{key!r}]"
            return ([key] if key is not None else []), text, self._route_nodes(func), True
        if isinstance(func, ast.Attribute) and self._is_builtins_namespace(func.value):
            return [func.attr], f"__builtins__.{func.attr}", self._route_nodes(func), True
        if isinstance(func, ast.Call) and self._call_name(func.func) == "getattr" and len(func.args) >= 2:
            target, key = func.args[0], _literal_str(func.args[1])
            if self._is_builtins_namespace(target):
                text = "getattr(__builtins__, <dynamic>)" if key is None else f"getattr(__builtins__, {key!r})"
                return ([key] if key is not None else []), text, self._route_nodes(func), True
            base = self._chain(target) if isinstance(target, (ast.Name, ast.Attribute, ast.Call)) else []
            if key is not None and base:
                # The inner getattr(...) is still visited (protected root / dynamic
                # name / dunder checks); the outer call is checked as base.key(...).
                return base + [key], f"getattr({'.'.join(base)}, {key!r})", [], False
        return None

    def _attr_rule(self, chain: Sequence[str]) -> Optional[Tuple[str, str, str, str]]:
        """Chain-level refusal ``(rule, target, detail, remediation)`` or ``None``.

        Applied to every attribute chain, to aliases that stand for one
        (``from pickle import loads``) and to ``getattr(x, "literal")``.
        """
        if len(chain) < 2:
            return None
        root = chain[0]
        for i, part in enumerate(chain[1:], start=1):
            if (_is_dunder(part) and part not in _DUNDER_ALLOW) or part in _FRAME_ATTRS:
                target = ".".join(chain[:i + 1])
                return RULE_DUNDER_ESCAPE, target, f"introspection chain {target}", _REM_DUNDER
        for i, part in enumerate(chain[1:], start=1):
            if part in _JVM_BRIDGE_ATTRS or (root in _SPARK_ROOTS and part.startswith("_")):
                target = ".".join(chain[:i + 1])
                return RULE_POLICY_TAMPER, target, f"Spark JVM bridge access {target}", _REM_JVM
            if root in _PROTECTED_ROOTS and part.startswith("_"):
                target = ".".join(chain[:i + 1])
                return RULE_POLICY_TAMPER, target, f"access to a private attribute of {root} ({target})", _REM_TAMPER
            if root in _WATCHED_MODULES and part.startswith("_") and not _is_dunder(part):
                # pickle._loads, torch.serialization._load, yaml._x: the unguarded twin of the public API.
                target = ".".join(chain[:i + 1])
                rule = RULE_DESERIALIZE if root in _DESERIALIZE_MODULES else RULE_INDIRECT
                return rule, target, f"access to a private attribute of {root} ({target})", \
                    _REM_DESERIALIZE if rule == RULE_DESERIALIZE else _REM_INDIRECT
            if part in _YAML_HOOK_ATTRS:
                target = ".".join(chain[:i + 1])
                return RULE_DESERIALIZE, target, f"{target}() registers a constructor that runs while parsing", \
                    _REM_DESERIALIZE
            if part in ("Unpickler", "_Unpickler"):
                target = ".".join(chain[:i + 1])
                return RULE_DESERIALIZE, target, f"deserialisation via {target}", _REM_DESERIALIZE
            reroot = part.lstrip("_") if not _is_dunder(part) else part
            if reroot in _REROOT_NAMES and reroot != root and not (root in _SPARK_ROOTS and reroot in _SPARK_ROOTS):
                # shutil.os.system / pd.io.common.os.environ / self.spark._jvm, and the private
                # re-exports tempfile._os / random._os: the chain is re-rooted at the module it
                # names and the module rules apply from there (pyspark.sql.SparkSession is
                # already judged by the Spark rules).
                return self._attr_rule([reroot] + list(chain[i + 1:]))
        # Module rules. One table for every entry point: a direct attribute
        # chain, an alias that stands for one (``from os import system``,
        # ``import posix as p``), ``getattr(mod, "literal")`` and an import.
        if root in _PROCESS_ROOT_REFUSED:
            target = f"{root}.{chain[1]}"
            return RULE_OS_PROCESS, target, f"access to the process module attribute {target}", _REM_PROC
        if root in _CODE_LOAD_ROOT_REFUSED or (root == "site" and chain[1] in _SITE_CODE_LOAD_ATTRS):
            target = f"{root}.{chain[1]}"
            return RULE_BUILTIN_EXEC, target, f"{target}() loads code from a path at run time", _REM_CODE_LOAD
        if root == "os":
            if chain[1] in _OS_ENV_ATTRS:
                return RULE_OS_ENVIRON, f"os.{chain[1]}", f"access to os.{chain[1]}", _REM_ENV
            if chain[1] in _OS_PROCESS_ATTRS or chain[1].startswith(_OS_PROCESS_PREFIXES):
                return RULE_OS_PROCESS, f"os.{chain[1]}", f"access to os.{chain[1]}", _REM_PROC
        if root == "shutil" and chain[1] == "rmtree":
            return RULE_SHUTIL_RMTREE, "shutil.rmtree", "access to shutil.rmtree", \
                "Use dbutils.fs.rm on a sandbox path instead."
        if root in _INDIRECT_MODULES:
            return RULE_INDIRECT, f"{root}.{chain[1]}", f"access to {root}.{chain[1]}", _REM_INDIRECT
        if root == "asyncio" and chain[1] in _ASYNCIO_PROCESS_ATTRS:
            return RULE_OS_PROCESS, f"asyncio.{chain[1]}", f"access to asyncio.{chain[1]}", _REM_PROC
        if chain[-1] in _ASYNCIO_LOOP_PROCESS_ATTRS:
            target = ".".join(chain)
            return RULE_OS_PROCESS, target, f"{target}() starts a subprocess through the event loop", _REM_PROC
        if root == "aidp_compat":
            target = ".".join(chain[:3])
            return RULE_POLICY_TAMPER, target, f"attribute access on the aidp_compat package ({target})", _REM_TAMPER
        if root in _SPARK_ROOTS and chain[-1] in _SPARK_CODE_LOAD_ATTRS:
            target = ".".join(chain)
            return RULE_BUILTIN_EXEC, target, f"{target}() loads code into the session", _REM_CODE_LOAD
        if root in _SPARK_ROOTS and chain[-1] in _SPARK_JVM_UDF_ATTRS:
            target = ".".join(chain)
            return RULE_POLICY_TAMPER, target, f"{target}() registers a JVM class", _REM_JVM
        if root == "get_ipython":
            target = ".".join(chain)
            if chain[-1] in _IPYTHON_SHELL_ATTRS:
                return RULE_OS_PROCESS, target, f"IPython shell escape {target}", _REM_PROC
            return RULE_IPYTHON_ESCAPE, target, f"IPython shell object access {target}", _REM_IPYTHON
        if root == "sys" and chain[1] in _SYS_INDIRECT_ATTRS:
            return RULE_INDIRECT, f"sys.{chain[1]}", f"access to sys.{chain[1]}", _REM_INDIRECT
        if root == "gc" and chain[1] in _GC_INDIRECT_ATTRS:
            return RULE_INDIRECT, f"gc.{chain[1]}", f"live object graph access via gc.{chain[1]}", _REM_INDIRECT
        if root == "inspect" and chain[1] in _INSPECT_FRAME_ATTRS:
            return RULE_INDIRECT, f"inspect.{chain[1]}", f"frame access via inspect.{chain[1]}", _REM_INDIRECT
        if root == "types" and chain[1] in _TYPES_EXEC_ATTRS:
            return RULE_BUILTIN_EXEC, f"types.{chain[1]}", f"code object construction via types.{chain[1]}", \
                "Dynamic code execution is refused; inline the code as a cell."
        if any(part in _PROCESS_POOL_NAMES for part in chain):
            return RULE_IMPORT_PROCESS, "concurrent.futures.ProcessPoolExecutor", \
                "process pool executor forks worker processes", \
                "Process and FFI modules are not available inside the sandbox; use ThreadPoolExecutor."
        if root == "asyncio" and chain[1] in _ASYNCIO_NETWORK_ATTRS and not self.policy.allow_network:
            return RULE_IMPORT_NETWORK, f"asyncio.{chain[1]}", f"network access via asyncio.{chain[1]}", \
                self._import_remediation(RULE_IMPORT_NETWORK)
        if root in _PICKLE_MODULES and chain[1] not in _PICKLE_DUMP_ALLOW:
            # deny-by-default: everything but the dump side constructs objects from bytes
            return RULE_DESERIALIZE, f"{root}.{chain[1]}", f"deserialisation via {root}.{chain[1]}", _REM_DESERIALIZE
        if root in _DESERIALIZE_ATTRS and chain[1] in _DESERIALIZE_ATTRS[root]:
            return RULE_DESERIALIZE, f"{root}.{chain[1]}", f"deserialisation via {root}.{chain[1]}", _REM_DESERIALIZE
        if root == "yaml" and (chain[1] in _YAML_REFUSED_ATTRS or chain[1].startswith(_YAML_REFUSED_PREFIXES)):
            target = f"yaml.{chain[1]}"
            return RULE_DESERIALIZE, target, f"{target} is an unsafe yaml loader / constructor entry point", \
                _REM_DESERIALIZE
        if root == "yaml" and chain[1] == "load":
            return RULE_DESERIALIZE, "yaml.load", "yaml.load without a safe Loader", _REM_DESERIALIZE
        if root == "torch" and any(part in _TORCH_HOOK_ATTRS for part in chain[1:]):
            target = ".".join(chain)
            return RULE_DESERIALIZE, target, f"{target}() widens what weights_only=True may unpickle", _REM_DESERIALIZE
        if root == "torch" and "load" in chain[1:]:
            target = ".".join(chain)
            return RULE_DESERIALIZE, target, f"{target} without weights_only=True", _REM_DESERIALIZE
        if chain[-1] == "read_pickle":
            target = ".".join(chain)
            return RULE_DESERIALIZE, target, f"deserialisation via {target}", _REM_DESERIALIZE
        return None

    def _add_rule(self, node: ast.AST, hit: Optional[Tuple[str, str, str, str]]) -> bool:
        if hit is None:
            return False
        rule, target, detail, remediation = hit
        before = len(self.violations)
        self._add(rule, node, detail, target=target, remediation=remediation)
        return len(self.violations) > before

    # -- imports ------------------------------------------------------
    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if _module_root(alias.name) == "aidp_compat":
                self._add(RULE_POLICY_TAMPER, node, f"import of '{alias.name}' binds a compat module object",
                          target=alias.name, remediation=_REM_TAMPER)
                continue
            hit = _is_prohibited_module(alias.name, self.policy)
            if hit:
                rule, mod = hit
                self._add(rule, node, f"import of prohibited module '{alias.name}'", target=mod,
                          remediation=self._import_remediation(rule))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        mod = node.module or ""
        names = {a.name for a in node.names}
        if _module_root(mod) == "aidp_compat":
            self._check_compat_import(node, mod, names)
            self.generic_visit(node)
            return
        hit = _is_prohibited_module(mod, self.policy) if mod else None
        if hit:
            rule, root = hit
            self._add(rule, node, f"import from prohibited module '{mod}'", target=root,
                      remediation=self._import_remediation(rule))
        else:
            chain = list(_import_chain(mod)) if mod else []       # from posix import system -> os.system
            if mod == "http" and "client" in names and not self.policy.allow_network:
                self._add(RULE_IMPORT_NETWORK, node, "import of prohibited module 'http.client'",
                          target="http.client", remediation=self._import_remediation(RULE_IMPORT_NETWORK))
            if chain == ["os"] and "*" in names:
                self._add(RULE_OS_ENVIRON, node, "star import of os brings os.environ into the namespace",
                          target="os.*", remediation=_REM_ENV)
            if chain == ["sys"] and "*" in names:
                self._add(RULE_INDIRECT, node, "import of sys.modules", target="sys.modules",
                          remediation=_REM_INDIRECT)
            # Every name that stands for a gated chain (``from os import system``,
            # ``from pickle import loads``, ``from inspect import currentframe``,
            # ``from concurrent.futures import ProcessPoolExecutor``) is judged
            # as that chain at import time, by the same table as attribute access.
            for name in sorted(names - {"*"}):
                if (mod, name) in (("yaml", "load"), ("torch", "load")):
                    continue  # judged at the call (Loader= / weights_only=)
                if chain and not self._add_rule(node, self._attr_rule(chain + [name])) \
                        and name.startswith("_") and not _is_dunder(name) and chain[0] != "__future__":
                    # from tempfile import _os / from mymod import _helper: a private name of
                    # any module is not its public API (the gated modules are judged above)
                    self._add(RULE_INDIRECT, node, f"import of the private name {mod}.{name}",
                              target=f"{mod}.{name}", remediation=_REM_PRIVATE)
            if "*" in names and chain != ["os"] and _module_root(mod) in _STAR_IMPORT_REFUSED:
                self._add(RULE_INDIRECT, node, f"star import of {mod} binds its API under unqualified names",
                          target=mod + ".*", remediation=_REM_INDIRECT)
        self.generic_visit(node)

    def _check_compat_import(self, node: ast.AST, mod: str, names: Set[str]) -> None:
        parts = mod.split(".")
        sub = parts[1] if len(parts) > 1 else ""
        if sub == "notebook_policy":
            self._add(RULE_POLICY_TAMPER, node, "import from aidp_compat.notebook_policy",
                      target=mod, remediation=_REM_TAMPER)
            return
        if "*" in names:
            self._add(RULE_POLICY_TAMPER, node, f"star import from {mod} binds the policy API",
                      target=mod + ".*", remediation=_REM_TAMPER)
            return
        if sub and sub not in _COMPAT_INTERNAL_MODULES:
            return  # helper modules (safe_io functions, path_translator, ...) are fine by name
        for name in sorted(names):
            if name in _COMPAT_PROTECTED_NAMES or name.startswith("_"):
                self._add(RULE_POLICY_TAMPER, node, f"import of {mod}.{name}", target=f"{mod}.{name}",
                          remediation=_REM_TAMPER)

    @staticmethod
    def _import_remediation(rule: str) -> str:
        if rule == RULE_IMPORT_NETWORK:
            return ("Network access is off for this run. Set AIDP_SANDBOX_ALLOW_NETWORK=1 "
                    "after review, or remove the network call.")
        if rule == RULE_INDIRECT:
            return _REM_INDIRECT
        return "Process and FFI modules are not available inside the sandbox; remove the import."

    # -- attribute access --------------------------------------------
    def visit_Attribute(self, node: ast.Attribute):
        if id(node) in self._consumed:
            self.generic_visit(node)
            return
        chain = self._chain(node)
        if len(chain) < 2:
            # Attribute on an expression the chain cannot name (``().__class__``,
            # ``x[0].__dict__``): the attribute itself is still judged.
            self._add_rule(node, self._attr_rule(["<expr>", node.attr]))
            if not self._receiver_resolved(node):
                self._check_sink_attr(node, "<expr>")
        else:
            if not self._add_rule(node, self._attr_rule(chain)):
                # the rule table did not judge the chain: the private-attribute and
                # sink rules on receivers the gate cannot vouch for apply
                self._check_private_module_attr(node, chain)
                if not self._receiver_resolved(node):
                    self._check_sink_attr(node, ".".join(chain[:-1]))
        self.generic_visit(node)

    def _check_private_module_attr(self, node: ast.AST, chain: Sequence[str]) -> None:
        """``mymod._run(..)`` / ``np._core``: a ``_private`` (non-dunder) attribute of
        an imported module the gate has no rules for. The gated modules' private
        attributes are refused by the rule table; a module the gate does not know
        may re-export the same interpreter internals under a private name, so the
        same rule applies to every imported module."""
        if chain[0] not in self.ctx.modules:
            return
        for i, part in enumerate(chain[1:], start=1):
            if part.lstrip("_") in _REROOT_NAMES:
                return      # tempfile._os / mymod._subprocess: the re-rooting rule judges the chain
            if part.startswith("_") and not _is_dunder(part):
                target = ".".join(chain[:i + 1])
                self._add(RULE_INDIRECT, node, f"access to a private attribute of the imported module {chain[0]} "
                          f"({target})", target=target, remediation=_REM_PRIVATE)
                return

    def _receiver_resolved(self, node: ast.Attribute) -> bool:
        """True when the receiver of ``node`` is a plain name chain the gate knows:
        a module it has rules for, an import / shim alias, a Spark root, or an
        imported module the gate has no rules for when the attribute is not a
        process sink (``import mymod; mymod.system(..)`` is refused like
        ``obj.system(..)``: the module may re-export ``os``; the stdlib homonyms
        in ``_SINK_HOMONYMS`` are the exception). Call results, subscripts,
        unknown names and chains through a ``_private`` segment are not."""
        chain = self._chain(node.value)      # calls skipped: spark.sparkContext.getConf().x is still spark's
        if not chain:
            if isinstance(node.value, ast.Subscript):
                # sys.modules[k].x / __builtins__[k].x: the subscript itself is judged by the table
                inner = self._chain(node.value.value)
                return bool(inner) and inner[0] in _VALUE_GUARDED
            return False                     # lambda / conditional / literal receiver
        root = chain[0]
        if any(part.startswith("_") and not _is_dunder(part) for part in chain[1:]):
            return False                     # mod._private.system: the private segment is opaque
        if root in _VALUE_GUARDED or root in _IPYTHON_NAMES or root in _PY4J_NAMES or root in _DATAFRAME_LIB_ROOTS:
            return True                      # the rule table judges the chain
        if _pure_chain(node.value) is None:
            return False                     # call result on an unknown root: helper().system
        if root in self.ctx.aliases or root in self.ctx.identities:
            if root in self.ctx.imported:
                # import mymod: a module the gate has no rules for vouches for nothing
                return (root, node.attr) in _SINK_HOMONYMS or node.attr not in _SINK_ATTRS
            return True
        return False

    def _check_sink_attr(self, node: ast.Attribute, shown: str) -> None:
        """A process / environment / introspection sink name on a receiver the
        gate cannot resolve (``helper().system``, ``obj.popen``, ``x[0].fork``)
        is refused: the receiver may be any of the gated modules."""
        if node.attr in _SINK_ATTRS:
            self._add(RULE_INDIRECT, node, f"{node.attr}() on a receiver the gate cannot resolve ({shown})",
                      target=f"{shown}.{node.attr}", remediation=_REM_SINK)

    def _value_position_ok(self, node: ast.Name) -> bool:
        """Positions in which a gated module / Spark object may appear: the root
        of an attribute chain, the callee of a call, the whole right-hand side of
        a plain name assignment, an argument of an introspection / display
        builtin, or a bare expression statement."""
        parent = self._parents.get(id(node))
        if parent is None or isinstance(parent, ast.Expr):
            return True
        if isinstance(parent, ast.Attribute):
            return parent.value is node
        if isinstance(parent, ast.Call):
            return parent.func is node or self._call_name(parent.func) in _VALUE_SAFE_CALLEES \
                or self._chain(parent.func) == ["inspect", "getattr_static"]      # judged like getattr
        if isinstance(parent, ast.Assign):
            return parent.value is node and all(isinstance(t, ast.Name) for t in parent.targets)
        if isinstance(parent, ast.AnnAssign):
            return parent.value is node and isinstance(parent.target, ast.Name)
        return False

    def visit_ClassDef(self, node: ast.ClassDef):
        for base in node.bases:
            chain = self._chain(base) if isinstance(base, (ast.Name, ast.Attribute)) else []
            if chain and chain[0] == "yaml" and len(chain) >= 2 and (
                    chain[-1].endswith(("Loader", "Constructor")) or chain[1] in ("loader", "constructor")):
                self._add(RULE_DESERIALIZE, node, f"class {node.name} subclasses the yaml loader {'.'.join(chain)}; "
                          "a subclass can register constructors that run while parsing",
                          target=".".join(chain), remediation=_REM_DESERIALIZE)
        self.generic_visit(node)

    # -- assignments to module / shim attributes ------------------------
    def _check_mutation_target(self, target: ast.AST, what: str) -> None:
        base = target
        keys: List[Optional[str]] = []
        while isinstance(base, ast.Subscript):
            keys.append(_literal_str(base.slice))
            base = base.value
        if keys and self._is_builtins_namespace(base):
            self._add(RULE_POLICY_TAMPER, target, f"{what} to the builtins namespace",
                      target="__builtins__", remediation=_REM_TAMPER)
            self._consume(self._route_nodes(target))
            return
        if keys and self._is_namespace_call(base):
            key = keys[-1]
            if key is None or _is_dunder(key) or key in _PROTECTED_ROOTS or key in _SPARK_ROOTS \
                    or key in _DANGEROUS_BUILTINS:
                self._add(RULE_POLICY_TAMPER, target,
                          f"{what} to a protected name through globals()/locals() ({key or '<dynamic>'})",
                          target=f"globals()[{key!r}]" if key is not None else "globals()[<dynamic>]",
                          remediation=_REM_TAMPER)
            self._consume(self._route_nodes(target))
            return
        if isinstance(base, ast.Name) and keys and self.ctx.resolve([base.id])[0] in _PROTECTED_ROOTS:
            chain = self.ctx.resolve([base.id])
            self._add(RULE_POLICY_TAMPER, target, f"{what} to an item of {chain[0]}",
                      target=".".join(chain), remediation=_REM_TAMPER)
            return
        if isinstance(base, ast.Call) and self._call_name(base.func) == "getattr" and len(base.args) >= 2 \
                and _literal_str(base.args[1]) is not None and isinstance(base.args[0], (ast.Name, ast.Attribute)):
            # getattr(yaml.SafeLoader, "yaml_constructors")["!x"] = h: judged as the chain it names
            chain = self._chain(base.args[0]) + [_literal_str(base.args[1])]
        elif isinstance(base, ast.Attribute):
            chain = self._chain(base)
        else:
            return
        if self._is_protected_root(chain) or (chain and chain[0] in _SPARK_ROOTS):
            self._add(RULE_POLICY_TAMPER, target, f"{what} to an attribute of {chain[0]} ({'.'.join(chain)})",
                      target=".".join(chain), remediation=_REM_TAMPER)
        elif self._is_gated_mutation(chain, item=bool(keys)):
            # yaml.SafeLoader.yaml_constructors["!x"] = h / L.yaml_constructors[..] = h (alias followed) /
            # yaml.SafeLoader.yaml_constructors = {..}: the registry a safe loader consults is rewritten
            rule = RULE_DESERIALIZE if chain[0] in _DESERIALIZE_MODULES else RULE_POLICY_TAMPER
            self._add(rule, target, f"{what} to the state of the gated module {chain[0]} ({'.'.join(chain)})",
                      target=".".join(chain), remediation=_REM_MUTATE)

    @staticmethod
    def _is_gated_mutation(chain: Sequence[str], item: bool) -> bool:
        """A store into the state of a gated module: an item of any attribute of
        it (``yaml.SafeLoader.yaml_constructors[k]``), or an attribute of it
        (``yaml.SafeLoader.yaml_constructors = ..``). ``torch`` is the one gated
        module whose public flag attributes notebooks set as everyday
        configuration (``torch.backends.cudnn.benchmark = True``); its
        serialisation namespace and its registries (item stores) stay refused."""
        if len(chain) < 2 or chain[0] not in _WATCHED_MODULES:
            return False
        if chain[0] == "torch" and not item and "serialization" not in chain:
            return False
        return True

    def visit_Assign(self, node: ast.Assign):
        for t in node.targets:
            elts = t.elts if isinstance(t, (ast.Tuple, ast.List)) else [t]
            for elt in elts:
                self._check_mutation_target(elt, "assignment")
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        self._check_mutation_target(node.target, "augmented assignment")
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        self._check_mutation_target(node.target, "assignment")
        self.generic_visit(node)

    def visit_Delete(self, node: ast.Delete):
        for t in node.targets:
            self._check_mutation_target(t, "deletion")
        self.generic_visit(node)

    # -- names and subscripts: the builtins namespace and loose builtins ----
    def visit_Name(self, node: ast.Name):
        if isinstance(node.ctx, ast.Load) and id(node) not in self._consumed:
            name = node.id
            resolved = self.ctx.resolve([name])
            root = resolved[0]
            if self.ctx.is_unresolved_taint(name):
                self._add(RULE_INDIRECT, node,
                          f"name '{name}' stood for a protected object earlier in this run and was rebound "
                          "to a value the gate cannot resolve", target=name, remediation=_REM_INDIRECT)
            elif len(resolved) >= 2:
                self._add_rule(node, self._attr_rule(resolved))      # from pickle import loads; loads(...)
            elif root in _BUILTINS_NAMESPACE_ROOTS:
                self._add(RULE_INDIRECT, node, "access to the builtins namespace", target=root,
                          remediation=_REM_INDIRECT)
            elif root in _IPYTHON_NAMES:
                self._add(RULE_IPYTHON_ESCAPE, node, f"IPython shell access via {root}", target=root,
                          remediation=_REM_IPYTHON)
            elif root in _PY4J_NAMES:
                self._add(RULE_POLICY_TAMPER, node, f"py4j gateway access via {root}", target=root,
                          remediation=_REM_JVM)
            elif root in _PROCESS_POOL_NAMES:
                self._add(RULE_IMPORT_PROCESS, node, "process pool executor forks worker processes",
                          target="concurrent.futures.ProcessPoolExecutor",
                          remediation="Process and FFI modules are not available inside the sandbox; "
                                      "use ThreadPoolExecutor.")
            elif root in _DANGEROUS_BUILTINS and id(node) not in self._call_funcs:
                self._add(RULE_INDIRECT, node, f"builtin {root} referenced without being called directly",
                          target=root, remediation=_REM_INDIRECT)
            if len(resolved) == 1 and root in _VALUE_GUARDED and root != "get_ipython" \
                    and not self.ctx.is_unresolved_taint(name) and not self._value_position_ok(node):
                # [os][0].system(..), run(os), (os if c else sys), {'a': os}['a'], return os,
                # lambda: os, dict(m=os), for m in (os,), with os as m, f(m=os), (m := os), *[os]
                self._add(RULE_INDIRECT, node, f"module / protected object '{root}' passed as a value",
                          target=root, remediation=_REM_VALUE)
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare):
        # 'my_var' in globals(): a membership test on the frame namespace with a
        # literal, non-protected key returns a bool and exposes nothing.
        key = _literal_str(node.left)
        if key is not None and len(node.comparators) == 1 and isinstance(node.ops[0], (ast.In, ast.NotIn)) \
                and self._is_namespace_call(node.comparators[0]) and not _is_dunder(key) \
                and key not in _VALUE_GUARDED and key not in _DANGEROUS_BUILTINS:
            self._consume(self._route_nodes(node.comparators[0]))
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript):
        if id(node) not in self._consumed:
            if self._is_builtins_namespace(node.value):
                key = _literal_str(node.slice)
                self._add(RULE_INDIRECT, node,
                          "non-literal key on the builtins namespace" if key is None
                          else f"indirect builtin access to {key}",
                          target="__builtins__[<dynamic>]" if key is None else f"__builtins__[{key!r}]",
                          remediation=_REM_INDIRECT)
                self._consume(self._route_nodes(node.value))
            elif self._is_namespace_call(node.value):
                key = _literal_str(node.slice)
                parent = self._parents.get(id(node))
                dereferenced = (isinstance(parent, (ast.Attribute, ast.Subscript)) and parent.value is node) \
                    or (isinstance(parent, ast.Call) and parent.func is node)
                if key is not None and not _is_dunder(key) and key not in _VALUE_GUARDED \
                        and key not in _DANGEROUS_BUILTINS and key not in self.ctx.tainted \
                        and key not in self.ctx.aliases and key not in self.ctx.identities and not dereferenced:
                    # globals()["my_var"]: the one tolerated use of the frame namespace, a plain
                    # read of a literal key that is not a protected / tainted / alias name and
                    # whose result is not dereferenced (globals()["o"].x is unresolvable: refused).
                    self._consume(self._route_nodes(node.value))
        self.generic_visit(node)

    # -- calls ----------------------------------------------------------
    def visit_Call(self, node: ast.Call):
        if id(node) in self._consumed:
            self.generic_visit(node)
            return
        func = node.func
        route = self._indirect_route(func)
        if route is not None:
            chain, text, nodes, via_builtins = route
            before = len(self.violations)
            if len(chain) == 1:
                self._check_name_call(node, chain[0])
            elif len(chain) >= 2:
                self._check_attribute_call(node, chain, chain[-1])
            if via_builtins and len(self.violations) == before:
                self._add(RULE_INDIRECT, node, f"indirect builtin access via {text}", target=text,
                          remediation=_REM_INDIRECT)
            self._consume(nodes)
        elif isinstance(func, ast.Name):
            self._call_funcs.add(id(func))
            resolved = self.ctx.resolve([func.id])
            if self.ctx.is_unresolved_taint(func.id):
                pass  # visit_Name refuses the rebound alias
            elif len(resolved) == 1:
                self._check_name_call(node, resolved[0], bare=func.id)
            else:
                self._check_attribute_call(node, resolved, resolved[-1])
        elif isinstance(func, ast.Attribute):
            self._check_attribute_call(node, self._chain(func), func.attr)
            self._check_format_call(node, func)
        self.generic_visit(node)

    def _check_name_call(self, node: ast.Call, name: str, bare: Optional[str] = None) -> None:
        """A call to a single (alias-resolved) name: builtins and well-known globals."""
        if name in _DYNAMIC_BUILTINS or (bare in _DYNAMIC_BUILTINS):
            self._add(RULE_BUILTIN_EXEC, node, f"call to builtin {name}()", target=name,
                      remediation="Dynamic code execution is refused; inline the code as a cell.")
        elif name in _NAMESPACE_BUILTINS and not node.args and not node.keywords:
            self._add(RULE_INDIRECT, node, f"{name}() exposes the interpreter namespace", target=f"{name}()",
                      remediation=_REM_INDIRECT)
        elif name in _INTROSPECT_BUILTINS or name in _MUTATE_BUILTINS:
            self._check_introspection(node, name)
        elif name == "open":
            self._check_open(node)
        elif name == "sql":
            self._check_sql(node, "sql")
        elif name in _IPYTHON_NAMES:
            self._add(RULE_IPYTHON_ESCAPE, node, f"IPython shell access via {name}()", target=name,
                      remediation=_REM_IPYTHON)
        elif name in _PY4J_NAMES:
            self._add(RULE_POLICY_TAMPER, node, f"py4j gateway access via {name}()", target=name,
                      remediation=_REM_JVM)
        elif name in _PROCESS_POOL_NAMES:
            self._add(RULE_IMPORT_PROCESS, node, "process pool executor forks worker processes",
                      target="concurrent.futures.ProcessPoolExecutor",
                      remediation="Process and FFI modules are not available inside the sandbox; "
                                  "use ThreadPoolExecutor.")

    # -- str.format templates ----------------------------------------------
    def _fold_literal(self, node: Optional[ast.AST]) -> Optional[str]:
        """Literal text of ``node``: a constant, a name bound once to one, ``"a" + "b"``."""
        node = self._resolve_value(node)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = self._fold_literal(node.left), self._fold_literal(node.right)
            return None if left is None or right is None else left + right
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "join" and len(node.args) == 1 and not node.keywords:
                # "/".join(["/etc", "passwd"]) / "/".join(parts) with parts bound once to a literal list
                sep = self._fold_literal(node.func.value)
                seq = self._resolve_value(node.args[0])
                if sep is not None and seq is not None and _is_str_sequence(seq):
                    return sep.join(_literal_str(e) for e in seq.elts)
            elif self._chain(node.func) == ["os", "path", "join"] and node.args and not node.keywords:
                parts = [self._fold_literal(a) for a in node.args]
                if all(p is not None for p in parts):
                    return posixpath.join(*parts)
        return _literal_str(node)

    def _resolve_template(self, node: Optional[ast.AST]) -> Optional[str]:
        """The format template behind ``node``, through text-preserving wrappers
        (``textwrap.dedent("...")``, ``"...".strip()``), or ``None``."""
        while isinstance(self._resolve_value(node), ast.Call):
            call = self._resolve_value(node)
            fn = call.func
            if isinstance(fn, ast.Attribute) and fn.attr in _STR_PRESERVING_METHODS:
                node = fn.value
            elif tuple(self._chain(fn)) in _STR_PRESERVING_CALLS and call.args:
                node = call.args[0]
            else:
                return None
        return self._fold_literal(node)

    def _check_format_call(self, node: ast.Call, func: ast.Attribute) -> None:
        """``<template>.format(..)`` / ``.format_map(..)``, ``str.format(t, ..)``,
        ``string.Formatter().format / vformat(t, ..)``: a replacement field can
        walk attributes of the formatted objects (``{0.__class__.__mro__}``)."""
        chain = self._chain(func)
        if func.attr in ("format", "format_map") and chain == ["str", func.attr]:
            if node.args:
                self._check_format_template(node, node.args[0], node.args[1:], node.keywords)
            return
        if func.attr in ("format", "vformat") and chain[:2] == ["string", "Formatter"]:
            if node.args:
                self._check_format_template(node, node.args[0], node.args[1:], node.keywords)
            return
        if func.attr not in ("format", "format_map"):
            return
        if any(part in _SPARK_IO_CHAIN for part in chain[:-1]):
            return   # DataFrameReader / DataFrameWriter .format("delta")
        self._check_format_template(node, func.value, node.args, node.keywords)

    def _check_format_template(self, node: ast.Call, template: ast.AST, args: Sequence[ast.AST],
                               keywords: Sequence[ast.keyword]) -> None:
        text = self._resolve_template(template)
        if text is not None:
            field = _format_field_escape(text)
            if field is not None:
                self._add(RULE_DUNDER_ESCAPE, node, "dunder / frame attribute lookup inside a str.format() field",
                          target=field[:80], remediation=_REM_DUNDER)
            return
        # Unresolvable template. With only literal arguments nothing of the
        # notebook's objects is reachable; with a run-time argument the
        # template decides which of its attributes are walked: fail closed.
        dynamic = any(isinstance(a, ast.Starred) or not isinstance(self._resolve_value(a), ast.Constant)
                      for a in args)
        dynamic = dynamic or any(k.arg is None or not isinstance(self._resolve_value(k.value), ast.Constant)
                                 for k in keywords)
        if dynamic:
            self._add(RULE_DUNDER_ESCAPE, node, "str.format() on a template that cannot be resolved statically",
                      target="<dynamic>", remediation=_REM_FORMAT)

    def _check_attribute_call(self, node: ast.Call, chain: List[str], attr: str) -> None:
        if chain[:1] == ["get_ipython"] and len(chain) >= 2:
            self._add_rule(node, self._attr_rule(chain))
            self._consume_base(node.func)
            return
        if attr == "pipe":
            self._check_pipe(node, chain)
        if len(chain) == 2 and tuple(chain) in _ATTR_ACCESSOR_CALLS:
            self._check_attr_accessor(node, chain)
            return
        if chain == ["functools", "reduce"] and node.args:
            fn = node.args[0]
            fn_name = self._call_name(fn) if isinstance(fn, ast.Name) else None
            fn_chain = tuple(self._chain(fn)) if isinstance(fn, (ast.Attribute, ast.Name)) else ()
            if fn_name in _ATTR_RESOLVING_NAMES or fn_chain in _ATTR_ACCESSOR_CALLS:
                self._add(RULE_INDIRECT, node, "functools.reduce() with an attribute-resolving function walks a "
                          "dotted path the gate cannot see", target="functools.reduce(getattr, ...)",
                          remediation=_REM_INDIRECT)
                return
        if chain[:1] == ["inspect"] and attr == "getattr_static":
            self._check_introspection(node, "getattr")
            self._consume_base(node.func)
            return
        if chain[:1] == ["inspect"] and attr == "getmembers":
            self._add(RULE_INDIRECT, node, "inspect.getmembers() enumerates every attribute of an object, "
                      "private and dunder names included", target="inspect.getmembers", remediation=_REM_INDIRECT)
            return
        if attr in _REGISTRY_MUTATORS and len(chain) >= 3 and chain[0] in _WATCHED_MODULES \
                and tuple(chain[:2]) not in _MUTABLE_GATED_CHAINS:
            # yaml.SafeLoader.yaml_constructors.update({..}) / .setdefault / .pop / sys.meta_path.append:
            # the registry a gated module consults is rewritten in place (sys.path is the exception)
            shown = ".".join(chain)
            rule = RULE_DESERIALIZE if chain[0] in _DESERIALIZE_MODULES else RULE_POLICY_TAMPER
            self._add(rule, node, f"{shown}() mutates the state of the gated module {chain[0]}",
                      target=shown, remediation=_REM_MUTATE)
            return
        if attr == "load" and isinstance(node.func, ast.Attribute) and not self._receiver_resolved(node.func) \
                and not any(part in _SPARK_IO_CHAIN for part in chain[:-1]):
            # <unresolved>.load(p, **kw) / .load(p, None, True): the receiver may be numpy / torch /
            # any keyword-gated loader, and the switch is hidden in the splat or passed positionally
            if self._refuse_loader_args(node, ".".join(chain), positional_switch=2):
                return
        for k in node.keywords:
            # numpy / torch loader switches, keyed on the keyword so the receiver does not matter
            if k.arg == "allow_pickle" and not (isinstance(k.value, ast.Constant) and k.value.value is False):
                literal_true = isinstance(k.value, ast.Constant) and k.value.value is True
                self._add(RULE_DESERIALIZE, node, f"{'.'.join(chain)}(allow_pickle=...) not the literal False",
                          target="numpy.load(allow_pickle=True)" if literal_true
                          else f"{'.'.join(chain)}(allow_pickle=<dynamic>)", remediation=_REM_DESERIALIZE)
                return
            if k.arg == "weights_only" and attr == "load" \
                    and not (isinstance(k.value, ast.Constant) and k.value.value is True):
                self._add(RULE_DESERIALIZE, node, f"{'.'.join(chain)}(weights_only=...) not the literal True",
                          target=".".join(chain), remediation=_REM_DESERIALIZE)
                return
        if len(chain) == 2 and (chain[0], attr) in _IO_OPEN_CALLS:
            call_name = f"{chain[0]}.{attr}()"
            if (chain[0], attr) in (("io", "open"), ("codecs", "open")):
                self._check_open(node, call_name)       # mode-aware, like builtin open()
                return
            if self._refuse_splat(node, call_name):
                return
            arg = _first_arg(node, ("file", "filename", "name", "path", "database", "files"))
            if arg is not None:
                self._check_io_target(node, arg, call_name)
            return
        reader = self._reader_call_name(chain, attr)
        if reader is not None:
            arg = _first_arg(node, _READER_PATH_KWARGS)
            if arg is not None:
                self._check_read_path(node, arg, reader)
        if chain[:1] == ["os"] and attr in ("chdir", "fchdir"):
            # Relative paths are tolerated for open(); the working directory must therefore stay put.
            lit = self._resolve_literal(_first_arg(node, ("path",)))
            if lit is None:
                self._add(RULE_FS_DYNAMIC, node, f"os.{attr}() with a path that cannot be resolved statically",
                          target="<dynamic>", remediation="Keep the working directory; use absolute sandbox paths.")
            elif not (_is_abs_path(lit) and self.policy.path_in_sandbox(lit)):
                self._add(RULE_FS_PATH, node, f"os.{attr}() target outside the sandbox prefix", target=lit,
                          remediation=f"Only directories under {self.policy.prefix} may become the working directory.")
            return
        if self._check_deserialize_call(node, chain, attr):
            return
        if len(chain) >= 3 and chain[-2] == "fs" and attr in _DBFS_WRITE_METHODS:
            self._check_dbfs(node, ".".join(chain[-3:]), attr)
        elif attr in _TABLE_WRITE_METHODS and ("write" in chain or attr == "writeTo"):
            self._check_table_write(node, attr)
        elif attr in _SQL_METHODS and len(chain) >= 2:
            self._check_sql(node, ".".join(chain[-2:]))
        elif attr in _PATH_WRITE_METHODS and "write" in chain:
            self._check_path_write(node, attr)
        elif attr in _WRITER_OPTION_METHODS and ("write" in chain or "writeTo" in chain):
            self._check_writer_option(node, attr)
        elif attr in _WRITER_OPTION_METHODS and any(part in _SPARK_READER_CHAIN for part in chain):
            self._check_reader_option(node, attr, ".".join(chain))
        elif attr == "open" and chain[:1] == ["builtins"]:
            self._check_open(node)
        elif chain[:1] == ["os"] and attr in _OS_FS_ATTRS:
            self._check_fs_call(node, f"os.{attr}", two_arg=attr in _OS_FS_TWO_ARG)
        elif chain[:1] == ["os"] and chain[1:2] == ["path"] and attr in ("unlink", "remove"):
            self._check_fs_call(node, f"os.path.{attr}")
        elif chain[:1] == ["shutil"] and attr in _SHUTIL_FS_ATTRS:
            self._check_fs_call(node, f"shutil.{attr}", two_arg=True, dst_only=attr != "move")
        elif attr in _PATHLIB_IO_ATTRS or attr in _PATHLIB_FS_ATTRS or attr in _PATHLIB_RESOLVED_ONLY_ATTRS:
            handled = self._check_pathlib(node, attr)
            if not handled and attr == "open" and chain[0] not in _WATCHED_MODULES:
                # <anything>.open(path): a literal local path is checked, a dynamic one recorded
                self._check_receiver_open(node, chain)

    def _refuse_splat(self, node: ast.Call, call_name: str) -> bool:
        """``open(*args)`` / ``open(**kw)``: path and mode are invisible; refused (fail closed)."""
        if any(isinstance(a, ast.Starred) for a in node.args) or any(k.arg is None for k in node.keywords):
            self._add(RULE_OPEN_DYNAMIC, node, f"{call_name} with *args / **kwargs hides the path and mode",
                      target="<dynamic>", remediation="Pass the path (and mode) as plain arguments the gate can see.")
            return True
        return False

    def _is_string_typed(self, node: ast.AST) -> bool:
        """A string-valued argument: literal, f-string, concatenation / ``%`` with a literal,
        ``.format(..)`` / ``.join(..)`` result, or a name bound once to one of these."""
        node = self._resolve_value(node)
        if node is None:
            return False
        if _is_stringish(node):
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("format", "join"):
            return True
        return isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and _is_stringish(node.left)

    def _check_pipe(self, node: ast.Call, chain: List[str]) -> None:
        """``.pipe(cmd)`` on an RDD runs ``cmd`` in a shell on every executor.

        Refused when the receiver chain is rooted at a Spark object or passes
        through an RDD-producing step (``parallelize``, ``textFile``, ``.rdd``,
        a name bound to one), or when the argument is string-typed on any
        receiver. A callable-looking argument (lambda, a ``def`` in the run, an
        attribute chain) on a non-Spark receiver is ``DataFrame.pipe(func)``.
        Residual: a bare name the gate cannot type on an unknown receiver is
        allowed and recorded (``unverified_pipe_callable``).
        """
        shown = ".".join(chain)
        arg = _first_arg(node, ("command", "func"))
        if arg is None:
            return
        spark_receiver = chain[0] in _SPARK_ROOTS or chain[0] in self.ctx.rdd_names or "sparkContext" in chain \
            or any(part in _RDD_CHAIN_ATTRS for part in chain[:-1])
        if spark_receiver or self._is_string_typed(arg):
            self._add(RULE_OS_PROCESS, node, f"{shown}() pipes data through a shell command on the executors",
                      target=f"{shown}()", remediation=_REM_PIPE)
            return
        if isinstance(arg, ast.Name) and arg.id not in self.ctx.functions and arg.id not in self.ctx.aliases:
            if not self._receiver_accounted(chain):
                # thing.pipe(cmd): the receiver was never bound in the notebook, so it cannot be
                # typed as a DataFrame at all, and the argument may be a command string
                self._add(RULE_OS_PROCESS, node, f"{shown}() on a receiver the notebook never bound, with an "
                          "argument the gate cannot type", target=f"{shown}()", remediation=_REM_RECEIVER)
                return
            self._note(NOTE_UNVERIFIED_PIPE, node,
                       f"{shown}({arg.id}) with an argument the gate cannot type; allowed as DataFrame.pipe(func) "
                       "and unverified", target=f"{shown}({arg.id})")

    def _check_attr_accessor(self, node: ast.Call, chain: List[str]) -> None:
        """``operator.attrgetter("a.b")`` / ``operator.methodcaller("name", ..)``:
        judged like ``getattr`` with a literal name. A non-literal name is
        refused; every dotted segment of a literal one is run through the
        dunder / frame / private / JVM-bridge / sink rules. The object the
        getter is applied to is judged where it appears (a gated module or
        Spark object handed to the getter is a value, refused there)."""
        shown = ".".join(chain)
        names = node.args if chain[1] == "attrgetter" else node.args[:1]
        if not names:
            return
        for name_node in names:
            lit = _literal_str(name_node)
            if lit is None:
                self._add(RULE_INDIRECT, node, f"{shown}() with an attribute name that is not a literal",
                          target=f"{shown}(<dynamic>)", remediation=_REM_INDIRECT)
                return
            for seg in lit.split("."):
                if self._add_rule(node, self._attr_rule(["<expr>", seg])):
                    return
                if seg in _SINK_ATTRS or (seg.startswith("_") and not _is_dunder(seg)):
                    self._add(RULE_INDIRECT, node, f"{shown}({lit!r}) reaches a process sink / private attribute",
                              target=f"{shown}({lit!r})", remediation=_REM_INDIRECT)
                    return

    def _check_receiver_open(self, node: ast.Call, chain: List[str]) -> None:
        """``<receiver>.open(path, ..)`` on a receiver that is not a Path / stdlib
        module: a literal local path outside the sandbox is refused, a dynamic
        one is allowed and recorded (object-store filesystems, zip members)."""
        shown = ".".join(chain)
        if self._refuse_splat(node, f"{shown}()"):
            return
        arg = _first_arg(node, ("file", "path", "name"))
        if arg is None:
            return
        lit = self._resolve_literal(arg)
        if lit is not None:
            if _is_local_path(lit) and not self.policy.path_in_sandbox(_local_path_for_check(lit)):
                self._add(RULE_OPEN_PATH, node, f"{shown}() on a local path outside the sandbox prefix", target=lit,
                          remediation=_REM_READ_PATH)
            return
        head = self._literal_head(arg)
        if head and _is_local_path(head) and not self.policy.path_in_sandbox(_local_path_for_check(head)):
            self._add(RULE_OPEN_PATH, node, f"{shown}() on a path under a local prefix outside the sandbox",
                      target=head, remediation=_REM_READ_PATH)
            return
        if not self._receiver_accounted(chain):
            # thing.open(path_var): neither the receiver nor the path is anything the notebook
            # bound; the gate cannot tell it from the builtin or a Path, so it is judged as one
            self._add(RULE_OPEN_DYNAMIC, node, f"{shown}() on a receiver the notebook never bound, with a path "
                      "that cannot be resolved statically", target=f"{shown}(<dynamic>)",
                      remediation=_REM_RECEIVER)
            return
        self._note(NOTE_UNVERIFIED_READ_PATH, node,
                   f"{shown}() with a path that cannot be resolved statically; the open is allowed and unverified "
                   "(the cluster's IAM scope is the control)", target=f"{shown}(<dynamic>)")

    def _receiver_accounted(self, chain: Sequence[str]) -> bool:
        """The root of a receiver chain is something the run bound (an import, an
        assignment, a parameter, a loop / with target) or a library root the gate
        knows. An unbound bare name is a value the gate never saw come into being."""
        return bool(chain) and (self.ctx.is_bound(chain[0]) or chain[0] in _DATAFRAME_LIB_ROOTS
                                or chain[0] in _VALUE_GUARDED)

    def _literal_head(self, arg: ast.AST) -> Optional[str]:
        resolved = self._resolve_value(arg)
        return _joined_literal_head(resolved) if resolved is not None else None

    def _check_introspection(self, node: ast.Call, builtin: str) -> None:
        arg = node.args[0] if node.args else None
        if arg is None:
            return
        chain = self._chain(arg) if isinstance(arg, (ast.Attribute, ast.Name, ast.Call)) else []
        mutate = builtin in _MUTATE_BUILTINS
        name = _literal_str(node.args[1]) if len(node.args) >= 2 else None
        # A Spark object tolerates getattr with a literal, public attribute name
        # (``getattr(spark, "version")``); the name is then judged like
        # ``spark.version`` below. Dynamic names, private / dunder names, vars()
        # and every mutation stay refused. The interpreter / compat roots have
        # no legitimate reflective use in a notebook: refused whatever the name.
        spark_obj = bool(chain) and chain[0] in _SPARK_ROOTS
        spark_refused = spark_obj and (mutate or builtin == "vars" or name is None or name.startswith("_"))
        # vars(<any gated module>) dumps its namespace: refused. getattr(<gated module>, "literal")
        # is judged by the rule table below (getattr(pickle, "loads") is pickle.loads).
        # setattr / delattr on any gated module (setattr(yaml.SafeLoader, "yaml_constructors", {..}))
        # rewrites state the gate reasons about: refused like an attribute assignment.
        protected = (self._is_protected_root(chain)
                     or ((builtin == "vars" or mutate) and bool(chain) and chain[0] in _WATCHED_MODULES)) \
            and not spark_obj
        if protected or spark_refused or self._is_builtins_namespace(arg):
            rule = RULE_POLICY_TAMPER if mutate else RULE_INDIRECT
            shown = ".".join(chain) if chain else "__builtins__"
            self._add(rule, node, f"{builtin}() on {shown}", target=shown,
                      remediation=_REM_TAMPER if rule == RULE_POLICY_TAMPER else _REM_INDIRECT)
            return
        if builtin == "vars" or len(node.args) < 2:
            return
        shown = ".".join(chain) if chain else "<expr>"
        if name is None:
            # getattr(obj, "sys" + "tem") / setattr(obj, key, v): the attribute name is built at run time.
            self._add(RULE_INDIRECT, node, f"{builtin}() with an attribute name that is not a literal",
                      target=f"{builtin}({shown}, <dynamic>)", remediation=_REM_INDIRECT)
        elif (_is_dunder(name) and name not in _DUNDER_ALLOW) or name in _FRAME_ATTRS:
            self._add(RULE_DUNDER_ESCAPE, node, f"{builtin}() reaching {shown}.{name}",
                      target=f"{shown}.{name}", remediation=_REM_DUNDER)
        elif name in _JVM_BRIDGE_ATTRS:
            self._add(RULE_POLICY_TAMPER, node, f"{builtin}() reaching the Spark JVM bridge {shown}.{name}",
                      target=f"{shown}.{name}", remediation=_REM_JVM)
        elif chain:
            self._add_rule(node, self._attr_rule(chain + [name]))

    def _check_deserialize_call(self, node: ast.Call, chain: List[str], attr: str) -> bool:
        """Call-level judgement of loaders whose safety depends on an argument.

        Returns True when the call was judged here (safe or refused).
        """
        root = chain[0]
        if root == "yaml" and attr == "load" and len(chain) == 2:
            # Safe only when the Loader resolves, through aliases and from-imports, to
            # exactly yaml.SafeLoader / CSafeLoader / BaseLoader / CBaseLoader. A bare
            # name the gate cannot resolve (``from yaml import Loader as SafeLoader``
            # resolves to yaml.Loader) is not safe. ``load_all`` is refused outright.
            loader = node.args[1] if len(node.args) >= 2 else None
            for k in node.keywords:
                if k.arg == "Loader":
                    loader = k.value
            lchain = self._chain(loader) if isinstance(loader, (ast.Name, ast.Attribute)) else []
            if len(lchain) == 2 and lchain[0] == "yaml" and lchain[1] in _YAML_SAFE_LOADERS:
                self._consumed.add(id(node.func))
            else:
                self._add(RULE_DESERIALIZE, node, "yaml.load() without a safe Loader", target="yaml.load",
                          remediation=_REM_DESERIALIZE)
                self._consumed.add(id(node.func))
            return True
        if root == "torch" and attr == "load":
            # torch.load / torch.serialization.load / torch.jit.load: any depth under torch.
            # Safe only with the literal weights_only=True AND no pickle_module (keyword or the
            # third positional): an explicit unpickler is honoured for the non-tensor payload.
            target = ".".join(chain)
            self._consumed.add(id(node.func))
            if self._refuse_loader_args(node, target, positional_switch=2):
                return True
            safe = any(k.arg == "weights_only" and isinstance(k.value, ast.Constant) and k.value.value is True
                       for k in node.keywords)
            if not safe:
                self._add(RULE_DESERIALIZE, node, f"{target}() without weights_only=True", target=target,
                          remediation=_REM_DESERIALIZE)
            elif any(k.arg == "pickle_module" for k in node.keywords):
                self._add(RULE_DESERIALIZE, node, f"{target}() with an explicit pickle_module", target=target,
                          remediation=_REM_DESERIALIZE)
            return True
        if root == "numpy" and attr == "load" and len(chain) == 2:
            # allow_pickle must be absent or the literal False: as a keyword (the generic
            # keyword rule in _check_attribute_call refuses every other value), as the
            # third positional argument, or hidden in *args / **kwargs (refused).
            self._refuse_loader_args(node, ".".join(chain), positional_switch=2)
            return True
        return False

    def _refuse_loader_args(self, node: ast.Call, shown: str, positional_switch: int) -> bool:
        """Loader arguments the gate cannot judge: ``*args`` / ``**kwargs`` (the
        safety switch may be inside) or the switch passed positionally with
        anything but the literal ``False`` / ``None`` (``np.load(p, None, True)``,
        ``torch.load(p, None, custom_pickle)``). Returns True when refused."""
        if any(isinstance(a, ast.Starred) for a in node.args) or any(k.arg is None for k in node.keywords):
            self._add(RULE_DESERIALIZE, node, f"{shown}() with *args / **kwargs hides the loader's safety switch",
                      target=f"{shown}(<dynamic>)", remediation=_REM_LOADER_ARGS)
            return True
        if len(node.args) > positional_switch:
            switch = node.args[positional_switch]
            if not (isinstance(switch, ast.Constant) and switch.value in (False, None)):
                self._add(RULE_DESERIALIZE, node, f"{shown}() with the loader's safety switch passed positionally",
                          target=f"{shown}(<positional>)", remediation=_REM_LOADER_ARGS)
                return True
        return False

    def _check_open(self, node: ast.Call, call_name: str = "open()"):
        """``open(file, ..)`` and its twins ``io.open`` / ``codecs.open``.

        ``*args`` / ``**kwargs`` are refused (the path is invisible). A literal
        or foldable path (``"a" + "b"``, ``"/".join([..])``, ``os.path.join(..)``,
        a name bound once) is checked against the sandbox, the literal head of
        an f-string / concatenation is checked as a directory, and a path the
        gate cannot resolve is refused in every mode (``NBP-OPEN-DYNAMIC``): a
        read of an arbitrary local file leaves the sandbox as much as a write,
        and the library-reader scope decision does not extend to ``open()``.
        """
        if self._refuse_splat(node, call_name):
            return
        arg = _first_arg(node, ("file",))
        if arg is None:
            return
        self._check_io_target(node, arg, call_name)

    # -- library readers: local path literals ------------------------------
    @staticmethod
    def _reader_call_name(chain: List[str], attr: str) -> Optional[str]:
        """Dotted name when ``chain`` is a known path reader, else ``None``.

        pandas-style ``read_* / scan_* / open_*`` on a dataframe library,
        the loaders in ``_LIB_READER_CALLS``, ``spark.read[Stream].<fmt>/load``
        and ``sparkContext.textFile``-style RDD readers.
        """
        if len(chain) < 2:
            return None
        root = chain[0]
        if root in _DATAFRAME_LIB_ROOTS and attr.startswith(_DATAFRAME_READ_PREFIXES) \
                and attr not in _DATAFRAME_NON_PATH_READERS:
            return ".".join(chain)
        if tuple(chain) in _LIB_READER_CALLS:
            return ".".join(chain)
        if attr in _SPARK_PATH_READ_METHODS and any(part in _SPARK_READER_CHAIN for part in chain[:-1]):
            return ".".join(chain)
        if attr in _SC_PATH_READ_METHODS and (root in _SPARK_ROOTS or "sparkContext" in chain):
            return ".".join(chain)
        return None

    def _check_reader_option(self, node: ast.Call, method: str, call_name: str) -> None:
        if method == "option":
            if len(node.args) >= 2 and _literal_str(node.args[0]) == "path":
                self._check_read_path(node, node.args[1], call_name + "('path')")
            return
        for k in node.keywords:
            if k.arg == "path":
                self._check_read_path(node, k.value, call_name + "(path=)")

    def _check_read_path(self, node: ast.Call, arg: ast.AST, call_name: str) -> None:
        """Literal local path outside the sandbox -> refused; object-storage /
        relative literal -> fine; unresolvable -> allowed, recorded."""
        lit = self._resolve_literal(arg)
        if lit is None:
            self._note(NOTE_UNVERIFIED_READ_PATH, node,
                       f"{call_name}() with a path that cannot be resolved statically; the read is allowed "
                       "and unverified (the cluster's IAM scope is the control)",
                       target=f"{call_name}(<dynamic>)")
            return
        if _is_local_path(lit) and not self.policy.path_in_sandbox(_local_path_for_check(lit)):
            self._add(RULE_OPEN_PATH, node, f"{call_name}() reads a local path outside the sandbox prefix",
                      target=lit, remediation=_REM_READ_PATH)

    def _check_io_target(self, node: ast.Call, arg: ast.AST, call_name: str) -> None:
        lit = self._resolve_literal(arg)
        if lit is not None:
            if _is_abs_path(lit) and not self.policy.path_in_sandbox(lit):
                self._add(RULE_OPEN_PATH, node, f"{call_name} on absolute path outside the sandbox prefix",
                          target=lit,
                          remediation=f"Read/write under the sandbox prefix {self.policy.prefix} "
                                      "or use a relative path.")
            return
        head = self._literal_head(arg)
        if head and _is_local_path(head) and not self.policy.path_in_sandbox(_local_path_for_check(head)):
            # open(f"/etc/{name}") / open("/Volumes/prod/" + x): the literal head fixes the directory
            self._add(RULE_OPEN_PATH, node, f"{call_name} on a path under a local prefix outside the sandbox",
                      target=head,
                      remediation=f"Read/write under the sandbox prefix {self.policy.prefix} "
                                  "or use a relative path.")
            return
        self._add(RULE_OPEN_DYNAMIC, node, f"{call_name} with a path that cannot be resolved statically",
                  target="<dynamic>",
                  remediation="Use a literal sandbox path (or a name bound once to one), or list "
                              "NBP-OPEN-DYNAMIC in AIDP_NOTEBOOK_POLICY_ALLOW after review.")

    def _check_pathlib(self, node: ast.Call, attr: str) -> bool:
        """Returns True when the call was judged as a ``pathlib`` operation."""
        receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
        if receiver is None:
            return False
        path_arg = self._path_ctor_arg(receiver)
        if path_arg is None and isinstance(receiver, ast.Name):
            bound = self.ctx.constants.get(receiver.id)
            path_arg = self._path_ctor_arg(bound) if bound is not None else None
        resolved_receiver = path_arg is not None
        if attr in _PATHLIB_RESOLVED_ONLY_ATTRS and not resolved_receiver:
            return False  # str.replace / df.rename / zipfile.open ... not a path operation
        call_name = f"Path.{attr}()"
        if attr in _PATHLIB_IO_ATTRS or attr == "open":
            if resolved_receiver:
                if self._refuse_splat(node, call_name):
                    return True
                self._check_io_target(node, path_arg, call_name)
            else:
                self._add(RULE_OPEN_DYNAMIC, node, f"{call_name} on a path that cannot be resolved statically",
                          target="<dynamic>",
                          remediation="Build the Path from a literal sandbox path, or list NBP-OPEN-DYNAMIC "
                                      "in AIDP_NOTEBOOK_POLICY_ALLOW after review.")
            return True
        targets: List[Optional[ast.AST]] = [path_arg]
        if attr in ("rename", "replace", "symlink_to", "hardlink_to") and node.args:
            targets.append(node.args[0])
        for t in targets:
            self._check_fs_target(node, t, call_name)
        return True

    def _check_fs_call(self, node: ast.Call, call_name: str, two_arg: bool = False, dst_only: bool = False) -> None:
        args = list(node.args)
        for k in node.keywords:
            if k.arg in ("src", "dst", "path", "name", "src_dir_fd", "dst_dir_fd"):
                if k.arg in ("src", "path", "name"):
                    args.insert(0, k.value)
                elif k.arg == "dst":
                    args.append(k.value)
        if not args:
            return
        if two_arg:
            targets = args[1:2] if dst_only else args[:2]
        else:
            targets = args[:1]
        for t in targets:
            self._check_fs_target(node, t, call_name)

    def _check_fs_target(self, node: ast.Call, arg: Optional[ast.AST], call_name: str) -> None:
        lit = self._resolve_literal(arg) if arg is not None else None
        if lit is None:
            self._add(RULE_FS_DYNAMIC, node, f"{call_name} with a path that cannot be resolved statically",
                      target="<dynamic>",
                      remediation="Use a literal sandbox path, or list NBP-FS-DYNAMIC in "
                                  "AIDP_NOTEBOOK_POLICY_ALLOW after review.")
        elif _is_abs_path(lit) and not self.policy.path_in_sandbox(lit):
            self._add(RULE_FS_PATH, node, f"{call_name} target outside the sandbox prefix", target=lit,
                      remediation=f"Only paths under {self.policy.prefix} may be created, removed or "
                                  "renamed during this run.")

    def _check_dbfs(self, node: ast.Call, call_name: str, method: str):
        # rm(path) / put(path, ...) / mkdirs(path) -> arg0 ; cp(src, dst) -> dst ; mv(src, dst) -> src AND dst
        if method == "mv":
            targets = list(node.args[:2])
            for k in node.keywords:
                if k.arg in ("src", "dst", "source", "destination"):
                    targets.append(k.value)
        elif method == "cp":
            targets = [node.args[1]] if len(node.args) >= 2 else \
                [k.value for k in node.keywords if k.arg in ("dst", "destination")]
        else:
            t = _first_arg(node, ("path", "file", "dir"))
            targets = [t] if t is not None else []
        if not targets:
            return
        for t in targets:
            lit = self._resolve_literal(t)
            if lit is None:
                self._add(RULE_DBFS_DYNAMIC, node, f"{call_name}() with a non-literal path target",
                          target="<dynamic>",
                          remediation="Use a literal sandbox path, or list NBP-DBFS-DYNAMIC in "
                                      "AIDP_NOTEBOOK_POLICY_ALLOW after review.")
            elif not self.policy.path_in_sandbox(lit):
                self._add(RULE_DBFS_PATH, node, f"{call_name}() target outside the sandbox prefix",
                          target=lit,
                          remediation=f"Only paths under {self.policy.prefix} may be removed, "
                                      "moved, created or written during this run.")

    def _check_table_write(self, node: ast.Call, method: str):
        arg = _first_arg(node, ("name", "tableName", "table"))
        if arg is None:
            return
        lit = self._resolve_literal(arg)
        if lit is None:
            self._add(RULE_TABLE_DYNAMIC, node, f".{method}() with a non-literal table name",
                      target="<dynamic>",
                      remediation="Use a literal sandbox table, or list NBP-TABLE-DYNAMIC in "
                                  "AIDP_NOTEBOOK_POLICY_ALLOW after review.")
        elif not self.policy.table_in_sandbox(lit):
            self._add(RULE_TABLE_TARGET, node, f".{method}() target outside {self.policy.catalog}.{self.policy.schema}",
                      target=lit,
                      remediation=f"Write to {self.policy.catalog}.{self.policy.schema}.<table> "
                                  "(use the 2- or 3-part name).")

    def _check_path_write(self, node: ast.Call, method: str):
        arg = _first_arg(node, ("path",))
        if arg is None:
            return  # e.g. .save() with no path -> saveAsTable-style; option("path") is checked separately
        self._check_path_write_target(node, arg, f".write.{method}()")

    def _check_writer_option(self, node: ast.Call, method: str) -> None:
        if method == "option":
            if len(node.args) >= 2 and _literal_str(node.args[0]) == "path":
                self._check_path_write_target(node, node.args[1], ".write.option('path')")
            return
        for k in node.keywords:
            if k.arg == "path":
                self._check_path_write_target(node, k.value, ".write.options(path=)")

    def _check_path_write_target(self, node: ast.Call, arg: ast.AST, call_name: str) -> None:
        lit = self._resolve_literal(arg)
        if lit is None:
            self._add(RULE_PATH_WRITE_DYNAMIC, node, f"{call_name} with a non-literal path",
                      target="<dynamic>",
                      remediation="Use a literal sandbox path, or list NBP-PATH-WRITE-DYNAMIC in "
                                  "AIDP_NOTEBOOK_POLICY_ALLOW after review.")
        elif not self.policy.path_in_sandbox(lit):
            self._add(RULE_PATH_WRITE, node, f"{call_name} target outside the sandbox prefix",
                      target=lit,
                      remediation=f"Write under {self.policy.prefix}.")

    def _check_sql(self, node: ast.Call, call_name: str):
        arg = _first_arg(node, ("sqlQuery", "query"))
        if arg is None:
            return
        resolved = self._resolve_value(arg)
        lit = _literal_str(resolved)
        if lit is None:
            head = _joined_literal_head(resolved) if resolved is not None else None
            if head is None:
                self._add(RULE_SQL_DYNAMIC, node, f"{call_name}() statement that cannot be resolved statically",
                          target="<dynamic>",
                          remediation="Pass a literal statement (or a name bound once to one), or list "
                                      "NBP-SQL-DYNAMIC in AIDP_NOTEBOOK_POLICY_ALLOW after review.")
                return
            # Spark runs one statement per call: a statement whose literal head
            # (after whitespace / comments) is a read keyword, or a session-scoped
            # TEMP VIEW, cannot become a write whatever the run-time tail is.
            head_text = _SQL_COMMENT_RE.sub(" ", head).strip()
            if _SQL_READ_HEAD_RE.match(head_text) or _SQL_TEMP_VIEW_RE.match(head_text):
                self._note(NOTE_UNVERIFIED_SQL_READ, node,
                           f"{call_name}() read statement with run-time fragments; allowed, the literal head "
                           "fixes the statement type", target=head_text[:80])
            elif head_text and _is_sql_write_verb(head_text):
                self._add(RULE_SQL_DYNAMIC, node, f"{call_name}() DDL/DML with a non-literal target",
                          target="<dynamic>",
                          remediation="Use a literal sandbox table, or list NBP-SQL-DYNAMIC in "
                                      "AIDP_NOTEBOOK_POLICY_ALLOW after review.")
            else:
                self._add(RULE_SQL_DYNAMIC, node,
                          f"{call_name}() statement whose leading keyword is not a literal read keyword",
                          target="<dynamic>",
                          remediation="Start the statement with a literal SELECT / WITH / SHOW / DESCRIBE / "
                                      "EXPLAIN (or CREATE TEMP VIEW), pass a fully literal statement, or list "
                                      "NBP-SQL-DYNAMIC in AIDP_NOTEBOOK_POLICY_ALLOW after review.")
            return
        name, is_schema_stmt, locations = _sql_write_target(lit)
        for location in locations:
            if not self.policy.path_in_sandbox(location):
                self._add(RULE_SQL_TARGET, node, f"{call_name}() LOCATION / OPTIONS path outside the sandbox prefix",
                          target=location, remediation=f"Use a LOCATION under {self.policy.prefix}.")
        if name is None:
            return
        if name == "":
            self._add(RULE_SQL_TARGET, node, f"{call_name}() write statement whose target could not be resolved",
                      target=lit.strip().split("\n", 1)[0][:80],
                      remediation="Qualify the target as <catalog>.<schema>.<table> inside the sandbox.")
            return
        inside = self.policy.schema_in_sandbox(name) if is_schema_stmt else self.policy.table_in_sandbox(name)
        if not inside:
            self._add(RULE_SQL_TARGET, node,
                      f"{call_name}() DDL/DML target outside {self.policy.catalog}.{self.policy.schema}",
                      target=name,
                      remediation=f"Target {self.policy.catalog}.{self.policy.schema}.<table> "
                                  "(1-part names are treated as outside the sandbox).")


def scan_source(source: str, *, filename: str = "<cell>", policy: Optional[SandboxPolicy] = None,
                context: Optional[ScanContext] = None) -> List[Violation]:
    """Parse ``source`` and return every policy violation (empty when clean).

    ``context`` carries import/shim aliases and single-assignment string
    constants from earlier cells of the same run. ``SyntaxError``
    propagates: a cell that cannot be parsed is not executed, except that a
    cell broken by an IPython ``%magic`` / ``!command`` line is reported as
    a refusal (``NBP-OS-PROCESS`` / ``NBP-IPYTHON-ESCAPE``) so the attempt
    shows up in the policy log.
    """
    violations, _notes = _scan(source, filename=filename, policy=policy or require_policy(), context=context)
    return violations


def _scan(source: str, *, filename: str, policy: SandboxPolicy,
          context: Optional[ScanContext]) -> Tuple[List[Violation], List[Violation]]:
    """``(violations, notes)`` for one cell; see :func:`scan_source`."""
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError:
        magic = _magic_violation(source)
        if magic is None:
            raise
        return [magic], []
    scanner = _PolicyScanner(policy, context)
    scanner.prepare(tree)
    scanner.visit(tree)
    scanner.violations.sort(key=lambda v: (v.lineno, v.rule))
    scanner.notes.sort(key=lambda v: (v.lineno, v.rule))
    return scanner.violations, scanner.notes


def enforce_cell_policy(source: str, *, notebook_path: str, cell_index: int,
                        policy: Optional[SandboxPolicy] = None,
                        context: Optional[ScanContext] = None) -> List[Violation]:
    """Gate one code cell. Returns the allowed exceptions; raises on refusal.

    Allowed-but-unverified operations (a library reader with a dynamic path,
    a ``spark.sql`` read statement with run-time fragments) are recorded in
    the policy log under the :data:`POLICY_NOTES` events before the verdict.

    Raises:
        SandboxUndeclaredError: no policy declared.
        PolicyViolation: the first refused violation (all are logged first).
    """
    pol = policy or require_policy()
    violations, notes = _scan(source, filename=str(notebook_path), policy=pol, context=context)
    for n in notes:
        _record(n.rule, rule="", target=n.target, notebook_path=str(notebook_path), cell_index=cell_index,
                detail={"line": n.lineno, "detail": n.detail})
    refused: List[Violation] = []
    allowed: List[Violation] = []
    for v in violations:
        if pol.is_allowed_exception(v.rule):
            allowed.append(v)
            _record("allowed_exception", rule=v.rule, target=v.target, notebook_path=str(notebook_path),
                    cell_index=cell_index, remediation=v.remediation,
                    detail={"line": v.lineno, "detail": v.detail})
        else:
            refused.append(v)
            _record("refused", rule=v.rule, target=v.target, notebook_path=str(notebook_path),
                    cell_index=cell_index, remediation=v.remediation,
                    detail={"line": v.lineno, "detail": v.detail})
    if refused:
        v = refused[0]
        more = f" (+{len(refused) - 1} more)" if len(refused) > 1 else ""
        raise PolicyViolation(
            f"{notebook_path} cell {cell_index} line {v.lineno}: [{v.rule}] {v.detail}"
            f" (target: {v.target or '-'}){more}. Remediation: {v.remediation}",
            notebook_path=str(notebook_path), cell_index=cell_index, rule_id=v.rule,
            target=v.target, remediation=v.remediation,
        )
    return allowed


# ── Runtime assertions for compat helpers ──────────────────────────────
def assert_path_in_sandbox(path: str, *, operation: str, policy: Optional[SandboxPolicy] = None) -> str:
    """Refuse ``operation`` unless ``path`` is under the sandbox prefix. Returns ``path``.

    Paths with a ``..`` segment are refused outright; URIs and local paths are
    canonicalised before the comparison (see :meth:`SandboxPolicy.path_in_sandbox`).
    """
    pol = policy or require_policy()
    if not pol.path_in_sandbox(path):
        why = " (parent-directory segment)" if isinstance(path, str) and _has_parent_segment(path) else ""
        remediation = f"Only paths under {pol.prefix} may be written by {operation} during this run."
        _record("runtime_refused", rule=RULE_RUNTIME_PATH, target=str(path), remediation=remediation,
                detail={"operation": operation})
        raise PolicyViolation(
            f"{operation}: target outside the sandbox prefix{why}: {path}. Remediation: {remediation}",
            rule_id=RULE_RUNTIME_PATH, target=str(path), remediation=remediation,
        )
    return path


def assert_table_in_sandbox(table_name: str, *, operation: str, policy: Optional[SandboxPolicy] = None) -> str:
    """Refuse ``operation`` unless ``table_name`` resolves to ``catalog.schema``."""
    pol = policy or require_policy()
    if not pol.table_in_sandbox(table_name):
        remediation = (f"Only tables in {pol.catalog}.{pol.schema} may be written by {operation} "
                       "during this run (1-part names are treated as outside).")
        _record("runtime_refused", rule=RULE_RUNTIME_TABLE, target=str(table_name), remediation=remediation,
                detail={"operation": operation})
        raise PolicyViolation(
            f"{operation}: table outside the sandbox schema: {table_name}. Remediation: {remediation}",
            rule_id=RULE_RUNTIME_TABLE, target=str(table_name), remediation=remediation,
        )
    return table_name


def record_secret_refusal(target: str, *, operation: str, remediation: str) -> None:
    """Log a ``dbutils.secrets`` allowlist refusal (raised by ``aidp_compat.secrets``)."""
    _record("runtime_refused", rule=RULE_RUNTIME_SECRET, target=target, remediation=remediation,
            detail={"operation": operation})


def record_skipped_cell(source: str, *, notebook_path: str, cell_index: int) -> None:
    """Log a magic-led cell (``%sql ...`` / ``!cmd`` on its first line).

    ``dbutils.notebook.run`` skips such a cell as a whole: no line of it is
    compiled or executed. The skip is recorded so the migration report shows
    which cells never ran.
    """
    head = source.strip().split("\n", 1)[0][:80]
    _record("skipped_magic", rule="", target=head, notebook_path=str(notebook_path), cell_index=cell_index,
            remediation="Magic-led cells are not executed by dbutils.notebook.run; express the step in plain "
                        "Python or dbutils.")


__all__ = [
    "SandboxPolicy", "NotebookPolicyError", "SandboxUndeclaredError", "PolicyViolation", "Violation",
    "ScanContext",
    "set_sandbox_policy", "current_policy", "require_policy",
    "scan_source", "enforce_cell_policy",
    "assert_path_in_sandbox", "assert_table_in_sandbox", "record_secret_refusal", "record_skipped_cell",
    "get_policy_log", "clear_policy_log", "policy_log_json", "policy_log_markdown",
    "ALL_RULES", "POLICY_NOTES",
]
