# aidp_compat â€” Supported Operations

Version: **0.5.3** (wheel: `aidp_compat-0.5.3-py3-none-any.whl`)
OCI auth: **API key** via `/Workspace/<oci-config-workspace-path>` (DEFAULT profile).
Override with env vars: `OCI_CONFIG_FILE` / `OCI_CONFIG_PROFILE`.

> Resource principal auth is NOT used (known failure modes on AIDP; forbidden by policy).

---

## 1. `dbutils.fs.*` â€” File System Operations

Import:

```python
from aidp_compat import dbutils
```

All `dbutils.fs.*` methods support **two path types**:
- **OCI Object Storage** â€” `oci://<bucket>@<namespace>/<key>` (uses OCI Python SDK with API key)
- **Local filesystem** â€” `/Workspace/...`, `/Volumes/...`, `/tmp/...`, etc. (uses native `os`/`shutil`)

`dbfs:/...`, `/mnt/...`, `s3://...` paths are auto-translated to `oci://` via the mount config first.

| Method | Signature | OCI | Local | Recurse | Notes |
|---|---|:---:|:---:|:---:|---|
| `ls` | `dbutils.fs.ls(path) -> List[FileInfo]` | âœ… | âœ… | n/a | Returns FileInfo (path, name, size, modificationTime, isDir, isFile). Subdirectories appear as `isDir=True`. |
| `cp` | `dbutils.fs.cp(src, dst, recurse=False) -> bool` | âœ… | âœ… | âœ… | All 4 directions: ociâ†”local, localâ†”local, ociâ†”oci. `recurse=True` walks a "directory" (prefix). |
| `mv` | `dbutils.fs.mv(src, dst, recurse=False) -> bool` | âœ… | âœ… | âœ… | Cross-scheme = copy then delete src. |
| `rm` | `dbutils.fs.rm(path, recurse=False) -> bool` | âœ… | âœ… | âœ… | Recurse for prefix removal. |
| `mkdirs` | `dbutils.fs.mkdirs(path) -> bool` | âœ… | âœ… | n/a | OCI: writes a zero-byte placeholder ending in `/` (Object Storage is flat). Local: `os.makedirs`. |
| `head` | `dbutils.fs.head(path, max_bytes=65536) -> str` | âœ… | âœ… | n/a | OCI: uses Range request for partial download. Returns UTF-8 string. |
| `put` | `dbutils.fs.put(path, contents, overwrite=False) -> bool` | âœ… | âœ… | n/a | Raises `FileExistsError` if `overwrite=False` and target exists. |
| `mount` | `dbutils.fs.mount(source, mountPoint, ...) -> bool` | n/a | n/a | n/a | Path mapping only (not a real FUSE mount). Stored in memory + env vars. |
| `unmount` | `dbutils.fs.unmount(mountPoint) -> bool` | n/a | n/a | n/a | Removes a path mapping. |
| `mounts` | `dbutils.fs.mounts() -> List[MountInfo]` | n/a | n/a | n/a | Lists current mappings. |
| `refreshMounts` | `dbutils.fs.refreshMounts() -> bool` | n/a | n/a | n/a | Reloads `AIDP_MOUNT_CONFIG` json. |
| `updateMount` | `dbutils.fs.updateMount(source, mountPoint, ...) -> bool` | n/a | n/a | n/a | Alias for `mount`. |
| `help` | `dbutils.fs.help([method]) -> None` | n/a | n/a | n/a | Prints help text. |

**Implementation note**: All file-content ops use OCI Python SDK directly (no `jvm.org.apache.hadoop.fs`). Works in both interactive notebooks AND scheduled workflows. `copy_object` waits for OCI's async work-request to COMPLETE (up to 300s timeout).

---

## 2. Other `dbutils.*` Namespaces

| Namespace | Status | Notes |
|---|---|---|
| `dbutils.fs.*` | âœ… Full | See table above. |
| `dbutils.widgets.*` | âœ… | Backed by `oidlUtils.parameters` on AIDP. Use `oidlUtils.parameters.getParameter("name", "default")` for new code. |
| `dbutils.secrets.*` | âœ… | **Vault-only by default**: OCI Vault (API key auth), requires `AIDP_VAULT_OCID` env var + secret named `<scope>/<key>`. Plaintext `AIDP_SECRET_<SCOPE>_<KEY>` env vars and the JSON file named by `AIDP_SECRETS_FILE` are consulted only with `AIDP_ALLOW_PLAINTEXT_SECRETS=1` (file must be `0600` on POSIX; one `insecure plaintext secrets mode active` log line, never values). `AIDP_SECRET_SCOPES=<scope,scope>` and `AIDP_SECRET_KEYS=<scope/key,scope/*,...>` restrict `get`/`list`/`listScopes` (read per call; `none` = nothing allowed; a refusal is logged as `NBP-RUNTIME-SECRET`); `job_migrate.py` derives both from the `dbutils.secrets.get(scope, key)` literals of the planned notebooks and declares them in the cluster bootstrap (an operator-provided value wins). List operations return names only. |
| `dbutils.notebook.*` | âœ… | `notebook.run` and `notebook.exit` go to `oidlUtils.notebook.*`. Use `oidlUtils.notebook.run(path, timeout=3600)` for new code (timeout=0 is rejected by AIDP). The compat `notebook.run` passes every non-magic cell through the mandatory sandbox gate (section 8) before `exec`. |
| `dbutils.library.*` | âš ï¸ | No-op shim. Cluster libraries must be installed via cluster libraries API, not at runtime. |
| `dbutils.credentials.*` | âš ï¸ | Stub only. Use API key auth directly. `assumeRole` not supported. |
| `dbutils.data.*` | âš ï¸ | Stub. Use pandas `describe()` instead. |
| `dbutils.jobs.*` | âœ… | `dbutils.jobs.taskValues.get/set` works. |

---

## 3. Top-Level Helpers

```python
from aidp_compat import displayHTML, display, sql, translate_path, set_notebook_dir
```

| Function | Purpose | Example |
|---|---|---|
| `display(df)` | Pretty-print Spark/Pandas DataFrame in notebook | `display(spark.read.table("default.x.y"))` |
| `displayHTML(html)` | Render HTML in notebook | `displayHTML("<b>title</b>")` |
| `sql(query)` | Run a SQL query, return DataFrame | `df = sql("SELECT * FROM default.x.y LIMIT 10")` |
| `translate_path(p)` | Idempotent `/dbfs/FileStore/...` â†’ `/Volumes/default/default/dbfs/FileStore/...` translation. NO-OP on already-translated paths. | `local = translate_path("/dbfs/FileStore/foo.csv")` |
| `set_notebook_dir(path)` | Set the dir used by `dbutils.notebook.run("../relative")` to resolve relative paths | Called automatically by the migration tool's bootstrap. |

---

## 4. `aidp_compat.safe_io` â€” Spark-Safe I/O Helpers

For situations where naive `df.write.parquet(...)` / `pickle.dump(...)` can corrupt or lose data on AIDP. Import individually:

```python
from aidp_compat import safe_pickle_dump, safe_pickle_load, safe_write_parquet, ...
```

| Function | Purpose |
|---|---|
| `safe_pickle_dump(obj, path)` / `safe_pickle_load(path)` | Atomic pickle write/read (handles FUSE write-then-read consistency) |
| `safe_write_parquet(df, path, mode="overwrite", partitionBy=None)` | DataFrame write with overwrite-safety (clears stale `_temporary` dirs) |
| `safe_save_as_table(df, table_name, mode="overwrite", ...)` | Like saveAsTable but with retry + cleanup |
| `safe_read_modify_write_parquet(...)` | Read + transform + write back without leaving the original in inconsistent state |
| `safe_write_parquet_coalesced(df, path, num_files=1, ...)` | Write N target files (use for small-result optimization) |
| `safe_save_as_table_coalesced(...)` | Same coalesce + saveAsTable |
| `safe_pandas_to_csv(pdf, path, ...)` | Pandas â†’ CSV with `/Volumes` FUSE retry |
| `safe_materialize(df)` / `safe_unpersist(df)` | Force-cache + cleanup helpers |
| `safe_read_file(path)` | Read text file with FUSE retry |
| `load_saved_model_from_volumes(path)` | Read model artifacts from `/Volumes/...` (handles FUSE delays) |
| `safe_joblib_dump(obj, path)` / `safe_joblib_load(path)` | joblib with FUSE-safe semantics |

All `safe_io` helpers are **pure Python / PySpark** â€” no JVM Hadoop FS dependency.

---

## 5. `aidp_compat.s3_compat` â€” S3 â†’ OCI Routing

For code that still references S3 buckets (use only if migrating boto3 code minimally):

```python
from aidp_compat.s3_compat import read_s3_object, write_s3_object
data = read_s3_object("source-prod-bucket", "path/to/key")  # auto-routes to OCI
write_s3_object("source-prod-bucket", "path/to/key", data)
```

S3-to-OCI bucket mapping comes from `reports/s3_to_oci_bucket_mapping.csv`. Uses OCI SDK with API key auth.

---

## 6. `aidp_compat.glue_compat` â€” AWS Glue Replacement

```python
from aidp_compat import get_glue_table_s3_location
location = get_glue_table_s3_location("database_name", "table_name")
# Internally calls: spark.sql(f"DESCRIBE FORMATTED `{db}`.`{tbl}`")
```

Use as a drop-in replacement for `boto3.client('glue').get_table(...)['Table']['StorageDescriptor']['Location']`.

---

## 7. `aidp_compat.oci_throttle` â€” Object Storage Tuning

For bulk migrations or high-concurrency object-storage workloads:

```python
from aidp_compat.oci_throttle import tune_for_parallel_migration
tune_for_parallel_migration(spark, concurrent_jobs=48, verbose=True)
```

Applies CircuitBreaker + retry tuning to mitigate OCI 429 bursts. Profiles: conservative â‰¤8, balanced 9-200, aggressive >200.

---

## 8. `aidp_compat.notebook_policy` — Mandatory Sandbox Gate

Runtime enforcement at the execution sink. `dbutils.notebook.run(...)`, `dbutils.fs.rm/mv/cp/put/mkdirs` and every `safe_io` write helper refuse to run until a sandbox is declared; undeclared = `PermissionError` naming the missing variables (fail closed).

| Variable | Meaning |
|---|---|
| `AIDP_SANDBOX_CATALOG` / `AIDP_SANDBOX_SCHEMA` | Only `catalog.schema` that `saveAsTable` / `insertInto` / `writeTo` / `CREATE TABLE` / `INSERT` / `DROP` / `MERGE` / `DELETE` may target (1-part names count as outside) |
| `AIDP_SANDBOX_PREFIX` | Comma list of prefixes that path writes, `dbutils.fs` deletes/moves/mkdirs, `os`/`shutil`/`pathlib` file operations and absolute `open()` must stay under. The first entry is the object-storage prefix (`oci://bucket@ns/path/`); the rest are staging areas. Paths are canonicalised first; a `..` segment is always outside, and on POSIX a symlink inside a prefix pointing outside is outside |
| `AIDP_SANDBOX_ALLOW_NETWORK` | `1` permits `socket` / `requests` / `urllib` / `urllib3` / `httpx` / `aiohttp` / `http.client` / `paramiko` / `ftplib` / `smtplib` / ... imports (default off) |
| `AIDP_NOTEBOOK_POLICY_ALLOW` | Comma list of rule ids accepted as a reviewed exception (logged as `allowed_exception`) |
| `AIDP_NOTEBOOK_POLICY_LOG` | Optional JSONL file mirroring the in-process policy log |
| `AIDP_SECRET_SCOPES` / `AIDP_SECRET_KEYS` | `dbutils.secrets` allowlist (scopes; `scope/key` or `scope/*`), see `dbutils.secrets.*` above; `none` = nothing allowed |

Or declare programmatically: `from aidp_compat import SandboxPolicy, set_sandbox_policy; set_sandbox_policy(SandboxPolicy(catalog="default", schema="<sandbox>", prefix="oci://<bucket>@<ns>/<sandbox>/", extra_prefixes=("/Volumes/default/default/dbfs/",)))`.

**Declared once, frozen for the kernel.** The first policy resolved (explicit object, or the environment on first use) is a one-shot snapshot: later `AIDP_SANDBOX_*` changes are ignored by every assertion, and `set_sandbox_policy` with a different policy (or `None`) is refused as `NBP-POLICY-TAMPER`. Re-running the same declaration (bootstrap replay on reconnect) is a no-op.

**What `job_migrate.py` declares** on every cluster connect and per task (`build_sandbox_policy_snippet`; an operator-provided variable wins and replaces the whole list):

| Prefix | Why |
|---|---|
| `oci://<oci_backup_bucket>@<WORKSPACE_NAMESPACE>/` | the write-redirect bucket; every OCI write the migrator produces lands here |
| `/Volumes/default/default/dbfs/` | the `/dbfs/` and `dbfs:/` translation target the migration prompt rewrites paths to |
| `/tmp/` | local-disk staging the prompt prescribes for torch / h5py / sqlite before copying to `/Volumes` |
| `<output-base>/` | the tool's own output directory (`task_values.json`, `manifest_params.json`, reports) |

Together with catalog `default` / schema `<oci_backup_bucket>_overwrite` and the planned `dbutils.secrets` allowlist (section `dbutils.secrets.*`). Everything else on `/Volumes`, `/Workspace` or in other buckets stays refused.

Before each non-magic cell runs it is `ast.parse`d and refused (`PolicyViolation`, a `PermissionError` with notebook path, cell index, rule id, target and remediation) on:

| Rule | Refuses |
|---|---|
| `NBP-IMPORT-PROCESS` | `import subprocess` / `ctypes` / `cffi` / `pty` / `multiprocessing` / `signal` / `resource` / `webbrowser` / `antigravity` / `pexpect` / `psutil` / `sh` / `plumbum` / `fabric` / `invoke` / `_posixsubprocess`; `concurrent.futures.ProcessPoolExecutor` (import, attribute or bare name; `ThreadPoolExecutor` is fine) |
| `NBP-IMPORT-NETWORK` | `import socket` / `requests` / `urllib` / `urllib3` / `httpx` / `aiohttp` / `http.client` / `paramiko` / `ftplib` / `smtplib` / `pycurl` / `telnetlib` / `poplib` / `imaplib` / `websocket(s)` / `grpc` / `xmlrpc` / `socketserver` / `ssl`, `asyncio.open_connection/start_server/create_connection/...` (unless `AIDP_SANDBOX_ALLOW_NETWORK=1`) |
| `NBP-OS-ENVIRON` / `NBP-OS-PROCESS` | `os.environ` / `os.getenv` / `os.putenv` / `from os import *` (also through an alias, `import os as o`, and through `posix` / `nt`, the platform modules `os` re-exports: `import posix as p; p.environ`, `from posix import system`, `from nt import *`); `os.system` / `os.popen` / `os.exec*` / `os.spawn*` / `os.posix_spawn` / `os.fork` / `os.forkpty` / `os.kill` / `asyncio.create_subprocess_*` / `loop.subprocess_exec` / `loop.subprocess_shell`; `get_ipython().system/system_raw/getoutput/run_line_magic/run_cell_magic/magic`; a `%sh` / `%%bash` / `%pip` / `!cmd` line inside a cell body. One rule table serves every entry point: the direct chain, a `from m import n` alias, an `import m as a` alias and `getattr(m, "literal")` (`asyncio.run(getattr(asyncio, "create_subprocess_exec")(..))` is `asyncio.create_subprocess_exec`) |
| `NBP-SHUTIL-RMTREE` | `shutil.rmtree` |
| `NBP-BUILTIN-EXEC` | `eval` / `exec` / `compile` / `__import__` / `breakpoint` by any route (direct, `__builtins__['exec']`, `globals()['__builtins__']`, `getattr(__builtins__, ..)`, an alias); `import pdb` / `bdb` / `code` / `codeop` / `runpy` / `doctest` / `timeit` / `cProfile` / `profile` / `trace`; `types.FunctionType` / `CodeType`; `sc.addPyFile` / `addJar` / `addArchive` |
| `NBP-INDIRECT` | `import importlib` / `builtins` / `pkgutil` / `zipimport` / `imp` and any private `_module`; `sys.modules` / `sys.settrace` / `sys.setprofile` / `sys.addaudithook` / `sys.meta_path` / `sys.path_hooks`; `inspect.currentframe/stack/trace`; `gc.get_objects/get_referrers/get_referents`; the builtins namespace by any door (`__builtins__`, `builtins`, `globals()['__builtins__']`, `locals()`, `vars()`, `__builtins__.__dict__`, `getattr(__builtins__, ..)`) including a non-literal key on it; `globals()` / `locals()` / `vars()` other than a literal non-dunder key; `getattr` / `setattr` / `delattr` with a non-literal name, or with any name on `os` / `sys` / `builtins` / `__builtins__` / `importlib` / `shutil` / `dbutils` / `aidp_compat` and the other interpreter roots (no legitimate reflective use in a notebook); on `spark` / `sc` / the other Spark roots only `getattr` with a literal public name is tolerated (`getattr(spark, "version")`, then judged like `spark.version`), an underscore / dunder / non-literal name, `vars()` and every `setattr` / `delattr` stay refused; a dangerous builtin handed around without being called (`map(open, ..)`, `partial(exec, ..)`); star imports of gated modules; a name that was bound to any of these and later rebound to a value the gate cannot resolve (fail closed) |
| `NBP-POLICY-TAMPER` | `import aidp_compat[.x]`, `from aidp_compat[.fs/.safe_io/.secrets/.notebook] import` of the policy API / shim classes / private names, anything from `aidp_compat.notebook_policy`, attribute assignment / `del` / `setattr` on `os` / `sys` / `builtins` / `shutil` / `importlib` / `aidp_compat` / `dbutils` / `spark` / `sc`, `__builtins__[..] = ` and `globals()['dbutils'] = ` style mutation, private `_x` attributes of any protected root (`dbutils._x`, `os._exit`, `sys._getframe`); the Spark JVM / py4j bridge: any `_private` attribute of `spark` / `sc` / `sqlContext` / `SparkSession` / `SparkContext` / `pyspark` (`_jvm`, `_jsc`, `_gateway`, `_jsparkSession`, `_conf`, `_active_spark_context`, `_instantiatedSession`, ...), `_jvm` / `_jsc` / `_gateway` / `_jdf` / `_jrdd` / `_jc` / `_jconf` / `_sc` on any object, `import py4j`, `JavaGateway`, `spark.udf.registerJavaFunction`; at runtime, redeclaring or clearing the frozen policy |
| `NBP-DUNDER-ESCAPE` | Attribute access to any dunder not on the short read allowlist (`__name__`, `__doc__`, `__version__`, `__class__`, `__module__`, `__qualname__`, `__fields__`, the operator / container protocol methods such as `__init__` / `__repr__` / `__len__` / `__getitem__`): `__subclasses__`, `__bases__`, `__mro__`, `__globals__`, `__builtins__`, `__dict__`, `__code__`, `__closure__`, `__getattribute__`, `__reduce__`, `__reduce_ex__`, `__init_subclass__`, `__loader__`, `__spec__`, `__self__`, `__func__`, `__traceback__`, ...; frame / code attributes `f_globals` / `f_locals` / `f_back` / `tb_frame` / `gi_frame` / `co_code` / `mro`; the same names via `getattr(x, "__subclasses__")` or inside a replacement field of `"..".format(..)` / `.format_map(..)` / `str.format(t, ..)` / `str.format_map(t, ..)` / `string.Formatter().format / vformat(t, ..)`, nested format-spec fields included (`{0:{1.__class__.__mro__}}`). The template is resolved like any other target: a literal, a name bound once to one (this or an earlier cell), `"a" + "b"`, or a literal wrapped in `textwrap.dedent` / `inspect.cleandoc` / `.strip()`-style methods; fields consult the same read allowlist (`"{0.__class__.__name__}".format(obj)` is fine; `{x[__class__]}` is an item lookup, not attribute access). A template the gate cannot resolve (`tpl.format(obj)` with `tpl` from a widget, `TEMPLATES["x"].format(..)`, a rebound name) formatted with any run-time argument is refused as `<dynamic>` (fail closed); with literal-only arguments (`writer.format("delta")`) it is fine, and `DataFrameReader` / `DataFrameWriter` `.format(..)` chains are not templates. Dunder *definitions* in class bodies are untouched |
| `NBP-IPYTHON-ESCAPE` | `import IPython` / `ipykernel`, `get_ipython` (call or bare name), `InteractiveShell`, any `get_ipython().x` not listed under `NBP-OS-PROCESS` (`ev`, `ex`, `run_cell`, `user_ns`, ...); a `%magic` line inside a cell body (`%matplotlib`, `%run`, ...) |
| `NBP-DESERIALIZE` | `pickle` / `_pickle` / `dill` / `cloudpickle` `.load` / `.loads` / `Unpickler`, `marshal.load(s)`, `shelve.open`, `joblib.load`, `jsonpickle.decode`, `*.read_pickle`, `yaml.load` / `load_all` without `Loader=SafeLoader` / `CSafeLoader` / `BaseLoader`, `yaml.unsafe_load` / `full_load` / `Loader` / `UnsafeLoader` / `FullLoader`, `torch.load` without `weights_only=True`, `numpy.load(allow_pickle=True)` (the dump side stays allowed) |
| `NBP-OPEN-PATH` / `NBP-OPEN-DYNAMIC` | `open()` (also through the builtins namespace or an alias), `io.open` / `io.FileIO` / `os.open` / `codecs.open` / `gzip` / `bz2` / `lzma` / `tarfile` `.open`, `zipfile.ZipFile`, `tokenize.open`, `fileinput.input`, `sqlite3.connect`, `dbm.open`, `linecache.getline(s)` and `Path(...).read_text/read_bytes/write_text/write_bytes/open` on an absolute path (`/...`, `~`, `C:\` / UNC, `scheme://`) outside the prefix; any mode with a path that cannot be resolved statically. **Local file reads through library readers** (`NBP-OPEN-PATH` only): `pandas` / `polars` / `modin` / `dask` / `cudf` / `geopandas` / `xarray` / `pyarrow` / `vaex` `read_*` / `scan_*` / `open_*` (not `read_sql*` / `read_clipboard`), `numpy.load/loadtxt/genfromtxt/fromfile/memmap`, `pyarrow.parquet.ParquetFile/ParquetDataset`, `pyarrow.dataset.dataset`, `pyarrow.memory_map/OSFile/input_stream`, `spark.read[Stream].parquet/csv/json/orc/text/xml/avro/load` and `.option("path", ..)` / `.options(path=..)` / `.load(path=..)` on a reader chain, `sc.textFile/wholeTextFiles/binaryFiles/binaryRecords/sequenceFile/hadoopFile/newAPIHadoopFile/pickleFile`, `PIL.Image.open`, `cv2.imread`, `h5py.File`, `scipy.io.loadmat`, `xml.etree.ElementTree.parse`, `openpyxl.load_workbook`, `xlrd.open_workbook`, `imageio` / `tifffile` `.imread`, `netCDF4.Dataset`, `rasterio.open`, `zarr.open`, `librosa.load`, `soundfile.read` with a LITERAL local-filesystem path outside the prefix: POSIX-absolute (`/etc`, `/dbfs`, `/Workspace`, `/tmp`, `/Volumes`), `~`, a Windows drive / UNC path, or a `file://` URI (compared without the scheme). A reader path the gate cannot resolve is **allowed** and recorded in the policy log as `unverified_read_path` (reading source data through variables is the normal migration case; the cluster's IAM scope is the control); object-storage URIs (`oci://`, `abfss://`, `s3://`, ...), catalog tables and relative paths are never path-checked |
| `NBP-FS-PATH` / `NBP-FS-DYNAMIC` | `os.remove/unlink/rmdir/removedirs/rename/renames/replace/truncate/mkdir/makedirs/link/symlink`, `shutil.move/copy/copy2/copyfile/copytree` (destination), `Path(...).unlink/rmdir/mkdir/touch/rename/replace/symlink_to` outside the prefix; `os.chdir` to anything but a literal absolute sandbox path (relative `open()` targets depend on the working directory); unresolvable path |
| `NBP-DBFS-PATH` / `NBP-DBFS-DYNAMIC` | `*.fs.rm/mv/cp/put/mkdirs` (also through `fs = dbutils.fs`) whose target is outside the prefix; unresolvable target |
| `NBP-TABLE-TARGET` / `NBP-TABLE-DYNAMIC` | `.write...saveAsTable/insertInto`, `.writeTo(...)` outside `catalog.schema`; unresolvable name |
| `NBP-SQL-TARGET` / `NBP-SQL-DYNAMIC` | `spark.sql` / `sql` DDL/DML (and `LOCATION '..'` / `LOCATION ".."` / `OPTIONS (path ...)`) outside the sandbox; a statement that cannot be resolved statically, unless its literal head (the first literal fragment of the f-string / concatenation / `%` / `.format(..)`, after whitespace and SQL comments) is `SELECT` / `WITH` / `SHOW` / `DESCRIBE` / `DESC` / `EXPLAIN` or `CREATE [OR REPLACE] [GLOBAL] TEMP VIEW`: Spark executes one statement per `spark.sql()` call, so such a statement cannot become a write; it is allowed and recorded in the policy log as `unverified_sql_read`. Any other head (DDL/DML, `USE`, empty, a variable, a call, a non-literal `.format` receiver) is `NBP-SQL-DYNAMIC` |
| `NBP-PATH-WRITE` / `NBP-PATH-WRITE-DYNAMIC` | `.write...parquet/csv/json/orc/text/save`, `.write...option("path", ..)` / `.options(path=..)` outside the prefix; unresolvable path |
| `NBP-RUNTIME-PATH` / `NBP-RUNTIME-TABLE` / `NBP-RUNTIME-SECRET` | Runtime assertion inside `dbutils.fs.*` / `safe_io` write helpers / `dbutils.secrets` |

**Static resolution.** A target that is a plain name bound exactly once (in this or an earlier cell of the run, at module level including `for` / `while` / `if` / `with` / `try` bodies but not inside a function or class body) to a string literal is checked as that literal; `import x as y`, `from m import n as y`, `y = dbutils.fs`, `sp = spark`, `f = getattr`, `b = __builtins__`, `o = os` aliases are followed across cells and the alias is checked exactly like the thing it stands for. A name that once stood for a gated module, protected root, Spark object or dangerous builtin and is later rebound to something the gate cannot resolve (`f = make_getter()`, `os = fake()`) is refused wherever it is used afterwards (`NBP-INDIRECT`, fail closed). Anything else that is not a literal is a `*-DYNAMIC` refusal unless its rule id is in `AIDP_NOTEBOOK_POLICY_ALLOW`.

**Magic-led cells.** A cell whose first line is `%...` or `!...` is skipped as a whole by `dbutils.notebook.run`: no line of it is compiled or executed, and the skip is recorded in the policy log as `skipped_magic` (notebook path, cell index, first line). A `%magic` / `!command` line further down a cell is a `SyntaxError` for `exec`; the gate reports it as `NBP-OS-PROCESS` / `NBP-IPYTHON-ESCAPE` instead so the attempt is logged.

**Scope of the gate.** It is a static check of the forms listed above, not a Python sandbox, and a static AST gate over a full Python runtime is a mitigation layer: the platform-level control is the IAM scope of the cluster the notebook runs on (what the cluster's principal may read, write and call), and the runtime assertions are the enforcement layer for every write that goes through the compat helpers (`dbutils.fs.*`, `safe_io`, `dbutils.secrets`); Spark writes are covered by the AST rules plus the migrator's write-redirect interceptors. Not covered, by design or by limit: direct OCI SDK calls (`import oci` is allowed because migrated notebooks use the API-key init pattern); reads of source data through variables (`spark.read.parquet(src)`, `pd.read_csv(path)`): a reader path the gate cannot resolve is allowed and only recorded (`unverified_read_path`), because reading source data through parameters is the normal migration case and the cluster's IAM scope is the control there, and object-storage (`oci://`, `abfss://`, `s3://`) and catalog-table reads are never path-checked (a literal local path is, see `NBP-OPEN-PATH`); `spark.sql` read statements with run-time fragments (literal `SELECT` / `WITH` / `SHOW` / `DESCRIBE` / `EXPLAIN` head; recorded as `unverified_sql_read`); native Spark writers reached through objects the gate cannot see (a `DataFrameWriter` stored in a variable); the code of imported modules, including the in-tree module mirror the migrator itself puts on `sys.path` (`sys.path.insert` is therefore allowed; a notebook that writes a `.py` file into the sandbox and imports it runs unscanned code); third-party string evaluators (`sympy.sympify`, `jinja2` templates, `pandas.eval` / `DataFrame.query`); `spark.conf.get` and `sparkContext.getConf()` reads; directory listing (`os.listdir`, `Path.glob`); `tempfile`; `input()` / `help()`. `CREATE [OR REPLACE] [GLOBAL] TEMP VIEW` and plain `SELECT` are not writes. `dbutils.fs.mount(...)` keeps `extra_configs` in memory only (never in the process environment).

**Known false refusals** (deny-by-default; rewrite the cell or list the rule id in `AIDP_NOTEBOOK_POLICY_ALLOW` after review): `self.__dict__.update(kwargs)` and other `__dict__` reads (`NBP-DUNDER-ESCAPE`, use explicit attributes); `for k, v in opts.items(): setattr(self, k, v)` (`NBP-INDIRECT`, non-literal attribute name); iterating `globals()` / `locals()` (`NBP-INDIRECT`); `gzip.open(path_var)` and the other open-equivalents with a non-literal path (`NBP-OPEN-DYNAMIC`, same rule as `open(path_var)`); `torch.load(p)` (`NBP-DESERIALIZE`, pass `weights_only=True`), `pd.read_pickle` / `pickle.load` of your own files (`NBP-DESERIALIZE`, use parquet / json or allowlist); `spark.sparkContext._conf.getAll()` (`NBP-POLICY-TAMPER`, use `spark.sparkContext.getConf().getAll()`); `os._exit`; a name once bound to `spark` / `os` / `getattr` and later reused for something else (`NBP-INDIRECT`, use a fresh name); `%timeit` / `%%time` lines inside a cell body (`NBP-IPYTHON-ESCAPE`, they would not `exec` anyway); `tpl.format(obj)` / `TEMPLATES["x"].format(row=row)` where the template is not a literal the gate can resolve (`NBP-DUNDER-ESCAPE`, inline the template or bind it once to a literal); `writer.format(fmt_var)` on a `DataFrameWriter` held in a plain variable the gate cannot follow (`NBP-DUNDER-ESCAPE`, chain it from `df.write...` or bind `fmt_var` once to a literal); `spark.sql(f"USE {db}")`, `spark.sql("  " + q)` and other dynamic statements without a literal read-keyword head (`NBP-SQL-DYNAMIC`); `pd.read_csv("/Volumes/prod/in.csv")` and other literal local reads outside the prefix (`NBP-OPEN-PATH`, read through `oci://` or declare the volume as a prefix). Every refusal, allowed exception, skipped magic cell, unverified read (`unverified_read_path` / `unverified_sql_read`) and sandbox declaration is appended to the policy log (`get_policy_log()`, `policy_log_markdown()`); `job_migrate.py` pulls it into each task's test report as **Notebook Policy Log**.

---

## 9. What NOT to Use in Migrated Notebooks

âŒ **Direct JVM Hadoop FS calls** â€” `spark._jvm.org.apache.hadoop.fs.FileSystem.get(...)`, `fs.open(...)`, `fs.exists(...)`. These FAIL in scheduled workflow runs even though they work interactively.
**Use instead**: `dbutils.fs.*` (above) or OCI Python SDK directly.

âŒ **`oci.auth.signers.get_resource_principals_signer()`** â€” Known failure modes on AIDP.
**Use instead**: API key auth (see top of this doc).

âŒ **`boto3` for S3** â€” AWS SDK not configured on AIDP.
**Use instead**: `aidp_compat.s3_compat` for routing, or OCI SDK directly.

âŒ **`dbutils.notebook.run(path, 0, ...)`** â€” AIDP rejects `timeout=0`.
**Use instead**: `oidlUtils.notebook.run(path, timeout=3600, ...)`.

---

## 10. Quick Smoke Test

After installing the wheel, run this in a notebook to verify install:

```python
import os
from aidp_compat import dbutils

OCI_BASE = "oci://oracle_ai_automation@<WORKSPACE_NAMESPACE>/aidp_compat_smoke"
# Declare the sandbox first: dbutils.fs writes refuse without it (section 8).
os.environ.setdefault("AIDP_SANDBOX_CATALOG", "default")
os.environ.setdefault("AIDP_SANDBOX_SCHEMA", "<sandbox_schema>")
os.environ.setdefault("AIDP_SANDBOX_PREFIX", OCI_BASE + "/")
dbutils.fs.put(f"{OCI_BASE}/hi.txt", "hello", overwrite=True)
print(dbutils.fs.head(f"{OCI_BASE}/hi.txt", 100))
dbutils.fs.rm(f"{OCI_BASE}/", recurse=True)
print("âœ“ smoke test passed")
```

---

## 11. Changelog (recent)

| Version | Date | Highlights |
|---|---|---|
| unreleased | 2026-10 | `notebook_policy` mandatory sandbox gate on `notebook.run` + runtime assertions in `fs`/`safe_io` writers; `secrets` Vault-only by default (plaintext opt-in, `0600` file check, scope allowlist); gate is deny-by-default for indirect routes (builtins namespace, dunder / frame chains, IPython shell API and magics, Spark JVM / py4j bridge, deserialisers, process / debugger modules, rebound aliases) with new rule ids `NBP-DUNDER-ESCAPE`, `NBP-IPYTHON-ESCAPE`, `NBP-DESERIALIZE`; skipped magic-led cells are logged; round 2: `posix` / `nt` judged as `os`, one rule table for direct / aliased / imported / `getattr` access (`loop.subprocess_exec` added), `str.format` / `format_map` / `string.Formatter` templates resolved and walked (unresolvable template + run-time argument fails closed), literal local paths through library readers refused (`NBP-OPEN-PATH`; dynamic reader paths allowed and logged as `unverified_read_path`), dynamic `spark.sql` needs a literal read-keyword head (allowed and logged as `unverified_sql_read`; any other head is `NBP-SQL-DYNAMIC`), constants bound inside `for` / `if` / `with` / `try` bodies are resolved, `~` / Windows / `file://` paths are absolute on every host; `getattr(spark, "version")` and `"{0.__class__.__name__}".format(obj)` are no longer refused |
| **0.5.3** | 2026-05-20 | `cp/mv` OCI â†’ OCI now waits for async `copy_object` work-request to COMPLETE |
| 0.5.2 | 2026-05-20 | `cp` OCI â†’ OCI passes required `destination_region` to `copy_object` |
| 0.5.1 | 2026-05-20 | All `dbutils.fs.*` methods rewritten to use OCI Python SDK (API key) â€” works in workflow; `s3_compat`, `secrets` use API key auth; resource principal removed |
| 0.5.0 | (prior) | JVM Hadoop FS based; resource principal auth |
