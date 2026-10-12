# Changelog

All notable changes to this plugin are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Security
- Cluster-side dependency resolution no longer installs an import name just because a PyPI
  package of that name exists; only curated mappings are installed and the rest are
  reported for the operator to add explicitly. The generated availability check follows
  the same rule.
- `aidp_executor` session calls carry a timeout; `run_migration.sh` logs to a private
  temp file and asks for `kill <PID>` instead of `pkill -f`.
- **Mandatory notebook sandbox gate** (`engine/aidp_compat/notebook_policy.py`,
  SEC-AIDP-SAMPLES-005). `dbutils.notebook.run` refuses to execute anything until a sandbox
  (`AIDP_SANDBOX_CATALOG` / `AIDP_SANDBOX_SCHEMA` / `AIDP_SANDBOX_PREFIX`, or an explicit
  `SandboxPolicy`) is declared, and AST-checks every non-magic cell before `exec`: process /
  network imports, `os.environ` / `os.getenv` / `os.system` / `os.popen` / `os.exec*`,
  `shutil.rmtree`, `eval` / `exec` / `compile` / `__import__`, `open()` on absolute paths
  outside the prefix, and `dbutils.fs.rm/mv/cp/put`, `saveAsTable` / `insertInto`,
  `df.write.*`, `spark.sql` DDL/DML whose literal target leaves the sandbox are refused with a
  `PermissionError` naming notebook path, cell index, rule id and remediation. Non-literal
  write targets are refused unless the rule id is listed in `AIDP_NOTEBOOK_POLICY_ALLOW`.
  `dbutils.fs.rm/mv/cp/put` and the `safe_io` write helpers assert their target at runtime.
  Refusals and allowed exceptions are recorded in a policy log that `job_migrate.py` renders
  into each task's test report (**Notebook Policy Log**); the cluster bootstrap declares the
  write-redirect schema/bucket as the sandbox automatically.
- **Sandbox gate hardening** (review of SEC-AIDP-SAMPLES-005 / 006). The bootstrap now also
  declares the staging areas the migrator itself generates (`/Volumes/default/default/dbfs/`,
  `/tmp/`) and the output directory as sandbox prefixes, so migrated FUSE / local writes are
  not refused. The policy is a one-shot snapshot per kernel: later `AIDP_SANDBOX_*` changes are
  ignored and redeclaring / clearing it is refused (`NBP-POLICY-TAMPER`). `path_in_sandbox`
  canonicalises paths, refuses `..` segments and (POSIX) symlinks leading outside. The AST gate
  follows import / shim aliases and single-assignment string constants across cells, refuses
  `importlib` / `builtins` / `sys.modules` / `getattr(os, ..)` (`NBP-INDIRECT`), imports and
  attribute rebinding of the compat shims and policy module (`NBP-POLICY-TAMPER`),
  `os.remove/rename/mkdir...`, `shutil.move/copy*` and `pathlib` file operations
  (`NBP-FS-PATH` / `NBP-FS-DYNAMIC`), `writeTo`, `option("path")` / `options(path=)`,
  double-quoted `LOCATION` and `OPTIONS (path ...)`, `dbutils.fs.mkdirs`, `os.fork`,
  `asyncio` subprocess helpers and more network modules; `open()` with an unresolvable path is
  refused in any mode and `spark.sql()` with an unresolvable statement is `NBP-SQL-DYNAMIC`.
  `dbutils.fs.mkdirs` asserts its target at runtime; `dbutils.fs.mount` no longer writes
  `extra_configs` to the process environment.
- **Sandbox gate: deny-by-default for indirect routes** (SEC-AIDP-SAMPLES-005 re-verification).
  The reviewer's probes `__builtins__['__import__']('os').system('id')`,
  `__builtins__['open']('/etc/passwd')`, `globals()['__builtins__'][...]`,
  `get_ipython().system('id')`, `spark._jvm...` and `sc._jvm...` all passed the AST gate at
  d877d90. The scanner now resolves the builtins namespace through every door (`__builtins__`,
  `builtins`, `globals()` / `locals()` / `vars()`, `__dict__`, `getattr`) and checks the resolved
  builtin exactly like the direct form (`NBP-BUILTIN-EXEC` / `NBP-OPEN-PATH`), refusing any
  non-literal key and any other use of the frame namespace (`NBP-INDIRECT`); refuses `getattr` /
  `setattr` / `delattr` with a non-literal name, `pkgutil` / `runpy` / `code` / `zipimport` /
  private `_modules`, `sys.settrace` / `meta_path`, `inspect` frames and `gc.get_objects`;
  refuses dunder / frame introspection chains (`__subclasses__`, `__globals__`, `__dict__`,
  `__code__`, `f_globals`, `tb_frame`, ...) under the new `NBP-DUNDER-ESCAPE` (dunder
  definitions in class bodies stay allowed); refuses the IPython shell API (`get_ipython` call
  or name, `InteractiveShell`, `IPython` imports, `%magic` / `!cmd` lines inside a cell body)
  under `NBP-OS-PROCESS` for shell / magic execution and the new `NBP-IPYTHON-ESCAPE`
  otherwise, and logs the magic-led cells `dbutils.notebook.run` skips (`skipped_magic`; no
  line of such a cell is executed); refuses the Spark JVM / py4j bridge (any `_private`
  attribute of `spark` / `sc` / `SparkSession` / `SparkContext`, `_jvm` / `_jsc` / `_gateway` /
  `_jdf` / ... on any object, `py4j`, `JavaGateway`, `registerJavaFunction`, `addPyFile` /
  `addJar`) under `NBP-POLICY-TAMPER` / `NBP-BUILTIN-EXEC`; refuses further process / exec
  routes (`concurrent.futures.ProcessPoolExecutor`, `os.posix_spawn` / `forkpty` / `kill`,
  `cffi`, `signal`, `resource`, `pdb`, `timeit`, `cProfile`, `doctest`, `webbrowser`,
  `types.FunctionType`, `breakpoint()`), code-executing deserialisers (`pickle` / `marshal` /
  `shelve` / `dill` / `joblib` loads, `read_pickle`, `yaml.load` without a safe loader,
  `torch.load` without `weights_only=True`, `numpy.load(allow_pickle=True)`; new
  `NBP-DESERIALIZE`), the stdlib open-equivalents (`io.open`, `os.open`, `codecs` / `gzip` /
  `bz2` / `lzma` / `tarfile` / `zipfile` / `sqlite3` / `linecache`) on paths outside the sandbox
  and `os.chdir` away from it; and follows aliases of all of these across cells (`sp = spark`,
  `f = getattr`, `b = __builtins__`), refusing a name that was rebound to something it cannot
  resolve (fail closed). The test suite adds the reviewer's six probes verbatim plus per-class
  refused and clean cells; every new test fails against the d877d90 scanner. The gate remains a
  static mitigation layer over a full Python runtime; the platform-level control is the IAM
  scope of the cluster (documented in `SUPPORTED_OPERATIONS.md` section 8 together with the
  known false refusals).
- **Sandbox gate: round-2 gaps closed by generalising the rules** (static review of the
  SEC-AIDP-SAMPLES-005 gate at edcb186). `posix` / `nt`, the platform modules `os` re-exports,
  are tracked as aliases of `os`, so `import posix; posix.system(..)`, `from posix import
  environ`, `import nt as n; n.environ` meet every os rule. The os / shutil / sys.modules /
  importlib / asyncio / aidp_compat attribute rules moved into the one rule table that already
  served `getattr(mod, "literal")`, `from m import n` aliases and imports, so the indirect
  route (`asyncio.run(getattr(asyncio, "create_subprocess_exec")(..))`) is judged exactly like
  the direct one; `loop.subprocess_exec` / `subprocess_shell` added. `str.format` templates are
  resolved like any other target (a literal, a name bound once in this or an earlier cell,
  `"a" + "b"`, `textwrap.dedent(..)`, `.strip()`) and every replacement field is walked
  (`format_map`, `str.format(t, ..)`, `string.Formatter().format / vformat`, nested format-spec
  fields) against the dunder read allowlist, so `t = "{0.__class__.__mro__}"; t.format(obj)`
  and `"{x.__init__.__globals__[os].environ}".format_map(..)` are `NBP-DUNDER-ESCAPE` while
  `"{0.__class__.__name__}".format(obj)` is no longer refused; an unresolvable template
  formatted with a run-time argument fails closed. Local file reads through library readers
  (`pandas` / `polars` / `pyarrow` / `xarray` `read_*`, `numpy.load*`, `spark.read.<fmt>` /
  `load` / `option("path")`, `sc.textFile`, `PIL.Image.open`, `h5py.File`,
  `ElementTree.parse`, ...) with a literal local path (`/etc`, `/dbfs`, `/Workspace`, `/tmp`,
  `~`, `C:\`, `file://`) outside the prefix are `NBP-OPEN-PATH`; scope decision: a reader path
  the gate cannot resolve is allowed (reading source data through variables is the normal
  migration case; the cluster's IAM scope is the control) and recorded in the policy log as
  `unverified_read_path`, and object-storage / catalog reads are never path-checked. Scope
  decision for dynamic SQL: a `spark.sql` statement whose literal head (after whitespace and
  comments) is `SELECT` / `WITH` / `SHOW` / `DESCRIBE` / `DESC` / `EXPLAIN` (or a TEMP VIEW)
  cannot become a write because Spark runs one statement per call, so it is allowed and
  recorded as `unverified_sql_read`; every other dynamic head (DDL/DML, `USE`, empty, a
  variable) is `NBP-SQL-DYNAMIC`, which also closes `spark.sql(f"{verb} TABLE prod.t")`.
  Constants bound once inside `for` / `if` / `with` / `try` bodies are resolved (the loop-bound
  `q = "SELECT .." + str(cid); spark.sql(q)` false refusal); `getattr(spark, "version")` and
  other literal public names on Spark objects are allowed (dynamic, private and dunder names,
  and the interpreter / compat roots, stay refused); `~`, Windows drive / UNC and `file://`
  paths count as absolute on every host. Every new refused / allowed cell is in the test suite
  and fails against the edcb186 scanner.
- Python 3.9 floor: `cluster_lifecycle.py` and `fuse_package_analyzer.py` used PEP 604
  `X | None` annotations evaluated at import time; `from __future__ import annotations` added.
- **Secrets shim is Vault-only by default** (`engine/aidp_compat/secrets.py`,
  SEC-AIDP-SAMPLES-006). `AIDP_SECRET_*` environment scanning and the JSON file fallback
  (now only via an explicit `AIDP_SECRETS_FILE`) happen only with
  `AIDP_ALLOW_PLAINTEXT_SECRETS=1`; the file must be owner-only (`0600`) on POSIX (skipped
  with a note on Windows); plaintext mode logs one `insecure plaintext secrets mode active`
  line without values; `AIDP_SECRET_SCOPES` restricts `get` / `list` / `listScopes` to
  allowlisted scopes and list operations never reveal values. The allowlist is created during
  planning: `job_migrate.py` collects the `dbutils.secrets.get(scope, key)` literals of each
  task and declares `AIDP_SECRET_SCOPES` / `AIDP_SECRET_KEYS` (`scope/key`, `scope/*`) in the
  cluster bootstrap (`none` before the first task; an operator-provided value wins); the shim
  reads both per call and logs refusals as `NBP-RUNTIME-SECRET`.
- **`get_tool_output` is confined to the tool output directory**
  (`engine/scripts/context_compactor.py`, `agent_migrate.py`, SEC-AIDP-SAMPLES-DBX-NEW-01).
  The model-callable tool passed its `filename` argument straight to `os.path.join` + `open`,
  so an indirect prompt injection in customer notebook content could read any file the
  consultant's account can read (`../../../oci_api_key.pem`, absolute paths) into model
  context. `ContextCompactor.get_saved_output` now accepts only the bare
  `tool_<NNN>_<tool>.txt` names it generates itself, additionally resolves the path with
  `os.path.realpath` and requires it to be a direct child of the compactor directory (so a
  planted symlink cannot escape either), logs refusals and returns a
  `[context_compactor] Refused` string; `_handle_get_tool_output` validates before consulting
  any compactor and stops walking the compactor history on a refusal. "File not found" and
  read errors no longer echo the host path or non-output files. The name allow-list is
  anchored with `\A`/`\Z`, applied with `fullmatch` and restricted to ASCII digits, so a
  newline-terminated name or one spelt with non-ASCII decimal digits is refused before any
  filesystem access instead of reaching `open()`.
- **The Databricks PAT no longer travels on the command line**
  (`engine/scripts/extract_catalog_databricks.py`, SEC-NEW-DATABRICKS-03). `--token <value>`
  is refused with exit code 2 and the message "Do not pass tokens in argv. Use
  DATABRICKS_TOKEN or --token-file." -- the flag is kept only so an old command fails loudly
  instead of being re-parsed, and the value is never stored or echoed. `--token-file <path>`
  reads the PAT from a file only its owner can read (mode & 0o077 must be 0 on POSIX; on
  Windows, where `st_mode` carries no such bits, the check is skipped with a note).
  `DATABRICKS_TOKEN` keeps working and the file wins when both are present. A `--host` /
  `DATABRICKS_HOST` of the form `https://user:token@workspace` is rejected. Output names the
  token's *source*, never the token, and the token is redacted (`***`) from error text the
  script prints or stores in the catalog pack. Mistyped forms are not echoed either:
  abbreviated long options are off and unknown arguments are reported by count, so
  `--tok=<value>`, `-t <value>` or a bare value exit 2 with the remediation text instead of
  argparse's own "ambiguous option: ..." / "unrecognized arguments: ..." diagnostics, which
  repeat the value; every parser error message is also scrubbed of the argv values as defence
  in depth. `extract_catalog_databricks.py` is the only entry point that talks to Databricks;
  the other `engine/scripts/*.py` entry points take no credential on argv (they talk to AIDP
  with the OCI profile, or read the model API key, `ANTHROPIC_API_KEY`, from the environment).
- Added `engine/tests/` (pytest) covering these controls; `pytest.ini` scopes collection to
  them.

## [0.2.0] — 2026-06-24

**Self-contained engine bundled.** The plugin no longer requires a separate clone of the migrator toolkit. The full Python engine ships under `engine/` and is invoked from skills via `${CLAUDE_PLUGIN_ROOT}/engine/scripts/...`.

### Added

- **`engine/` directory bundled with the plugin:**
  - `engine/scripts/` — Python engine modules (`job_migrate.py`, `agent_migrate.py`, `cluster_session.py`, `aidp_executor.py`, `build_dag.py`, `check_data_availability.py`, `migrate_catalog.py`, `extract_catalog_databricks.py`, `acceptance_contract.py`, `fixup_cell` helpers, etc.)
  - `engine/aidp_compat/` — 21 Python files (drop-in `dbutils` compatibility shim)
  - `engine/schemas/` — JSON schemas (acceptance contract)
  - `engine/setup.py`, `engine/requirements.txt` — Python package metadata + deps
  - `engine/run_migration.sh` — generic convenience script
- LICENSE at plugin root (MIT).

### Changed

- All 10 SKILL.md script-path examples updated from `python3 scripts/...` to `python3 ${CLAUDE_PLUGIN_ROOT}/engine/scripts/...`.
- `references/cli-map.md` updated to canonical bundled-engine paths.
- `README.md` Prerequisites section: "Clone the migrator repo" → "the engine ships bundled — just `pip install -r ${CLAUDE_PLUGIN_ROOT}/engine/requirements.txt`".
- `PRIVACY.md`: "knowledge-only" framing → "self-contained, bundled engine, no telemetry".
- All hardcoded customer identifiers (OCIDs, UUIDs, region, namespaces, customer name, workspace paths, internal hostnames, personal usernames) in the bundled engine replaced with `<PLACEHOLDER>` style values.

### Security / governance

- Generalized examples and identifiers from the source migration toolkit so the public plugin is engagement-neutral.
- Source customer output artifacts (`reports/`, `dbx_export/`) removed from the source repo.

## [0.1.0] — 2026-06-20 (initial release)

First public release of the Claude Code plugin for the Oracle AIDP Databricks Migration Toolkit.

### Skills (10)

- `aidp-migrator-overview` — router / lay of the toolkit
- `aidp-migrator-bootstrap` — environment readiness check (Python deps, OCI auth, cluster state, env-coords)
- `aidp-build-dag` — build migration manifest from a Databricks workspace path
- `aidp-check-data` — pre-migration data-availability scan
- `aidp-migrate-job` — Pass-1 deps + Pass-2 cell-by-cell execute/verify/fix on a live AIDP cluster
- `aidp-fixup-cell` — targeted rewind: re-execute cells from a history index
- `aidp-resume-migration` — resume an interrupted run
- `aidp-migrate-catalog` — Unity Catalog / HMS DDL → 18-rule rewriter → batched replay
- `aidp-bucket-mapping` — `s3://` → `oci://` bucket/namespace mapping config
- `aidp-acceptance-contract` — consecutive-zero-window convergence for batch / streaming

### Slash commands (4)

- `/migrate-job` — guided full-job migration flow
- `/migrate-catalog` — guided catalog migration flow
- `/check-data` — data-availability scan
- `/migration-status` — parse + summarize a `JOB_REPORT.md`

### Agents (2)

- `databricks-notebook-analyzer` — pre-migration notebook analysis
- `migration-reviewer` — post-Pass-2 migrated-notebook correctness review

### References (5)

- DDL rewrite rules (18 rules with examples)
- 15 Databricks → AIDP gotchas + fix recipes
- Env-coords scaffold
- `JOB_REPORT.md` parsing format
- CLI map (every migrator entrypoint → purpose + canonical invocation)
