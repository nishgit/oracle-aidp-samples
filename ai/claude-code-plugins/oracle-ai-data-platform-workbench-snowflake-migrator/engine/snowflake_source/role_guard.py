"""Prove the session's role is read-only BEFORE anything is discovered.

The transport refuses every non-read verb, so this plugin never writes to
Snowflake. A credential that reaches someone else is not bound by the
transport, though: what it can do is what its ROLE can do. So the first
thing a session does, before discovery or copy planning, is read the grants
of the role it holds and stop if any of them is a write on the source --
or can become one.

A role holds more than its own grants. `GRANT ROLE SYSADMIN TO ROLE MIG`
shows up in `SHOW GRANTS TO ROLE MIG` as one row, `USAGE on ROLE SYSADMIN`,
and nothing SYSADMIN itself holds is listed there -- yet MIG can do all of
it. The same goes for a database role (`USAGE on DATABASE_ROLE DB.WRITER`).
So the check WALKS the hierarchy: every role or database role a listing
names is listed in turn, with a visited set so a cycle terminates, and a
write found anywhere in the tree is a write the session can make. Each
offending grant says which inherited role carried it.

Not every grant is ON source data, and the ones that are not are judged
too. MANAGE GRANTS on the ACCOUNT lets a role grant itself any privilege,
INSERT on every table included; OWNERSHIP of a role or a user lets it take
over what they hold; CREATE ROLE, CREATE USER, EXECUTE TASK, the APPLY ...
POLICY privileges, CREATE SHARE and CREATE INTEGRATION each widen what the
credential can do or where the data can go. A grant on such a class is
therefore judged against a per-class ALLOWLIST of privileges that cannot
lead to a source write (`NON_SOURCE_PRIVILEGES`: USAGE and OPERATE on a
warehouse, USAGE on an integration, MONITOR USAGE on the account, ...), and
anything else on it is refused with the escalation named. On a source
class a privilege is a known read (`READ_PRIVILEGES`), a known write, or
unknown -- and unknown is refused as well, on every class. The check
cannot prove a privilege it does not know is harmless.

A system role (ACCOUNTADMIN, SECURITYADMIN, USERADMIN, SYSADMIN, ORGADMIN,
GLOBALORGADMIN) anywhere in the walked hierarchy is refused without
listing it: what those roles can do is set by Snowflake, not by the rows
`SHOW GRANTS` returns for them.

Future grants are read too (`SHOW FUTURE GRANTS TO ROLE`, and `TO DATABASE
ROLE` for a database role). A future INSERT on a schema is an INSERT on
every table created there later -- a write the session can make -- and is
judged by the same rules as a grant on an existing object.

The check fails CLOSED. A role whose grants or future grants cannot be
read, a session with no current role, a secondary-roles setting whose
roles cannot be named, or a listing cut off at Snowflake's 10,000-row cap
is refused the same as a role that holds INSERT: in each case the plugin
cannot prove the credential is read-only, and it does not guess.

Pure except for `run_sql`, which is injected; a fake cursor tests all of it.
"""
from __future__ import annotations

import json
from typing import Callable

from .conn import AuthError

__all__ = ["RoleNotReadOnly", "READ_PRIVILEGES", "WRITE_PRIVILEGES",
           "NON_SOURCE_PRIVILEGES", "NON_SOURCE_CLASSES", "ESCALATIONS",
           "SYSTEM_ROLES", "INHERITED_ROLE_CLASSES", "SHOW_GRANTS_CAP",
           "read_role_grants", "assert_role_read_only",
           "describe_role_grants"]

# The privileges on a source object (database, schema, table, view, stage,
# function, ...) that only read it or make it addressable. Anything else on
# a source class is refused: a known write by name, an unknown privilege as
# unproven. REFERENCE_USAGE lets a secure view reference the object;
# IMPORTED PRIVILEGES on a shared database confers what the share grants,
# and a share is read-only.
READ_PRIVILEGES = frozenset({
    "USAGE", "SELECT", "REFERENCES", "MONITOR", "READ", "REFERENCE_USAGE",
    "IMPORTED PRIVILEGES",
})

# A privilege that changes or removes a source object, or creates one inside
# it. OWNERSHIP implies every other. Any privilege spelled `CREATE ...` is
# a write too (CREATE TABLE, CREATE SCHEMA, CREATE DYNAMIC TABLE, ...) and
# is matched by prefix rather than listed. OPERATE on a task, pipe, alert
# or dynamic table starts or refreshes something that writes; APPLY on a
# policy or tag changes what a source object shows. Both are reads only on
# a warehouse, which the class allowlist below says.
WRITE_PRIVILEGES = frozenset({
    "ALTER", "DROP", "INSERT", "UPDATE", "DELETE", "MERGE", "TRUNCATE",
    "OWNERSHIP", "MODIFY", "WRITE", "EVOLVE SCHEMA", "REBUILD", "OPERATE",
    "APPLY",
})

# A grant ON one of these is not a privilege on data: it is another role the
# grantee holds, together with everything THAT role holds. Its grants are
# read too (`SHOW GRANTS TO ROLE` / `SHOW GRANTS TO DATABASE ROLE`).
INHERITED_ROLE_CLASSES = {"ROLE": "role", "DATABASE_ROLE": "database role"}

# Object classes a grant can be ON that are not source data, each with the
# privileges on it that cannot lead to a write on the source. A privilege
# on one of these classes that is NOT listed is refused, whatever it is:
# the escalations in `ESCALATIONS` with their reason, anything else as
# unknown. None of these classes is a table, view, schema or database of
# the estate being migrated, so a grant on one is not counted among the
# source privileges either.
#
#   WAREHOUSE    USAGE and OPERATE are what resuming the warehouse needs;
#                MONITOR reads its history; MODIFY changes its size, which
#                is the warehouse's business, not the source's.
#   INTEGRATION  USAGE of an existing integration (an external stage or
#                the key-pair/SSO integration the session authenticates
#                through); creating one is refused below.
#   ACCOUNT      MONITOR USAGE / EXECUTION / SECURITY read account history.
#                IMPORTED PRIVILEGES reads what another account shared.
#                CREATE DATABASE and CREATE WAREHOUSE are kept: a database
#                or warehouse the role creates is its own, new and empty,
#                not the estate being migrated, and discovery is scoped to
#                `database:` so nothing in it is read. MANAGE GRANTS is
#                NOT here: with it the role grants itself anything.
#   the rest     USAGE or MONITOR of an existing resource monitor, network
#                policy, compute pool, connection, replication or failover
#                group, external volume, application or share.
#   ROLE, DATABASE_ROLE, USER, APPLICATION_ROLE
#                nothing. USAGE on a ROLE or DATABASE_ROLE is the inherited
#                role itself and is followed before this table is read;
#                OWNERSHIP of a role or user is an escalation; an
#                application role's grants are not walked, so USAGE of one
#                is refused unproven.
_USAGE_MONITOR = frozenset({"USAGE", "MONITOR"})
NON_SOURCE_PRIVILEGES: dict[str, frozenset] = {
    "WAREHOUSE": frozenset({"USAGE", "OPERATE", "MONITOR", "MODIFY"}),
    "INTEGRATION": frozenset({"USAGE"}),
    "ACCOUNT": frozenset({"MONITOR USAGE", "MONITOR EXECUTION",
                          "MONITOR SECURITY", "IMPORTED PRIVILEGES",
                          "CREATE DATABASE", "CREATE WAREHOUSE"}),
    "RESOURCE_MONITOR": _USAGE_MONITOR,
    "NETWORK_POLICY": _USAGE_MONITOR,
    "COMPUTE_POOL": _USAGE_MONITOR,
    "CONNECTION": _USAGE_MONITOR,
    "REPLICATION_GROUP": _USAGE_MONITOR,
    "FAILOVER_GROUP": _USAGE_MONITOR,
    "EXTERNAL_VOLUME": _USAGE_MONITOR,
    "APPLICATION": _USAGE_MONITOR,
    "APPLICATION_PACKAGE": _USAGE_MONITOR,
    "SHARE": _USAGE_MONITOR,
    "ROLE": frozenset(),
    "DATABASE_ROLE": frozenset(),
    "USER": frozenset(),
    "APPLICATION_ROLE": frozenset(),
}
NON_SOURCE_CLASSES = frozenset(NON_SOURCE_PRIVILEGES)

# Why a privilege on a non-source class is refused, when the reason is a
# known path from "not a write" to "a write": each of these lets the role
# widen its own reach, change what the source shows, or move the data.
# A privilege on a non-source class that is neither allowed above nor
# named here (MANAGE ACCOUNT SUPPORT CASES, CREATE ACCOUNT, ...) is refused
# as unknown: harmless or not, the check cannot say.
ESCALATIONS = {
    "MANAGE GRANTS": ("lets the role grant itself any privilege, including "
                      "writes on every table"),
    "OWNERSHIP": ("the owner of an object can grant itself anything the "
                  "object confers: a role's grants, a user's sign-in"),
    "CREATE ROLE": "lets the role create roles it owns and grant them on",
    "CREATE USER": "lets the role create a user it owns and sign in as it",
    "CREATE INTEGRATION": ("lets the role stand up a path for data to leave "
                           "the account"),
    "CREATE SHARE": "lets the role share the source out of the account",
    "APPLY MASKING POLICY": "lets the role change what source columns show",
    "APPLY ROW ACCESS POLICY": ("lets the role change which source rows are "
                                "visible"),
    "APPLY AGGREGATION POLICY": ("lets the role change how the source may be "
                                 "queried"),
    "APPLY TAG": "lets the role change the tags that drive source policies",
    "APPLY AUTHENTICATION POLICY": ("lets the role change how users sign "
                                    "in"),
    "EXECUTE TASK": "lets the role run tasks, which write",
    "EXECUTE MANAGED TASK": "lets the role run serverless tasks, which write",
    "MANAGE WAREHOUSES": ("lets the role control every warehouse, more than "
                          "reading needs"),
}

_WRITE = "a write on the source"
_UNKNOWN = ("not a privilege this check knows to be read-only, so it is "
            "refused unproven")

# Roles whose reach Snowflake defines; a session that is, holds or inherits
# one is refused without reading its grants. Compared case-insensitively.
SYSTEM_ROLES = frozenset({
    "ACCOUNTADMIN", "SECURITYADMIN", "USERADMIN", "SYSADMIN", "ORGADMIN",
    "GLOBALORGADMIN",
})

# SHOW GRANTS returns at most this many rows. A listing that long may have
# been cut, so it cannot prove anything.
SHOW_GRANTS_CAP = 10_000


class RoleNotReadOnly(AuthError):
    """The role is not provably read-only on the source. Nothing ran."""


def _lower_keys(row: dict) -> dict:
    return {str(k).lower(): v for k, v in (row or {}).items()}


def _quote_role(name: str) -> str:
    return '"' + str(name).replace('"', '""') + '"'


def _split_identifier(name: str) -> list[str]:
    """The parts of a dotted identifier as SHOW GRANTS prints it, unquoted.

    A quoted part is read up to its closing quote (a doubled quote inside
    is one quote) and kept as written; an unquoted part is kept as written
    too, since SHOW GRANTS prints the stored name. The parts are requoted
    one by one to address the object again, so a dot inside a quoted part
    stays inside it.
    """
    text = str(name or "").strip()
    parts: list[str] = []
    buf: list[str] = []
    quoted = False
    i = 0
    while i < len(text):
        ch = text[i]
        if quoted:
            if ch == '"':
                if i + 1 < len(text) and text[i + 1] == '"':
                    buf.append('"')
                    i += 2
                    continue
                quoted = False
            else:
                buf.append(ch)
        elif ch == '"':
            quoted = True
        elif ch == ".":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return parts


def _sql_name(listed: str) -> str:
    """A name from a SHOW GRANTS row, requoted part by part for a statement."""
    return ".".join(_quote_role(p) for p in _split_identifier(listed))


def _database_of(name: str) -> str:
    """The first identifier of a dotted object name, unquoted and folded.

    SHOW GRANTS names a table `DB.SCHEMA.TABLE`, a schema `DB.SCHEMA` and a
    database `DB`, quoting any part that needs it. Only the database part
    is wanted here, so a quoted first part is read up to its closing quote
    and kept as written (a quoted identifier IS its case); an unquoted one
    folds to upper case, as Snowflake resolves it. `_unquote` applies the
    same rule to the config's `database:`, so the two compare equal.
    """
    text = str(name or "").strip()
    if text.startswith('"'):
        end, i = -1, 1
        while i < len(text):
            if text[i] == '"':
                if i + 1 < len(text) and text[i + 1] == '"':
                    i += 2
                    continue
                end = i
                break
            i += 1
        return text[1:end].replace('""', '"') if end > 0 else text[1:]
    return text.split(".", 1)[0].upper()


def _is_write(privilege: str) -> bool:
    p = str(privilege or "").strip().upper()
    return p in WRITE_PRIVILEGES or p.startswith("CREATE")


def _refusal(privilege: str, granted_on: str) -> str | None:
    """Why a grant of `privilege` ON a `granted_on` is refused; None when it
    cannot lead to a write on the source.

    A non-source class is judged by its allowlist; a source class by the
    read list. Either way a privilege the check does not know is refused:
    the burden of proof is on the grant.
    """
    allowed = NON_SOURCE_PRIVILEGES.get(granted_on)
    if allowed is not None:
        if privilege in allowed:
            return None
        if privilege in ESCALATIONS:
            return ESCALATIONS[privilege]
        if granted_on == "APPLICATION_ROLE":
            return ("an application role's grants are not walked by this "
                    "check, so what it holds is unproven")
        return _UNKNOWN
    if privilege in READ_PRIVILEGES:
        return None
    if _is_write(privilege):
        return _WRITE
    return _UNKNOWN


def _unquote(value) -> str:
    text = str(value or "").strip()
    if len(text) >= 2 and text[0] == text[-1] == '"':
        return text[1:-1].replace('""', '"')
    return text.upper()


def _refuse_system_role(name: str, described: str) -> None:
    """Stop if `name` is a system role. `described` names it and says where
    in the hierarchy it was found."""
    if _unquote(name).upper() not in SYSTEM_ROLES:
        return
    raise RoleNotReadOnly(
        f"{described} is a system role: what a system role can do is set by "
        f"Snowflake, not by its grants listing, so the session is refused "
        f"without reading it and is not provably read-only. The migration "
        f"role must not be, hold or inherit "
        f"{', '.join(sorted(SYSTEM_ROLES))}; set `role:` to a dedicated "
        f"read-only role.")


_SECONDARY_HELP = (
    "Run with --only-primary-role to scope the session to `role:` alone, or "
    "set the user's DEFAULT_SECONDARY_ROLES to none.")


def _roles_granted_to_user(run_sql: Callable[..., list], role: str
                           ) -> list[str]:
    """Every role granted to the session's user, besides `role`.

    `USE SECONDARY ROLES ALL` puts every role granted to the user in effect,
    and `current_secondary_roles()` names them -- except when it does not
    (an empty `roles` next to `value: ALL`). The user's own grants list is
    the authority then; when it cannot be read the session is refused,
    because the roles in effect are unknown.
    """
    try:
        rows = run_sql("select current_user() U")
        user = _lower_keys(rows[0]).get("u") if rows else None
        if not user:
            raise ValueError("the session has no current user")
        listing = run_sql(f"show grants to user {_quote_role(user)}")
    except Exception as exc:
        raise RoleNotReadOnly(
            "secondary roles are active (USE SECONDARY ROLES ALL) but the "
            f"roles in effect could not be read ({str(exc)[:200]}). The "
            "migration does not run on a session whose roles it cannot "
            f"name. {_SECONDARY_HELP}") from exc
    if len(listing) >= SHOW_GRANTS_CAP:
        raise RoleNotReadOnly(
            f"the user holds {len(listing)} role grants, at or over SHOW "
            f"GRANTS' {SHOW_GRANTS_CAP}-row cap; the listing may be cut, "
            f"so the roles in effect are unknown. {_SECONDARY_HELP}")
    names: list[str] = []
    for raw in listing:
        name = str(_lower_keys(raw).get("role") or "").strip()
        if name and name != role and name not in names:
            names.append(name)
    return names


def _session_roles(run_sql: Callable[..., list]) -> tuple[str, list[str]]:
    rows = run_sql("select current_role() R, current_secondary_roles() S")
    row = _lower_keys(rows[0]) if rows else {}
    role = row.get("r")
    if not role:
        raise RoleNotReadOnly(
            "the session has no current role, so its privileges cannot be "
            "read. Set `role:` in the migration config to a read-only role.")
    role = str(role)
    names, mode = "", ""
    raw = row.get("s")
    if raw:
        try:
            parsed = json.loads(raw) if isinstance(raw, str) else raw
            names = str((parsed or {}).get("roles") or "")
            mode = str((parsed or {}).get("value") or "").strip().upper()
        except (ValueError, TypeError, AttributeError) as exc:
            raise RoleNotReadOnly(
                "current_secondary_roles() returned a shape this cannot read, "
                "so the roles in effect are unknown and the session is not "
                f"provably read-only. {_SECONDARY_HELP}") from exc
    secondary = []
    for part in names.split(","):
        name = part.strip()
        if name and name != role and name not in secondary:
            secondary.append(name)
    if mode == "ALL" and not secondary:
        # Every role granted to the user is in effect, unnamed. Name them
        # from the user's grants, or stop: an empty list here would pass a
        # session whose other roles were never checked.
        secondary = _roles_granted_to_user(run_sql, role)
    return role, secondary


def _list_grants(run_sql: Callable[..., list], kind: str, sql_name: str,
                 label: str, *, future: bool = False) -> list:
    """One `SHOW [FUTURE] GRANTS TO <kind> <name>`, complete or refused."""
    what = "future grants" if future else "grants"
    try:
        rows = run_sql(f"show {what} to {kind} {sql_name}")
    except Exception as exc:
        raise RoleNotReadOnly(
            f"the {what} of {label} could not be read "
            f"({str(exc)[:200]}). The migration does not run against a "
            f"role whose privileges it cannot prove read-only.") from exc
    if len(rows) >= SHOW_GRANTS_CAP:
        raise RoleNotReadOnly(
            f"{label} holds {len(rows)} {what}, at or over SHOW GRANTS' "
            f"{SHOW_GRANTS_CAP}-row cap; the listing may be cut, so it "
            f"cannot prove the role is read-only. Use a narrower role for "
            f"the migration.")
    return rows


def read_role_grants(run_sql: Callable[..., list], *,
                     database: str | None = None) -> dict:
    """Every grant the session's roles hold, judged against the source.

    The session's primary and secondary roles are listed with `SHOW GRANTS
    TO ROLE` and `SHOW FUTURE GRANTS TO ROLE`, and every role or database
    role a listing names is listed in turn, so a write inherited through
    the role hierarchy counts the same as one granted directly. A system
    role met anywhere refuses the session before it is listed.

    Returns evidence, never a credential:

        role, secondary_roles  -- what the session holds
        inherited_roles        -- roles reached through those, as
                                  "role NAME" / "database role DB.NAME"
        grants_read            -- rows read across every SHOW GRANTS
        future_grants_read     -- rows read across every SHOW FUTURE GRANTS
        by_privilege           -- {privilege: count} over the source; a
                                  future grant counts as "PRIV (future)"
        write_grants           -- the refused rows, each
                                  {role, privilege, granted_on, name, via,
                                   future, reason}
                                  (`via` names the inherited role chain
                                  that carried it, None for a direct grant;
                                  `reason` says why it is refused: a write,
                                  an escalation, or unknown)
        out_of_scope_writes    -- refused rows on OTHER databases (reported
                                  only)
        read_only              -- True when write_grants is empty

    Raises RoleNotReadOnly when the grants cannot be read in full, or a
    system role is in the hierarchy: the caller must treat that as a
    failure, not as a pass.
    """
    role, secondary = _session_roles(run_sql)
    _refuse_system_role(role, f"the session's role {role}")
    for name in secondary:
        _refuse_system_role(name, f"the session's secondary role {name}")
    scope = _unquote(database) if database else None
    grants_read = 0
    future_read = 0
    by_privilege: dict[str, int] = {}
    writes: list[dict] = []
    inherited: list[str] = []
    out_of_scope = 0
    # (session role it descends from, kind, quoted name, inherited chain,
    #  what to call it in a refusal)
    pending = [(name, "role", _quote_role(name), None, f"role {name}")
               for name in [role, *secondary]]
    seen = {(kind, sql_name) for _, kind, sql_name, _, _ in pending}
    while pending:
        held_by, kind, sql_name, via, label = pending.pop(0)
        for future in (False, True):
            rows = _list_grants(run_sql, kind, sql_name, label, future=future)
            if future:
                future_read += len(rows)
            else:
                grants_read += len(rows)
            for raw in rows:
                row = _lower_keys(raw)
                # SHOW GRANTS says `granted_on`; SHOW FUTURE GRANTS `grant_on`.
                granted_on = str(row.get("granted_on")
                                 or row.get("grant_on") or "").upper()
                privilege = str(row.get("privilege") or "").upper()
                obj = str(row.get("name") or "")
                if (granted_on in INHERITED_ROLE_CLASSES
                        and privilege == "USAGE" and not future):
                    # Another role this one holds: its grants are ours too.
                    sub_kind = INHERITED_ROLE_CLASSES[granted_on]
                    sub_sql = _sql_name(obj)
                    if (sub_kind, sub_sql) not in seen:
                        seen.add((sub_kind, sub_sql))
                        shown = (obj if sub_kind == "role"
                                 else f"{sub_kind} {obj}")
                        chain = shown if via is None else f"{via} -> {shown}"
                        if sub_kind == "role":
                            _refuse_system_role(
                                obj, f"role {obj}, granted to role "
                                     f"{held_by} via {chain},")
                        inherited.append(f"{sub_kind} {obj}")
                        pending.append((held_by, sub_kind, sub_sql, chain,
                                        f"{sub_kind} {obj} (granted to role "
                                        f"{held_by})"))
                    continue
                reason = _refusal(privilege, granted_on)
                if granted_on in NON_SOURCE_CLASSES:
                    # Not a source object: not counted among the source
                    # privileges, refused only when it leads somewhere.
                    if reason is not None:
                        writes.append({"role": held_by, "privilege": privilege,
                                       "granted_on": granted_on, "name": obj,
                                       "via": via, "future": future,
                                       "reason": reason})
                    continue
                # A row with no object name cannot be placed outside the
                # source, so it is judged as inside it.
                if scope and obj and _database_of(obj) != scope:
                    if reason is not None:
                        out_of_scope += 1
                    continue
                key = f"{privilege} (future)" if future else privilege
                by_privilege[key] = by_privilege.get(key, 0) + 1
                if reason is not None:
                    writes.append({"role": held_by, "privilege": privilege,
                                   "granted_on": granted_on, "name": obj,
                                   "via": via, "future": future,
                                   "reason": reason})
    return {"role": role, "secondary_roles": secondary,
            "inherited_roles": inherited,
            "database": scope, "grants_read": grants_read,
            "future_grants_read": future_read,
            "by_privilege": dict(sorted(by_privilege.items())),
            "write_grants": writes, "out_of_scope_writes": out_of_scope,
            "read_only": not writes}


def _roles_text(evidence: dict) -> str:
    text = evidence["role"]
    if evidence.get("secondary_roles"):
        text += f' (+ secondary {", ".join(evidence["secondary_roles"])})'
    if evidence.get("inherited_roles"):
        text += f' (+ inherited {", ".join(evidence["inherited_roles"])})'
    return text


def _write_text(w: dict) -> str:
    text = (("future " if w.get("future") else "")
            + f'{w["privilege"]} on {w["granted_on"]} {w["name"] or "?"}')
    text += f' via {w["via"]}' if w.get("via") else ""
    return text + (f' ({w["reason"]})' if w.get("reason") else "")


def describe_role_grants(evidence: dict) -> str:
    """One line of evidence for a report or a console. No values."""
    roles = _roles_text(evidence)
    where = (f' on {evidence["database"]}' if evidence.get("database")
             else " on the account's objects")
    held = ", ".join(f"{p} x{n}" for p, n in evidence["by_privilege"].items()
                     ) or "none"
    read = f'{evidence["grants_read"]} grant(s)'
    if evidence.get("future_grants_read"):
        read += f' and {evidence["future_grants_read"]} future grant(s)'
    extra = (f'; {evidence["out_of_scope_writes"]} refused grant(s) on other '
             f'databases, outside this migration'
             if evidence.get("out_of_scope_writes") else "")
    if evidence["read_only"]:
        return (f"role {roles} is read-only{where}: {read} read, "
                f"held: {held}{extra}")
    shown = [_write_text(w) for w in evidence["write_grants"][:5]]
    more = len(evidence["write_grants"]) - len(shown)
    return (f"role {roles} holds privilege(s) that write the source or lead "
            f"to a write{where}: "
            + ", ".join(shown) + (f" (+{more} more)" if more > 0 else "")
            + ". The migration role must be read-only: grant it USAGE and "
              "SELECT only, nothing on the account beyond warehouse usage, "
              "and no role that holds more, or set `role:` to one that is"
            + extra)


def assert_role_read_only(run_sql: Callable[..., list], *,
                          database: str | None = None) -> dict:
    """The evidence, or RoleNotReadOnly. Call before the first read."""
    evidence = read_role_grants(run_sql, database=database)
    if not evidence["read_only"]:
        raise RoleNotReadOnly(describe_role_grants(evidence))
    return evidence
