"""The role gate (SEC-AIDP-SAMPLES-001): before any discovery, the session's
role is proven read-only on the source, and the check fails CLOSED.

All of it runs against a fake cursor: `run_sql` is injected everywhere.
"""
import json

import pytest

from snowflake_source.conn import AuthError
from snowflake_source.role_guard import (
    RoleNotReadOnly, SHOW_GRANTS_CAP, assert_role_read_only,
    describe_role_grants, read_role_grants)


def _grant(privilege, granted_on, name):
    # The columns SHOW GRANTS TO ROLE returns, as the cursor hands them back.
    return {"created_on": "2026-01-01", "privilege": privilege,
            "granted_on": granted_on, "name": name, "granted_to": "ROLE",
            "grantee_name": "READER", "grant_option": "false",
            "granted_by": "SECURITYADMIN"}


READ_ONLY = [
    _grant("USAGE", "DATABASE", "SALES_DB"),
    _grant("USAGE", "SCHEMA", "SALES_DB.PUBLIC"),
    _grant("SELECT", "TABLE", "SALES_DB.PUBLIC.ORDERS"),
    _grant("SELECT", "VIEW", "SALES_DB.PUBLIC.V_ORDERS"),
    _grant("REFERENCES", "TABLE", "SALES_DB.PUBLIC.ORDERS"),
    # Resuming the warehouse is not a write on the source.
    _grant("USAGE", "WAREHOUSE", "MIGRATE_WH"),
    _grant("OPERATE", "WAREHOUSE", "MIGRATE_WH"),
    _grant("MODIFY", "WAREHOUSE", "MIGRATE_WH"),
]


class FakeCursor:
    """Answers the statements the guard sends; records every call.

    `by_role` maps a role name to its SHOW GRANTS rows; a database role is
    keyed by its dotted name (`SALES_DB.WRITER`). A role not in `by_role`
    answers `grants`. `future_by_role` is the same for SHOW FUTURE GRANTS
    (a role not in it has none); `fail_future` makes that statement fail.
    `user_roles` is what SHOW GRANTS TO USER lists; None makes that
    statement fail, as a cursor that may not run it would.
    """

    def __init__(self, grants, *, role="READER", secondary="",
                 secondary_value="", by_role=None, fail_grants=None,
                 user_roles=None, future_by_role=None, fail_future=None):
        self.grants = grants
        self.role = role
        self.secondary = secondary
        self.secondary_value = secondary_value
        self.by_role = by_role or {}
        self.fail_grants = fail_grants
        self.user_roles = user_roles
        self.future_by_role = future_by_role or {}
        self.fail_future = fail_future
        self.calls = []

    def __call__(self, sql, params=None):
        self.calls.append(sql)
        low = " ".join(sql.split()).lower()
        if "current_role()" in low:
            return [{"R": self.role,
                     "S": json.dumps({"roles": self.secondary,
                                      "value": self.secondary_value})}]
        if low.startswith("select current_user()"):
            return [{"U": "SVC"}]
        if low.startswith("show grants to user"):
            if self.user_roles is None:
                raise RuntimeError("SQL access control error")
            return [{"created_on": "x", "role": r, "granted_to": "USER",
                     "grantee_name": "SVC"} for r in self.user_roles]
        if low.startswith("show grants to role") or \
                low.startswith("show grants to database role"):
            if self.fail_grants:
                raise RuntimeError(self.fail_grants)
            name = ".".join(part.strip('"') for part in
                            sql.split("role", 1)[1].strip().split('"."'))
            return self.by_role.get(name, self.grants)
        if low.startswith("show future grants to role") or \
                low.startswith("show future grants to database role"):
            if self.fail_future:
                raise RuntimeError(self.fail_future)
            name = ".".join(part.strip('"') for part in
                            sql.split("role", 1)[1].strip().split('"."'))
            return self.future_by_role.get(name, [])
        raise AssertionError(f"unexpected sql: {sql}")


def _future(privilege, grant_on, name):
    # The columns SHOW FUTURE GRANTS TO ROLE returns: `grant_on`, not
    # `granted_on`, and the object is a placeholder (`DB.S.<TABLE>`).
    return {"created_on": "2026-01-01", "privilege": privilege,
            "grant_on": grant_on, "name": name, "grant_to": "ROLE",
            "grantee_name": "READER", "grant_option": "false"}


def test_a_read_only_role_passes_with_its_grants_as_evidence():
    cur = FakeCursor(READ_ONLY)
    evidence = assert_role_read_only(cur, database="SALES_DB")
    assert evidence["read_only"] is True
    assert evidence["role"] == "READER"
    assert evidence["grants_read"] == len(READ_ONLY)
    # Warehouse grants are not source objects and are not counted.
    assert evidence["by_privilege"] == {"REFERENCES": 1, "SELECT": 2,
                                        "USAGE": 2}
    assert any(c.lower().startswith("show grants to role") for c in cur.calls)
    line = describe_role_grants(evidence)
    assert "read-only" in line and "SALES_DB" in line and "SELECT x2" in line


@pytest.mark.parametrize("privilege,granted_on,name", [
    ("CREATE TABLE", "SCHEMA", "SALES_DB.PUBLIC"),
    ("CREATE SCHEMA", "DATABASE", "SALES_DB"),
    ("ALTER", "TABLE", "SALES_DB.PUBLIC.ORDERS"),
    ("DROP", "TABLE", "SALES_DB.PUBLIC.ORDERS"),
    ("INSERT", "TABLE", "SALES_DB.PUBLIC.ORDERS"),
    ("UPDATE", "TABLE", "SALES_DB.PUBLIC.ORDERS"),
    ("DELETE", "TABLE", "SALES_DB.PUBLIC.ORDERS"),
    ("MERGE", "TABLE", "SALES_DB.PUBLIC.ORDERS"),
    ("TRUNCATE", "TABLE", "SALES_DB.PUBLIC.ORDERS"),
    ("OWNERSHIP", "TABLE", "SALES_DB.PUBLIC.ORDERS"),
    ("OWNERSHIP", "DATABASE", "SALES_DB"),
    ("INSERT", "TABLE", '"SALES_DB"."PUBLIC"."Mixed Case"'),
])
def test_a_write_privilege_on_the_source_refuses_the_session(
        privilege, granted_on, name):
    cur = FakeCursor(READ_ONLY + [_grant(privilege, granted_on, name)])
    with pytest.raises(RoleNotReadOnly) as caught:
        assert_role_read_only(cur, database="sales_db")
    message = str(caught.value)
    assert privilege in message and "read-only" in message
    assert "`role:`" in message, "it must say how to fix it"
    # It is an AuthError, so main() prints `error:` rather than a traceback.
    assert isinstance(caught.value, AuthError)


def test_the_source_database_is_the_scope_and_other_databases_are_reported():
    """A write grant on ANOTHER database is not a write on the source. It
    is counted and said, never silently dropped, and never fails the gate."""
    cur = FakeCursor(READ_ONLY + [
        _grant("INSERT", "TABLE", "SCRATCH.PUBLIC.T"),
        _grant("OWNERSHIP", "DATABASE", "SCRATCH")])
    evidence = assert_role_read_only(cur, database="SALES_DB")
    assert evidence["read_only"] is True
    assert evidence["out_of_scope_writes"] == 2
    assert "other databases" in describe_role_grants(evidence)


def test_a_quoted_mixed_case_database_is_matched_as_written():
    """`database: '"MyDb"'` names MyDb exactly, and SHOW GRANTS quotes it
    the same way; a fold to upper case on either side would miss the
    write and pass the gate."""
    cur = FakeCursor([_grant("INSERT", "TABLE", '"MyDb"."S"."T"')])
    with pytest.raises(RoleNotReadOnly, match="INSERT"):
        assert_role_read_only(cur, database='"MyDb"')
    # ...and a different-cased quoted database is a different database.
    other = FakeCursor([_grant("INSERT", "TABLE", '"MYDB"."S"."T"')])
    assert assert_role_read_only(other, database='"MyDb"')["read_only"]


def test_without_a_source_database_every_object_is_in_scope():
    cur = FakeCursor(READ_ONLY + [_grant("INSERT", "TABLE", "SCRATCH.PUBLIC.T")])
    with pytest.raises(RoleNotReadOnly, match="INSERT"):
        assert_role_read_only(cur)


def test_allowlisted_account_and_warehouse_grants_are_not_source_writes():
    """CREATE DATABASE on the ACCOUNT creates something new of the role's
    own; MONITOR USAGE reads history; USAGE/OPERATE on a warehouse resume
    it; USAGE on an integration is the stage or SSO path. None writes the
    source, and none is counted among the source privileges."""
    cur = FakeCursor(READ_ONLY + [
        _grant("CREATE DATABASE", "ACCOUNT", "ACME"),
        _grant("CREATE WAREHOUSE", "ACCOUNT", "ACME"),
        _grant("MONITOR USAGE", "ACCOUNT", "ACME"),
        _grant("MONITOR EXECUTION", "ACCOUNT", "ACME"),
        _grant("IMPORTED PRIVILEGES", "ACCOUNT", "ACME"),
        _grant("MONITOR", "WAREHOUSE", "MIGRATE_WH"),
        _grant("USAGE", "INTEGRATION", "S3_INT"),
        _grant("USAGE", "SHARE", "PARTNER_SHARE"),
        _grant("MONITOR", "RESOURCE_MONITOR", "RM")])
    evidence = assert_role_read_only(cur, database="SALES_DB")
    assert evidence["read_only"] is True
    assert evidence["by_privilege"] == {"REFERENCES": 1, "SELECT": 2,
                                        "USAGE": 2}


def test_unreadable_grants_fail_closed():
    cur = FakeCursor(READ_ONLY, fail_grants="SQL access control error: "
                                             "Insufficient privileges")
    with pytest.raises(RoleNotReadOnly, match="could not be read"):
        read_role_grants(cur, database="SALES_DB")


def test_a_session_with_no_current_role_fails_closed():
    cur = FakeCursor(READ_ONLY, role=None)
    with pytest.raises(RoleNotReadOnly, match="no current role"):
        read_role_grants(cur)


def test_a_grants_listing_at_the_cap_cannot_prove_anything():
    cur = FakeCursor([_grant("SELECT", "TABLE", f"SALES_DB.S.T{i}")
                      for i in range(SHOW_GRANTS_CAP)])
    with pytest.raises(RoleNotReadOnly, match="cap"):
        read_role_grants(cur, database="SALES_DB")


def test_secondary_roles_are_checked_too():
    """A write held through a secondary role is a write the session can
    make; the guard reads every role the session holds."""
    cur = FakeCursor(READ_ONLY, secondary="WRITER,READER",
                     by_role={"WRITER": [_grant("DELETE", "TABLE",
                                                "SALES_DB.PUBLIC.ORDERS")]})
    with pytest.raises(RoleNotReadOnly) as caught:
        assert_role_read_only(cur, database="SALES_DB")
    assert "DELETE" in str(caught.value) and "WRITER" in str(caught.value)
    asked = [c for c in cur.calls if c.lower().startswith("show grants")]
    assert len(asked) == 2, "the primary and the one distinct secondary"
    assert any('"WRITER"' in c for c in asked), "role names are quoted"


def test_the_evidence_carries_no_credential_and_only_grant_facts():
    evidence = read_role_grants(FakeCursor(READ_ONLY), database="SALES_DB")
    assert set(evidence) == {"role", "secondary_roles", "inherited_roles",
                             "database", "grants_read", "future_grants_read",
                             "by_privilege", "write_grants",
                             "out_of_scope_writes", "read_only"}


# --- the role hierarchy: a role holds what the roles granted to it hold ----

@pytest.mark.parametrize("granted", ["DATA_OWNER", "ETL_WRITER"])
def test_a_write_inherited_through_a_granted_role_refuses_the_session(granted):
    """`GRANT ROLE DATA_OWNER TO ROLE READER` is one row in READER's
    listing, `USAGE on ROLE DATA_OWNER`; what DATA_OWNER holds is not
    listed there. The guard follows the row and judges DATA_OWNER's grants
    as READER's own. (A system role in that position is refused before it
    is listed: see the system-role tests.)"""
    cur = FakeCursor(READ_ONLY + [_grant("USAGE", "ROLE", granted)],
                     by_role={granted: [
                         _grant("OWNERSHIP", "DATABASE", "SALES_DB"),
                         _grant("INSERT", "TABLE", "SALES_DB.PUBLIC.ORDERS")]})
    with pytest.raises(RoleNotReadOnly) as caught:
        assert_role_read_only(cur, database="SALES_DB")
    message = str(caught.value)
    assert "OWNERSHIP" in message and f"via {granted}" in message
    assert f"inherited role {granted}" in message
    assert any(c.lower().startswith("show grants to role") and
               f'"{granted}"' in c for c in cur.calls), \
        "the granted role's own listing is read"


def test_a_write_held_by_a_database_role_refuses_the_session():
    """A database role is granted the same way (`USAGE on DATABASE_ROLE
    DB.NAME`) and is listed with `SHOW GRANTS TO DATABASE ROLE`."""
    cur = FakeCursor(READ_ONLY + [_grant("USAGE", "DATABASE_ROLE",
                                          "SALES_DB.WRITER")],
                     by_role={"SALES_DB.WRITER": [
                         _grant("INSERT", "TABLE", "SALES_DB.PUBLIC.ORDERS")]})
    with pytest.raises(RoleNotReadOnly) as caught:
        assert_role_read_only(cur, database="SALES_DB")
    message = str(caught.value)
    assert "INSERT" in message and "via database role SALES_DB.WRITER" in message
    assert 'show grants to database role "SALES_DB"."WRITER"' in cur.calls, \
        "the dotted name is requoted part by part"


def test_a_granted_role_that_is_itself_read_only_passes_and_is_named():
    cur = FakeCursor(READ_ONLY + [_grant("USAGE", "ROLE", "VIEWER")],
                     by_role={"VIEWER": [
                         _grant("SELECT", "TABLE", "SALES_DB.PUBLIC.ITEMS")]})
    evidence = assert_role_read_only(cur, database="SALES_DB")
    assert evidence["read_only"] is True
    assert evidence["inherited_roles"] == ["role VIEWER"]
    assert evidence["grants_read"] == len(READ_ONLY) + 2
    assert evidence["by_privilege"]["SELECT"] == 3, "VIEWER's SELECT counts"
    assert "inherited role VIEWER" in describe_role_grants(evidence)


def test_a_write_two_levels_down_names_the_chain_that_carried_it():
    cur = FakeCursor([_grant("USAGE", "ROLE", "MIDDLE")],
                     by_role={"MIDDLE": [_grant("USAGE", "ROLE", "OWNER")],
                              "OWNER": [_grant("DROP", "SCHEMA",
                                               "SALES_DB.PUBLIC")]})
    with pytest.raises(RoleNotReadOnly, match="DROP on SCHEMA SALES_DB.PUBLIC "
                                              "via MIDDLE -> OWNER"):
        assert_role_read_only(cur, database="SALES_DB")


def test_a_cycle_in_the_hierarchy_terminates_and_each_role_is_read_once():
    cur = FakeCursor([_grant("USAGE", "ROLE", "A")],
                     by_role={"A": [_grant("USAGE", "ROLE", "B")],
                              "B": [_grant("USAGE", "ROLE", "READER"),
                                    _grant("USAGE", "ROLE", "A")]})
    evidence = assert_role_read_only(cur, database="SALES_DB")
    assert evidence["inherited_roles"] == ["role A", "role B"]
    listings = [c for c in cur.calls if c.lower().startswith("show grants")]
    assert len(listings) == 3, "READER, A, B: once each"


def test_an_unreadable_inherited_listing_fails_closed():
    """The fail-closed rule applies at every level: a granted role whose
    grants cannot be read may hold anything."""
    inner = FakeCursor(READ_ONLY + [_grant("USAGE", "ROLE", "ETL")])

    def deny_etl(sql, params=None):
        if '"ETL"' in sql:
            raise RuntimeError("Insufficient privileges")
        return inner(sql, params)
    with pytest.raises(RoleNotReadOnly, match="role ETL .*could not be read"):
        assert_role_read_only(deny_etl, database="SALES_DB")


def test_a_write_row_with_no_object_name_is_judged_inside_the_source():
    """A write that cannot be placed outside the source is not waved through
    as `out of scope`."""
    cur = FakeCursor(READ_ONLY + [{"privilege": "INSERT",
                                   "granted_on": "TABLE", "name": None}])
    with pytest.raises(RoleNotReadOnly, match="INSERT"):
        assert_role_read_only(cur, database="SALES_DB")


# --- secondary roles ALL: the roles in effect must be named, or refused ----

def test_secondary_roles_all_with_no_names_fails_closed_when_unreadable():
    """`{"roles":"","value":"ALL"}` says every role granted to the user is
    in effect without naming one. When SHOW GRANTS TO USER cannot say
    either, the session is refused rather than read as `no secondaries`."""
    cur = FakeCursor(READ_ONLY, secondary="", secondary_value="ALL",
                     user_roles=None)
    with pytest.raises(RoleNotReadOnly) as caught:
        assert_role_read_only(cur, database="SALES_DB")
    message = str(caught.value)
    assert "secondary roles are active" in message
    assert "--only-primary-role" in message, "it must say how to fix it"
    assert any(c.lower().startswith("show grants to user") for c in cur.calls)


def test_secondary_roles_all_with_no_names_is_resolved_from_the_user_grants():
    cur = FakeCursor(READ_ONLY, secondary="", secondary_value="ALL",
                     user_roles=["READER", "WRITER"],
                     by_role={"WRITER": [_grant("DELETE", "TABLE",
                                                "SALES_DB.PUBLIC.ORDERS")]})
    with pytest.raises(RoleNotReadOnly) as caught:
        assert_role_read_only(cur, database="SALES_DB")
    assert "DELETE" in str(caught.value) and "WRITER" in str(caught.value)
    assert 'show grants to user "SVC"' in cur.calls
    # ...and a user who holds only the primary role passes.
    alone = FakeCursor(READ_ONLY, secondary="", secondary_value="ALL",
                       user_roles=["READER"])
    evidence = assert_role_read_only(alone, database="SALES_DB")
    assert evidence["read_only"] is True and evidence["secondary_roles"] == []


def test_secondary_roles_all_with_names_trusts_the_names():
    cur = FakeCursor(READ_ONLY, secondary="VIEWER", secondary_value="ALL",
                     by_role={"VIEWER": []})
    assert assert_role_read_only(cur, database="SALES_DB")["read_only"]
    assert not any(c.lower().startswith("show grants to user")
                   for c in cur.calls)


def test_an_unreadable_secondary_roles_payload_fails_closed():
    inner = FakeCursor(READ_ONLY)

    def raw(sql, params=None):
        if "current_role()" in sql.lower():
            return [{"R": "READER", "S": "not json {"}]
        return inner(sql, params)
    with pytest.raises(RoleNotReadOnly, match="cannot read"):
        assert_role_read_only(raw, database="SALES_DB")


# --- grants that are not ON source data but lead to a source write ---------
#
# The reviewer's case: MANAGE GRANTS on the ACCOUNT lets a role grant itself
# any privilege, INSERT on every table included, so a role that holds it is
# not read-only whatever its table grants say. A grant on a non-source class
# is judged against that class's allowlist; everything else is refused with
# the escalation named.

def test_manage_grants_on_the_account_refuses_the_session():
    cur = FakeCursor(READ_ONLY + [_grant("MANAGE GRANTS", "ACCOUNT", "ACME")])
    with pytest.raises(RoleNotReadOnly) as caught:
        assert_role_read_only(cur, database="SALES_DB")
    message = str(caught.value)
    assert "MANAGE GRANTS on ACCOUNT ACME" in message
    assert "grant itself any privilege" in message, "it must name the escalation"
    assert "`role:`" in message, "it must say how to fix it"
    assert isinstance(caught.value, AuthError)


def test_manage_grants_inherited_through_a_granted_role_names_the_carrier():
    cur = FakeCursor(READ_ONLY + [_grant("USAGE", "ROLE", "GRANTS_MGR")],
                     by_role={"GRANTS_MGR": [
                         _grant("MANAGE GRANTS", "ACCOUNT", "ACME")]})
    with pytest.raises(RoleNotReadOnly) as caught:
        assert_role_read_only(cur, database="SALES_DB")
    message = str(caught.value)
    assert "MANAGE GRANTS on ACCOUNT ACME via GRANTS_MGR" in message
    evidence = read_role_grants(cur, database="SALES_DB")
    assert evidence["read_only"] is False
    [refused] = evidence["write_grants"]
    assert refused["privilege"] == "MANAGE GRANTS"
    assert refused["granted_on"] == "ACCOUNT" and refused["name"] == "ACME"
    assert refused["via"] == "GRANTS_MGR" and refused["role"] == "READER"
    assert refused["future"] is False
    assert "grant itself any privilege" in refused["reason"]


@pytest.mark.parametrize("privilege,granted_on,name", [
    ("OWNERSHIP", "ROLE", "ANALYST"),
    ("OWNERSHIP", "USER", "SVC_OTHER"),
    ("OWNERSHIP", "ACCOUNT", "ACME"),
    ("OWNERSHIP", "WAREHOUSE", "MIGRATE_WH"),
    ("OWNERSHIP", "INTEGRATION", "S3_INT"),
    ("OWNERSHIP", "DATABASE_ROLE", "SALES_DB.VIEWER"),
    ("CREATE ROLE", "ACCOUNT", "ACME"),
    ("CREATE USER", "ACCOUNT", "ACME"),
    ("CREATE INTEGRATION", "ACCOUNT", "ACME"),
    ("CREATE SHARE", "ACCOUNT", "ACME"),
    ("APPLY MASKING POLICY", "ACCOUNT", "ACME"),
    ("APPLY ROW ACCESS POLICY", "ACCOUNT", "ACME"),
    ("APPLY AGGREGATION POLICY", "ACCOUNT", "ACME"),
    ("APPLY TAG", "ACCOUNT", "ACME"),
    ("APPLY AUTHENTICATION POLICY", "ACCOUNT", "ACME"),
    ("EXECUTE TASK", "ACCOUNT", "ACME"),
    ("EXECUTE MANAGED TASK", "ACCOUNT", "ACME"),
    ("MANAGE WAREHOUSES", "ACCOUNT", "ACME"),
])
def test_an_escalating_privilege_on_a_non_source_class_refuses_the_session(
        privilege, granted_on, name):
    """None of these is ON a table, and each is a step from `cannot write`
    to `can`: owning a role or user, minting roles or users, running tasks,
    rewriting policies, opening a share or an integration."""
    cur = FakeCursor(READ_ONLY + [_grant(privilege, granted_on, name)])
    with pytest.raises(RoleNotReadOnly) as caught:
        assert_role_read_only(cur, database="SALES_DB")
    message = str(caught.value)
    assert f"{privilege} on {granted_on} {name}" in message
    assert "(" in message.split(f"{privilege} on {granted_on} {name}", 1)[1], (
        "the refusal carries a reason")
    assert "read-only" in message and "`role:`" in message


def test_an_unknown_privilege_name_fails_closed_on_any_class():
    """A privilege the check does not know might be harmless. It cannot
    say, so it does not pass it: the burden of proof is on the grant."""
    on_account = FakeCursor(READ_ONLY + [
        _grant("MANAGE ACCOUNT SUPPORT CASES", "ACCOUNT", "ACME")])
    with pytest.raises(RoleNotReadOnly, match="MANAGE ACCOUNT SUPPORT CASES "
                                              "on ACCOUNT ACME .*unproven"):
        assert_role_read_only(on_account, database="SALES_DB")
    on_table = FakeCursor(READ_ONLY + [
        _grant("FROBNICATE", "TABLE", "SALES_DB.PUBLIC.ORDERS")])
    with pytest.raises(RoleNotReadOnly, match="FROBNICATE on TABLE .*unproven"):
        assert_role_read_only(on_table, database="SALES_DB")
    on_warehouse = FakeCursor(READ_ONLY + [
        _grant("APPLYBUDGET", "WAREHOUSE", "MIGRATE_WH")])
    with pytest.raises(RoleNotReadOnly, match="APPLYBUDGET on WAREHOUSE"):
        assert_role_read_only(on_warehouse, database="SALES_DB")


def test_operate_is_a_warehouse_read_and_a_task_write():
    """The same privilege word means different things per class: OPERATE
    on a warehouse resumes it, OPERATE on a task runs whatever it writes."""
    assert assert_role_read_only(
        FakeCursor(READ_ONLY), database="SALES_DB")["read_only"]
    cur = FakeCursor(READ_ONLY + [_grant("OPERATE", "TASK",
                                          "SALES_DB.PUBLIC.LOAD_ORDERS")])
    with pytest.raises(RoleNotReadOnly, match="OPERATE on TASK"):
        assert_role_read_only(cur, database="SALES_DB")


def test_a_usage_grant_on_an_application_role_is_refused_unwalked():
    cur = FakeCursor(READ_ONLY + [_grant("USAGE", "APPLICATION_ROLE",
                                          "SOME_APP.APP_ADMIN")])
    with pytest.raises(RoleNotReadOnly, match="APPLICATION_ROLE .*not walked"):
        assert_role_read_only(cur, database="SALES_DB")


# --- system roles: refused before they are listed --------------------------

SYSTEM = ["ACCOUNTADMIN", "SECURITYADMIN", "USERADMIN", "SYSADMIN",
          "ORGADMIN", "GLOBALORGADMIN"]


@pytest.mark.parametrize("granted", SYSTEM)
def test_a_system_role_in_the_hierarchy_is_refused_even_unlisted(granted):
    """`GRANT ROLE SECURITYADMIN TO ROLE READER` makes READER able to do
    what SECURITYADMIN can, and that is defined by Snowflake, not by the
    rows SHOW GRANTS returns for it -- which may not be readable at all.
    The role is refused on sight, and its listing is never asked for."""
    cur = FakeCursor(READ_ONLY + [_grant("USAGE", "ROLE", granted)],
                     fail_grants=None,
                     by_role={granted: []})  # an EMPTY listing, if asked

    def deny_system(sql, params=None):
        if f'"{granted}"' in sql:
            raise RuntimeError("Insufficient privileges")
        return cur(sql, params)
    with pytest.raises(RoleNotReadOnly) as caught:
        assert_role_read_only(deny_system, database="SALES_DB")
    message = str(caught.value)
    assert (f"role {granted}, granted to role READER via {granted}, is a "
            f"system role") in message
    assert "read-only" in message and "`role:`" in message
    assert not any(f'"{granted}"' in c for c in cur.calls), "never listed"


def test_a_system_role_two_levels_down_names_the_chain():
    cur = FakeCursor([_grant("USAGE", "ROLE", "MIDDLE")],
                     by_role={"MIDDLE": [_grant("USAGE", "ROLE", "SYSADMIN")],
                              "SYSADMIN": []})
    with pytest.raises(RoleNotReadOnly, match="role SYSADMIN, granted to role "
                                              "READER via MIDDLE -> SYSADMIN, "
                                              "is a system role"):
        assert_role_read_only(cur, database="SALES_DB")


def test_a_session_whose_own_role_is_a_system_role_is_refused_unlisted():
    cur = FakeCursor([], role="ACCOUNTADMIN")
    with pytest.raises(RoleNotReadOnly, match="session's role ACCOUNTADMIN is "
                                              "a system role"):
        assert_role_read_only(cur, database="SALES_DB")
    assert not any(c.lower().startswith("show") for c in cur.calls)
    # ...and a system role among the secondaries is refused the same way.
    cur = FakeCursor(READ_ONLY, secondary="SECURITYADMIN")
    with pytest.raises(RoleNotReadOnly, match="secondary role SECURITYADMIN "
                                              "is a system role"):
        assert_role_read_only(cur, database="SALES_DB")


def test_a_system_role_name_is_matched_case_insensitively():
    cur = FakeCursor(READ_ONLY + [_grant("USAGE", "ROLE", "sysadmin")],
                     by_role={"sysadmin": []})
    with pytest.raises(RoleNotReadOnly, match="role sysadmin, granted .*is a "
                                              "system role"):
        assert_role_read_only(cur, database="SALES_DB")


# --- future grants: a write on every object created later -------------------

def test_a_future_grant_of_a_write_refuses_the_session():
    """`GRANT INSERT ON FUTURE TABLES IN SCHEMA ... TO ROLE READER` is not
    in SHOW GRANTS TO ROLE at all; it is in SHOW FUTURE GRANTS TO ROLE, as
    `INSERT on TABLE SALES_DB.PUBLIC.<TABLE>`. It is a write the session
    can make on every table created there from now on."""
    cur = FakeCursor(READ_ONLY, future_by_role={"READER": [
        _future("SELECT", "TABLE", "SALES_DB.PUBLIC.<TABLE>"),
        _future("INSERT", "TABLE", "SALES_DB.PUBLIC.<TABLE>")]})
    with pytest.raises(RoleNotReadOnly) as caught:
        assert_role_read_only(cur, database="SALES_DB")
    message = str(caught.value)
    assert "future INSERT on TABLE SALES_DB.PUBLIC.<TABLE>" in message
    assert 'show future grants to role "READER"' in cur.calls
    evidence = read_role_grants(cur, database="SALES_DB")
    assert evidence["future_grants_read"] == 2
    assert evidence["grants_read"] == len(READ_ONLY)
    assert evidence["by_privilege"]["SELECT (future)"] == 1
    assert evidence["by_privilege"]["INSERT (future)"] == 1
    [refused] = evidence["write_grants"]
    assert refused["future"] is True and refused["privilege"] == "INSERT"


def test_future_grants_are_read_for_every_walked_role():
    cur = FakeCursor(READ_ONLY + [_grant("USAGE", "ROLE", "VIEWER"),
                                  _grant("USAGE", "DATABASE_ROLE",
                                         "SALES_DB.READER_DBR")],
                     by_role={"VIEWER": [], "SALES_DB.READER_DBR": []},
                     future_by_role={"SALES_DB.READER_DBR": [
                         _future("DELETE", "TABLE", "SALES_DB.<TABLE>")]})
    with pytest.raises(RoleNotReadOnly, match="future DELETE on TABLE "
                                              "SALES_DB.<TABLE> via database "
                                              "role SALES_DB.READER_DBR"):
        assert_role_read_only(cur, database="SALES_DB")
    asked = [c for c in cur.calls if c.lower().startswith("show future grants")]
    assert 'show future grants to role "READER"' in asked
    assert 'show future grants to role "VIEWER"' in asked
    assert 'show future grants to database role "SALES_DB"."READER_DBR"' in asked
    # ...and a role whose future grants are all reads passes, with them
    # counted in the evidence.
    clean = FakeCursor(READ_ONLY, future_by_role={"READER": [
        _future("SELECT", "VIEW", "SALES_DB.PUBLIC.<VIEW>")]})
    evidence = assert_role_read_only(clean, database="SALES_DB")
    assert evidence["read_only"] is True
    assert evidence["future_grants_read"] == 1
    assert "1 future grant(s)" in describe_role_grants(evidence)


def test_a_future_write_on_another_database_is_out_of_scope_and_reported():
    cur = FakeCursor(READ_ONLY, future_by_role={"READER": [
        _future("INSERT", "TABLE", "SCRATCH.PUBLIC.<TABLE>")]})
    evidence = assert_role_read_only(cur, database="SALES_DB")
    assert evidence["read_only"] is True
    assert evidence["out_of_scope_writes"] == 1


def test_unreadable_future_grants_fail_closed():
    cur = FakeCursor(READ_ONLY, fail_future="SQL access control error")
    with pytest.raises(RoleNotReadOnly, match="future grants of role READER "
                                              "could not be read"):
        assert_role_read_only(cur, database="SALES_DB")


def test_a_future_grants_listing_at_the_cap_cannot_prove_anything():
    cur = FakeCursor(READ_ONLY, future_by_role={"READER": [
        _future("SELECT", "TABLE", f"SALES_DB.S{i}.<TABLE>")
        for i in range(SHOW_GRANTS_CAP)]})
    with pytest.raises(RoleNotReadOnly, match="future grants, at or over"):
        assert_role_read_only(cur, database="SALES_DB")
