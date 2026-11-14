from __future__ import annotations

import pytest

from proxy.config import SecurityPolicy
from proxy.models import Decision, ToolCall
from proxy.tool_firewall import ToolFirewall, check_sql


@pytest.fixture(scope="module")
def fw(policy: SecurityPolicy) -> ToolFirewall:
    return ToolFirewall(policy)


def verdict(fw: ToolFirewall, name: str, **args):
    return fw.evaluate_call(ToolCall(name=name, arguments=args))


def rule_ids(v) -> set[str]:
    return {f.rule_id for f in v.findings}


# --------------------------------------------------------------------------- #
# Allow / deny lists
# --------------------------------------------------------------------------- #
def test_allowlisted_tool_with_valid_args(fw: ToolFirewall) -> None:
    v = verdict(fw, "search_docs", query="deploy runbook", top_k=3)
    assert v.decision is Decision.ALLOW
    assert v.findings == []


@pytest.mark.parametrize("name", ["execute_shell", "EXECUTE_SHELL", "drop_table", "run_command", " eval_code "])
def test_denylisted_tools_blocked(fw: ToolFirewall, name: str) -> None:
    v = verdict(fw, name, command="ls")
    assert v.decision is Decision.BLOCK
    assert "TF-001" in rule_ids(v)


def test_unknown_tool_blocked_by_default_deny(fw: ToolFirewall) -> None:
    v = verdict(fw, "transfer_funds", amount=1_000_000)
    assert v.decision is Decision.BLOCK
    assert rule_ids(v) == {"TF-002"}


def test_default_allow_mode(policy: SecurityPolicy) -> None:
    pol = policy.model_copy(deep=True)
    pol.tool_firewall.default_action = "allow"
    assert (
        ToolFirewall(pol).evaluate_call(ToolCall(name="weather", arguments={"city": "Oslo"})).decision is Decision.ALLOW
    )


def test_denylist_wins_over_default_allow(policy: SecurityPolicy) -> None:
    pol = policy.model_copy(deep=True)
    pol.tool_firewall.default_action = "allow"
    assert ToolFirewall(pol).evaluate_call(ToolCall(name="execute_shell")).decision is Decision.BLOCK


# --------------------------------------------------------------------------- #
# Argument schema
# --------------------------------------------------------------------------- #
def test_missing_required_argument(fw: ToolFirewall) -> None:
    assert "TF-010" in rule_ids(verdict(fw, "search_docs"))


def test_unknown_argument(fw: ToolFirewall) -> None:
    assert "TF-011" in rule_ids(verdict(fw, "search_docs", query="x", shell="rm -rf /"))


@pytest.mark.parametrize("bad", [5, None, ["a"], True])
def test_type_mismatch(fw: ToolFirewall, bad) -> None:
    assert "TF-012" in rule_ids(verdict(fw, "search_docs", query=bad))


def test_boolean_is_not_integer(fw: ToolFirewall) -> None:
    assert "TF-012" in rule_ids(verdict(fw, "search_docs", query="x", top_k=True))


def test_max_length(fw: ToolFirewall) -> None:
    assert "TF-013" in rule_ids(verdict(fw, "search_docs", query="a" * 501))


@pytest.mark.parametrize("top_k", [0, 21, -5])
def test_numeric_range(fw: ToolFirewall, top_k: int) -> None:
    assert "TF-022" in rule_ids(verdict(fw, "search_docs", query="x", top_k=top_k))


def test_enum_and_pattern(fw: ToolFirewall) -> None:
    v = verdict(fw, "modify_iam", principal="bob; DROP", action="delete_account", policy="ReadOnlyAccess")
    assert {"TF-021", "TF-025"} <= rule_ids(v)
    assert v.decision is Decision.BLOCK


# --------------------------------------------------------------------------- #
# Filesystem
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "path",
    [
        "../../etc/passwd",
        "docs/../../etc/shadow",
        "/srv/docs/../../../root/.bashrc",
        "..\\..\\windows\\system32",
        "docs/%2e%2e/%2e%2e/etc/passwd",
        "docs/%252e%252e/secret",
        "docs/readme.md%00.png",
        "~/.aws/credentials",
    ],
)
def test_path_traversal_blocked(fw: ToolFirewall, path: str) -> None:
    v = verdict(fw, "read_file", path=path)
    assert v.decision is Decision.BLOCK
    assert "TF-014" in rule_ids(v)


@pytest.mark.parametrize("path", ["/etc/passwd", "/srv/docsevil/x.md", "src/app.py", "/srv/other/docs/x"])
def test_path_outside_prefix_blocked(fw: ToolFirewall, path: str) -> None:
    assert "TF-015" in rule_ids(verdict(fw, "read_file", path=path))


@pytest.mark.parametrize("path", ["docs/guide.md", "/srv/docs/runbooks/deploy.md", "docs/a/b/c.txt"])
def test_allowed_paths(fw: ToolFirewall, path: str) -> None:
    assert verdict(fw, "read_file", path=path).decision is Decision.ALLOW


@pytest.mark.parametrize("path", ["docs/.env", "/srv/docs/server.pem", "docs/.ssh/id_rsa"])
def test_path_deny_patterns(fw: ToolFirewall, path: str) -> None:
    assert "TF-023" in rule_ids(verdict(fw, "read_file", path=path))


# --------------------------------------------------------------------------- #
# Network
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "url",
    ["https://docs.python.org/3/library/re.html", "https://owasp.org/www-project-top-10/", "https://api.github.com/x"],
)
def test_allowed_urls(fw: ToolFirewall, url: str) -> None:
    assert verdict(fw, "http_fetch", url=url).decision is Decision.ALLOW


@pytest.mark.parametrize(
    ("url", "rule"),
    [
        ("https://evil.example/payload", "TF-016"),
        ("https://docs.python.org.evil.example/", "TF-016"),
        ("https://notgithub.com/", "TF-016"),
        ("https://docs.python.org@evil.example/", "TF-016"),
        ("http://docs.python.org/", "TF-017"),
        ("file:///etc/passwd", "TF-017"),
        ("gopher://owasp.org/", "TF-017"),
        ("https://169.254.169.254/latest/meta-data/", "TF-018"),
        ("https://127.0.0.1:8080/admin", "TF-018"),
        ("https://localhost/", "TF-018"),
        ("https://10.0.0.5/", "TF-018"),
        ("https://[::1]/", "TF-018"),
        ("https://[::ffff:127.0.0.1]/", "TF-018"),
        ("https://2130706433/", "TF-018"),
        ("https://0x7f000001/", "TF-018"),
        ("https://metadata.google.internal/computeMetadata/v1/", "TF-018"),
        ("not a url", "TF-017"),
    ],
)
def test_blocked_urls(fw: ToolFirewall, url: str, rule: str) -> None:
    v = verdict(fw, "http_fetch", url=url)
    assert v.decision is Decision.BLOCK
    assert rule in rule_ids(v), v.findings


# --------------------------------------------------------------------------- #
# SQL
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "sql",
    [
        "SELECT region, SUM(revenue) FROM sales GROUP BY region",
        "with t as (select 1) select * from t",
        "SELECT * FROM logs WHERE msg = 'please DROP the ball'",
        "EXPLAIN SELECT 1",
        "select 1;",
    ],
)
def test_read_only_sql_allowed(fw: ToolFirewall, sql: str) -> None:
    assert verdict(fw, "query_database", sql=sql).decision is Decision.ALLOW, check_sql(sql, "sql")


@pytest.mark.parametrize(
    ("sql", "rule"),
    [
        ("DROP TABLE users", "TF-019"),
        ("DELETE FROM users WHERE 1=1", "TF-019"),
        ("update accounts set balance = 0", "TF-019"),
        ("INSERT INTO admins VALUES ('eve')", "TF-019"),
        ("TRUNCATE audit_log", "TF-019"),
        ("GRANT ALL ON *.* TO 'eve'", "TF-019"),
        ("WITH x AS (DELETE FROM t RETURNING *) SELECT * FROM x", "TF-019"),
        ("SELECT * INTO OUTFILE '/tmp/x' FROM users", "TF-019"),
        ("SELECT 1; DROP TABLE users", "TF-020"),
        ("SELECT 1 /* hi */; DELETE FROM t -- bye", "TF-020"),
        ("PRAGMA writable_schema = 1", "TF-019"),
    ],
)
def test_destructive_sql_blocked(fw: ToolFirewall, sql: str, rule: str) -> None:
    v = verdict(fw, "query_database", sql=sql)
    assert v.decision is Decision.BLOCK
    assert rule in rule_ids(v)


# --------------------------------------------------------------------------- #
# Exfiltration, HITL, budget
# --------------------------------------------------------------------------- #
def test_secret_in_arguments_blocked_and_masked(fw: ToolFirewall) -> None:
    v = verdict(fw, "search_docs", query="AKIAIOSFODNN7EXAMPLE")
    assert v.decision is Decision.BLOCK
    assert "TF-024" in rule_ids(v)
    assert "AKIAIOSFODNN7EXAMPLE" not in str(v.arguments)


def test_secret_scan_can_be_disabled(policy: SecurityPolicy) -> None:
    pol = policy.model_copy(deep=True)
    pol.tool_firewall.scan_args_for_secrets = False
    v = ToolFirewall(pol).evaluate_call(ToolCall(name="search_docs", arguments={"query": "AKIAIOSFODNN7EXAMPLE"}))
    assert v.decision is Decision.ALLOW


@pytest.mark.parametrize(
    ("name", "args"),
    [
        ("send_email", {"to": "cfo@acme-corp.com", "subject": "Q3", "body": "numbers"}),
        ("modify_iam", {"principal": "contractor-42", "action": "attach_policy", "policy": "AdministratorAccess"}),
    ],
)
def test_high_risk_tools_require_approval(fw: ToolFirewall, name: str, args: dict) -> None:
    v = fw.evaluate_call(ToolCall(name=name, arguments=args))
    assert v.decision is Decision.REQUIRE_APPROVAL
    assert rule_ids(v) == {"TF-003"}


def test_approval_tool_with_invalid_args_is_blocked_not_queued(fw: ToolFirewall) -> None:
    v = verdict(fw, "send_email", to="x@y.com", subject="hi")  # missing body
    assert v.decision is Decision.BLOCK


def test_per_turn_budget(fw: ToolFirewall, policy: SecurityPolicy) -> None:
    limit = policy.tool_firewall.max_tool_calls_per_turn
    calls = [ToolCall(name="search_docs", arguments={"query": str(i)}) for i in range(limit + 2)]
    verdicts = fw.evaluate(calls)
    assert [v.decision for v in verdicts[:limit]] == [Decision.ALLOW] * limit
    assert all(v.decision is Decision.BLOCK and "TF-004" in rule_ids(v) for v in verdicts[limit:])


def test_disabled_firewall(policy: SecurityPolicy) -> None:
    pol = policy.model_copy(deep=True)
    pol.tool_firewall.enabled = False
    assert ToolFirewall(pol).evaluate([ToolCall(name="execute_shell")])[0].decision is Decision.ALLOW
