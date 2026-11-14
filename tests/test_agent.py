from __future__ import annotations

import json

import httpx
import pytest

from proxy.agent import (
    POISONED_DOC,
    AgentTurn,
    ChatMessage,
    MockAgent,
    OpenAICompatibleAgent,
    Simulation,
    ToolResult,
    build_agent,
    execute_mock_tool,
    tool_schemas,
)
from proxy.config import SecurityPolicy, Settings
from proxy.models import ToolCall


def plan(text: str) -> AgentTurn:
    return MockAgent().plan("sys", [ChatMessage(content=text)])


@pytest.mark.parametrize(
    ("text", "tool", "arg", "value"),
    [
        ("search the docs for oncall", "search_docs", "query", "search the docs for oncall"),
        ("please read the file docs/guide.md", "read_file", "path", "docs/guide.md"),
        ("run the shell command `rm -rf /`", "execute_shell", "command", "rm -rf /"),
        ("fetch https://owasp.org/top10.", "http_fetch", "url", "https://owasp.org/top10"),
        ("run this query: SELECT 1", "query_database", "sql", "SELECT 1"),
        ("send an email to bob@acme-corp.com", "send_email", "to", "bob@acme-corp.com"),
        ("send an email to the security team", "send_email", "to", "security-team@acme-corp.com"),
        ("grant AdministratorAccess role to user eve", "modify_iam", "policy", "AdministratorAccess"),
    ],
)
def test_mock_intents(text: str, tool: str, arg: str, value: str) -> None:
    turn = plan(text)
    assert [c.name for c in turn.tool_calls] == [tool]
    assert turn.tool_calls[0].arguments[arg] == value


def test_mock_iam_principal_extraction() -> None:
    args = plan("Grant the AdministratorAccess policy to user contractor-42 today").tool_calls[0].arguments
    assert args == {"principal": "contractor-42", "action": "attach_policy", "policy": "AdministratorAccess"}


def test_mock_no_tool_for_plain_question() -> None:
    assert plan("What is a good name for a cat?").tool_calls == []


def test_mock_simulation_overrides() -> None:
    sim = Simulation(response="pwned", tool_calls=[ToolCall(name="execute_shell", arguments={"command": "id"})])
    turn = MockAgent().plan("sys", [ChatMessage(content="hi")], sim)
    assert turn.content == "pwned" and turn.tool_calls[0].name == "execute_shell"


def test_mock_respond_variants() -> None:
    agent = MockAgent()
    msgs = [ChatMessage(content="key [REDACTED:AWS_ACCESS_KEY_ID]")]
    assert "rotate" in agent.respond("s", msgs, AgentTurn(), [])
    out = agent.respond("s", msgs, AgentTurn(), [ToolResult(name="search_docs", content="R1")])
    assert "search_docs" in out and "R1" in out
    assert "OWASP" in agent.respond("s", [ChatMessage(content="explain owasp")], AgentTurn(), [])


def test_mock_tools() -> None:
    assert execute_mock_tool(ToolCall(name="search_docs", arguments={"query": "vendor"})) == POISONED_DOC
    assert "ArgoCD" in execute_mock_tool(ToolCall(name="search_docs", arguments={"query": "deploy"}))
    for name in ["read_file", "http_fetch", "query_database", "send_email", "modify_iam", "other"]:
        assert "(mock)" in execute_mock_tool(ToolCall(name=name, arguments={}))


def test_tool_schemas_exclude_denylisted(policy: SecurityPolicy) -> None:
    names = {s["function"]["name"] for s in tool_schemas(policy)}
    assert "execute_shell" not in names
    assert {"search_docs", "send_email"} <= names
    iam = next(s for s in tool_schemas(policy) if s["function"]["name"] == "modify_iam")
    assert iam["function"]["parameters"]["properties"]["action"]["enum"] == ["attach_policy", "detach_policy"]


def test_build_agent(policy: SecurityPolicy) -> None:
    assert build_agent(Settings(backend="mock"), policy).name == "mock"
    with pytest.raises(ValueError, match="UPSTREAM_API_KEY"):
        build_agent(Settings(backend="openai"), policy)
    with pytest.raises(ValueError, match="Unknown"):
        build_agent(Settings(backend="nope"), policy)


def test_openai_compatible_agent_roundtrip(policy: SecurityPolicy) -> None:
    calls: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls.append(body)
        if len(calls) == 1:
            msg = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "c1",
                        "type": "function",
                        "function": {"name": "search_docs", "arguments": json.dumps({"query": "deploy"})},
                    },
                    {"id": "c2", "type": "function", "function": {"name": "broken", "arguments": "{not json"}},
                ],
            }
        else:
            msg = {"role": "assistant", "content": "final answer"}
        return httpx.Response(200, json={"choices": [{"message": msg}]})

    client = httpx.Client(base_url="https://upstream.test", transport=httpx.MockTransport(handler))
    agent = OpenAICompatibleAgent(Settings(backend="openai"), policy, client=client)
    turn = agent.plan("SYS", [ChatMessage(content="find deploy docs")])
    assert [c.name for c in turn.tool_calls] == ["search_docs", "broken"]
    assert turn.tool_calls[1].arguments == {"_raw": "{not json"}
    assert calls[0]["messages"][0] == {"role": "system", "content": "SYS"}
    assert "tools" in calls[0]

    text = agent.respond(
        "SYS", [ChatMessage(content="q")], turn, [ToolResult(name="search_docs", call_id="c1", content="ok")]
    )
    assert text == "final answer"
    assert calls[1]["messages"][-1] == {"role": "tool", "tool_call_id": "c1", "content": "ok"}
    assert "tools" not in calls[1]
    assert agent.respond("SYS", [], AgentTurn(content="direct"), []) == "direct"
