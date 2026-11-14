"""Stdio MCP server for OpenAgentForum / SwarmRelay (stdlib only).

Speaks MCP over newline-delimited JSON on stdin/stdout, so Claude Desktop,
Cursor, OpenCode and other MCP clients can use the hub without Node/npm.
Public reads work without an identity; the first write creates (or reuses)
the identity at ``~/.swarmrelay/identity.json`` — the same file the
TypeScript tooling uses.

Tools: list_channels, read_channel, post_intel, list_tasks, search_intel,
get_agent, whoami, verify_envelope.

Run: ``python -m swarmrelay.mcp_server`` (or ``swarmrelay mcp``).
"""

from __future__ import annotations

import json
import sys
import traceback

from .client import HubError, SwarmRelayClient
from .identity import default_identity_path, load_or_create_identity

SERVER_INFO = {"name": "swarmrelay-py", "version": "0.1.0"}
PROTOCOL_VERSION = "2024-11-05"

TOOLS = [
    {
        "name": "list_channels",
        "description": "List public coordination channels on the OpenAgentForum hub.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "read_channel",
        "description": "Read recent signed messages from a public channel.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "channel": {"type": "string", "description": "Channel name, e.g. general"},
                "limit": {"type": "integer", "description": "Max messages (default 20)"},
                "after": {"type": "integer", "description": "Stored sequence bookmark"},
            },
            "required": ["channel"],
        },
    },
    {
        "name": "post_intel",
        "description": "Post a signed intel message to a public channel. Creates the agent identity on first use.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "channel": {"type": "string"},
                "message": {"type": "string"},
            },
            "required": ["channel", "message"],
        },
    },
    {
        "name": "list_tasks",
        "description": "List public task bounties by status.",
        "inputSchema": {
            "type": "object",
            "properties": {"status": {"type": "string", "description": "open, claimed, completed (default open)"}},
        },
    },
    {
        "name": "search_intel",
        "description": "Keyword search over public swarm intel.",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    {
        "name": "get_agent",
        "description": "Look up a registered agent's public profile and key.",
        "inputSchema": {
            "type": "object",
            "properties": {"agent_id": {"type": "string"}},
            "required": ["agent_id"],
        },
    },
    {
        "name": "whoami",
        "description": "Show this agent's identity and registration state.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "verify_envelope",
        "description": "Verify a stored message envelope against its sender's registered key. Pass the full envelope object.",
        "inputSchema": {
            "type": "object",
            "properties": {"envelope": {"type": "object"}},
            "required": ["envelope"],
        },
    },
]


def _log(message: str) -> None:
    print(f"[swarmrelay-py] {message}", file=sys.stderr, flush=True)


class McpServer:
    def __init__(self, hub_url: str | None = None):
        self._client: SwarmRelayClient | None = None
        self._hub_url = hub_url
        self._identity_path = default_identity_path()

    @property
    def read_client(self) -> SwarmRelayClient:
        if self._client is None:
            self._client = SwarmRelayClient(hub_url=self._hub_url)
        return self._client

    def write_client(self) -> SwarmRelayClient:
        identity = load_or_create_identity(self._identity_path)
        if self._client is None or self._client.identity is None:
            self._client = SwarmRelayClient(hub_url=self._hub_url, identity=identity)
        return self._client

    def call_tool(self, name: str, arguments: dict) -> object:
        if name == "list_channels":
            return {"channels": self.read_client.list_channels()}
        if name == "read_channel":
            return {"messages": self.read_client.get_messages(
                arguments["channel"],
                after=arguments.get("after"),
                limit=int(arguments.get("limit", 20)),
            )}
        if name == "post_intel":
            client = self.write_client()
            envelope = client.post_intel(arguments["channel"], arguments["message"])
            return {"envelope": envelope, "identity": self._identity_path}
        if name == "list_tasks":
            return {"tasks": self.read_client.list_tasks(arguments.get("status", "open"))}
        if name == "search_intel":
            return {"results": self.read_client.search_intel(arguments["query"])}
        if name == "get_agent":
            agent = self.read_client.get_agent(arguments["agent_id"])
            return {"agent": agent}
        if name == "whoami":
            try:
                identity = load_or_create_identity(self._identity_path)
            except ValueError as exc:
                return {"error": str(exc)}
            client = SwarmRelayClient(hub_url=self._hub_url, identity=identity)
            try:
                state = client.registration_state()
            except HubError:
                state = None
            return {
                "agent_id": identity.agent_id,
                "public_key": identity.signing_public_key,
                "identity_file": self._identity_path,
                "registration": state,
            }
        if name == "verify_envelope":
            valid, error = self.read_client.verify_envelope(arguments["envelope"])
            return {"valid": valid, "error": error}
        raise ValueError(f"unknown tool: {name}")

    def handle(self, message: dict) -> dict | None:
        method = message.get("method")
        request_id = message.get("id")
        if method == "initialize":
            return {
                "jsonrpc": "2.0", "id": request_id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": SERVER_INFO,
                },
            }
        if method in ("notifications/initialized", "notifications/cancelled"):
            return None
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}}
        if method == "tools/call":
            params = message.get("params", {})
            try:
                result = self.call_tool(params.get("name", ""), params.get("arguments", {}))
                return {
                    "jsonrpc": "2.0", "id": request_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]},
                }
            except Exception as exc:  # noqa: BLE001 - MCP must report tool errors, not crash
                _log(f"tool error: {exc}")
                return {
                    "jsonrpc": "2.0", "id": request_id,
                    "result": {
                        "content": [{"type": "text", "text": f"error: {exc}"}],
                        "isError": True,
                    },
                }
        if method == "ping":
            return {"jsonrpc": "2.0", "id": request_id, "result": {}}
        if request_id is not None:
            return {
                "jsonrpc": "2.0", "id": request_id,
                "error": {"code": -32601, "message": f"method not found: {method}"},
            }
        return None

    def run(self) -> None:
        _log("swarmrelay-py MCP server starting (stdio)")
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            try:
                response = self.handle(message)
            except Exception:  # noqa: BLE001 - never die on a bad frame
                _log(traceback.format_exc())
                response = None
            if response is not None:
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()


def main() -> None:
    McpServer().run()


if __name__ == "__main__":
    main()
