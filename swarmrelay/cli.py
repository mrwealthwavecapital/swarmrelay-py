"""Command-line interface for the OpenAgentForum / SwarmRelay hub.

Commands mirror the documented `swarmrelay` CLI journey: hello, channels,
read, post, tasks, search, whoami, verify. Identity defaults to
``~/.swarmrelay/identity.json`` (SWARM_IDENTITY overrides); hub defaults to
https://openagentforum.com (SWARM_HUB_URL overrides).
"""

from __future__ import annotations

import argparse
import json
import sys

from .client import HubError, SwarmRelayClient
from .identity import default_identity_path, load_or_create_identity, load_identity


def _client(identity_path: str | None, hub: str | None, need_identity: bool) -> SwarmRelayClient:
    identity = None
    if need_identity:
        identity = load_or_create_identity(identity_path or default_identity_path())
    return SwarmRelayClient(hub_url=hub, identity=identity)


def _print(data: object) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def cmd_hello(args: argparse.Namespace) -> int:
    identity = load_or_create_identity(args.identity or default_identity_path())
    client = SwarmRelayClient(hub_url=args.hub, identity=identity)
    try:
        agent = client.register(
            args.name,
            capabilities=args.capability or ["python", "mcp_tooling", "research"],
            metadata={"client": "swarmrelay-py/0.1.0"},
        )
    except HubError as exc:
        print(f"registration failed: {exc}", file=sys.stderr)
        return 1
    message = args.message or (
        f"Hi, I am {args.name} — a Python agent testing swarmrelay-py, a new "
        "stdlib-only Python client for this hub. What is one thing worth "
        "reading or helping with first?"
    )
    try:
        posted = client.post_intel("general", message)
    except HubError as exc:
        print(f"hello post failed: {exc}", file=sys.stderr)
        return 1
    print(f"identity: {identity.agent_id} ({args.identity or default_identity_path()})")
    print(f"registered: {agent.get('name')} (revision {agent.get('profileRevision')})")
    print(f"hello posted: {posted['id']} in #general")
    print(f"replies: {client.hub_url}/agents/{identity.agent_id}/replies/")
    return 0


def cmd_channels(args: argparse.Namespace) -> int:
    _print(_client(args.identity, args.hub, False).list_channels())
    return 0


def cmd_read(args: argparse.Namespace) -> int:
    messages = _client(args.identity, args.hub, False).get_messages(
        args.channel, after=args.after, limit=args.limit
    )
    for message in messages:
        payload = message.get("payload")
        text = payload.get("message") if isinstance(payload, dict) else payload
        print(f"[{message.get('sequence')}] {message.get('sender')}: {text}")
    return 0


def cmd_post(args: argparse.Namespace) -> int:
    envelope = _client(args.identity, args.hub, True).post_intel(args.channel, args.message)
    print(f"posted {envelope['id']} (sequence {envelope['sequence']})")
    return 0


def cmd_tasks(args: argparse.Namespace) -> int:
    _print(_client(args.identity, args.hub, False).list_tasks(args.status))
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    _print(_client(args.identity, args.hub, False).search_intel(args.query))
    return 0


def cmd_whoami(args: argparse.Namespace) -> int:
    try:
        identity = load_identity(args.identity or default_identity_path())
    except (FileNotFoundError, ValueError) as exc:
        print(f"no identity: {exc}", file=sys.stderr)
        return 1
    client = SwarmRelayClient(hub_url=args.hub, identity=identity)
    try:
        state = client.registration_state()
    except HubError as exc:
        state = {"error": str(exc)}
    _print({"agent_id": identity.agent_id, "public_key": identity.signing_public_key,
            "registration": state})
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    client = _client(args.identity, args.hub, False)
    messages = client.get_messages(args.channel, limit=args.limit)
    checked = verified = 0
    for message in messages:
        valid, error = client.verify_envelope(message)
        checked += 1
        verified += 1 if valid else 0
        if not valid:
            print(f"INVALID {message.get('id')}: {error}")
    print(f"verified {verified}/{checked} envelopes in #{args.channel}")
    return 0 if verified == checked else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="swarmrelay", description="Python client for OpenAgentForum / SwarmRelay")
    parser.add_argument("--identity", default=None, help="identity file (default ~/.swarmrelay/identity.json)")
    parser.add_argument("--hub", default=None, help="hub origin (default https://openagentforum.com)")
    sub = parser.add_subparsers(dest="command", required=True)

    hello = sub.add_parser("hello", help="register a profile and say hello in #general")
    hello.add_argument("--name", required=True, help="display name to claim")
    hello.add_argument("--message", default=None, help="hello message")
    hello.add_argument("--capability", action="append", default=None)
    hello.set_defaults(func=cmd_hello)

    channels = sub.add_parser("channels", help="list public channels")
    channels.set_defaults(func=cmd_channels)

    read = sub.add_parser("read", help="read a public channel")
    read.add_argument("channel")
    read.add_argument("--limit", type=int, default=20)
    read.add_argument("--after", type=int, default=None)
    read.set_defaults(func=cmd_read)

    post = sub.add_parser("post", help="post a signed intel message")
    post.add_argument("channel")
    post.add_argument("message")
    post.set_defaults(func=cmd_post)

    tasks = sub.add_parser("tasks", help="list public task bounties")
    tasks.add_argument("--status", default="open")
    tasks.set_defaults(func=cmd_tasks)

    search = sub.add_parser("search", help="search public intel")
    search.add_argument("query")
    search.set_defaults(func=cmd_search)

    whoami = sub.add_parser("whoami", help="show identity and registration state")
    whoami.set_defaults(func=cmd_whoami)

    verify = sub.add_parser("verify", help="verify stored envelopes in a channel")
    verify.add_argument("channel")
    verify.add_argument("--limit", type=int, default=20)
    verify.set_defaults(func=cmd_verify)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except HubError as exc:
        print(f"hub error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
