"""Offline policy validator and Tailscale grants generator."""

from __future__ import annotations

import argparse
from collections import Counter
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any

from network_constants import RFC1918_NETWORKS


LEGACY_GRANTS_COMMAND = 'render'

REQUIRED_NEVER = {
    "unlisted_lan_hosts",
    "other_agents",
    "internet_or_exit_nodes",
    "tailnet_administration",
    "policy_or_device_changes",
    "all_unlisted_ports",
}
NEVER_TEXT = {
    "unlisted_lan_hosts": "This fragment grants LAN access only to listed addresses or ranges on listed TCP/UDP ports.",
    "other_agents": "This fragment grants no access to other agents' Tailscale node addresses.",
    "internet_or_exit_nodes": "This fragment adds no Internet or exit-node access grant.",
    "tailnet_administration": "These network grants do not confer tailnet or user administration authority.",
    "policy_or_device_changes": "These network grants do not confer policy-edit, device-tagging, or network-configuration authority.",
    "all_unlisted_ports": "This fragment adds no unlisted TCP/UDP ports or protocols.",
}
NAME_RE = re.compile(r"[a-z][a-z0-9-]{0,39}", re.ASCII)
SERVICE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,59}", re.ASCII)
PORT_RE = re.compile(r"(tcp|udp):([0-9]{1,5})(?:-([0-9]{1,5}))?", re.ASCII)
LAN_NETWORKS = RFC1918_NETWORKS
HOST_KEYS = {"name", "address", "service", "allow_broad_lan_range"}
AGENT_KEYS = {"name", "tag", "preset", "allow", "never"}
RULE_KEYS = {"host", "ports"}
MAX_POLICY_BYTES = 1_000_000
MAX_JSON_DEPTH = 16
MAX_ERROR_VALUE_CHARS = 80


class PolicyError(ValueError):
    """Raised when a policy is unsafe or malformed."""


def _safe(value: object) -> str:
    """Bound and escape strings without traversing malformed containers."""
    if not isinstance(value, str):
        return f"<{type(value).__name__}>"
    prefix = ascii(value[:MAX_ERROR_VALUE_CHARS])
    if len(value) > MAX_ERROR_VALUE_CHARS:
        return f"{prefix}... [truncated; original length: {len(value)} characters]"
    return prefix


def _object(value: object, keys: set[str], where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyError(f"{where} must be an object")
    extra = set(value) - keys
    if extra:
        raise PolicyError(f"{where} has unsupported field(s): {', '.join(sorted(_safe(key) for key in extra))}")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError(f"duplicate JSON key: {_safe(key)}")
        result[key] = value
    return result


def _check_json_depth(text: str) -> None:
    """Bound container nesting before handing input to the recursive decoder."""
    depth = 0
    in_string = escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise PolicyError(f"JSON nesting exceeds {MAX_JSON_DEPTH} container levels")
        elif character in "]}":
            depth -= 1


def _read_policy(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            content = stream.read(MAX_POLICY_BYTES + 1)
        if len(content) > MAX_POLICY_BYTES:
            raise PolicyError(f"policy file exceeds {MAX_POLICY_BYTES} bytes")
        text = content.decode("utf-8")
        _check_json_depth(text)
        policy = json.loads(text, object_pairs_hook=_unique_object)
    except OSError as exc:
        raise PolicyError(f"cannot read {_safe(str(path))}: {_safe(str(exc))}") from exc
    except UnicodeError as exc:
        raise PolicyError(f"policy file {_safe(str(path))} is not valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise PolicyError(f"invalid JSON in {_safe(str(path))} at line {exc.lineno}, column {exc.colno}") from exc
    except RecursionError as exc:
        raise PolicyError(f"JSON nesting is too deep in {_safe(str(path))}") from exc
    if not isinstance(policy, dict):
        raise PolicyError("policy root must be an object")
    return policy


def _normalize_address(name: str, value: object, broad_override: object) -> tuple[str, bool]:
    if not isinstance(value, str):
        raise PolicyError(f"host {name} address must be a canonical IPv4 host address or CIDR")
    if ":" in value:
        raise PolicyError(f"host {name} address must be IPv4; IPv6 destinations are unsupported")
    # IPv6, zone IDs, dotted masks, host masks, whitespace, and alternate
    # spellings are deliberately outside the accepted destination language.
    if "/" in value:
        parts = value.split("/")
        if len(parts) != 2 or not re.fullmatch(r"[0-9]{1,2}", parts[1], re.ASCII):
            raise PolicyError(f"host {name} address must be a canonical IPv4 CIDR with a numeric prefix")
        try:
            network = ipaddress.IPv4Network(value, strict=True)
        except ValueError as exc:
            raise PolicyError(f"host {name} address must be a canonical IPv4 CIDR network address") from exc
        if str(network) != value:
            raise PolicyError(f"host {name} address must use canonical IPv4 CIDR notation")
    else:
        try:
            address = ipaddress.IPv4Address(value)
        except ValueError as exc:
            raise PolicyError(f"host {name} address must be an IPv4 LAN address; IPv6 is unsupported") from exc
        if str(address) != value:
            raise PolicyError(f"host {name} address must use canonical dotted-decimal IPv4 notation")
        network = ipaddress.IPv4Network(f"{address}/32")

    if not isinstance(broad_override, bool):
        raise PolicyError(f"host {name} allow_broad_lan_range must be true or false")
    if not any(network.subnet_of(allowed) for allowed in LAN_NETWORKS):
        raise PolicyError(f"host {name} address must be a private LAN address within RFC1918 IPv4 ranges")
    broad = network.prefixlen <= 16
    if broad and not broad_override:
        raise PolicyError(
            f"host {name} uses a broad LAN range ({network}); set allow_broad_lan_range to true to acknowledge it"
        )
    return str(network.network_address) if network.prefixlen == 32 and "/" not in value else str(network), broad


def _normalize_port(value: object) -> str:
    if not isinstance(value, str):
        raise PolicyError("ports element must be a string; use tcp:443, udp:53, or tcp:8000-8010")
    if not (match := PORT_RE.fullmatch(value)):
        raise PolicyError(f"invalid port {_safe(value)}; use tcp:443, udp:53, or tcp:8000-8010")
    protocol, first, last = match.groups()
    start = int(first)
    end = int(last) if last is not None else start
    if not 1 <= start <= 65535 or not 1 <= end <= 65535:
        raise PolicyError(f"port or range endpoint out of range: {_safe(value)}")
    if str(start) != first or (last is not None and str(end) != last):
        raise PolicyError(f"port numbers must use canonical ASCII decimal without leading zeroes: {_safe(value)}")
    if end < start:
        raise PolicyError(f"port range end must be greater than or equal to its start: {_safe(value)}")
    suffix = f"{start}-{end}" if last is not None else str(start)
    return f"{protocol}:{suffix}"


def _normalize(policy: dict[str, Any]) -> dict[str, Any]:
    policy = _object(policy, {"version", "lan_hosts", "agents"}, "policy")
    if type(policy.get("version")) is not int or policy["version"] != 1:
        raise PolicyError("version must be the integer 1")

    hosts = policy.get("lan_hosts")
    agents = policy.get("agents")
    if not isinstance(hosts, list) or not isinstance(agents, list):
        raise PolicyError("lan_hosts and agents must be arrays")

    normalized_hosts: list[dict[str, Any]] = []
    host_by_name: dict[str, dict[str, Any]] = {}
    for raw_host in hosts:
        host = _object(raw_host, HOST_KEYS, "each lan_hosts entry")
        name = host.get("name")
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            raise PolicyError(
                "host name must be 1-40 characters, start with a lowercase ASCII letter (a-z), "
                "and contain only lowercase ASCII letters, digits (0-9), or hyphens (-); "
                "a trailing hyphen is allowed"
            )
        if name in host_by_name:
            raise PolicyError(f"duplicate LAN host alias: {name}")
        broad_override = host.get("allow_broad_lan_range", False)
        address, broad = _normalize_address(name, host.get("address"), broad_override)
        normalized_host = {"name": name, "address": address, "broad": broad}
        if "service" in host:
            service = host["service"]
            if not isinstance(service, str) or not SERVICE_RE.fullmatch(service) or service != service.strip():
                raise PolicyError(
                    f"host {name} service must be 1-60 characters, start with an ASCII letter or digit, "
                    "contain only ASCII letters, digits, spaces, periods (.), underscores (_), "
                    "or hyphens (-), and have no trailing space"
                )
            normalized_host["service"] = service
        host_by_name[name] = normalized_host
        normalized_hosts.append(normalized_host)

    normalized_agents: list[dict[str, Any]] = []
    by_name: dict[str, dict[str, Any]] = {}
    for raw_agent in agents:
        agent = _object(raw_agent, AGENT_KEYS, "each agent entry")
        name, tag = agent.get("name"), agent.get("tag")
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            raise PolicyError(
                f"agent name must be 1-40 characters, start with a lowercase ASCII letter, "
                f"and contain only lowercase ASCII letters, digits, or hyphens: {_safe(name)}"
            )
        if name in by_name:
            raise PolicyError(f"duplicate agent: {name}")
        if not isinstance(tag, str) or tag != f"tag:agent-{name}":
            raise PolicyError(f"agent {name} tag must be tag:agent-{name}")
        never = agent.get("never")
        if (
            not isinstance(never, list)
            or not all(isinstance(item, str) for item in never)
            or len(set(never)) != len(never)
            or set(never) != REQUIRED_NEVER
        ):
            raise PolicyError(f"agent {name} must retain all required never permissions")
        allow = agent.get("allow")
        if not isinstance(allow, list):
            raise PolicyError(f"agent {name} allow must be an array")
        normalized_allow: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for raw_rule in allow:
            rule = _object(raw_rule, RULE_KEYS, f"agent {name} allow entry")
            host_name = rule.get("host")
            if not isinstance(host_name, str):
                raise PolicyError(f"agent {name} refers to unknown LAN host alias: host must be a string")
            if host_name not in host_by_name:
                raise PolicyError(f"agent {name} refers to unknown LAN host alias: {_safe(host_name)}")
            ports = rule.get("ports")
            if not isinstance(ports, list) or not ports:
                raise PolicyError(f"agent {name} access to {host_name} needs one or more tcp/udp ports")
            normalized_ports = []
            for raw_port in ports:
                port = _normalize_port(raw_port)
                key = (host_name, port)
                if key in seen:
                    raise PolicyError(f"duplicate {port} access for {host_name} on {name}")
                seen.add(key)
                normalized_ports.append(port)
            normalized_allow.append({"host": host_name, "ports": normalized_ports})
        preset = agent.get("preset", "scoped")
        if preset not in ("everything", "scoped"):
            raise PolicyError(f"agent {name} preset must be everything or scoped")
        normalized_agent = {
            "name": name, "tag": tag, "preset": preset, "never": list(never), "allow": normalized_allow,
        }
        by_name[name] = normalized_agent
        normalized_agents.append(normalized_agent)
    if not normalized_agents:
        raise PolicyError("policy must define at least one agent")
    return {"version": 1, "lan_hosts": normalized_hosts, "agents": normalized_agents}


def validate(policy: dict[str, Any]) -> None:
    _normalize(policy)


def generate_grants(policy: dict[str, Any]) -> dict[str, Any]:
    normalized = _normalize(policy)
    hosts = {host["name"]: host for host in normalized["lan_hosts"]}
    grants = []
    tests = []
    for agent in normalized["agents"]:
        if agent["preset"] == "everything":
            grants.append({"src": [agent["tag"]], "dst": ["*"], "ip": ["*"]})
            continue
        flows: dict[str, dict[str, set[str]]] = {}
        for rule in agent["allow"]:
            host = hosts[rule["host"]]
            grants.append({"src": [agent["tag"]], "dst": [host["address"]], "ip": rule["ports"]})
            for port in rule["ports"]:
                protocol, port_spec = port.split(":", 1)
                case = flows.setdefault(protocol, {"accept": set(), "deny": set()})
                case["accept"].add(f"{host['address']}:{port_spec}")
                case["deny"].add(f"198.51.100.10:{port_spec}")
                for other in normalized["agents"]:
                    if other["name"] != agent["name"]:
                        case["deny"].add(f"{other['tag']}:{port_spec}")
        # A deny-only Tailscale test passes even if the source has no grants.
        # Emit a test only when it first asserts a real, explicitly allowed flow.
        for protocol, case in sorted(flows.items()):
            tests.append({"src": agent["tag"], "proto": protocol,
                          "accept": sorted(case["accept"]), "deny": sorted(case["deny"])})
    tag_owners = {agent["tag"]: ["autogroup:admin"] for agent in normalized["agents"]}
    return {"tagOwners": tag_owners, "grants": grants, "tests": tests}


# Preserve the original library entry point for existing callers.
render = generate_grants


def selected_policy(path: str | None) -> Path:
    if path:
        return Path(path)
    local = Path("policy.local.json")
    return local if local.exists() else Path("policy.json")


def summary(policy: dict[str, Any]) -> str:
    normalized = _normalize(policy)
    hosts = {host["name"]: host for host in normalized["lan_hosts"]}
    lines = [
        "Agent Tailscale grants",
        "This is an offline grant summary, not a connectivity or isolation guarantee.",
        "Effective access depends on the complete tailnet policy, device tags, subnet routers, and the LAN.",
        "Allowed LAN addresses or ranges may include another agent's LAN interface; those interfaces are not excluded.",
        "A range grants the listed TCP/UDP flows to every address it covers; service labels do not restrict destinations.",
        "Scoped mode does not model or test ICMP; the everything preset grants all IP traffic, including ICMP.",
        "This fragment does not revoke credentials, host permissions, or access provided elsewhere.",
    ]
    for host in normalized["lan_hosts"]:
        if host["broad"]:
            lines.append(f"\n!!! BROAD LAN RANGE OVERRIDE IN USE: {host['address']} ({host['name']}) !!!")
    for agent in normalized["agents"]:
        lines.append(f"\n{agent['name']} ({agent['tag']})")
        if agent["preset"] == "everything":
            lines.append("  Everything preset: grants all IP traffic to all destinations.")
        elif agent["allow"]:
            for rule in agent["allow"]:
                host = hosts[rule["host"]]
                service = host.get("service", rule["host"])
                lines.append(f"  Grants access to {service} ({host['address']}) on {', '.join(rule['ports'])}.")
        else:
            lines.append("  This fragment grants no LAN access.")
        if agent["preset"] == "scoped":
            for key in agent["never"]:
                lines.append(f"  {NEVER_TEXT[key]}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "generate", LEGACY_GRANTS_COMMAND, "summary", "diff"))
    parser.add_argument("--policy", help="policy JSON (defaults to policy.local.json if present, else policy.json)")
    parser.add_argument("--output", help="write generated JSON to this file instead of stdout")
    parser.add_argument("--against", help="existing Tailscale policy JSON for the read-only diff command")
    args = parser.parse_args(argv)
    try:
        policy = _read_policy(selected_policy(args.policy))
        if args.command == "diff":
            if args.output:
                parser.error("diff never writes files; --output is not supported")
            if not args.against:
                parser.error("diff requires --against PATH")
            existing = _read_policy(Path(args.against))
            current_grants = existing.get("grants", [])
            if not isinstance(current_grants, list) or not all(isinstance(item, dict) for item in current_grants):
                raise PolicyError("existing policy grants must be an array of objects")
            generated_grants = generate_grants(policy)["grants"]
            current = Counter(json.dumps(item, sort_keys=True, separators=(",", ":")) for item in current_grants)
            generated = Counter(json.dumps(item, sort_keys=True, separators=(",", ":")) for item in generated_grants)
            added = sorted((generated - current).elements())
            removed = sorted((current - generated).elements())
            print("Added grants:")
            print("\n".join(f"+ {item}" for item in added) if added else "  (none)")
            print("Removed grants:")
            print("\n".join(f"- {item}" for item in removed) if removed else "  (none)")
            return 0
        if args.command == "validate":
            validate(policy)
            print("Policy is valid.")
        elif args.command == "summary":
            print(summary(policy))
        else:
            result = json.dumps(generate_grants(policy), indent=2) + "\n"
            if args.output:
                Path(args.output).write_text(result, encoding="utf-8")
            else:
                sys.stdout.write(result)
    except PolicyError as exc:
        parser.exit(2, f"policy error: {ascii(str(exc))}\n")
    except OSError as exc:
        parser.exit(2, f"output error: {_safe(str(exc))}\n")
    except Exception:
        # Keep the CLI clean; library calls still expose unexpected bugs to tests.
        parser.exit(2, "policy error: unexpected error while processing policy\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
