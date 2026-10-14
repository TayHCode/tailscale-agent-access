# Tailscale agent access

An offline tool for reviewing and generating Tailscale grants for `agent-a`, `agent-b`, and `agent-c`. It never connects to Tailscale. Choose `everything` to grant an agent all IP traffic to all destinations, or `scoped` to grant only its listed LAN hosts and ports.

## Quickstart

Requires Python 3.10 or newer; no packages or network access are needed.

```sh
python3 agent_access.py summary
```

Commands use `policy.local.json` when present, otherwise `policy.json`; `--policy PATH` selects a different file. Copy `policy.json` to the gitignored `policy.local.json` to customize it. Each agent has a `preset`: `everything` grants all IP traffic to all destinations, and `scoped` uses that agent's `allow` entries. The checked-in policy selects `everything` for all three agents. To scope one agent, change its preset to `scoped`, then add only the LAN hosts and protocol/port entries it needs. Keep every agent's `never` list unchanged. Example shapes (use your own local values):

```json
"lan_hosts": [{"name": "printer", "address": "192.0.2.25", "service": "printer"}]
```

The address above is a documentation placeholder and is intentionally rejected by validation. Replace it with the intended RFC1918 LAN address in `policy.local.json`; never commit personal names, host names, network names, or real addresses. The test fixture uses documentation addresses too; the tests derive valid LAN cases from the shared protocol constants at runtime.

```json
"allow": [{"host": "printer", "ports": ["tcp:631", "udp:8000-8010"]}]
```

Run `python3 agent_access.py validate`, `python3 agent_access.py summary`, and `python3 agent_access.py generate --output generated-fragment.hujson`. To review grant changes without writing, run `python3 agent_access.py diff --against existing-policy.json`; it compares generated grants with the existing policy's `grants` array and prints additions and removals. The diff command never writes files. The generator emits a Tailscale policy fragment with `tagOwners`, source tags, grants, and scoped-access tests. Scoped sources with grants have a separate test per protocol with explicit `proto: "tcp"` or `proto: "udp"`; acceptance destinations retain the granted ports or ranges, and denials check other agent tags and a documentation-only Internet address on those same ports or ranges. Everything grants are intentionally broad. The JSON output is valid HuJSON input; merge its `tagOwners`, `grants`, and `tests` sections into the tailnet policy. The generated tag owners are `autogroup:admin`; review that choice for your tailnet. Assign those tags to the agent devices and ensure target LAN routes are already approved and reachable.

## Manual application

Review the summary and generated fragment against the complete tailnet policy before any use. The generated `deny` entries are test expectations, not blocking rules. Grants are additive: broader access elsewhere can make those expectations fail, and the fragment alone cannot guarantee an agent is blocked from a destination. Check overlapping grants and run the full policy tests in Tailscale's admin workflow. Nothing is enforced until the owner reviews and applies the policy. This project does not upload, apply, or validate a live tailnet policy.

## Permission model

Each agent has its own source tag. The `everything` preset generates a grant with destination `*` and IP protocol/port `*`. The `scoped` preset grants only explicitly listed addresses or ranges and TCP/UDP ports. An empty agent `allow` list in `scoped` mode grants no LAN access. The required `never` list records intended restrictions and the validator rejects its removal; this metadata does not create blocking rules:

- In `scoped` mode, this fragment adds no access outside listed LAN addresses or ranges and TCP/UDP ports. `everything` mode grants all IP traffic to all destinations.
- In `scoped` mode, this fragment grants no access to other agents' Tailscale node addresses. Allowed LAN addresses or ranges may include another agent's LAN interface; those interfaces are not excluded.
- In `scoped` mode, this fragment adds no exit-node or Internet access grant. Network grants do not confer tailnet administration, policy-edit, device-tagging, or network-configuration authority.

The summary describes grants, not guaranteed reachability or isolation. Effective access depends on the complete tailnet policy, device tags, subnet routers, and the LAN. Grants control network reachability; they do not grant Tailscale account, API, device-management, or host operating-system permissions or revoke existing credentials and permissions. Scoped mode does not model or test ICMP; the everything preset grants all IP traffic, including ICMP. Do not provide credentials to the agents. Add each needed LAN address explicitly after reviewing its service and port. A range grants the listed flows to all addresses it covers, not only the named service. Use narrow host addresses rather than a whole subnet whenever possible.

## Limitations

The accepted scoped destination forms are canonical IPv4 host addresses and canonical IPv4 CIDRs wholly inside RFC1918 private ranges (defined once in `network_constants.py`). IPv6, hostnames, dotted masks, host masks, and the Tailscale IPv4 node range are rejected. CIDRs narrower than `/16` are accepted by default. A `/16` or broader private range requires `"allow_broad_lan_range": true` on that host and the summary calls out the override. Ports use ASCII decimal without leading zeroes in `tcp:PORT`, `udp:PORT`, `tcp:START-END`, or `udp:START-END` form; endpoints must be 1 through 65535 and the end must be greater than or equal to the start. Duplicate JSON keys are rejected at every object level, including equivalent escaped spellings. `version` must be the JSON integer `1`; `1.0` and booleans are rejected.

Host aliases (`lan_hosts[].name`) must be 1-40 characters, start with a lowercase ASCII letter (`a-z`), and contain only lowercase ASCII letters, digits (`0-9`), or hyphens (`-`). The last character may be a letter, digit, or hyphen; `printer-` is valid. Each alias must be unique. An `allow[].host` reference must exactly match a listed host alias, so it uses the same rule.

Optional service labels (`lan_hosts[].service`) must be 1-60 characters, start with an ASCII letter or digit (`A-Z`, `a-z`, `0-9`), and contain only ASCII letters, digits, spaces, periods (`.`), underscores (`_`), or hyphens (`-`). The last character may be any of these except a space; leading and trailing spaces are rejected. Labels are descriptive only and need not be unique.

Agent names come from the policy file. Define at least one agent with a unique name following the host-alias character and length rules above. The starter policy uses `agent-a`, `agent-b`, and `agent-c`; replace those examples with your own names only in the gitignored `policy.local.json`. Each tag must be exactly `tag:agent-NAME`, with `NAME` replaced by that agent's name. Each agent's `never` list must contain exactly these six strings, once each, in any order: `unlisted_lan_hosts`, `other_agents`, `internet_or_exit_nodes`, `tailnet_administration`, `policy_or_device_changes`, and `all_unlisted_ports`.

Policy files must be UTF-8, at most 1,000,000 bytes (including whitespace), and at most 16 nested object/array levels, counting the root object as level 1. Brackets inside strings do not count. Size and nesting are checked before JSON decoding; excessive input produces a clean policy error with exit code 2. Malformed field types are rejected with a field-specific error. Error messages show at most the first 80 characters of an echoed string, escaped for display, and mark truncation with its original length. Unexpected processing errors also produce a clean policy error in the CLI; direct library calls expose unexpected exceptions for debugging and tests.

The tool cannot discover LAN hosts, confirm that a route exists, identify which Tailscale device runs an agent, validate a full tailnet policy offline, or guarantee restrictions when combined with other grants. The owner must supply each scoped agent's required LAN hosts and ports, the private address for each host, and arrange suitable Tailscale device tags and LAN routes. No real network values belong in this repository; `policy.local.json` is ignored by Git.
