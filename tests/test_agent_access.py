import ipaddress
import json
import re
import string
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from agent_access import PolicyError, generate_grants, summary, validate
from network_constants import (
    RFC1918_NETWORKS, TAILSCALE_CGNAT_NETWORK, TAILSCALE_IPV6_NETWORK, IPV6_ULA_NETWORK,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "one_grant.json"

# Public fixture placeholders become valid LAN cases without embedding LAN values.
LAN_HOST = str(RFC1918_NETWORKS[2].network_address + 20)
LAN_NEXT_HOST = str(ipaddress.ip_address(LAN_HOST) + 1)
LAN_SUBNET = str(ipaddress.ip_network(LAN_HOST + "/24", strict=False))
LAN_NEXT_SUBNET = str(ipaddress.ip_network((int(ipaddress.ip_network(LAN_SUBNET).network_address) + 256, 24)))
BROAD_LAN = str(next(RFC1918_NETWORKS[0].subnets(new_prefix=16)))


def load_fixture():
    policy = json.loads(FIXTURE.read_text(encoding="utf-8"))
    policy["lan_hosts"][0]["address"] = LAN_HOST
    return policy


class PolicyTests(unittest.TestCase):
    def test_readme_alias_and_service_limits_match_validator_and_errors(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8").replace("`", "")
        for field, heading, alphabet, first, last in (
            ("name", "Host aliases (lan_hosts[].name)",
             string.ascii_lowercase + string.digits + "-",
             string.ascii_lowercase, string.ascii_lowercase + string.digits + "-"),
            ("service", "Optional service labels (lan_hosts[].service)",
             string.ascii_letters + string.digits + " ._-",
             string.ascii_letters + string.digits,
             string.ascii_letters + string.digits + "._-"),
        ):
            with self.subTest(field=field):
                limits = re.search(re.escape(heading) + r" must be (\d+)-(\d+) characters", readme)
                self.assertIsNotNone(limits)
                minimum, maximum = map(int, limits.groups())
                self.assertIn("contain only lowercase ASCII letters, digits (0-9), or hyphens (-)", readme)
                self.assertIn("start with a lowercase ASCII letter (a-z)", readme)
                self.assertIn("The last character may be a letter, digit, or hyphen", readme)
                self.assertIn("start with an ASCII letter or digit (A-Z, a-z, 0-9)", readme)
                self.assertIn("contain only ASCII letters, digits, spaces, periods (.), underscores (_), or hyphens (-)", readme)
                self.assertIn("The last character may be any of these except a space", readme)
                # Derive boundaries from the README, then exercise the public
                # validator rather than copying its regex or length constants.
                cases = [("a" * length, minimum <= length <= maximum)
                         for length in range(maximum + 2)]
                for character in [chr(value) for value in range(128)] + ["é", "４"]:
                    cases.extend((
                        (character + "a", character in first),
                        ("a" + character + "a", character in alphabet),
                        ("a" + character, character in last),
                    ))
                for value, accepted in cases:
                    with self.subTest(field=field, value=value):
                        policy = load_fixture()
                        policy["lan_hosts"][0][field] = value
                        if field == "name":
                            policy["agents"][0]["allow"][0]["host"] = value
                        if accepted:
                            validate(policy)
                        else:
                            with self.assertRaises(PolicyError) as caught:
                                validate(policy)
                            message = str(caught.exception)
                            self.assertIn(f"{minimum}-{maximum} characters", message)
                            self.assertIn("start with", message)
                            self.assertIn("contain only", message)
                            self.assertIn("a trailing hyphen is allowed" if field == "name"
                                          else "no trailing space", message)

    def test_policy_driven_agent_names_tags_and_never_keys(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        paragraph = next(line for line in readme.splitlines() if line.startswith("Agent names come from"))
        never = re.findall(r"`([^`]+)`", paragraph.split("in any order:")[1])
        for names in (("worker",), ("worker-a", "worker-b", "worker-c", "worker-d")):
            with self.subTest(names=names):
                policy = load_fixture()
                template = policy["agents"][0]
                policy["agents"] = [dict(template, name=name, tag=f"tag:agent-{name}", never=never[:])
                                    for name in names]
                validate(policy)
                fragment = generate_grants(policy)
                self.assertEqual(set(fragment["tagOwners"]), {f"tag:agent-{name}" for name in names})
                self.assertEqual({grant["src"][0] for grant in fragment["grants"]},
                                 {f"tag:agent-{name}" for name in names})
                for name in names:
                    self.assertIn(f"{name} (tag:agent-{name})", summary(policy))
        for value in ("", "Uppercase", "bad_name", "a" * 41, 7, None):
            policy = load_fixture()
            policy["agents"][0]["name"] = value
            with self.assertRaisesRegex(PolicyError, "agent name"):
                validate(policy)
        policy = load_fixture()
        policy["agents"][0]["tag"] = "tag:agent-worker"
        with self.assertRaisesRegex(PolicyError, "tag must be"):
            validate(policy)
        policy = load_fixture()
        policy["agents"].append(policy["agents"][0].copy())
        with self.assertRaisesRegex(PolicyError, "duplicate agent"):
            validate(policy)
        policy["agents"] = []
        with self.assertRaisesRegex(PolicyError, "at least one agent"):
            validate(policy)

    def test_original_output_interfaces_preserve_behavior(self):
        import agent_access
        policy = load_fixture()
        self.assertEqual(getattr(agent_access, agent_access.LEGACY_GRANTS_COMMAND)(policy),
                         generate_grants(policy))
        legacy = self.run_cli_input(json.dumps(policy), agent_access.LEGACY_GRANTS_COMMAND)
        neutral = self.run_cli_input(json.dumps(policy), "generate")
        self.assertEqual(legacy.returncode, 0, legacy.stderr)
        self.assertEqual(neutral.returncode, 0, neutral.stderr)
        self.assertEqual(legacy.stdout, neutral.stdout)

    def test_fixture_placeholder_is_documentation_only(self):
        policy = json.loads(FIXTURE.read_text(encoding="utf-8"))
        with self.assertRaisesRegex(PolicyError, "private LAN address"):
            validate(policy)

    def run_cli_input(self, content, command):
        scratch = ROOT / ".scratch" / "policy.local.json"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="build-regression-", dir=scratch) as directory:
            path = Path(directory) / "policy.json"
            path.write_text(content, encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(ROOT / "agent_access.py"), command, "--policy", str(path)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )

    def test_cli_tests_preserve_protocol_ports_and_nonvacuous_denials(self):
        for ports in (
            ["udp:53"], ["tcp:53", "udp:53"],
            ["tcp:631", "udp:8000-8010"],
            ["tcp:8000-8010", "udp:53", "udp:65535"],
        ):
            with self.subTest(ports=ports):
                policy = load_fixture()
                policy["agents"][0]["allow"][0]["ports"] = ports
                result = self.run_cli_input(json.dumps(policy), "generate")
                self.assertEqual(result.returncode, 0, result.stderr)
                fragment = json.loads(result.stdout)
                self.assertEqual(fragment["grants"][0]["ip"], ports)
                cases = fragment["tests"]
                self.assertEqual(len(cases), len({port.split(":")[0] for port in ports}))
                for case in cases:
                    self.assertIn(case.get("proto"), ("tcp", "udp"))
                    specs = {port.split(":", 1)[1] for port in ports
                             if port.startswith(case["proto"] + ":")}
                    self.assertTrue(specs)
                    self.assertEqual(set(case["accept"]),
                                     {f"{LAN_HOST}:{port}" for port in specs})
                    self.assertEqual(set(case["deny"]), {
                        f"{destination}:{port}" for port in specs for destination in
                        ("tag:agent-agent-b", "tag:agent-agent-c", "198.51.100.10")
                    })

    def test_other_agent_lan_interface_summary_does_not_promise_isolation(self):
        for address in (LAN_HOST, LAN_SUBNET):
            with self.subTest(address=address):
                policy = load_fixture()
                policy["lan_hosts"][0].update(name="agent-b-lan", address=address,
                                              service="agent-b agent device")
                policy["agents"][0]["allow"][0]["host"] = "agent-b-lan"
                generated = generate_grants(policy)
                self.assertEqual(generated["grants"][0]["dst"], [address])
                result = self.run_cli_input(json.dumps(policy), "summary")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"Grants access to agent-b agent device ({address}) on tcp:443.", result.stdout)
                claim = "This fragment grants no access to other agents' Tailscale node addresses."
                self.assertIn(claim, result.stdout)
                self.assertIn(
                    "In `scoped` mode, this fragment grants no access to other agents' Tailscale node addresses.",
                    (ROOT / "README.md").read_text(encoding="utf-8"),
                )
                self.assertIn("those interfaces are not excluded", result.stdout)
                self.assertIn("complete tailnet policy", result.stdout)
                self.assertIn("subnet routers", result.stdout)
                self.assertIn("ICMP", result.stdout)
                self.assertNotIn("Cannot", result.stdout)
                self.assertNotIn("Can reach", result.stdout)
                if "/" in address:
                    self.assertIn("every address it covers", result.stdout)

    def test_multiple_sources_hosts_and_ranges_keep_tests_with_their_grants(self):
        policy = load_fixture()
        policy["lan_hosts"].append({"name": "lab-range", "address": LAN_NEXT_SUBNET})
        policy["agents"][0]["allow"].append({
            "host": "lab-range", "ports": ["udp:8000-8010", "tcp:443"],
        })
        policy["agents"][1]["allow"] = [{
            "host": "docs-server", "ports": ["udp:53", "tcp:8000-8010"],
        }]
        result = self.run_cli_input(json.dumps(policy), "generate")
        self.assertEqual(result.returncode, 0, result.stderr)
        fragment = json.loads(result.stdout)
        # Compare all accepted flows to all emitted grants, retaining source,
        # protocol, destination and the complete port range independently.
        granted = {
            (source, port.split(":", 1)[0], destination, port.split(":", 1)[1])
            for grant in fragment["grants"] for source in grant["src"]
            for destination in grant["dst"] for port in grant["ip"]
        }
        accepted = set()
        for case in fragment["tests"]:
            self.assertTrue(case["accept"])
            self.assertTrue(case["deny"])
            accepted.update((case["src"], case["proto"], *destination.rsplit(":", 1))
                            for destination in case["accept"])
            specs = {flow[3] for flow in granted
                     if flow[:2] == (case["src"], case["proto"])}
            self.assertEqual({destination.rsplit(":", 1)[1] for destination in case["deny"]}, specs)
        self.assertEqual(accepted, granted)
        self.assertNotIn("tag:agent-agent-c", {case["src"] for case in fragment["tests"]})

    def test_cli_deep_json_is_a_clean_policy_error(self):
        content = "[" * 100000 + "0" + "]" * 100000
        for command in ("validate", "generate", "summary"):
            with self.subTest(command=command):
                result = self.run_cli_input(content, command)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertIn("policy error:", result.stderr)
                self.assertIn("nesting", result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_error_values_are_truncated_with_original_length(self):
        for value in ("x" * 80, "x" * 81, "x" * 990_000, "\x1b" * 81):
            for field in ("agent", "host", "port", "key"):
                with self.subTest(length=len(value), field=field):
                    policy = load_fixture()
                    if field == "agent":
                        policy["agents"][0]["name"] = value
                    elif field == "host":
                        policy["agents"][0]["allow"][0]["host"] = value
                    elif field == "port":
                        policy["agents"][0]["allow"][0]["ports"] = [value]
                    elif field == "key":
                        policy[value] = 0
                    with self.assertRaises(PolicyError) as caught:
                        validate(policy)
                    message = str(caught.exception)
                    self.assertIn(ascii(value[:80]), message)
                    self.assertLess(len(message), 1000)
                    if len(value) > 80:
                        self.assertIn(f"[truncated; original length: {len(value)} characters]", message)
                    else:
                        self.assertNotIn("truncated", message)
                    for command in ("validate", "generate", "summary"):
                        result = self.run_cli_input(json.dumps(policy), command)
                        self.assertEqual(result.returncode, 2, result.stderr)
                        self.assertEqual(result.stdout, "")
                        self.assertLess(len(result.stderr), 1500)
                        self.assertNotIn("\x1b", result.stderr)
                        self.assertNotIn("Traceback", result.stderr)
                        if len(value) > 80:
                            self.assertIn(f"[truncated; original length: {len(value)} characters]", result.stderr)

    def test_cli_duplicate_json_keys_are_rejected_at_every_level(self):
        original = json.dumps(load_fixture())
        for first, replacement in (
            ('"version": 1', '"version": 2, "version": 1'),
            (f'"address": "{LAN_HOST}"',
             f'"address": "{LAN_NEXT_HOST}", "address": "{LAN_HOST}"'),
            (f'"address": "{LAN_HOST}"',
             f'"address": "{BROAD_LAN}", "allow_broad_lan_range": false, '
             '"allow_broad_lan_range": true'),
            ('"tag": "tag:agent-agent-a"',
             '"tag": "tag:agent-agent-c", "tag": "tag:agent-agent-a"'),
            ('"ports": ["tcp:443"]',
             '"ports": ["udp:53"], "ports": ["tcp:443"]'),
            ('"version": 1', '"version": 1, "ver\\u0073ion": 1'),
            ('"version": 1', '"\\u001b": 1, "\\u001b": 2, "version": 1'),
        ):
            content = original.replace(first, replacement, 1)
            self.assertNotEqual(content, original)
            for command in ("validate", "generate", "summary"):
                with self.subTest(replacement=replacement, command=command):
                    result = self.run_cli_input(content, command)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertIn("duplicate JSON key", result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertNotIn("\x1b", result.stderr)

    def test_checked_in_policy_selects_everything_for_all_agents(self):
        policy = json.loads((ROOT / "policy.json").read_text(encoding="utf-8"))
        validate(policy)
        generated = generate_grants(policy)
        self.assertEqual(generated["grants"], [
            {"src": [f"tag:agent-{name}"], "dst": ["*"], "ip": ["*"]}
            for name in ("agent-a", "agent-b", "agent-c")
        ])
        self.assertEqual(generated["tests"], [])

    def test_scoped_and_everything_presets_are_selectable_per_agent(self):
        policy = load_fixture()
        policy["agents"][0]["preset"] = "everything"
        validate(policy)
        generated = generate_grants(policy)
        self.assertEqual(generated["grants"][0], {
            "src": ["tag:agent-agent-a"], "dst": ["*"], "ip": ["*"],
        })
        self.assertIn("Everything preset: grants all IP traffic to all destinations.", summary(policy))
        policy["agents"][0]["preset"] = "scoped"
        self.assertEqual(generate_grants(policy)["grants"][0], {
            "src": ["tag:agent-agent-a"], "dst": [LAN_HOST], "ip": ["tcp:443"],
        })
        policy["agents"][0]["preset"] = "open"
        with self.assertRaisesRegex(PolicyError, "preset must be everything or scoped"):
            validate(policy)

    def test_diff_reports_added_and_removed_grants_without_writing(self):
        policy = load_fixture()
        generated_grant = generate_grants(policy)["grants"][0]
        removed_grant = {"src": ["tag:agent-agent-c"], "dst": ["*"], "ip": ["*"]}
        existing = {"grants": [removed_grant]}
        scratch = ROOT / ".scratch" / "policy.local.json"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="diff-", dir=scratch) as directory:
            policy_path = Path(directory) / "policy.json"
            existing_path = Path(directory) / "existing.json"
            output_path = Path(directory) / "should-not-exist.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            existing_path.write_text(json.dumps(existing), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ROOT / "agent_access.py"), "diff", "--policy", str(policy_path),
                 "--against", str(existing_path)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("+ " + json.dumps(generated_grant, sort_keys=True, separators=(",", ":")), result.stdout)
            self.assertIn("- " + json.dumps(removed_grant, sort_keys=True, separators=(",", ":")), result.stdout)
            self.assertFalse(output_path.exists())
            rejected = subprocess.run(
                [sys.executable, str(ROOT / "agent_access.py"), "diff", "--policy", str(policy_path),
                 "--against", str(existing_path), "--output", str(output_path)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertFalse(output_path.exists())

    def test_generate(self):
        generated = generate_grants(load_fixture())
        self.assertEqual(generated["grants"], [{
            "src": ["tag:agent-agent-a"],
            "dst": [LAN_HOST],
            "ip": ["tcp:443"],
        }])
        case = generated["tests"][0]
        self.assertIn("tag:agent-agent-b:443", case["deny"])
        self.assertIn(f"{LAN_HOST}:443", case["accept"])

    def test_unknown_host_is_rejected(self):
        policy = load_fixture()
        policy["agents"][0]["allow"][0]["host"] = "not-listed"
        with self.assertRaisesRegex(PolicyError, "unknown LAN host"):
            validate(policy)

    def test_public_address_is_rejected(self):
        policy = load_fixture()
        policy["lan_hosts"][0]["address"] = "203.0.113.20"
        with self.assertRaisesRegex(PolicyError, "private LAN address"):
            validate(policy)

    def test_invalid_port_is_rejected(self):
        policy = load_fixture()
        policy["agents"][0]["allow"][0]["ports"] = ["tcp:65536"]
        with self.assertRaisesRegex(PolicyError, "out of range"):
            validate(policy)

    def test_ipv6_tailnet_range_is_rejected(self):
        policy = load_fixture()
        policy["lan_hosts"][0]["address"] = str(TAILSCALE_IPV6_NETWORK)
        with self.assertRaisesRegex(PolicyError, "IPv6 destinations are unsupported"):
            validate(policy)

    def test_unsupported_or_noncanonical_address_forms_are_rejected(self):
        for address in (
            LAN_HOST + "/" + str(ipaddress.ip_network(LAN_SUBNET).netmask),
            LAN_HOST + "/" + str(ipaddress.ip_network(LAN_SUBNET).hostmask),
            "2001:db8::25%eth0/128",
            str(TAILSCALE_CGNAT_NETWORK.network_address + 1),
            str(TAILSCALE_CGNAT_NETWORK),
            str(IPV6_ULA_NETWORK),
        ):
            with self.subTest(address=address):
                policy = load_fixture()
                policy["lan_hosts"][0]["address"] = address
                with self.assertRaises(PolicyError):
                    validate(policy)

    def test_unicode_and_noncanonical_ports_are_rejected(self):
        for port in ("tcp:４４３", "udp:١٢", "tcp:0443", "tcp:0", "tcp:1-65536"):
            with self.subTest(port=port):
                policy = load_fixture()
                policy["agents"][0]["allow"][0]["ports"] = [port]
                with self.assertRaises(PolicyError):
                    validate(policy)

    def test_service_control_characters_are_rejected(self):
        policy = load_fixture()
        policy["lan_hosts"][0]["service"] = "printer\r\x1b[2K hidden"
        with self.assertRaisesRegex(PolicyError, "service"):
            validate(policy)
        with self.assertRaises(PolicyError):
            summary(policy)
        with self.assertRaises(PolicyError):
            generate_grants(policy)

    def test_malformed_container_values_are_policy_errors(self):
        policy = load_fixture()
        policy["agents"][0]["allow"][0]["host"] = []
        with self.assertRaisesRegex(PolicyError, "host alias"):
            validate(policy)

    def test_cli_reports_bad_utf8_and_types_without_tracebacks(self):
        scratch = ROOT / ".scratch"
        scratch.mkdir(exist_ok=True)
        path = scratch / "bad-policy-input.json"
        try:
            path.write_bytes(b'{"version": 1, "lan_hosts": [\xff], "agents": []}')
            invalid_utf8 = subprocess.run(
                [sys.executable, str(ROOT / "agent_access.py"), "validate", "--policy", str(path)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(invalid_utf8.returncode, 2)
            self.assertIn("not valid UTF-8", invalid_utf8.stderr)
            self.assertNotIn("Traceback", invalid_utf8.stderr)

            malformed = load_fixture()
            malformed["agents"][0]["allow"][0]["host"] = []
            path.write_text(json.dumps(malformed), encoding="utf-8")
            bad_shape = subprocess.run(
                [sys.executable, str(ROOT / "agent_access.py"), "generate", "--policy", str(path)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(bad_shape.returncode, 2)
            self.assertIn("unknown LAN host alias", bad_shape.stderr)
            self.assertNotIn("Traceback", bad_shape.stderr)
        finally:
            path.unlink(missing_ok=True)

    def test_broad_network_requires_explicit_override(self):
        policy = load_fixture()
        policy["lan_hosts"][0]["address"] = BROAD_LAN
        with self.assertRaisesRegex(PolicyError, "broad LAN range"):
            validate(policy)
        policy["lan_hosts"][0]["allow_broad_lan_range"] = True
        generated = generate_grants(policy)
        self.assertEqual(generated["grants"][0]["dst"], [BROAD_LAN])
        self.assertIn("BROAD LAN RANGE OVERRIDE", summary(policy))

    def test_fragment_tests_pair_expected_access_with_denials(self):
        generated = generate_grants(load_fixture())
        tests = [case for case in generated["tests"] if case["src"] == "tag:agent-agent-a"]
        self.assertEqual(len(tests), 1)
        self.assertIn(f"{LAN_HOST}:443", tests[0]["accept"])
        self.assertTrue(tests[0]["deny"])
        self.assertIn("tag:agent-agent-b:443", tests[0]["deny"])

    def test_supported_cidr_and_port_range_generate(self):
        policy = load_fixture()
        policy["lan_hosts"][0]["address"] = LAN_SUBNET
        policy["agents"][0]["allow"][0]["ports"] = ["tcp:8000-8010"]
        generated = generate_grants(policy)
        self.assertEqual(generated["grants"][0]["dst"], [LAN_SUBNET])
        self.assertEqual(generated["grants"][0]["ip"], ["tcp:8000-8010"])
        self.assertEqual(generated["tests"][0]["accept"], [f"{LAN_SUBNET}:8000-8010"])

    def test_required_denials_cannot_be_removed(self):
        policy = load_fixture()
        policy["agents"][0]["never"].remove("tailnet_administration")
        with self.assertRaisesRegex(PolicyError, "required never permissions"):
            validate(policy)

    def test_cli_summary_runs_offline(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "agent_access.py"), "summary", "--policy", str(ROOT / "policy.json")],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("agent-a (tag:agent-agent-a)", result.stdout)
        self.assertIn("Everything preset: grants all IP traffic to all destinations.", result.stdout)
        self.assertNotIn("This fragment grants no LAN access.", result.stdout)
        self.assertNotIn("adds no Internet or exit-node access grant", result.stdout)


if __name__ == "__main__":
    unittest.main()
