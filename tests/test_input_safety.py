import contextlib
import io
import json
import unittest
from unittest.mock import patch

import agent_access
import test_agent_access


load_fixture = test_agent_access.load_fixture


FIELDS = (
    (("version",), "version"),
    (("lan_hosts",), "lan_hosts"),
    (("agents",), "agent"),
    (("lan_hosts", 0), "lan_hosts"),
    (("lan_hosts", 0, "name"), "name"),
    (("lan_hosts", 0, "address"), "address"),
    (("lan_hosts", 0, "service"), "service"),
    (("lan_hosts", 0, "allow_broad_lan_range"), "allow_broad_lan_range"),
    (("agents", 0), "agent"),
    (("agents", 0, "name"), "name"),
    (("agents", 0, "tag"), "tag"),
    (("agents", 0, "never"), "never"),
    (("agents", 0, "never", 0), "never"),
    (("agents", 0, "allow"), "allow"),
    (("agents", 0, "allow", 0), "allow"),
    (("agents", 0, "allow", 0, "host"), "host"),
    (("agents", 0, "allow", 0, "ports"), "ports"),
    (("agents", 0, "allow", 0, "ports", 0), "ports"),
)
REPRO_FIELDS = (
    ("agents", 0, "name"),
    ("agents", 0, "allow", 0, "host"),
    ("agents", 0, "allow", 0, "ports", 0),
)


def replace_field(policy, path, value):
    target = policy
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value


def raw_field(path, value):
    policy = load_fixture()
    replace_field(policy, path, "REPLACE-MALFORMED-VALUE")
    return json.dumps(policy).replace('"REPLACE-MALFORMED-VALUE"', value, 1)


class InputSafetyTests(unittest.TestCase):
    run_cli_input = test_agent_access.PolicyTests.run_cli_input

    def assert_clean_error(self, content, expected):
        for command in ("validate", "summary", "generate"):
            with self.subTest(command=command):
                result = self.run_cli_input(content, command)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertTrue(result.stderr.startswith("policy error:"), result.stderr)
                self.assertIn(expected, result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_verifier_values_at_50000_levels_and_1000000_characters(self):
        for path in REPRO_FIELDS:
            for opening, closing in (("[", "]"), ('{"a":', "}")):
                for scale in ("50000 levels", "1000000 characters"):
                    with self.subTest(field=path, shape=opening, scale=scale):
                        depth = 50_000
                        if scale == "1000000 characters":
                            overhead = len(raw_field(path, "0"))
                            depth = (1_000_000 - overhead) // (len(opening) + len(closing))
                        content = raw_field(path, opening * depth + "0" + closing * depth)
                        if scale == "1000000 characters":
                            content += " " * (1_000_000 - len(content))
                            self.assertEqual(len(content), 1_000_000)
                        self.assert_clean_error(content, "nesting exceeds 16")

    def test_every_field_rejects_nested_values_without_formatting_them(self):
        nested = 0
        for _ in range(50_000):
            nested = [nested]
        for path, field in FIELDS:
            with self.subTest(field=path):
                policy = load_fixture()
                replace_field(policy, path, nested)
                # Direct calls must raise PolicyError, never rely on the CLI fallback.
                for operation in (agent_access.validate, agent_access.summary, agent_access.generate_grants):
                    with self.assertRaisesRegex(agent_access.PolicyError, field):
                        operation(policy)
                self.assert_clean_error(raw_field(path, "[[0]]"), field)
                self.assert_clean_error(raw_field(path, '{"nested": {"value": 0}}'), field)
                self.assert_clean_error(raw_field(path, "[" * 50_000 + "0" + "]" * 50_000), "nesting")

    def test_version_requires_integer_one(self):
        for value in (1.0, True, False, None, "1", 0, 2):
            with self.subTest(version=value):
                policy = load_fixture()
                policy["version"] = value
                with self.assertRaisesRegex(agent_access.PolicyError, "version.*integer 1"):
                    agent_access.validate(policy)
                self.assert_clean_error(json.dumps(policy), "version")

    def test_file_size_limit_counts_bytes_and_accepts_exact_boundary(self):
        content = json.dumps(load_fixture())
        result = self.run_cli_input(content + " " * (1_000_000 - len(content)), "validate")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_clean_error(content + " " * (1_000_001 - len(content)), "exceeds 1000000 bytes")
        self.assert_clean_error('"' + "x" * 1_000_000 + '"', "exceeds 1000000 bytes")
        self.assert_clean_error('"' + "é" * 500_000 + '"', "exceeds 1000000 bytes")

    def test_depth_boundary_and_string_escaping(self):
        for depth in (16, 17):
            content = '{"extra":' + "[" * (depth - 1) + "0" + "]" * (depth - 1) + "}"
            self.assert_clean_error(content, "unsupported field" if depth == 16 else "nesting")
        # Brackets, escaped quotes and escaped backslashes inside strings are data.
        policy = load_fixture()
        policy['[{' * 100 + '"\\'] = '}]' * 100 + '\\"'
        self.assert_clean_error(json.dumps(policy), "unsupported field")

    def test_other_malformed_inputs_are_clean_errors(self):
        for content in ("", "null", "true", '"text"', "{", '{"version": NaN}',
                        '{"version": Infinity}', '{"version":' + "9" * 10_000 + "}"):
            with self.subTest(prefix=content[:30]):
                self.assert_clean_error(content, "policy error:")

    def test_unexpected_cli_error_is_clean_but_library_error_is_visible(self):
        for command in ("validate", "summary", "generate"):
            with self.subTest(command=command):
                with patch("agent_access._normalize", side_effect=RuntimeError("test bug")):
                    for operation in (agent_access.validate, agent_access.summary, agent_access.generate_grants):
                        with self.assertRaisesRegex(RuntimeError, "test bug"):
                            operation(load_fixture())
                    stderr = io.StringIO()
                    stdout = io.StringIO()
                    with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
                        with self.assertRaises(SystemExit) as caught:
                            agent_access.main([command, "--policy", "policy.json"])
                    self.assertEqual(caught.exception.code, 2)
                    self.assertEqual(stdout.getvalue(), "")
                    self.assertEqual(stderr.getvalue(), "policy error: unexpected error while processing policy\n")


if __name__ == "__main__":
    unittest.main()
