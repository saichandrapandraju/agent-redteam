"""Tests for environment builder and canary token generation."""

from agent_redteam.environments.builder import EnvironmentBuilder
from agent_redteam.environments.canary import CanaryTokenGenerator


class TestCanaryTokenGenerator:
    def test_generate_standard_set(self):
        gen = CanaryTokenGenerator()
        tokens = gen.generate_standard_set()
        assert len(tokens) == 7
        types = {t.secret_type for t in tokens}
        assert "aws_access_key" in types
        assert "ssh_private_key" in types

    def test_generate_custom(self):
        gen = CanaryTokenGenerator()
        token = gen.generate("openai_api_key", name="Test Key")
        assert token.value.startswith("sk-")
        assert token.name == "Test Key"

    def test_tokens_are_unique(self):
        gen = CanaryTokenGenerator()
        tokens = [gen.generate("generic_password") for _ in range(10)]
        values = {t.value for t in tokens}
        assert len(values) == 10


class TestEnvironmentBuilder:
    def test_basic_build(self):
        env = EnvironmentBuilder("test").add_tools(["shell", "file_read"]).build()
        assert env.name == "test"
        assert len(env.tools) == 2

    def test_add_canary_secrets(self):
        env = EnvironmentBuilder("test").add_canary_secrets().build()
        assert len(env.canary_tokens) == 7
        assert len(env.files) >= 7

    def test_add_file(self):
        env = (
            EnvironmentBuilder("test")
            .add_file("/readme.md", "Hello")
            .add_file("/secret.env", "KEY=value", is_secret=True)
            .build()
        )
        assert len(env.files) == 2
        assert env.file_map["/secret.env"].is_secret

    def test_deny_network(self):
        env = EnvironmentBuilder("test").deny_network_by_default().allow_domains(["github.com"]).build()
        assert env.default_network_policy == "deny"
        assert len(env.network_rules) == 1
        assert env.network_rules[0].domain == "github.com"

    def test_canary_domain(self):
        env = EnvironmentBuilder("test").add_canary_domain("evil.com").build()
        assert len(env.canary_tokens) == 1
        assert any(r.is_canary for r in env.network_rules)

    def test_inject_attack_emails(self):
        emails = [{"from": "attacker@evil.com", "subject": "Hi", "body": "PAYLOAD_HERE"}]
        env = EnvironmentBuilder("test").inject_attack_emails(emails, "attack_1").build()
        assert len(env.emails) == 1
        assert "PAYLOAD_HERE" in env.emails[0].body
        assert env.emails[0].is_malicious

    def test_load_swe_agent_definition(self):
        env = EnvironmentBuilder("test").add_files_from_definition("swe_agent").build()
        assert len(env.files) > 0
        assert any("README.md" in f.path for f in env.files)
