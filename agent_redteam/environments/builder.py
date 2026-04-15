"""EnvironmentBuilder — fluent API for constructing test environments."""

from __future__ import annotations

import copy
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

import yaml
from jinja2 import Environment as JinjaEnvironment

from agent_redteam.core.models import (
    CanaryToken,
    EmailEntry,
    Environment,
    FileEntry,
    NetworkRule,
    ToolDefinition,
)
from agent_redteam.environments.canary import CanaryTokenGenerator

if TYPE_CHECKING:
    from agent_redteam.core.models import AgentCapabilities, Attack

logger = logging.getLogger("agent_redteam.environments.builder")

_jinja = JinjaEnvironment()


_TOOL_TO_PROFILE: dict[str, str] = {
    "read_emails": "customer_support_agent",
    "send_email": "customer_support_agent",
    "email": "customer_support_agent",
    "search_kb": "customer_support_agent",
    "update_ticket": "customer_support_agent",
    "lookup_customer": "customer_support_agent",
    "sql_query": "data_analyst_agent",
    "db_query": "data_analyst_agent",
    "database": "data_analyst_agent",
    "sql": "data_analyst_agent",
}

_DEFAULT_PROFILE = "swe_agent"


def select_environment_profile(capabilities: AgentCapabilities) -> str:
    """Infer the best environment definition from declared agent capabilities.

    Counts tool-name matches against known profiles and returns the profile
    with the most hits, falling back to ``swe_agent``.
    """
    votes: dict[str, int] = {}
    tool_names = {t.name.lower() for t in capabilities.tools}

    for tool_name in tool_names:
        for pattern, profile in _TOOL_TO_PROFILE.items():
            if pattern in tool_name:
                votes[profile] = votes.get(profile, 0) + 1

    if not votes:
        return _DEFAULT_PROFILE
    return max(votes, key=votes.get)  # type: ignore[arg-type]


class EnvironmentBuilder:
    """Fluent builder for constructing test environments.

    Example::

        env = (
            EnvironmentBuilder("swe_agent_test")
            .add_tools(["shell", "file_read", "file_write", "git"])
            .add_canary_secrets()
            .deny_network_by_default()
            .allow_domains(["github.com", "pypi.org"])
            .build()
        )
    """

    def __init__(self, name: str = "default") -> None:
        self._name = name
        self._files: list[FileEntry] = []
        self._tools: list[ToolDefinition] = []
        self._canaries: list[CanaryToken] = []
        self._emails: list[EmailEntry] = []
        self._network_rules: list[NetworkRule] = []
        self._default_network_policy = "deny"
        self._context: dict[str, Any] = {}

    # -- Tools ---------------------------------------------------------------

    def add_tools(self, tool_names: list[str]) -> EnvironmentBuilder:
        for name in tool_names:
            self._tools.append(ToolDefinition(name=name, description=f"{name} tool"))
        return self

    def add_tool(self, tool: ToolDefinition) -> EnvironmentBuilder:
        self._tools.append(tool)
        return self

    # -- Files ---------------------------------------------------------------

    def add_file(self, path: str, content: str, is_secret: bool = False) -> EnvironmentBuilder:
        self._files.append(FileEntry(path=path, content=content, is_secret=is_secret))
        return self

    # -- Canary secrets ------------------------------------------------------

    def add_canary_secrets(self, tokens: list[CanaryToken] | None = None) -> EnvironmentBuilder:
        if tokens is None:
            tokens = CanaryTokenGenerator().generate_standard_set()
        self._canaries.extend(tokens)
        for token in tokens:
            if token.file_path:
                self._files.append(
                    FileEntry(
                        path=token.file_path,
                        content=token.value,
                        is_secret=True,
                        canary_id=token.id,
                    )
                )
        return self

    # -- Emails --------------------------------------------------------------

    def add_email(self, email: EmailEntry) -> EnvironmentBuilder:
        self._emails.append(email)
        return self

    # -- Network -------------------------------------------------------------

    def deny_network_by_default(self) -> EnvironmentBuilder:
        self._default_network_policy = "deny"
        return self

    def allow_domains(self, domains: list[str]) -> EnvironmentBuilder:
        for domain in domains:
            self._network_rules.append(NetworkRule(domain=domain, allowed=True))
        return self

    def add_canary_domain(self, domain: str) -> EnvironmentBuilder:
        canary = CanaryToken(
            id=f"canary_domain_{uuid4().hex[:8]}",
            name=f"Canary domain: {domain}",
            secret_type="url",
            value=f"https://{domain}/",
        )
        self._canaries.append(canary)
        self._network_rules.append(
            NetworkRule(domain=domain, allowed=True, is_canary=True, canary_id=canary.id)
        )
        return self

    # -- Attack injection ----------------------------------------------------

    @staticmethod
    def _render_value(value: str, ctx: dict[str, str]) -> str:
        """Render Jinja2 placeholders in a single string value."""
        if "{{" not in value:
            return value
        try:
            return _jinja.from_string(value).render(**ctx)
        except Exception:
            logger.debug("Jinja render failed for: %s", value[:80])
            return value

    @staticmethod
    def _render_deep(obj: Any, ctx: dict[str, str]) -> Any:
        """Recursively render all string values in a nested dict/list."""
        if isinstance(obj, str):
            return EnvironmentBuilder._render_value(obj, ctx)
        if isinstance(obj, dict):
            return {k: EnvironmentBuilder._render_deep(v, ctx) for k, v in obj.items()}
        if isinstance(obj, list):
            return [EnvironmentBuilder._render_deep(v, ctx) for v in obj]
        return obj

    def inject_attack_emails(
        self, emails_config: list[dict[str, Any]], attack_id: str
    ) -> EnvironmentBuilder:
        """Inject attack emails from template environment_setup."""
        for email_def in emails_config:
            body = email_def.get("body", email_def.get("body_html", ""))
            self._emails.append(
                EmailEntry(
                    from_addr=email_def.get("from", "unknown@company.com"),
                    subject=email_def.get("subject", ""),
                    body=body,
                    is_malicious=True,
                    attack_id=attack_id,
                )
            )
        return self

    def inject_attack_files(
        self, files_config: list[dict[str, Any]], attack_id: str
    ) -> EnvironmentBuilder:
        """Inject attack files from template environment_setup."""
        for file_def in files_config:
            self._files.append(
                FileEntry(
                    path=file_def.get("path", f"/tmp/{attack_id}"),
                    content=file_def.get("content", ""),
                    is_secret=file_def.get("is_secret", False),
                )
            )
        return self

    def inject_attack_memory(
        self, memory_config: list[dict[str, Any]], attack_id: str
    ) -> EnvironmentBuilder:
        """Inject memory entries from template environment_setup."""
        for mem_def in memory_config:
            key = mem_def.get("key", f"memory_{attack_id}")
            value = mem_def.get("value", "")
            self._context.setdefault("memory", {})[key] = value
        return self

    def inject_attack_env_vars(
        self, env_config: dict[str, str] | list[dict[str, str]]
    ) -> EnvironmentBuilder:
        """Inject environment variables from template environment_setup."""
        if isinstance(env_config, dict):
            self._context.setdefault("env_vars", {}).update(env_config)
        elif isinstance(env_config, list):
            for item in env_config:
                if isinstance(item, dict):
                    self._context.setdefault("env_vars", {}).update(item)
        return self

    def inject_attack_secrets(self, secrets_config: list[dict[str, Any]]) -> EnvironmentBuilder:
        """Seed canary secrets specified by the attack template."""
        gen = CanaryTokenGenerator()
        for secret_def in secrets_config:
            canary = gen.generate(
                secret_type=secret_def.get("type", "generic_password"),
                name=secret_def.get("name", ""),
                file_path=secret_def.get("path"),
            )
            if "canary_id" in secret_def:
                canary = canary.model_copy(update={"id": secret_def["canary_id"]})
            self._canaries.append(canary)
            if canary.file_path:
                self._files.append(
                    FileEntry(
                        path=canary.file_path,
                        content=canary.value,
                        is_secret=True,
                        canary_id=canary.id,
                    )
                )
        return self

    # -- Template loading ----------------------------------------------------

    def add_files_from_definition(self, definition_name: str) -> EnvironmentBuilder:
        """Load files from a built-in environment definition YAML."""
        definitions_dir = Path(__file__).parent / "definitions"
        template_path = definitions_dir / f"{definition_name}.yaml"
        if not template_path.exists():
            return self
        with open(template_path) as f:
            data = yaml.safe_load(f)
        for file_def in data.get("files", []):
            self.add_file(file_def["path"], file_def["content"])
        for tool_def in data.get("tools", []):
            self._tools.append(
                ToolDefinition(
                    name=tool_def["name"],
                    description=tool_def.get("description", ""),
                )
            )
        return self

    # -- Attack injection (consolidated) ------------------------------------

    def _build_template_context(self, attack: Attack) -> dict[str, str]:
        """Build the Jinja context for rendering environment_setup placeholders.

        Merges the attack's planner-resolved parameters (``secret_file_path``,
        ``exfil_url``, ...) with ``resolved_payload`` and a ``payload_template``
        alias so both ``{{ resolved_payload }}`` and ``{{ payload_template }}``
        work in YAML templates.  If canary tokens are already seeded, their
        first value is exposed as ``{{ canary_value }}``.
        """
        ctx: dict[str, str] = dict(attack.parameters)
        ctx["resolved_payload"] = attack.resolved_payload
        ctx["payload_template"] = attack.resolved_payload
        if self._canaries:
            ctx.setdefault("canary_value", self._canaries[0].value)
        return ctx

    def inject_attack(self, attack: Attack) -> EnvironmentBuilder:
        """Configure the environment for a specific attack.

        Reads the template's ``environment_setup``, renders **all** Jinja
        placeholders (``{{ secret_file_path }}``, ``{{ payload_template }}``,
        ``{{ canary_value }}``, etc.), then injects emails, files, memory,
        env vars, and secrets.
        """
        raw_setup = attack.template.environment_setup
        attack_id = str(attack.id)

        ctx = self._build_template_context(attack)
        setup = self._render_deep(raw_setup, ctx)

        if "secrets" in setup:
            self.inject_attack_secrets(setup["secrets"])
            ctx = self._build_template_context(attack)
            setup = self._render_deep(raw_setup, ctx)

        if "emails" in setup:
            self.inject_attack_emails(setup["emails"], attack_id)
        if "files" in setup:
            self.inject_attack_files(setup["files"], attack_id)
        if "memory" in setup:
            self.inject_attack_memory(setup["memory"], attack_id)
        if "env" in setup:
            self.inject_attack_env_vars(setup["env"])
        return self

    def build_for_attack(self, attack: Attack) -> Environment:
        """Create an independent environment with attack content injected.

        Non-mutating: copies the builder state first so the base builder
        can be reused across attacks.
        """
        return self.copy().inject_attack(attack).build()

    # -- Copy ----------------------------------------------------------------

    def copy(self) -> EnvironmentBuilder:
        """Return a deep copy of this builder so mutations don't affect the original."""
        clone = EnvironmentBuilder(self._name)
        clone._files = copy.deepcopy(self._files)
        clone._tools = copy.deepcopy(self._tools)
        clone._canaries = copy.deepcopy(self._canaries)
        clone._emails = copy.deepcopy(self._emails)
        clone._network_rules = copy.deepcopy(self._network_rules)
        clone._default_network_policy = self._default_network_policy
        clone._context = copy.deepcopy(self._context)
        return clone

    # -- Build ---------------------------------------------------------------

    def build(self) -> Environment:
        return Environment(
            name=self._name,
            files=self._files,
            tools=self._tools,
            canary_tokens=self._canaries,
            emails=self._emails,
            network_rules=self._network_rules,
            default_network_policy=self._default_network_policy,
            agent_context=self._context,
        )
