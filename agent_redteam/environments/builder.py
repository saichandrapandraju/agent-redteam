"""EnvironmentBuilder — fluent API for constructing test environments."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import uuid4

import yaml

from agent_redteam.core.models import (
    CanaryToken,
    EmailEntry,
    Environment,
    FileEntry,
    NetworkRule,
    ToolDefinition,
)
from agent_redteam.environments.canary import CanaryTokenGenerator


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

    def add_file(
        self, path: str, content: str, is_secret: bool = False
    ) -> EnvironmentBuilder:
        self._files.append(FileEntry(path=path, content=content, is_secret=is_secret))
        return self

    # -- Canary secrets ------------------------------------------------------

    def add_canary_secrets(
        self, tokens: list[CanaryToken] | None = None
    ) -> EnvironmentBuilder:
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

    def inject_attack_emails(
        self, emails_config: list[dict[str, Any]], resolved_payload: str, attack_id: str
    ) -> EnvironmentBuilder:
        """Inject attack emails from template environment_setup."""
        for email_def in emails_config:
            body = email_def.get("body", "")
            body = body.replace("{{ resolved_payload }}", resolved_payload)
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
        self, files_config: list[dict[str, Any]], resolved_payload: str, attack_id: str
    ) -> EnvironmentBuilder:
        """Inject attack files from template environment_setup."""
        for file_def in files_config:
            content = file_def.get("content", "")
            content = content.replace("{{ resolved_payload }}", resolved_payload)
            self._files.append(
                FileEntry(
                    path=file_def["path"],
                    content=content,
                    is_secret=file_def.get("is_secret", False),
                )
            )
        return self

    def inject_attack_secrets(
        self, secrets_config: list[dict[str, Any]]
    ) -> EnvironmentBuilder:
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
