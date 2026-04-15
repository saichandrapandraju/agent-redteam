"""Stateful environment runtime — typed domain models with mutable state.

Replaces the monolithic ``_simulate_tool`` approach with domain-specific
Pydantic models where tools read and write shared state, producing
consistent cross-tool behavior (write-then-read, email-then-check-outbox,
network rules actually enforced, SQL against seeded data).
"""

from __future__ import annotations

import csv
import io
import logging
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from agent_redteam.core.models import (
    EmailEntry,
    Environment,
    NetworkRule,
)

logger = logging.getLogger("agent_redteam.environments.runtime")


# ---------------------------------------------------------------------------
# Domain state models
# ---------------------------------------------------------------------------


class NetworkPolicy(BaseModel):
    """Enforced network policy derived from Environment.network_rules."""

    default_policy: str = "deny"
    allowed_domains: set[str] = Field(default_factory=set)
    denied_domains: set[str] = Field(default_factory=set)
    canary_domains: dict[str, str] = Field(default_factory=dict)

    @classmethod
    def from_rules(cls, rules: list[NetworkRule], default: str = "deny") -> NetworkPolicy:
        allowed: set[str] = set()
        denied: set[str] = set()
        canary: dict[str, str] = {}
        for r in rules:
            if r.is_canary:
                canary[r.domain] = r.canary_id or ""
            elif r.allowed:
                allowed.add(r.domain)
            else:
                denied.add(r.domain)
        return cls(
            default_policy=default,
            allowed_domains=allowed,
            denied_domains=denied,
            canary_domains=canary,
        )

    def check(self, url: str) -> tuple[bool, str, str | None]:
        """Return (allowed, reason, canary_id_or_none)."""
        domain = urlparse(url).hostname or ""
        if domain in self.canary_domains:
            return True, f"canary domain: {domain}", self.canary_domains[domain]
        if domain in self.denied_domains:
            return False, f"denied domain: {domain}", None
        if domain in self.allowed_domains:
            return True, f"allowed domain: {domain}", None
        if self.default_policy == "allow":
            return True, "default allow", None
        return False, f"denied by default policy (domain: {domain})", None


class GitState(BaseModel):
    """Minimal git state for shell git commands."""

    branch: str = "main"
    branches: list[str] = Field(default_factory=lambda: ["main", "develop"])
    log_entries: list[str] = Field(
        default_factory=lambda: [
            "a1b2c3d Initial commit\n  Author: Dev User <dev@example.com>  2024-01-15",
            "e5f6a7b Add authentication module\n  Author: Dev User <dev@example.com>  2024-02-10",
            "c8d9e0f Fix SQL injection in search endpoint\n  Author: Security Bot <bot@ci.internal>  2024-03-01",
        ]
    )
    has_uncommitted: bool = False
    remote: str = "origin"


class DbTable(BaseModel):
    """A simple in-memory table for SQL simulation."""

    name: str
    columns: list[str]
    rows: list[list[str]]


class CustomerRecord(BaseModel):
    customer_id: str
    name: str
    email: str
    tier: str = "Standard"
    account_balance: float = 0.0
    notes: str = ""


class TicketRecord(BaseModel):
    ticket_id: str
    customer_id: str = ""
    subject: str = ""
    status: str = "open"
    priority: str = "medium"
    assigned_to: str = ""


# ---------------------------------------------------------------------------
# Environment Runtime
# ---------------------------------------------------------------------------


class EnvironmentRuntime:
    """Stateful tool executor backed by typed domain models.

    Constructed from an ``Environment`` and used by adapters to execute
    tool calls with consistent, mutable state.
    """

    def __init__(self, environment: Environment) -> None:
        self.env = environment

        self.filesystem: dict[str, str] = {}
        for f in environment.files:
            self.filesystem[f.path] = f.content

        self.env_vars: dict[str, str] = {
            "HOME": "/home/user",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "SHELL": "/bin/bash",
            "USER": "user",
            "LANG": "en_US.UTF-8",
        }
        for ct in environment.canary_tokens:
            if ct.env_var:
                self.env_vars[ct.env_var] = ct.value
        ctx_env = environment.agent_context.get("env_vars", {})
        if isinstance(ctx_env, dict):
            self.env_vars.update(ctx_env)

        self.inbox: list[EmailEntry] = list(environment.emails)
        self.outbox: list[EmailEntry] = []

        self.network = NetworkPolicy.from_rules(
            environment.network_rules, environment.default_network_policy
        )

        self.git = GitState()

        self.db_tables: list[DbTable] = self._load_tables_from_files()

        self.customers: list[CustomerRecord] = [
            CustomerRecord(
                customer_id="C-1001", name="Jane Doe", email="jane@example.com",
                tier="Gold", account_balance=1250.00,
            ),
            CustomerRecord(
                customer_id="C-1002", name="Bob Smith", email="bob@example.com",
                tier="Standard", account_balance=340.00,
            ),
            CustomerRecord(
                customer_id="C-1003", name="Alice Chen", email="alice@example.com",
                tier="Platinum", account_balance=8700.00,
            ),
        ]

        self.tickets: list[TicketRecord] = [
            TicketRecord(
                ticket_id="TKT-4501", customer_id="C-1001", subject="Billing discrepancy",
                status="open", priority="high",
            ),
            TicketRecord(
                ticket_id="TKT-4502", customer_id="C-1002", subject="Password reset",
                status="in_progress", priority="medium",
            ),
        ]

        self.memory: dict[str, str] = dict(environment.agent_context.get("memory", {}))

        self.shell_history: list[str] = []
        self.cwd: str = "/home/user/project"

    # -- Dispatch -----------------------------------------------------------

    def execute(self, tool_name: str, kwargs: dict[str, Any]) -> Any:
        """Execute a tool call against the stateful environment."""
        dispatch: dict[str, Any] = {
            "file_read": self.file_read,
            "read_file": self.file_read,
            "file_write": self.file_write,
            "write_file": self.file_write,
            "shell": self.shell,
            "shell_exec": self.shell,
            "bash": self.shell,
            "execute": self.shell,
            "run_command": self.shell,
            "terminal": self.shell,
            "git": self.git_cmd,
            "http_request": self.http_request,
            "http_get": self.http_request,
            "curl": self.http_request,
            "fetch": self.http_request,
            "requests": self.http_request,
            "send_email": self.send_email,
            "email": self.send_email,
            "read_emails": self.read_emails,
            "search": self.search,
            "search_kb": self.search,
            "search_files": self.search,
            "sql_query": self.sql_query,
            "db_query": self.sql_query,
            "sql": self.sql_query,
            "lookup_customer": self.lookup_customer,
            "crm_lookup": self.lookup_customer,
            "update_ticket": self.update_ticket,
            "close_ticket": self.update_ticket,
            "save_note": self.save_note,
            "remember": self.save_note,
            "store_memory": self.save_note,
            "memory_write": self.save_note,
        }
        handler = dispatch.get(tool_name)
        if handler:
            return handler(**kwargs)
        return f"Tool '{tool_name}' returned: OK (args: {list(kwargs.keys())})"

    # -- Filesystem ---------------------------------------------------------

    def file_read(self, *, path: str = "", **_kw: Any) -> str:
        if path in self.filesystem:
            return self.filesystem[path]
        for ct in self.env.canary_tokens:
            if ct.file_path == path:
                return ct.value
        return f"Error: file not found: {path}"

    def file_write(self, *, path: str = "/tmp/output.txt", content: str = "", **_kw: Any) -> str:
        self.filesystem[path] = content
        return f"OK: wrote {len(content)} bytes to {path}"

    # -- Shell --------------------------------------------------------------

    def shell(self, *, command: str = "", **_kw: Any) -> str:
        self.shell_history.append(command)
        cmd = command.strip()
        cmd_lower = cmd.lower()

        if cmd_lower.startswith("cat "):
            path = cmd.split(None, 1)[1].strip().split()[0] if len(cmd.split()) > 1 else ""
            return self.file_read(path=path)

        if cmd_lower in ("env", "printenv") or cmd_lower.startswith("printenv") or cmd_lower.startswith("env "):
            return "\n".join(f"{k}={v}" for k, v in self.env_vars.items())

        if cmd_lower.startswith("export "):
            match = re.match(r"export\s+(\w+)=(.*)", cmd)
            if match:
                self.env_vars[match.group(1)] = match.group(2).strip("'\"")
                return ""
            return "export: invalid syntax"

        if cmd_lower.startswith("ls"):
            target = cmd.split(None, 1)[1].strip().split()[0] if len(cmd.split()) > 1 else self.cwd
            entries = []
            for p in sorted(self.filesystem):
                if p.startswith(target):
                    relative = p[len(target):].lstrip("/")
                    top = relative.split("/")[0] if "/" in relative else relative
                    if top and top not in entries:
                        entries.append(top)
            return "\n".join(entries[:30]) if entries else f"ls: cannot access '{target}': No such file or directory"

        if cmd_lower.startswith("pwd"):
            return self.cwd

        if cmd_lower.startswith("cd "):
            self.cwd = cmd.split(None, 1)[1].strip()
            return ""

        if cmd_lower.startswith("whoami"):
            return self.env_vars.get("USER", "user")

        if cmd_lower.startswith("id"):
            user = self.env_vars.get("USER", "user")
            return f"uid=1000({user}) gid=1000({user}) groups=1000({user})"

        if cmd_lower.startswith("uname"):
            return "Linux agent-sandbox 6.1.0-generic #1 SMP x86_64 GNU/Linux"

        if cmd_lower.startswith("echo "):
            text = cmd.split("echo ", 1)[1]
            for k, v in self.env_vars.items():
                text = text.replace(f"${k}", v).replace(f"${{{k}}}", v)
            return text

        if "pip install" in cmd_lower:
            pkg = cmd.split("install", 1)[1].strip().split()[0] if "install" in cmd else "package"
            return f"Successfully installed {pkg}-1.0.0"

        if cmd_lower.startswith("curl ") or cmd_lower.startswith("wget "):
            url_match = re.search(r'https?://\S+', cmd)
            if url_match:
                return self.http_request(url=url_match.group(0), method="GET")
            return '{"status": "ok"}'

        if cmd_lower.startswith("python"):
            return "(python process exited with code 0)"

        if cmd_lower.startswith("grep "):
            parts = cmd.split(None, 2)
            pattern = parts[1] if len(parts) > 1 else ""
            target = parts[2] if len(parts) > 2 else ""
            results = []
            if target and target in self.filesystem:
                for i, line in enumerate(self.filesystem[target].splitlines(), 1):
                    if pattern.lower() in line.lower():
                        results.append(f"{target}:{i}:{line}")
            else:
                for fpath, content in self.filesystem.items():
                    for i, line in enumerate(content.splitlines(), 1):
                        if pattern.lower() in line.lower():
                            results.append(f"{fpath}:{i}:{line}")
            return "\n".join(results[:20]) if results else f"(no matches for '{pattern}')"

        if cmd_lower.startswith("mkdir"):
            return ""

        if cmd_lower.startswith("rm "):
            target_path = cmd.split(None)[-1]
            if target_path in self.filesystem:
                del self.filesystem[target_path]
            return ""

        if cmd_lower.startswith("git "):
            return self.git_cmd(command=cmd.split("git ", 1)[1])

        return f"$ {cmd}\n(command completed)"

    # -- Git ----------------------------------------------------------------

    def git_cmd(self, *, command: str = "", **_kw: Any) -> str:
        cmd = command.strip().lower()

        if cmd.startswith("status"):
            if self.git.has_uncommitted:
                return (
                    f"On branch {self.git.branch}\n"
                    "Changes not staged for commit:\n"
                    "  modified:   app.py\n"
                )
            return f"On branch {self.git.branch}\nnothing to commit, working tree clean"

        if cmd.startswith("log"):
            return "\n\n".join(self.git.log_entries[:5])

        if cmd.startswith("diff"):
            return "(no changes)" if not self.git.has_uncommitted else "+added line\n-removed line"

        if cmd.startswith("push"):
            if "--force" in cmd or "-f" in cmd:
                return (
                    f"To {self.git.remote}\n"
                    " + abc123...def456 main -> main (forced update)"
                )
            return "Everything up-to-date"

        if cmd.startswith("branch"):
            return "\n".join(
                f"{'* ' if b == self.git.branch else '  '}{b}" for b in self.git.branches
            )

        if cmd.startswith("checkout") or cmd.startswith("switch"):
            branch = cmd.split()[-1]
            if branch not in self.git.branches:
                self.git.branches.append(branch)
            self.git.branch = branch
            return f"Switched to branch '{branch}'"

        if cmd.startswith("clone"):
            return "Cloning into 'repo'...\ndone."

        if cmd.startswith("add"):
            self.git.has_uncommitted = True
            return ""

        if cmd.startswith("commit"):
            self.git.has_uncommitted = False
            self.git.log_entries.insert(0, "f1e2d3c New commit\n  Author: user  " + str(datetime.now(timezone.utc)))
            return "[main f1e2d3c] New commit"

        return f"git: '{command}' executed"

    # -- HTTP (network-policy-enforced) -------------------------------------

    def http_request(self, *, url: str = "", method: str = "GET", body: str = "", **_kw: Any) -> str:
        method = method.upper()
        allowed, reason, canary_id = self.network.check(url)

        if canary_id:
            logger.debug("Canary domain hit: %s (canary_id=%s)", url, canary_id)
            return (
                f'{{"status": 200, "method": "{method}", "url": "{url}", '
                f'"body": "Request received", "x-request-id": "{canary_id}"}}'
            )

        if not allowed:
            return (
                f'{{"status": 403, "error": "Forbidden", '
                f'"message": "Network policy denied request to {url}: {reason}"}}'
            )

        domain = urlparse(url).hostname or ""
        if "api" in domain or "internal" in domain:
            return (
                f'{{"status": 200, "method": "{method}", "url": "{url}", '
                f'"data": {{"result": "ok", "items": []}}}}'
            )

        return (
            f'{{"status": 200, "method": "{method}", "url": "{url}", '
            f'"body": "Response from {url}"}}'
        )

    # -- Email (inbox + outbox) ---------------------------------------------

    def send_email(self, *, to: str = "", subject: str = "", body: str = "", **_kw: Any) -> str:
        entry = EmailEntry(
            from_addr="agent@company.com",
            to_addr=to,
            subject=subject,
            body=body,
        )
        self.outbox.append(entry)
        return f"Email sent to {to} with subject '{subject}'."

    def read_emails(self, **_kw: Any) -> str:
        if not self.inbox:
            return "No emails in inbox."
        parts = []
        for i, e in enumerate(self.inbox, 1):
            parts.append(
                f"--- Email {i} ---\n"
                f"From: {e.from_addr}\nTo: {e.to_addr}\n"
                f"Subject: {e.subject}\n\n{e.body}"
            )
        return "\n\n".join(parts)

    # -- Search (actually searches filesystem) ------------------------------

    def search(self, *, query: str = "", **_kw: Any) -> str:
        results = []
        q = query.lower()
        for path, content in self.filesystem.items():
            if q in content.lower() or q in path.lower():
                snippet = ""
                for line in content.splitlines():
                    if q in line.lower():
                        snippet = line.strip()[:120]
                        break
                results.append(f"  {path}: {snippet}")
        if results:
            return f"Found {len(results)} result(s):\n" + "\n".join(results[:10])
        return f"No results found for '{query}'."

    # -- SQL (queries seeded data) ------------------------------------------

    def sql_query(self, *, query: str = "", **_kw: Any) -> str:
        q = query.strip().lower()

        if q.startswith("select"):
            for table in self.db_tables:
                if table.name.lower() in q:
                    return self._format_table(table)
            if self.db_tables:
                return self._format_table(self.db_tables[0])
            return "(0 rows)"

        if any(q.startswith(k) for k in ("insert", "update", "delete")):
            return "Query OK, 1 row affected."

        if q.startswith("drop") or q.startswith("alter") or q.startswith("truncate"):
            return "ERROR: permission denied for relation"

        return "Query OK, 0 rows affected."

    # -- CRM ---------------------------------------------------------------

    def lookup_customer(self, *, id: str = "", email: str = "", **_kw: Any) -> str:
        for c in self.customers:
            if c.customer_id == id or c.email == email or id in (c.customer_id, c.email, c.name):
                return c.model_dump_json()
        return f'{{"error": "Customer not found", "query": "{id or email}"}}'

    def update_ticket(self, *, ticket_id: str = "", status: str = "", notes: str = "", **_kw: Any) -> str:
        tid = ticket_id or ""
        for t in self.tickets:
            if t.ticket_id == tid:
                if status:
                    t.status = status
                return f"Ticket {tid} updated (status={t.status})."
        return f"Ticket {tid} not found."

    # -- Memory -------------------------------------------------------------

    def save_note(self, *, key: str = "", title: str = "", content: str = "", **_kw: Any) -> str:
        k = key or title or "note"
        self.memory[k] = content
        return f"Stored memory entry '{k}'."

    # -- Internal helpers ---------------------------------------------------

    def _load_tables_from_files(self) -> list[DbTable]:
        """Parse CSV files from the environment into DbTable objects."""
        tables: list[DbTable] = []
        for f in self.env.files:
            if f.path.endswith(".csv"):
                try:
                    reader = csv.reader(io.StringIO(f.content))
                    header = next(reader, None)
                    if header:
                        rows = [list(r) for r in reader if r]
                        name = f.path.rsplit("/", 1)[-1].replace(".csv", "")
                        tables.append(DbTable(name=name, columns=header, rows=rows))
                except Exception:
                    pass
        return tables

    @staticmethod
    def _format_table(table: DbTable) -> str:
        if not table.rows:
            return "(0 rows)"
        col_widths = [max(len(c), *(len(r[i]) if i < len(r) else 0 for r in table.rows)) for i, c in enumerate(table.columns)]
        header = " | ".join(c.ljust(w) for c, w in zip(table.columns, col_widths))
        sep = "-+-".join("-" * w for w in col_widths)
        row_lines = []
        for r in table.rows:
            cells = [r[i].ljust(col_widths[i]) if i < len(r) else " " * col_widths[i] for i in range(len(table.columns))]
            row_lines.append(" | ".join(cells))
        return f"{header}\n{sep}\n" + "\n".join(row_lines) + f"\n({len(table.rows)} rows)"
