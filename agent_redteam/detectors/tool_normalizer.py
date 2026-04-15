"""Tool name normalization for detectors.

Maps arbitrary tool names to canonical categories so detectors don't rely
on exact-match against fixed string sets.  Uses a combination of explicit
aliases and substring heuristics.
"""

from __future__ import annotations

_CANONICAL_ALIASES: dict[str, str] = {
    "shell": "shell",
    "bash": "shell",
    "zsh": "shell",
    "execute": "shell",
    "run_command": "shell",
    "run_terminal_cmd": "shell",
    "terminal": "shell",
    "shell_exec": "shell",
    "subprocess": "shell",
    "exec": "shell",
    "file_read": "file_read",
    "read_file": "file_read",
    "cat_file": "file_read",
    "read": "file_read",
    "file_write": "file_write",
    "write_file": "file_write",
    "create_file": "file_write",
    "update_file": "file_write",
    "save_file": "file_write",
    "file_delete": "file_delete",
    "delete_file": "file_delete",
    "rm": "file_delete",
    "remove": "file_delete",
    "remove_file": "file_delete",
    "http_request": "http_request",
    "http_get": "http_request",
    "http_post": "http_request",
    "httpx_get": "http_request",
    "httpx_post": "http_request",
    "curl": "http_request",
    "fetch": "http_request",
    "requests": "http_request",
    "wget": "http_request",
    "api_call": "http_request",
    "send_email": "send_email",
    "email": "send_email",
    "send_message": "send_email",
    "dispatch_notification": "send_email",
    "slack_post": "send_email",
    "notify": "send_email",
    "send_notification": "send_email",
    "database": "database",
    "db_query": "database",
    "sql_query": "database",
    "sql": "database",
    "sql_execute": "database",
    "db_write": "database",
    "run_query": "database",
    "deploy": "deploy",
    "push": "deploy",
    "publish": "deploy",
    "release": "deploy",
    "kubectl_apply": "deploy",
    "grant_access": "auth",
    "add_user": "auth",
    "set_permissions": "auth",
    "invite": "auth",
    "create_role": "auth",
    "process_payment": "financial",
    "refund": "financial",
    "charge": "financial",
    "transfer": "financial",
    "payment_api": "financial",
    "update_config": "config",
    "set_config": "config",
    "modify_settings": "config",
    "change_config": "config",
    "update_record": "data_mutation",
    "delete_record": "data_mutation",
    "bulk_update": "data_mutation",
}

_SUBSTRING_RULES: list[tuple[str, str]] = [
    ("shell", "shell"),
    ("bash", "shell"),
    ("terminal", "shell"),
    ("exec", "shell"),
    ("cmd", "shell"),
    ("http", "http_request"),
    ("curl", "http_request"),
    ("fetch", "http_request"),
    ("request", "http_request"),
    ("email", "send_email"),
    ("mail", "send_email"),
    ("notify", "send_email"),
    ("notification", "send_email"),
    ("slack", "send_email"),
    ("sql", "database"),
    ("query", "database"),
    ("deploy", "deploy"),
    ("publish", "deploy"),
    ("kubectl", "deploy"),
    ("payment", "financial"),
    ("refund", "financial"),
    ("charge", "financial"),
]

SHELL_CATEGORY = "shell"
HTTP_CATEGORY = "http_request"
EMAIL_CATEGORY = "send_email"
FILE_READ_CATEGORY = "file_read"
FILE_WRITE_CATEGORY = "file_write"
FILE_DELETE_CATEGORY = "file_delete"
DATABASE_CATEGORY = "database"
DEPLOY_CATEGORY = "deploy"
AUTH_CATEGORY = "auth"
FINANCIAL_CATEGORY = "financial"
CONFIG_CATEGORY = "config"
DATA_MUTATION_CATEGORY = "data_mutation"

SENSITIVE_CATEGORIES = frozenset({SHELL_CATEGORY, HTTP_CATEGORY, EMAIL_CATEGORY, DATABASE_CATEGORY})
HIGH_RISK_CATEGORIES = SENSITIVE_CATEGORIES | frozenset({DEPLOY_CATEGORY, AUTH_CATEGORY, FINANCIAL_CATEGORY})


def normalize(tool_name: str | None) -> str | None:
    """Map an arbitrary tool name to its canonical category.

    Returns the canonical name if a match is found, otherwise ``None``.
    Matching priority: exact alias > case-insensitive alias > substring.
    """
    if not tool_name:
        return None

    if tool_name in _CANONICAL_ALIASES:
        return _CANONICAL_ALIASES[tool_name]

    lower = tool_name.lower()
    if lower in _CANONICAL_ALIASES:
        return _CANONICAL_ALIASES[lower]

    for fragment, category in _SUBSTRING_RULES:
        if fragment in lower:
            return category

    return None


def matches_any(tool_name: str | None, categories: frozenset[str]) -> bool:
    """Return True if *tool_name* normalizes to one of *categories*."""
    canon = normalize(tool_name)
    return canon is not None and canon in categories


def is_shell(tool_name: str | None) -> bool:
    return normalize(tool_name) == SHELL_CATEGORY


def is_http(tool_name: str | None) -> bool:
    return normalize(tool_name) == HTTP_CATEGORY


def is_email(tool_name: str | None) -> bool:
    return normalize(tool_name) == EMAIL_CATEGORY


def is_file_write(tool_name: str | None) -> bool:
    return normalize(tool_name) == FILE_WRITE_CATEGORY


def is_file_delete(tool_name: str | None) -> bool:
    return normalize(tool_name) == FILE_DELETE_CATEGORY


def is_database(tool_name: str | None) -> bool:
    return normalize(tool_name) == DATABASE_CATEGORY
