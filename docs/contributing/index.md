# How to Contribute

Welcome! agent-redteam is an open-source project and contributions are encouraged. This section covers everything you need to know to contribute effectively.

## Quick Start

```bash
git clone https://github.com/spandraj/agent-redteam.git
cd agent-redteam
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,http,rich]"
pytest tests/ -v
```

## Contribution Types

### Attack Templates (Highest Impact)

The easiest and most impactful way to contribute. Each template is a standalone YAML file that defines an adversarial scenario. No Python code required.

**Start here:** [Adding Attack Templates](adding-templates.md)

### Signal Detectors

Detectors analyze agent traces for security signals. Each detector implements a simple protocol and targets specific vulnerability classes.

**Start here:** [Adding Detectors](adding-detectors.md)

### Agent Adapters

Adapters integrate new agent frameworks (LangChain, CrewAI, AutoGen, etc.) with the scanner.

**Start here:** [Adding Adapters](adding-adapters.md)

### Other Contributions

- **Bug fixes** — check the [issue tracker](https://github.com/spandraj/agent-redteam/issues)
- **Tests** — improve coverage, add edge cases
- **Documentation** — fix typos, add examples, improve clarity
- **Environment definitions** — new YAML environment presets

## Development Workflow

1. **Fork and clone** the repository
2. **Create a feature branch**: `git checkout -b feat/my-contribution`
3. **Make changes** with appropriate tests
4. **Verify locally**:

    ```bash
    pytest tests/ -v              # All tests pass
    ruff check agent_redteam/     # No lint errors
    ```

5. **Commit** with a clear message
6. **Open a pull request** against `main`

## Code Standards

| Tool | Purpose | Config |
|---|---|---|
| ruff | Linting + formatting | `pyproject.toml` — line-length 110 |
| mypy | Type checking | `pyproject.toml` — strict mode |
| pytest | Testing | `pyproject.toml` — asyncio auto mode |

### Conventions

- All modules start with `from __future__ import annotations`
- Pydantic v2 for data models
- Python Protocols (not ABC) for interfaces
- Async-first: all adapter and detector methods are `async`
- YAML for attack templates and environment definitions

## Questions?

- [GitHub Discussions](https://github.com/spandraj/agent-redteam/discussions) for questions and ideas
- [GitHub Issues](https://github.com/spandraj/agent-redteam/issues) for bug reports and feature requests
