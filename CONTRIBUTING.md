# Contributing to agent-redteam

Thank you for your interest in contributing to agent-redteam! This document covers the essentials to get you started.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/spandraj/agent-redteam.git
cd agent-redteam

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate

# Install in development mode with all extras
pip install -e ".[dev,http,rich]"
```

## Running Tests

```bash
# Full test suite
pytest tests/ -v

# Specific test file
pytest tests/detectors/test_tool_misuse.py -v

# With coverage
coverage run -m pytest tests/ && coverage report
```

## Code Quality

We use **ruff** for linting and formatting, and **mypy** for type checking:

```bash
# Lint
ruff check agent_redteam/

# Auto-fix lint issues
ruff check agent_redteam/ --fix

# Type check
mypy agent_redteam/
```

### Code Style

- Line length: 110 characters
- Python 3.11+ features (StrEnum, `X | Y` unions, etc.)
- All public APIs must have docstrings
- Use `from __future__ import annotations` in every module
- Pydantic v2 for all data models

## Making Changes

1. **Create a branch** from `main`
2. **Make your changes** with tests
3. **Run the full test suite** — all tests must pass
4. **Run ruff and mypy** — no new errors
5. **Submit a pull request** with a clear description

## What to Contribute

The most impactful contributions right now:

- **New attack templates** — see [Adding Templates](https://spandraj.github.io/agent-redteam/contributing/adding-templates/)
- **New detectors** — see [Adding Detectors](https://spandraj.github.io/agent-redteam/contributing/adding-detectors/)
- **New adapters** — see [Adding Adapters](https://spandraj.github.io/agent-redteam/contributing/adding-adapters/)
- **Bug fixes** and **test improvements**
- **Documentation** improvements

## Project Structure

See the full [Project Structure](https://spandraj.github.io/agent-redteam/contributing/project-structure/) guide for a detailed walkthrough of every module.

## Questions?

Open a [GitHub Discussion](https://github.com/spandraj/agent-redteam/discussions) or an issue.
