# Contributing to LogLens AI

Thanks for your interest in improving LogLens AI. This guide covers the local
setup, the quality bar, and how to get a change merged.

## Development setup

```bash
git clone https://github.com/LoglensAI/LogLens-AI.git
cd LogLens-AI
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"          # add ".[deep]" for the MiniLM engine
pre-commit install               # runs ruff + mypy + hygiene hooks on commit
```

## Quality bar

All checks are configured in `pyproject.toml` and mirrored in CI:

```bash
pytest -q                        # full test suite
ruff check src/ tests/           # lint
ruff format src/ tests/          # auto-format
mypy src/loglens                 # type check
```

- **Tests are required.** New behaviour needs a test; bug fixes need a
  regression test. Keep the suite green.
- **Lint and types** are advisory in CI today and will become blocking. Please
  don't add new violations - run the tools before pushing.
- **No silent failures.** Every `except` should log, re-raise, or be justified
  by a comment. Never swallow exceptions bare.
- **No invisible/unicode artifacts** in source (a test enforces this).

## Commit & PR conventions

- Keep commits focused and messages descriptive; the changelog is generated
  from history via git-cliff.
- Open a PR against `main`. CI must pass (tests + accuracy gates).
- For anything security-related, see [SECURITY.md](SECURITY.md) - do not open a
  public issue.

## Reporting issues and triage labels

Open issues through the forms under **New issue** (bug report or feature
request). Each form applies a starting label. A maintainer then triages the
issue by adding **one type**, **one priority** and (for work someone can pick
up) **one difficulty** label.

**Type** (what kind of change it is)

| Label | Use for |
|---|---|
| `bug` | Something is broken or behaves differently from the docs |
| `feature` | A new capability (new data source, engine, command) |
| `enhancement` | An improvement to something that already exists |
| `optimization` | Speed, memory, binary size or cold-start work with no behaviour change |
| `ci` | GitHub Actions, release pipeline, packaging and installers |
| `documentation` | README, docs/, docstrings, templates |
| `question` | A usage question; convert or close once answered |

**Priority** (how soon it matters)

| Label | Meaning |
|---|---|
| `P1-high` | Breaks installs, releases or core detection for many users; fix next |
| `P2-medium` | Real problem or valuable feature, but a workaround exists |
| `P3-low` | Nice to have; picked up when there is time |

**Difficulty** (for contributors choosing work)

| Label | Meaning |
|---|---|
| `good-first-issue` | Small and well scoped; little knowledge of the codebase needed |
| `difficulty-medium` | Touches one subsystem; expect to read some surrounding code |
| `difficulty-hard` | Cross-cutting or design work; discuss the approach in the issue first |

**Status / resolution**: `help wanted` (maintainers would welcome a PR),
`duplicate`, `invalid` and `wontfix` (close with a short comment saying why).

A PR that fully resolves an issue should say `Fixes #N` in its description so
the issue closes on merge. If a PR only covers part of an issue, list what is
left in the issue rather than closing it.

## Project layout

See [docs/SYSTEM_DESIGN.md](docs/SYSTEM_DESIGN.md) for the architecture, the
module responsibilities, and the in-progress refactor roadmap.
