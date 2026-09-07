# Developing LogLens AI in a container

You no longer need a local `venv`. The dev container installs everything and
bind-mounts the repo, so your edits are live inside the container with no
rebuild between runs.

## Prerequisites

- Docker (Desktop on macOS/Windows, or Engine + Compose plugin on Linux)

## One-time build

```bash
make build
# or, without make:
docker compose -f docker-compose.dev.yml build \
    --build-arg UID=$(id -u) --build-arg GID=$(id -g)
```

The `UID/GID` args (Linux only) make files created in the container owned by
you on the host instead of by root. On macOS/Windows they're harmless.

## Daily loop

```bash
make dev        # interactive shell inside the container
```

Inside that shell everything works against your live source:

```bash
loglens version
loglens analyze --source tests/fixtures/demo_incident.log
pytest -q
```

Edit any file in `src/loglens/` on your host in your normal editor — the change
is picked up immediately on the next command (editable install, `pip install -e`).
No rebuild is needed unless you change dependencies in `pyproject.toml`.

## Common one-shot commands

```bash
make test       # run the full test suite
make bench      # fetch the public BGL sample and benchmark
```

Or directly:

```bash
docker compose -f docker-compose.dev.yml run --rm test
docker compose -f docker-compose.dev.yml run --rm bench
```

## Neural (`--deep`) mode

`--deep` needs `sentence-transformers` + `torch` (~2 GB) and downloads a model
on first use. It's off by default to keep the image small. To enable it:

```bash
docker compose -f docker-compose.dev.yml build --build-arg INSTALL_DEEP=1 dev
```

Downloaded models are cached in the `loglens-cache` named volume, so you only
pay the download once.

## When to rebuild

| You changed…                     | Action                         |
| -------------------------------- | ------------------------------ |
| Python source in `src/`          | nothing — it's live            |
| `pyproject.toml` dependencies    | `make build`                   |
| Want deep mode                   | rebuild with `INSTALL_DEEP=1`  |

## Production image

The dev image is for iterating. Ship the slim, non-root production image built
from the main `Dockerfile`:

```bash
make prod-build
docker run --rm -v "$PWD/logs:/data" loglensai/loglens:latest \
    analyze --source app.log
```

## Cleanup

```bash
make clean      # remove dev containers, image, and cache volume
```
