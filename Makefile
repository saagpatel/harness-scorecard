.PHONY: setup check test build require-uv

setup: require-uv
	uv sync --locked

check: require-uv
	uv lock --check
	uv run --no-sync ruff format --check src/ tests/
	uv run --no-sync ruff check src/ tests/
	uv run --no-sync ty check src/
	$(MAKE) test

test: require-uv
	uv run --no-sync coverage run -m unittest discover -s tests
	uv run --no-sync coverage report

build: require-uv
	uv build

require-uv:
	@command -v uv >/dev/null 2>&1 || { \
		printf '%s\n' 'Install uv 0.12.12, add it to PATH, then run make setup.' >&2; \
		exit 1; \
	}
