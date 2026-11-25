.PHONY: verify live test lint fmt fmt-check typecheck mdlint

verify: lint fmt-check typecheck test mdlint

test:
	uv run pytest

lint:
	uv run ruff check .

fmt:
	uv run ruff format .

fmt-check:
	uv run ruff format --check .

typecheck:
	uv run pyright

mdlint:
	uv run pymarkdown --config .pymarkdown.json scan -r --respect-gitignore .

# Live suite: posts marked test messages to your own workflow. Never part of verify or CI.
# Set SLACK_NOTICE_LIVE_URL_ENV to the NAME of the variable that holds the trigger URL.
live:
	@test -n "$$SLACK_NOTICE_LIVE_URL_ENV" || { echo "set SLACK_NOTICE_LIVE_URL_ENV to the name of the variable holding the trigger URL (docs/live-testing.md)"; exit 2; }
	uv run pytest -m live tests/test_live.py -s -v
