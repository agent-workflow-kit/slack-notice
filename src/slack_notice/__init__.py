"""slack-notice: send a notification to Slack via an incoming webhook."""

from importlib.metadata import PackageNotFoundError, version

# The release job owns the version in pyproject.toml; read it from the installed metadata.
try:
    __version__ = version("slack-notice")
except PackageNotFoundError:
    # Running from a source tree that was never installed: stay importable instead of
    # crashing at import time. Tests compare against pyproject.toml, so this is not silent.
    __version__ = "0.0.0+unknown"
