"""slack-notice: send a notification to Slack via an incoming webhook."""

from importlib.metadata import version

# The release job owns the version in pyproject.toml; read it from the installed metadata.
__version__ = version("slack-notice")
