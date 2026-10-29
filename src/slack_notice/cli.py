"""Command-line entry point for slack-notice."""

from __future__ import annotations

import argparse
import sys

from slack_notice import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="slack-notice",
        description="Send a notification to Slack via an incoming webhook.",
    )
    parser.add_argument("--version", action="version", version=f"slack-notice {__version__}")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_subparsers(dest="command", metavar="<command>")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help(sys.stderr)
        return 2
    return 0
