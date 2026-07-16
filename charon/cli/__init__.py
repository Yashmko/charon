"""Deterministic command-line interface for Charon.

The ``cli`` module is a thin wrapper around the pipeline that provides
a human-friendly interface for running Charon end-to-end. It parses
capture files, credentials, and output options, then delegates to the
:class:`~charon.pipeline.engine.Pipeline`.

The CLI never fabricates findings, credentials, or evidence. All inputs
must be explicitly provided.
"""

from charon.cli.main import build_arg_parser, main

__all__ = ["build_arg_parser", "main"]
