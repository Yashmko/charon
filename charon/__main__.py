"""Allow running Charon via ``python -m charon``.

Usage::

    python -m charon analyze <input> [options]
    python -m charon version
"""

from charon.cli.main import main

main()
