#!/usr/bin/env python3
"""Run an external VAmPI checkout on loopback without editing its source.

Pass the external VAmPI app.py path (or run this from the VAmPI checkout).
The wrapper only overrides Flask's bind address and disables the debug
reloader; it does not copy, patch, or modify VAmPI files.
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

from flask import Flask


def main() -> None:
    app_path = Path(sys.argv[1] if len(sys.argv) > 1 else "app.py").resolve()
    if not app_path.is_file():
        raise SystemExit(f"VAmPI app.py not found: {app_path}")

    # Imports such as `from config import vuln_app` must resolve from the
    # external VAmPI checkout, even though this launcher lives in Charon.
    sys.path.insert(0, str(app_path.parent))
    sys.argv = [str(app_path)]

    original_run = Flask.run

    def run_on_loopback(self: Flask, *args: object, **kwargs: object) -> object:
        # Connexion passes its host positionally. Replace it rather than
        # supplying a duplicate `host=` argument.
        if args:
            args = ("127.0.0.1", *args[1:])
        else:
            kwargs["host"] = "127.0.0.1"
        kwargs["use_reloader"] = False
        return original_run(self, *args, **kwargs)

    Flask.run = run_on_loopback
    runpy.run_path(str(app_path), run_name="__main__")


if __name__ == "__main__":
    main()
