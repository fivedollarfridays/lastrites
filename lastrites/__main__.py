"""`python -m lastrites` -- the no-install path to the same CLI."""

from lastrites.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
