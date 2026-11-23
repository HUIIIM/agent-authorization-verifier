"""Allow `python -m agent_auth_verifier` as an alias for the aav CLI."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
