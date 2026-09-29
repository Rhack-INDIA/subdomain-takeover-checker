"""Submission entrypoint alias routing to checker.py."""

import sys
from pathlib import Path

# Ensure project root is in sys.path
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.checker import main

if __name__ == "__main__":
    sys.exit(main())
