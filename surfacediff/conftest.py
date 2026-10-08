"""Path bootstrap: tests import the package whether or not it is
installed (pip install -e . in CI, or plain pytest locally)."""
import os
import sys

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)
