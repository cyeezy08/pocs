"""Path bootstrap so tests run from anywhere, installed or not."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
