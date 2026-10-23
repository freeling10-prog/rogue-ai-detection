"""Usage: python scripts/fingerprint_confusion.py [--seeds 5] [--out docs/fingerprint-confusion.md]"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from agentwatch.fingerprint_eval import main

if __name__ == "__main__":
    raise SystemExit(main())
