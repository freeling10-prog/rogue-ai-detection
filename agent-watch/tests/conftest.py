import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
# Never write a salt file into the real home directory during tests.
os.environ.setdefault("AGENT_WATCH_SALT_FILE", str(Path(tempfile.mkdtemp(prefix="aw-test-salt-")) / "scrub.salt"))
os.environ.pop("AGENT_WATCH_SCRUB_SALT", None)
os.environ.pop("AGENT_WATCH_BEHIND_PROXY", None)
