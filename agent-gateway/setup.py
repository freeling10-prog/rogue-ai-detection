"""Copy the lab registry into the wheel. Metadata lives in pyproject.toml."""
from __future__ import annotations

import shutil
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py


class BuildPy(build_py):
    def run(self) -> None:
        super().run()
        src = Path("config") / "agents.json"
        if not src.is_file():
            return
        dest_dir = Path(self.build_lib) / "agent_gateway" / "data"
        dest_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy(src, dest_dir / "agents.json")


setup(cmdclass={"build_py": BuildPy})
