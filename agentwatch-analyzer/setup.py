"""Copy Sigma rules into the wheel. Metadata lives in pyproject.toml."""
from __future__ import annotations

import shutil
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py


class BuildPy(build_py):
    def run(self) -> None:
        super().run()
        src = Path("rules") / "sigma"
        if not src.is_dir():
            return
        dest = Path(self.build_lib) / "agentwatch_analyzer" / "sigma"
        dest.mkdir(parents=True, exist_ok=True)
        for yml in sorted(src.glob("*.yml")):
            shutil.copy(yml, dest / yml.name)


setup(cmdclass={"build_py": BuildPy})
