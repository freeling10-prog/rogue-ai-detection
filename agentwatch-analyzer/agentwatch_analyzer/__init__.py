"""Offline log analyzer — zero honeypot runtime. Lab/SOC self-serve on your own logs."""
from .paths import sigma_rules_dir

__version__ = "1.0.0"

__all__ = ["sigma_rules_dir", "__version__"]
