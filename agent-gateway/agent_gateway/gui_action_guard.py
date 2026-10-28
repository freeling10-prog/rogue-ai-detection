"""Computer-use action validator: viewport bounds and keyboard-shortcut deny-list.

Two deterministic access-control checks over GUI tool calls:

1. **Reserved screen regions.** Pointer actions (``click``, ``double_click``,
   ``right_click``, ``mouse_move``, ``drag``) carry ``(x, y)`` coordinates.
   A point inside any configured reserved rectangle
   ``[x_min, y_min, x_max, y_max, label]`` (edges inclusive), or outside the
   viewport, is ``GUI_REGION_DENIED``. A drag is checked at both ends.
   Default regions are the browser chrome band at the top and the OS taskbar
   band at the bottom of the configured viewport. Where a credential or
   permission dialog appears depends on the deployment, so those rectangles
   must be added to the configuration.

2. **Shortcut deny-list.** Modifier names are normalized (``Cmd`` /
   ``Command`` / ``Super`` / ``Win`` -> ``Meta``; ``Control`` -> ``Ctrl``;
   ``Opt`` / ``Option`` -> ``Alt``) and the chord is compared as a set, so
   key order does not matter. Denied chords: ``Meta+Space``, ``Alt+F4``,
   ``Ctrl+Shift+I``, ``Ctrl+Shift+J``, ``Meta+Alt+I`` (``Cmd+Option+I``),
   ``Ctrl+Alt+T``, ``Meta+R``. Text input containing the raw control
   characters ``\\x03``, ``\\x1a`` or ``\\x1b`` is denied as well. Both are
   ``GUI_KEYCHORD_DENIED``.

Scope: this checks coordinates and key names only. It does not look at the
screen, so it cannot tell what is drawn at a point, and it does not follow
windows that move. No model call.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

GUI_REGION_DENIED = "GUI_REGION_DENIED"
GUI_KEYCHORD_DENIED = "GUI_KEYCHORD_DENIED"

POINTER_ACTIONS = frozenset({"click", "double_click", "right_click", "mouse_move", "drag"})
KEY_ACTIONS = frozenset({"key", "key_combo", "hotkey"})
TEXT_ACTIONS = frozenset({"type", "type_text"})

_MODIFIER_ALIASES = {
    "meta": "meta", "cmd": "meta", "command": "meta", "super": "meta", "win": "meta", "windows": "meta",
    "ctrl": "ctrl", "control": "ctrl",
    "alt": "alt", "opt": "alt", "option": "alt",
    "shift": "shift",
}
_KEY_ALIASES = {"spacebar": "space", "esc": "escape"}
DENIED_CONTROL_CHARS = frozenset({"\x03", "\x1a", "\x1b"})


def normalize_chord(chord: Any) -> frozenset[str]:
    """``"Cmd+Option+I"`` or ``["cmd", "option", "i"]`` -> ``{"meta", "alt", "i"}``."""
    if isinstance(chord, str):
        parts = chord.split("+") if chord.strip() != "+" else ["+"]
    elif isinstance(chord, (list, tuple)):
        parts = [str(p) for p in chord]
    else:
        return frozenset()
    out = set()
    for part in parts:
        token = part.strip().casefold()
        if not token:
            continue
        out.add(_MODIFIER_ALIASES.get(token, _KEY_ALIASES.get(token, token)))
    return frozenset(out)


DEFAULT_DENIED_CHORDS = frozenset(normalize_chord(c) for c in (
    "Meta+Space", "Alt+F4", "Ctrl+Shift+I", "Ctrl+Shift+J", "Cmd+Option+I", "Ctrl+Alt+T", "Meta+R",
))


@dataclass(frozen=True)
class Region:
    x_min: float
    y_min: float
    x_max: float
    y_max: float
    label: str

    @classmethod
    def from_list(cls, spec: Iterable[Any]) -> "Region":
        x_min, y_min, x_max, y_max, label = list(spec)
        lo_x, hi_x = sorted((float(x_min), float(x_max)))
        lo_y, hi_y = sorted((float(y_min), float(y_max)))
        return cls(lo_x, lo_y, hi_x, hi_y, str(label))

    def contains(self, x: float, y: float) -> bool:
        return self.x_min <= x <= self.x_max and self.y_min <= y <= self.y_max

    def as_list(self) -> list[Any]:
        return [self.x_min, self.y_min, self.x_max, self.y_max, self.label]


def default_regions(width: int = 1440, height: int = 900, chrome_px: int = 80, taskbar_px: int = 48) -> list[Region]:
    """Top browser-chrome band and bottom taskbar band for a ``width`` x ``height`` viewport."""
    return [
        Region(0, 0, width - 1, chrome_px - 1, "browser_chrome"),
        Region(0, height - taskbar_px, width - 1, height - 1, "os_taskbar"),
    ]


@dataclass
class GuiVerdict:
    ok: bool
    code: str = ""
    action: str = ""
    detail: dict = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"ok": self.ok, "action": self.action, **self.detail}
        if self.code:
            out["code"] = self.code
        return out


def _coord(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    v = float(value)
    return v if math.isfinite(v) else None


class GuiActionGuard:
    """Validates one GUI action at a time against regions and the shortcut deny-list."""

    def __init__(self, regions: Optional[Iterable[Any]] = None, viewport: tuple[int, int] = (1440, 900),
                 denied_chords: Optional[Iterable[Any]] = None):
        self.viewport = (int(viewport[0]), int(viewport[1]))
        if regions is None:
            self.regions = default_regions(*self.viewport)
        else:
            self.regions = [r if isinstance(r, Region) else Region.from_list(r) for r in regions]
        self.denied_chords = (DEFAULT_DENIED_CHORDS if denied_chords is None
                              else frozenset(normalize_chord(c) for c in denied_chords))

    def _check_point(self, action: str, x: Any, y: Any) -> Optional[GuiVerdict]:
        fx, fy = _coord(x), _coord(y)
        w, h = self.viewport
        if fx is None or fy is None or not (0 <= fx < w and 0 <= fy < h):
            return GuiVerdict(False, GUI_REGION_DENIED, action,
                              {"reason": "outside_viewport", "x": x, "y": y, "viewport": [w, h]})
        for region in self.regions:
            if region.contains(fx, fy):
                return GuiVerdict(False, GUI_REGION_DENIED, action,
                                  {"reason": "reserved_region", "region": region.label,
                                   "rect": region.as_list(), "x": fx, "y": fy})
        return None

    def check(self, action: str, args: Optional[dict] = None) -> GuiVerdict:
        args = args if isinstance(args, dict) else {}
        action = str(action or "")
        if action in POINTER_ACTIONS:
            points = [(args.get("x"), args.get("y"))]
            if action == "drag":
                points = [(args.get("start_x", args.get("x")), args.get("start_y", args.get("y"))),
                          (args.get("end_x"), args.get("end_y"))]
            for x, y in points:
                hit = self._check_point(action, x, y)
                if hit is not None:
                    return hit
            return GuiVerdict(True, action=action)
        if action in KEY_ACTIONS:
            chord = normalize_chord(args.get("keys", args.get("key", args.get("combo"))))
            if chord in self.denied_chords:
                return GuiVerdict(False, GUI_KEYCHORD_DENIED, action,
                                  {"reason": "denied_chord", "chord": sorted(chord)})
            return GuiVerdict(True, action=action, detail={"chord": sorted(chord)})
        if action in TEXT_ACTIONS:
            text = str(args.get("text") or "")
            found = sorted({f"\\x{ord(c):02x}" for c in text if c in DENIED_CONTROL_CHARS})
            if found:
                return GuiVerdict(False, GUI_KEYCHORD_DENIED, action,
                                  {"reason": "control_character", "chars": found})
            return GuiVerdict(True, action=action)
        return GuiVerdict(True, action=action, detail={"reason": "not_a_gui_action"})
