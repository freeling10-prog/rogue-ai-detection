from __future__ import annotations

import pytest
from hypothesis import given, settings, strategies as st

from agent_gateway.gui_action_guard import (
    GUI_KEYCHORD_DENIED,
    GUI_REGION_DENIED,
    GuiActionGuard,
    Region,
    default_regions,
    normalize_chord,
)

W, H = 1440, 900


def _guard(**kw) -> GuiActionGuard:
    return GuiActionGuard(viewport=(W, H), **kw)


# --- reserved regions -------------------------------------------------------------

def test_click_in_page_content_is_allowed():
    assert _guard().check("click", {"x": 720, "y": 450}).ok


@pytest.mark.parametrize("x,y,label", [(10, 10, "browser_chrome"), (W - 1, 79, "browser_chrome"),
                                       (0, H - 48, "os_taskbar"), (W - 1, H - 1, "os_taskbar")])
def test_default_regions_deny_including_edges(x, y, label):
    v = _guard().check("click", {"x": x, "y": y})
    assert not v.ok and v.code == GUI_REGION_DENIED and v.detail["region"] == label


@pytest.mark.parametrize("x,y", [(0, 80), (W - 1, 80), (0, H - 49), (W - 1, H - 49)])
def test_points_just_outside_default_regions_are_allowed(x, y):
    assert _guard().check("click", {"x": x, "y": y}).ok


@pytest.mark.parametrize("x,y", [(-1, 400), (W, 400), (400, H), (400, -0.5), (float("nan"), 400),
                                 (float("inf"), 400), ("400", 400), (True, 400), (None, None)])
def test_outside_viewport_or_non_numeric_is_denied(x, y):
    v = _guard().check("click", {"x": x, "y": y})
    assert not v.ok and v.code == GUI_REGION_DENIED and v.detail["reason"] == "outside_viewport"


def test_configured_region_from_list_and_reversed_corners():
    g = _guard(regions=[[900, 300, 600, 500, "credential_dialog"]])
    assert g.regions == [Region(600, 300, 900, 500, "credential_dialog")]
    v = g.check("double_click", {"x": 600, "y": 500})
    assert not v.ok and v.detail["region"] == "credential_dialog"
    assert g.check("double_click", {"x": 599, "y": 500}).ok
    assert g.check("right_click", {"x": 10, "y": 10}).ok  # defaults replaced by the configured list


def test_empty_region_list_only_checks_viewport():
    g = _guard(regions=[])
    assert g.check("mouse_move", {"x": 0, "y": 0}).ok
    assert g.check("mouse_move", {"x": W, "y": 0}).code == GUI_REGION_DENIED


def test_drag_is_checked_at_both_ends():
    g = _guard()
    assert g.check("drag", {"start_x": 300, "start_y": 300, "end_x": 500, "end_y": 400}).ok
    assert g.check("drag", {"start_x": 300, "start_y": 300, "end_x": 500, "end_y": 20}).code == GUI_REGION_DENIED
    assert g.check("drag", {"x": 300, "y": 20, "end_x": 500, "end_y": 400}).code == GUI_REGION_DENIED
    assert g.check("drag", {"start_x": 300, "start_y": 300}).code == GUI_REGION_DENIED  # missing end


def test_default_regions_scale_with_viewport():
    regions = default_regions(800, 600)
    assert regions[0].as_list() == [0, 0, 799, 79, "browser_chrome"]
    assert regions[1].as_list() == [0, 552, 799, 599, "os_taskbar"]


# --- shortcut deny-list ------------------------------------------------------------

@pytest.mark.parametrize("chord", [
    "Meta+Space", "Cmd+Space", "Super+space", "Win+Spacebar",
    "Alt+F4", "Option+F4", "alt+f4",
    "Ctrl+Shift+I", "Control+Shift+i", "Shift+Ctrl+I",
    "Ctrl+Shift+J", "Cmd+Option+I", "Command+Opt+I", "Option+Cmd+I",
    "Ctrl+Alt+T", "Alt+Control+T", "Meta+R", "Windows+R",
    ["cmd", "option", "i"], ("ctrl", "shift", "j"),
])
def test_denied_chords_and_modifier_aliases(chord):
    v = _guard().check("key_combo", {"keys": chord})
    assert not v.ok and v.code == GUI_KEYCHORD_DENIED and v.detail["reason"] == "denied_chord"


@pytest.mark.parametrize("chord", ["Ctrl+C", "Ctrl+V", "Cmd+S", "Ctrl+Shift+T", "Alt+Tab", "Meta+Shift+R",
                                   "Ctrl+I", "Enter", "Tab", "Space", ""])
def test_ordinary_shortcuts_are_allowed(chord):
    assert _guard().check("key", {"key": chord}).ok


def test_normalize_chord_is_order_and_case_independent():
    assert normalize_chord("Cmd+Option+I") == normalize_chord("i+alt+META") == frozenset({"meta", "alt", "i"})
    assert normalize_chord(42) == frozenset()


def test_custom_deny_list_replaces_default():
    g = _guard(denied_chords=["Ctrl+Q"])
    assert g.check("hotkey", {"combo": "control+q"}).code == GUI_KEYCHORD_DENIED
    assert g.check("hotkey", {"combo": "Alt+F4"}).ok


@pytest.mark.parametrize("char", ["\x03", "\x1a", "\x1b"])
def test_text_with_control_characters_is_denied(char):
    v = _guard().check("type_text", {"text": f"hello{char}world"})
    assert not v.ok and v.code == GUI_KEYCHORD_DENIED
    assert v.detail["chars"] == [f"\\x{ord(char):02x}"]


def test_ordinary_text_is_allowed():
    g = _guard()
    assert g.check("type_text", {"text": "Order 55 checked, no action needed.\n"}).ok
    assert g.check("type", {"text": "tabs\tand unicode café"}).ok


def test_non_gui_action_passes_through():
    v = _guard().check("lookup_order_status", {"order_id": 7})
    assert v.ok and v.detail["reason"] == "not_a_gui_action"


def test_verdict_dict():
    d = _guard().check("click", {"x": 5, "y": 5}).as_dict()
    assert d["code"] == GUI_REGION_DENIED and d["action"] == "click" and d["ok"] is False


# --- properties -------------------------------------------------------------------

@settings(max_examples=300, deadline=None, database=None)
@given(x=st.integers(min_value=0, max_value=W - 1), y=st.integers(min_value=0, max_value=H - 1))
def test_property_region_verdict_matches_rectangles(x, y):
    g = _guard()
    inside = y <= 79 or y >= H - 48
    v = g.check("click", {"x": x, "y": y})
    assert v.ok is (not inside)


_MODS = st.lists(st.sampled_from(["Cmd", "Command", "Super", "Win", "Meta", "Ctrl", "Control",
                                  "Alt", "Opt", "Option", "Shift"]), max_size=3)


@settings(max_examples=200, deadline=None, database=None)
@given(mods=_MODS, key=st.sampled_from(["a", "C", "v", "Tab", "F5", "Enter"]))
def test_property_ordinary_keys_never_hit_the_default_list(mods, key):
    # None of these keys appear in the default deny-list, whatever modifiers precede them.
    assert _guard().check("key_combo", {"keys": "+".join([*mods, key])}).ok
