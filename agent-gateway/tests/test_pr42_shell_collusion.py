"""PR #42: Snapshot hardening, analyze_shell(snapshot=...), StagedCollusionGuard.

A 19-command corpus (9 denied, 10 allowed) plus the five staged-collusion
carriers. These exercise the reference MODEL only; they execute nothing.
"""
from __future__ import annotations

import pytest

from agent_gateway.common import Denied
from agent_gateway.workspace_path_validator import (
    Intent,
    Node,
    Snapshot,
    StagedCollusionGuard,
    analyze_shell,
)


@pytest.fixture
def snap():
    nodes = {
        "/ws": Node("dir"),
        "/ws/a": Node("file", inode=(1, 1)),
        "/ws/b": Node("file", inode=(1, 2)),
        "/ws/c": Node("file", inode=(1, 3)),
        "/ws/notes.txt": Node("file", inode=(1, 4)),
        "/ws/copy.txt": Node("file", inode=(1, 5)),
        "/ws/err.log": Node("file", inode=(1, 6)),
        "/ws/log.txt": Node("file", inode=(1, 7)),
        "/ws/out.txt": Node("file", inode=(1, 8)),
        "/ws/.mcp.json": Node("file", inode=(1, 9)),
        "/ws/secret.txt": Node("file", inode=(1, 10)),
        "/ws/d": Node("dir", inode=(1, 11)),
        "/ws/existing_dir": Node("dir", inode=(1, 12)),
        "/ws/linkdir": Node("symlink", inode=(1, 13), target="/ws/d"),
        "/ws/.git": Node("dir", inode=(1, 14)),
        "/ws/.git/config": Node("file", inode=(1, 15)),
        "/ws/.git/link": Node("symlink", inode=(1, 16), target="/ws/a"),
    }
    return Snapshot(nodes, generation=7, root="/ws")


DENIED_CASES = [
    "cat .git/config",                    # protected read
    "cat < .mcp.json",                    # protected redirection read
    "cp .mcp.json out.txt",               # protected copy source
    "ln -s /ws/.mcp.json link",           # symlink to protected target
    "rm .git/link",                       # unlink protected symlink node
    "mv a b; cat b",                      # move + read sequential revalidation
    "ln -s a b; cat b",                   # symlink + read sequential revalidation
    "sed -i 's/a/b/c' notes.txt",         # malformed sed script
    "chmod 999 notes.txt",                # invalid mode profile
]

PASS_CASES = [
    "(cat a; cat b) > c",                 # subshell + group redirection
    "cat a 2> err.log",                   # fd-prefixed redirection
    'echo "a\\"b"',                       # escaped quote in double quotes
    'echo "a\\$b"',                       # escaped dollar in double quotes
    'echo "a\nb"',                        # literal newline inside quotes
    "sed -i s/a/b/g notes.txt",           # valid in-place sed
    "cat a | tee -a log.txt",             # tee append
    "cp a linkdir",                       # cp into symlinked directory
    "cp a existing_dir",                  # cp into existing directory
    "ln -s ../notes.txt existing_dir",    # valid symlink into existing directory
]


@pytest.mark.parametrize("cmd", DENIED_CASES)
def test_corpus_denied(cmd, snap):
    with pytest.raises(Denied):
        analyze_shell(cmd, snapshot=snap)


@pytest.mark.parametrize("cmd", PASS_CASES)
def test_corpus_passes(cmd, snap):
    intents = analyze_shell(cmd, snapshot=snap)
    assert isinstance(intents, tuple)


def test_staged_collusion_guard_blocks_all_five(snap):
    def run(g, agent, cmd):
        intents = analyze_shell(cmd, snapshot=snap)
        g.observe(agent, intents, snap, cmd)

    # 1. Split payload across two files + multi-file concat
    g = StagedCollusionGuard()
    run(g, "A", "echo P1 > a")
    run(g, "A", "echo P2 > b")
    with pytest.raises(Denied):
        run(g, "B", "cat a b > c")

    # 2. Permission-bit covert carrier on existing file
    g = StagedCollusionGuard()
    with pytest.raises(Denied):
        run(g, "A", "chmod 640 notes.txt")

    # 3. Filename encoding carrier
    g = StagedCollusionGuard()
    with pytest.raises(Denied):
        run(g, "A", "echo x > 'p%61yload'")

    # 4. Cross-agent append log signal (including "/ws/log.txt" path alias)
    g = StagedCollusionGuard()
    run(g, "A", "echo sig | tee -a log.txt")
    with pytest.raises(Denied):
        run(g, "B", "cat /ws/log.txt")

    # 5. Cross-agent staged artifact copy
    g = StagedCollusionGuard()
    run(g, "A", "echo x > a")
    with pytest.raises(Denied):
        run(g, "B", "cp a b")


# --- Extra regressions pinning the reason codes and compatibility contract. ---

@pytest.mark.parametrize("cmd,reason", [
    ("cat .git/config", "PROTECTED_PATH"),
    ("cat < .mcp.json", "PROTECTED_PATH"),
    ("cp .mcp.json out.txt", "PROTECTED_PATH"),
    ("ln -s /ws/.mcp.json link", "PROTECTED_PATH"),
    # rm is not a modeled command: the parser fails closed before the model.
    ("rm .git/link", "UNMODELED_COMMAND"),
    ("mv a b; cat b", "SEQUENTIAL_NAMESPACE_REVALIDATION_REQUIRED"),
    ("sed -i 's/a/b/c' notes.txt", "SED_SCRIPT"),
    ("chmod 999 notes.txt", "CHMOD_PROFILE"),
])
def test_corpus_reason_codes(cmd, reason, snap):
    with pytest.raises(Denied) as exc:
        analyze_shell(cmd, snapshot=snap)
    assert exc.value.args[0] == reason


def test_remove_intent_of_protected_symlink_is_denied_by_the_model(snap):
    # The model-level unlink check behind the rm corpus case.
    with pytest.raises(Denied) as exc:
        snap.check(Intent("remove", ".git/link"))
    assert exc.value.args[0] == "PROTECTED_PATH"


def test_parse_only_mode_is_unchanged(snap):
    # snapshot=None keeps the original behaviour: protected reads parse fine.
    assert analyze_shell("cat .git/config") == (Intent("read", ".git/config"),)
    # And the default Snapshot.check still lets the label transducer read them.
    assert snap.check(Intent("read", ".mcp.json")).path == "/ws/.mcp.json"


def test_remove_does_not_follow_final_symlink(snap):
    # Removing an unprotected symlink unlinks the link, not its target.
    nodes = dict(snap.nodes)
    nodes["/ws/ptr"] = Node("symlink", inode=(1, 20), target="/ws/.mcp.json")
    s2 = Snapshot(nodes, root="/ws")
    assert s2.check(Intent("remove", "ptr")).path == "/ws/ptr"
    with pytest.raises(Denied):
        s2.check(Intent("remove", ".mcp.json"))
    with pytest.raises(Denied):
        s2.check(Intent("remove", "d"))  # no directory removal


def test_symlink_into_directory_resolves_child(snap):
    out = snap.check(Intent("symlink", "existing_dir", "../notes.txt"))
    assert out.path == "/ws/existing_dir/notes.txt"
    with pytest.raises(Denied):
        snap.check(Intent("symlink", "existing_dir", ".."))


def test_collusion_guard_allows_same_agent_and_canonicalises_aliases(snap):
    g = StagedCollusionGuard()
    for cmd in ("echo x > a", "cat ./a", "cat /ws/a"):
        g.observe("A", analyze_shell(cmd, snapshot=snap), snap, cmd)
    assert g.written_paths == {"/ws/a": {"A"}}
    with pytest.raises(Denied):
        g.observe("B", analyze_shell("cat ./a", snapshot=snap), snap, "cat ./a")


@pytest.mark.parametrize("mode", ["600", "644", "0755", "700"])
def test_collusion_guard_permits_profile_modes(mode, snap):
    cmd = f"chmod {mode} notes.txt"
    StagedCollusionGuard().observe("A", analyze_shell(cmd, snapshot=snap), snap, cmd)
