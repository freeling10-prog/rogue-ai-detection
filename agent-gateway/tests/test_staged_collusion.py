"""Shell model fixes (protected reads opt-in, nofollow rm, ln into a directory),
analyze_shell(snapshot=...), and StagedCollusionGuard. Reference profile, model only."""
from __future__ import annotations

import pytest

from agent_gateway.common import Denied
from agent_gateway.workspace_path_validator import (
    Intent, Node, Snapshot, StagedCollusionGuard, analyze_shell)


def nodes():
    return {
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
        "/ws/alink": Node("symlink", inode=(1, 17), target="/ws/a"),
    }


@pytest.fixture
def snap():
    # protect_reads=True: W itself denies reading or copying protected files.
    return Snapshot(nodes(), generation=7, root="/ws", protect_reads=True)


DENIED_CASES = [
    ("cat .git/config", "PROTECTED_PATH"),                      # protected read
    ("cat < .mcp.json", "PROTECTED_PATH"),                      # protected redirection read
    ("cp .mcp.json out.txt", "PROTECTED_PATH"),                 # protected copy source
    ("ln -s /ws/.mcp.json link", "PROTECTED_PATH"),             # symlink to protected target
    ("rm .git/link", "PROTECTED_PATH"),                         # unlink protected symlink node
    ("mv a b; cat b", "SEQUENTIAL_NAMESPACE_REVALIDATION_REQUIRED"),
    ("ln -s a b; cat b", "SEQUENTIAL_NAMESPACE_REVALIDATION_REQUIRED"),
    ("sed -i 's/a/b/c' notes.txt", "SED_SCRIPT"),               # malformed sed script
    ("chmod 999 notes.txt", "CHMOD_PROFILE"),                   # invalid mode profile
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


@pytest.mark.parametrize("cmd,code", DENIED_CASES)
def test_corpus_denied(cmd, code, snap):
    with pytest.raises(Denied) as err:
        analyze_shell(cmd, snapshot=snap)
    assert str(err.value) == code


@pytest.mark.parametrize("cmd", PASS_CASES)
def test_corpus_passes(cmd, snap):
    intents = analyze_shell(cmd, snapshot=snap)
    assert isinstance(intents, tuple)


def test_without_snapshot_behaviour_is_unchanged():
    assert analyze_shell("cat .git/config") == (Intent("read", ".git/config"),)
    assert analyze_shell("rm a") == (Intent("remove", "a"),)


def test_protected_reads_are_opt_in():
    default = Snapshot(nodes(), root="/ws")
    assert default.check(Intent("read", ".mcp.json")).path == "/ws/.mcp.json"
    assert default.check(Intent("copy", "out.txt", ".mcp.json")).path == "/ws/out.txt"
    with pytest.raises(Denied):
        default.check(Intent("write", ".mcp.json"))


def test_rm_unlinks_the_symlink_not_its_target(snap):
    leaf = snap.check(Intent("remove", "alink"))
    assert leaf.path == "/ws/alink" and leaf.node.kind == "symlink"
    assert snap.check(Intent("remove", "linkdir")).path == "/ws/linkdir"
    with pytest.raises(Denied, match="DIRECTORY_MUTATION"):
        snap.check(Intent("remove", "d"))
    for bad in ("..", "d/..", "/ws"):
        with pytest.raises(Denied):
            snap.check(Intent("remove", bad))


def test_ln_into_directory_and_shared_inode_target():
    n = nodes()
    n["/ws/hard"] = Node("file", inode=(2, 1), links=2)
    s = Snapshot(n, root="/ws")
    assert s.check(Intent("symlink", "existing_dir", "../notes.txt")).path == "/ws/existing_dir/notes.txt"
    with pytest.raises(Denied, match="PROTECTED_OR_SHARED_INODE"):
        s.check(Intent("symlink", "newlink", "hard"))
    with pytest.raises(Denied, match="LINK_DEST_EXISTS"):
        s.check(Intent("symlink", "a", "b"))


def test_staged_collusion_guard_blocks_all_five(snap):
    def run(g, agent, cmd):
        intents = analyze_shell(cmd, snapshot=snap)
        g.observe(agent, intents, snap, cmd)

    # 1. Split payload across two files + multi-file concat
    g = StagedCollusionGuard()
    run(g, "A", "echo P1 > a")
    run(g, "A", "echo P2 > b")
    with pytest.raises(Denied, match="CROSS_AGENT_STAGING"):
        run(g, "B", "cat a b > c")

    # 2. Permission-bit covert carrier on existing file
    g = StagedCollusionGuard()
    with pytest.raises(Denied, match="PERMISSION_CARRIER"):
        run(g, "A", "chmod 640 notes.txt")

    # 3. Filename encoding carrier
    g = StagedCollusionGuard()
    with pytest.raises(Denied, match="FILENAME_CARRIER"):
        run(g, "A", "echo x > 'p%61yload'")

    # 4. Cross-agent append log signal, read back through a path alias
    g = StagedCollusionGuard()
    run(g, "A", "echo sig | tee -a ./log.txt")
    with pytest.raises(Denied, match="CROSS_AGENT_STAGING"):
        run(g, "B", "cat /ws/log.txt")

    # 5. Cross-agent staged artifact copy
    g = StagedCollusionGuard()
    run(g, "A", "echo x > a")
    with pytest.raises(Denied, match="CROSS_AGENT_STAGING"):
        run(g, "B", "cp a b")


def test_guard_allows_ordinary_work(snap):
    g = StagedCollusionGuard()
    for cmd in ("echo x > a", "cat a", "chmod 644 a", "chmod -- 0755 a", "cp a copy.txt"):
        g.observe("A", analyze_shell(cmd, snapshot=snap), snap, cmd)
    g.observe("B", analyze_shell("cat notes.txt", snapshot=snap), snap, "cat notes.txt")
    with pytest.raises(Denied, match="MULTI_FILE_CONCAT"):
        g.observe("A", analyze_shell("cat a notes.txt > c", snapshot=snap), snap, "cat a notes.txt > c")
    with pytest.raises(Denied, match="PERMISSION_CARRIER"):
        g.observe("A", analyze_shell("chmod -- 640 a", snapshot=snap), snap, "chmod -- 640 a")


def test_guard_is_deterministic(snap):
    script = [("A", "echo x > a"), ("A", "cat a"), ("B", "echo y > b"), ("B", "cat a")]

    def replay():
        g, out = StagedCollusionGuard(), []
        for agent, cmd in script:
            try:
                g.observe(agent, analyze_shell(cmd, snapshot=snap), snap, cmd)
                out.append("ok")
            except Denied as exc:
                out.append(str(exc))
        return out

    assert replay() == replay() == ["ok", "ok", "ok", "CROSS_AGENT_STAGING"]
