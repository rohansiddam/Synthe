"""Synthe's terminal look stays out of the way of anything that isn't a person: plain text in pipes, logs,
tests and with NO_COLOR; and on the approval screen, colour never changes the text or lets the agent's
own escape codes through."""
import io
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import synthe_approve as sa  # noqa: E402
import synthe_init as si  # noqa: E402
import synthe_ui as sui  # noqa: E402


class _TTY(io.StringIO):
    encoding = "utf-8"

    def isatty(self):
        return True


DETAIL = {"id": "repo:agent/x:k/push_branch", "handoff_id": "h-1", "from": "rohan", "to": "openclaw",
          "effect": {"commit": "a" * 40, "remote": "origin", "branch": "agent/x", "expected_old": "new"},
          "changes": {"available": True, "stat": "1 file changed", "files": [{"status": "A", "path": "src/x.md"}],
                      "commits": [{"sha": "a" * 40, "author": "agent", "subject": "evil \x1b[2J\x1b]0;APPROVED\x07"}],
                      "patch": "+++ b/src/x.md\n@@ -0,0 +1 @@\n+hello \x1b[31mred\n-gone"},
          "handoff_expires_at": "2026-10-08T00:00:00Z", "agent_says": {"purpose": "do \x1b[2Jthings"}}


def test_plain_whenever_the_reader_is_not_a_person(monkeypatch):
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    assert not sui.UI(io.StringIO()).color                      # a pipe, a log, a test
    monkeypatch.setenv("NO_COLOR", "1")
    assert not sui.UI(_TTY()).color                             # the user's opt-out wins
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("TERM", "dumb")
    assert not sui.UI(_TTY()).color
    monkeypatch.setenv("TERM", "xterm-256color")
    assert sui.UI(_TTY()).color


def test_colour_never_changes_the_approval_screens_text_or_lets_agent_escapes_through(monkeypatch):
    monkeypatch.setenv("FORCE_COLOR", "1")
    ui = sui.UI(_TTY())
    plain = sa.render(DETAIL)
    coloured = sa.render(DETAIL, ui=ui)
    assert coloured != plain and sui.plain(coloured) == plain   # the same words, only our colour around them
    # the agent's own codes stay visible text: once our colour is stripped, no ESC or BEL remains
    assert "\x1b" not in sui.plain(coloured) and "\x07" not in sui.plain(coloured)
    assert "\\x1b[2J" in plain and "\\x07" in plain


def test_the_doctor_keeps_its_plain_lines_for_scripts(capsys, monkeypatch):
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    report = {"level": "ENFORCED", "checks": [{"status": "PASS", "check": "broker isolation", "detail": "uid 480"},
                                               {"status": "WARN", "check": "barrier plugin mode", "detail": "gateway"}]}
    si.print_report(report)
    out = capsys.readouterr().out
    assert "Enforcement level: ENFORCED" in out and "  PASS  broker isolation: uid 480" in out
    assert "\x1b" not in out


def test_the_coloured_doctor_puts_what_to_fix_first(monkeypatch):
    monkeypatch.setenv("FORCE_COLOR", "1")
    buf = _TTY()
    monkeypatch.setattr(sys, "stdout", buf)
    report = {"level": "ADVISORY", "checks": [{"status": "PASS", "check": "a", "detail": ""},
                                               {"status": "FAIL", "check": "direct push", "detail": "can push"}]}
    si.print_report(report, sui.UI(buf))
    text = sui.plain(buf.getvalue())
    assert "ADVISORY" in text and text.index("FAIL  direct push") < text.index("PASS  a ")


def test_the_spin_never_runs_outside_a_terminal(monkeypatch):
    buf = io.StringIO()
    assert sui.spin(sui.UI(buf), ["synthe"]) is False   # no terminal: didn't play
    assert buf.getvalue() == ""
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.setenv("SYNTHE_NO_ANIMATION", "1")
    tty = _TTY()
    assert sui.spin(sui.UI(tty), ["synthe"]) is False
    assert tty.getvalue() == ""


def test_every_intro_lands_exactly_on_the_mark():
    assert len(sui.MARK) == 9 and all(len(line) == sui.INTRO_COLS for line in sui.MARK)
    for frames in (sui.flip_frames, sui.lock_frames, sui.reveal_frames):
        lines, landed = list(frames(sui.INTRO_COLS))[-1]
        body = [line for line in lines if line.strip("\u2800")]
        assert landed and body == [line for line in sui.MARK if line.strip("\u2800")], frames.__name__


def test_every_subcommand_without_home_runs_from_the_command_line(capsys, monkeypatch):
    """`about` crashed the first time a person ran it (main read --home it doesn't have), the same way
    apply-config did before. Run it through main(), as a person does."""
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    assert si.main(["about"]) == 0
    out = capsys.readouterr().out
    assert "synthe" in out and sui.PROMISE in out and "\x1b" not in out


def test_the_intro_plays_inside_the_banner_and_leaves_it_on_screen(monkeypatch):
    """The text is beside the logo from the first frame; each frame is redrawn by moving up exactly the
    lines drawn; the last frame stays as the finished banner (nothing cleared, nothing reprinted)."""
    import os
    import re
    import shutil
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.delenv("SYNTHE_NO_ANIMATION", raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setattr(sui.time, "sleep", lambda s: None)
    monkeypatch.setattr(shutil, "get_terminal_size", lambda fallback=None: os.terminal_size((80, 24)))
    for style in ("spin", "lock", "draw"):
        tty = _TTY()
        assert sui.intro(sui.UI(tty), ["synthe", "the commit barrier"], style=style) is True
        out = tty.getvalue()
        blocks = re.split(r"\x1b\[\d+A\r", out)
        assert len(blocks) > 10 and all("synthe" in b for b in blocks)        # text in every frame
        ups = {int(n) for n in re.findall(r"\x1b\[(\d+)A", out)}
        assert len(ups) == 1 and ups.pop() <= 24 - 2                          # one frame back, fits
        assert "\x1b[J" not in out and out.endswith("\x1b[?25h")             # kept, not cleared
        last = sui.plain(blocks[-1])
        assert all(row.rstrip("\u2800 ") in last for row in sui.MARK if row.strip("\u2800"))  # ends on the mark
    tiny = _TTY()
    monkeypatch.setattr(shutil, "get_terminal_size", lambda fallback=None: os.terminal_size((60, 14)))
    assert sui.intro(sui.UI(tiny), ["synthe"]) is False and tiny.getvalue() == ""


def test_the_lock_intro_keeps_both_strokes_whole_and_lands():
    frames = list(sui.lock_frames(sui.INTRO_COLS))
    assert frames[-1][1] is True and frames[0][1] is False
    assert len({len(f) for f, _ in frames}) == 1 and len(frames[0][0]) <= 24 - 2
