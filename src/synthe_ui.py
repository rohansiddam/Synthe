"""Synthe's terminal look: one mark, one palette, and plain text whenever the reader isn't a person.

Colour and the mark appear only on an interactive terminal, never with NO_COLOR, TERM=dumb, a pipe
or a log, so agents, scripts and tests always read plain text. FORCE_COLOR=1 forces colour on.

Where each piece goes:
  - The 3D spin plays once, at the start of interactive setup and in `synthe-init about`. It's skippable
    (any key, SYNTHE_NO_ANIMATION=1) and never delays security output.
  - The mark (the logo in braille dots) heads the doctor's report and the end of setup.
  - A one-line header ("// synthe ▸ task") heads every other command.
  - The approval screen keeps its plain, identical layout. It only colours fixed labels and the diff's
    +/- lines, after the agent's text has been made safe.

The palette is synthe.live's terminal palette.
"""
from __future__ import annotations

import math
import os
import re
import sys
import time

# The logo (synthe-site/logo.svg) in braille dots, 16 columns: the same rendering the intros end on.
MARK = [
    "⠀⠀⠀⠀⠀⠀⣴⣿⣿⣿⣿⣿⠆",
    "⠀⠀⠀⠀⢠⣾⡿⠃⢠⣾⡿⠃",
    "⠀⠀⠀⣴⣿⠟⠁⣴⣿⠟⠁⢰⣿⡆",
    "⠀⠀⣾⣿⠋⢠⣾⡿⠋⢀⡆⠀⣿⣧",
    "⠀⠀⣿⣿⠀⢹⠟⠁⣰⣿⡗⠀⣿⣿",
    "⠀⠀⢸⣿⡆⠈⢀⣾⣿⠋⢀⣾⣿⠋",
    "⠀⠀⠈⠛⠁⣰⣿⡟⠁⣰⣿⡿⠁",
    "⠀⠀⠀⢀⣾⣿⣯⣤⣾⣿⠏",
    "⠀⠀⠀⠈⠛⠛⠛⠛⠛⠁",
]
# The same logo as slashes, for terminals without Unicode: its strokes in their own direction.
MARK_ASCII = [
    "       ///////",
    "      //  ///",
    "    ///  //  //",
    "   //  ///   //",
    "  //  //  // ///",
    "  /// /  /// ///",
    "   //  ///  ///",
    "      /// ///",
    "    ////////",
    "     /////",
]
# Every row the same width in braille cells (U+2800 is a blank braille cell), so the text beside the mark
# lines up even where a font draws braille wider or narrower than a space.
MARK = [row.replace(" ", "\u2800").ljust(16, "\u2800") for row in MARK]
INTRO_COLS = 16
TAGLINE = "the commit barrier for AI agents"
PROMISE = "agents propose · you approve · Synthe commits"

# synthe.live --term-* colours (truecolor, else the nearest of 256, else basic ANSI).
# Only the signal colours are fixed; brand and commands use the terminal's own text colour (bold) and
# muted text uses its dim style, so all of it reads on light and dark backgrounds alike.
_TRUE = {"ok": (127, 176, 105), "warn": (217, 154, 91), "bad": (236, 83, 88)}
_BASIC = {"brand": "1", "ok": "32", "warn": "33", "bad": "31", "muted": "2", "cmd": "1"}
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _to256(rgb) -> int:
    """The nearest xterm-256 colour (the 6x6x6 cube or the grey ramp)."""
    steps = [0, 95, 135, 175, 215, 255]
    q = [min(range(6), key=lambda i: abs(steps[i] - v)) for v in rgb]
    cube = 16 + 36 * q[0] + 6 * q[1] + q[2]
    cube_rgb = [steps[i] for i in q]
    grey = min(range(24), key=lambda i: abs(8 + 10 * i - sum(rgb) / 3))
    grey_rgb = [8 + 10 * grey] * 3
    dist = lambda a: sum((x - y) ** 2 for x, y in zip(a, rgb))  # noqa: E731
    return cube if dist(cube_rgb) <= dist(grey_rgb) else 232 + grey


class UI:
    """Formatting for one output stream. Every method returns a string; nothing prints by itself."""

    def __init__(self, stream=None):
        self.stream = stream or sys.stdout
        env = os.environ
        tty = getattr(self.stream, "isatty", lambda: False)()
        self.color = (env.get("FORCE_COLOR") not in (None, "", "0")) or (
            tty and "NO_COLOR" not in env and env.get("TERM") != "dumb")
        self.truecolor = self.color and env.get("COLORTERM", "").lower() in ("truecolor", "24bit")
        # macOS Terminal reports xterm-256color but no COLORTERM: use the 256-colour cube there
        self.c256 = self.color and not self.truecolor and "256color" in env.get("TERM", "")
        enc = (getattr(self.stream, "encoding", None) or "").lower().replace("-", "")
        self.unicode = enc.startswith("utf")
        self.tty = tty

    # ---- colour -----------------------------------------------------------------------------------
    def c(self, text: str, role: str, bold: bool = False) -> str:
        if not self.color or not text:
            return text
        if self.truecolor and role in _TRUE:
            r, g, b = _TRUE[role]
            code = f"38;2;{r};{g};{b}" + (";1" if bold else "")
        elif self.c256 and role in _TRUE:
            code = f"38;5;{_to256(_TRUE[role])}" + (";1" if bold else "")
        else:
            code = _BASIC.get(role, "0") + (";1" if bold and role not in ("brand", "cmd") else "")
        return f"\x1b[{code}m{text}\x1b[0m"

    def sym(self, kind: str) -> str:
        if self.unicode and self.color:
            return {"ok": "✓", "warn": "!", "bad": "✗", "dot": "●", "arrow": "▸", "rule": "─"}[kind]
        return {"ok": "PASS", "warn": "WARN", "bad": "FAIL", "dot": "*", "arrow": ">", "rule": "-"}[kind]

    # ---- building blocks --------------------------------------------------------------------------
    def header(self, command: str) -> str:
        """One line for every command: `// synthe ▸ doctor`."""
        if not self.color:
            return f"synthe {command}"
        return f"{self.c('//', 'bad', bold=True)} {self.c('synthe', 'brand', bold=True)} " \
               f"{self.c(self.sym('arrow'), 'muted')} {command}"

    def rule(self, width: int = 72) -> str:
        return self.c(self.sym("rule") * width, "muted")

    def cmd(self, text: str) -> str:
        """A command the reader should run, on its own line."""
        return f"    {self.c('$', 'muted')} {self.c(text, 'cmd', bold=True)}"

    def step(self, n: int, text: str) -> str:
        return f"  {self.c(str(n) + '.', 'brand', bold=True)} {text}"

    def kv(self, key: str, value: str, width: int = 10) -> str:
        return f"  {self.c(key.ljust(width), 'muted')} {value}"

    def level(self, level: str) -> str:
        role = {"ENFORCED": "ok", "GUARDED": "warn"}.get(level, "bad")
        return self.c(f"{self.sym('dot')} {level}", role, bold=True)

    def check(self, status: str, name: str, detail: str, width: int = 26) -> str:
        role = {"PASS": "ok", "WARN": "warn"}.get(status, "bad")
        mark = {"PASS": "ok", "WARN": "warn"}.get(status, "bad")
        if not self.color:
            return f"  {status:<4}  {name}: {detail}"
        word = status if status in ("PASS", "WARN") else "FAIL"  # green, burnt orange, red; all bold
        return f"  {self.c(word, role, bold=True)}  {name.ljust(width)} {self.c(detail, 'muted')}"

    def decision(self, word: str) -> str:
        role = {"executed": "ok", "approval_accepted": "ok", "staged": "warn", "ACCEPT": "ok",
                "COMPLETED": "ok"}.get(word, "bad")
        return self.c(word, role, bold=True)

    def banner(self, lines: list[str], mark: list[str] | None = None, top: int | None = None) -> str:
        """The mark on the left, `lines` beside it, centred on the logo. `mark` and `top` let an intro
        draw each frame of the logo inside the banner, with the text already in place."""
        if not self.tty and not self.color:
            return "\n".join(lines)
        mark = mark or (MARK if self.unicode else MARK_ASCII)
        width = max(len(m) for m in mark) + 4
        if top is None:
            top = max(0, (len(mark) - len(lines)) // 2)
        rows = []
        for i in range(max(len(mark), top + len(lines))):
            left = mark[i] if i < len(mark) else ""
            right = lines[i - top] if 0 <= i - top < len(lines) else ""
            rows.append(f"  {self.c(left.ljust(width), 'brand')}{right}".rstrip())
        return "\n".join(rows)

    def wordmark(self) -> list[str]:
        return [self.c("synthe", "brand", bold=True), self.c(TAGLINE, "muted")]


def plain(text: str) -> str:
    """Strip colour codes (for tests and for anyone piping a coloured string)."""
    return _ANSI.sub("", text)


# ---- the spin: the logo extruded and rotating, for the first moment of setup ----------------------

_PATHS = [
    "M 64.894 261.544 155.983 140.236 179.779 108.392 185.927 154.879 110.451 255.747 138.531 255.614 "
    "209.078 162.002 200.172 91.235 C 199.408 85.166 200.816 79.553 205.121 75.642 209.828 71.368 216.229 "
    "70.134 221.964 72.262 228.322 74.621 231.877 79.955 232.693 86.566 L 242.414 165.286 C 242.975 169.836 "
    "241.259 173.994 238.587 177.533 L 160.448 281.001 C 157.254 285.231 152.542 288.273 147.064 288.315 "
    "L 78.043 288.836 C 73.418 288.871 69.030 287.434 65.849 284.248 59.453 277.843 59.605 268.588 64.894 "
    "261.544",
    "M 135.339 35.105 119.916 56.166 65.976 129.689 75.562 201.351 C 76.765 210.340 71.240 218.418 62.432 "
    "220.185 53.895 221.859 45.295 216.549 43.298 207.725 L 32.651 127.593 C 32.196 124.170 32.576 120.045 "
    "34.689 117.171 L 83.489 50.805 113.299 10.126 C 116.532 5.714 121.004 2.677 126.682 2.564 L 196.616 "
    "1.166 C 203.544 1.028 209.471 5.555 211.787 11.932 213.849 17.594 212.818 23.577 209.138 28.271 L "
    "95.676 182.179 89.465 135.537 144.852 60.334 163.745 34.614 Z",
]
_W, _H = 275, 290


def _polys(paths=None):
    out = []
    for d in paths or _PATHS:
        toks = re.findall(r"[MLCZ]|-?\d+\.?\d*", d)
        cur, cmd, i, pt = [], None, 0, (0.0, 0.0)
        while i < len(toks):
            t = toks[i]
            if t in "MLCZ":
                cmd, i = t, i + 1
                if t == "Z":
                    out.append(cur)
                    cur = []
                continue
            if cmd == "M":
                if cur:
                    out.append(cur)
                pt = (float(toks[i]), float(toks[i + 1]))
                cur, cmd, i = [pt], "L", i + 2
            elif cmd == "L":
                pt = (float(toks[i]), float(toks[i + 1]))
                cur.append(pt)
                i += 2
            else:
                p0 = pt
                p1, p2, p3 = [(float(toks[i + k]), float(toks[i + k + 1])) for k in (0, 2, 4)]
                for k in range(1, 9):
                    u = k / 8
                    cur.append(tuple((1 - u) ** 3 * a + 3 * (1 - u) ** 2 * u * b + 3 * (1 - u) * u ** 2 * c + u ** 3 * e
                                     for a, b, c, e in zip(p0, p1, p2, p3)))
                pt, i = p3, i + 6
        if cur:
            out.append(cur)
    return out


def _inside(polys, x, y):
    c = False
    for poly in polys:
        n = len(poly)
        for a in range(n):
            (x1, y1), (x2, y2) = poly[a], poly[(a + 1) % n]
            if (y1 > y) != (y2 > y) and x < (x2 - x1) * (y - y1) / (y2 - y1) + x1:
                c = not c
    return c


def _dots(path: str, dw: int, dh: int) -> set:
    """One stroke of the logo as braille dot positions on a dw x dh grid (dots are square)."""
    polys, sx, sy = _polys([path]), _W / dw, _H / dh
    return {(x, y) for y in range(dh) for x in range(dw) if _inside(polys, (x + .5) * sx, (y + .5) * sy)}


def _braille(dots: set, cols: int, rows: int) -> list[str]:
    bits = {(0, 0): 0x01, (0, 1): 0x02, (0, 2): 0x04, (1, 0): 0x08, (1, 1): 0x10, (1, 2): 0x20,
            (0, 3): 0x40, (1, 3): 0x80}
    grid = [[0] * cols for _ in range(rows)]
    for x, y in dots:
        if 0 <= x < cols * 2 and 0 <= y < rows * 4:
            grid[y // 4][x // 2] |= bits[(x % 2, y % 4)]
    return ["".join(chr(0x2800 + v) for v in row) for row in grid]


def lock_frames(cols: int = 16, steps: int = 26, hold: int = 14):
    """The logo's two strokes slide in from above and below and lock into the mark: an agent proposes,
    you approve, Synthe commits. Both strokes are whole in every frame (the canvas has room for their
    travel). Yields (lines, locked); the last frames are the mark."""
    dw = cols * 2
    dh = int(dw * _H / _W + .5)
    travel = 4 * round(dh * 0.32 / 4)              # how far apart they start: whole rows, so the
                                                   # last frame is the mark, not a shifted copy
    rows = (dh + 2 * travel + 3) // 4
    lower, upper = _dots(_PATHS[0], dw, dh), _dots(_PATHS[1], dw, dh)
    for i in range(steps + hold):
        t = min(1.0, i / steps)
        d = round((1 - t) ** 3 * travel)           # ease out: fast, then settling
        frame = {(x, y + travel - d) for x, y in upper} | {(x, y + travel + d) for x, y in lower}
        yield _braille(frame, cols, rows), i >= steps


def reveal_frames(cols: int = 16, steps: int = 30, hold: int = 14):
    """The logo is drawn on, along its own diagonal, bottom-left to top-right. Yields (lines, done)."""
    dw = cols * 2
    dh = int(dw * _H / _W + .5)
    rows = (dh + 3) // 4
    dots = _dots(_PATHS[0], dw, dh) | _dots(_PATHS[1], dw, dh)
    key = {p: p[0] - p[1] for p in dots}            # distance along the diagonal
    lo, hi = min(key.values()), max(key.values())
    for i in range(steps + hold):
        t = min(1.0, i / steps)
        edge = lo + (hi - lo + 1) * (1 - (1 - t) ** 2)
        yield _braille({p for p in dots if key[p] <= edge}, cols, rows), i >= steps


def _play(ui: UI, blocks, fps: float = 30.0) -> None:
    """Draw blocks of lines in place: each is redrawn by moving up exactly the lines the last one drew
    (that survives the screen scrolling, unlike saving the cursor). The last block stays on screen;
    Ctrl-C jumps straight to it."""
    out, drawn, blocks = ui.stream, 0, list(blocks)

    def draw(block):
        nonlocal drawn
        if drawn:
            out.write(f"\x1b[{drawn}A\r")
        out.write("".join(line + "\x1b[K\n" for line in block))
        out.flush()
        drawn = len(block)

    try:
        out.write("\x1b[?25l")
        for block in blocks:
            draw(block)
            time.sleep(1 / fps)
    except KeyboardInterrupt:
        draw(blocks[-1])
    finally:
        out.write("\x1b[?25h")
        out.flush()


def _animate_ok(ui: UI) -> bool:
    return bool(ui.tty and ui.color and ui.unicode) and not os.environ.get("CI") \
        and not os.environ.get("SYNTHE_NO_ANIMATION")


def intro(ui: UI, lines: list[str], style: str = "lock") -> bool:
    """The banner with the logo animating inside it: the text is in place from the first frame, and the
    last frame is the finished banner, so nothing is cleared or reprinted. Returns False when it didn't
    play (not an interactive colour terminal, CI, SYNTHE_NO_ANIMATION, or a small window); the caller
    then prints the static banner."""
    if not _animate_ok(ui):
        return False
    import shutil
    size = shutil.get_terminal_size((80, 24))
    if size.lines < 20 or size.columns < 30:
        return False
    gen = {"draw": reveal_frames, "spin": flip_frames}.get(style, lock_frames)
    frames = [f for f, _ in gen(INTRO_COLS)]
    final = frames[-1]
    filled = [i for i, row in enumerate(final) if row.strip("\u2800 ")]
    top = filled[0] + max(0, (filled[-1] - filled[0] + 1 - len(lines)) // 2)  # centred on the landed logo
    _play(ui, (ui.banner(lines, mark=f, top=top).split("\n") for f in frames))
    return True


def flip_frames(cols: int = 16, turn: int = 46, hold: int = 16):
    """The logo turns like a coin (one turn, slowing down) and lands face-on on the mark. Drawn in braille
    dots, 8 per character, so the gaps between the strokes stay visible at every readable angle; a
    character-shaded 3D version lost them and read as a blob. Yields (lines, landed)."""
    dw = cols * 2
    dh = int(dw * _H / _W + .5)
    rows = (dh + 3) // 4
    dots = _dots(_PATHS[0], dw, dh) | _dots(_PATHS[1], dw, dh)
    cx = (dw - 1) / 2
    for i in range(turn + hold):
        a = 2 * math.pi * (1 - min(1.0, i / turn)) ** 3   # ease out: fast, then settling face-on
        k = math.cos(a)
        frame = {(round(cx + (x + off - cx) * k), y) for x, y in dots for off in (-0.25, 0.25)}
        yield _braille(frame, cols, rows), i >= turn


def spin(ui: UI, lines: list[str]) -> bool:
    """The coin-turn intro inside the banner (see intro)."""
    return intro(ui, lines, style="spin")