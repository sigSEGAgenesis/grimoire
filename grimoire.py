#!/usr/bin/env python3
# =====================================================================
#  grimoire — a local binary-analysis workbench for exploit dev
# ---------------------------------------------------------------------
#  PHILOSOPHY (read this, sober-me):
#    * LOCAL ONLY. There is intentionally NO network code in this tool.
#      It reads binaries and source that are already on THIS machine.
#    * It ANALYZES, SUGGESTS, and SCAFFOLDS. It never auto-exploits,
#      never fires anything at a target, never reaches off the box.
#    * Anything that would "send it" is left as a reviewable template
#      for a human to read and run deliberately. No one-click autopwn.
#    * A permission gate + log exists as an intent record and speed bump.
#      It is discipline, not a security control. The real safety is that
#      this tool has no offensive-against-remote capability by design.
# =====================================================================
import os, sys, datetime, re, subprocess

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich import box
except ImportError:
    print("Need rich:  pip install rich --break-system-packages")
    sys.exit(1)

try:
    from pwn import ELF, ROP, context, cyclic, cyclic_find
    context.log_level = 'error'
    HAVE_PWN = True
except ImportError:
    HAVE_PWN = False

# ---- Dracula palette --------------------------------------------------
BG="#282a36"; FG="#f8f8f2"; COMMENT="#6272a4"; CYAN="#8be9fd"
GREEN="#50fa7b"; ORANGE="#ffb86c"; PINK="#ff79c6"; PURPLE="#bd93f9"
RED="#ff5555"; YELLOW="#f1fa8c"
con = Console()

LOGFILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "grimoire.log")
STATE = {"binary": None, "elf": None, "srcdir": None}

# functions worth flagging when found imported/called
DANGER = {
    "gets":"unbounded stdin read -> classic overflow",
    "strcpy":"no bounds -> overflow if src attacker-controlled",
    "strcat":"no bounds -> overflow",
    "sprintf":"no bounds -> overflow / format issues",
    "scanf":"%s with no width -> overflow",
    "memcpy":"overflow if length attacker-controlled",
    "read":"overflow if size > buffer",
    "system":"command exec -> ret2system target",
    "execve":"exec -> shell primitive",
    "printf":"format string if arg is attacker-controlled",
}
WIN_HINTS = ["win","backdoor","shell","admin","flag","secret","give","magic","debug"]

def log(msg):
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    with open(LOGFILE, "a") as f:
        f.write(f"[{ts}] {msg}\n")

import random, time

def _boot(skip=False):
    """Terminal static that resolves into the title. Cosmetic only."""
    if skip or not sys.stdout.isatty():
        return
    con.clear()
    target = ["g r i m o i r e", "local binary analysis workbench"]
    glyphs = "!@#$%^&*()_+-=[]{}|;:,.<>?/\\~`01x░▒▓█▄▀■□◆◇"
    styles = [PURPLE, CYAN, GREEN, PINK, COMMENT]
    width = max(len(t) for t in target)
    # phase 1: pure static
    for _ in range(7):
        con.clear()
        block = Text()
        for _r in range(2):
            row = "".join(random.choice(glyphs) for _ in range(width))
            block.append("  " + row + "\n", style=random.choice(styles))
        con.print("\n\n"); con.print(block)
        time.sleep(0.045)
    # phase 2: resolve each line left-to-right out of the static
    for step in range(width + 1):
        con.clear()
        block = Text()
        for line in target:
            padded = line.ljust(width)
            shown = Text()
            for i, ch in enumerate(padded):
                if i < step:
                    shown.append(ch, style=f"bold {PURPLE}" if line==target[0] else CYAN)
                else:
                    shown.append(random.choice(glyphs), style=random.choice(styles))
            block.append("  "); block.append(shown); block.append("\n")
        con.print("\n\n"); con.print(block)
        time.sleep(0.028)
    time.sleep(0.15)

def banner():
    con.clear()
    art = Text()
    art.append("  ┌─────────────────────────────────────┐\n", style=COMMENT)
    art.append("  │  ", style=COMMENT); art.append("g r i m o i r e", style=f"bold {PURPLE}")
    art.append("                      │\n", style=COMMENT)
    art.append("  │  ", style=COMMENT); art.append("local binary analysis workbench", style=CYAN)
    art.append("    │\n", style=COMMENT)
    art.append("  └─────────────────────────────────────┘", style=COMMENT)
    con.print(art)
    con.print(f"  [{COMMENT}]it's Modelo time somewhere[/]\n")

def gate():
    _boot()
    banner()
    con.print(Panel(
        Text.assemble(
            ("Authorization check\n\n", f"bold {YELLOW}"),
            ("This tool analyzes binaries and source on THIS machine for\n", FG),
            ("exploit development on targets you are permitted to test\n", FG),
            ("(your own binaries, CTFs, or written-scope engagements).\n\n", FG),
            ("Do you have permission to analyze the target(s) this session?", f"bold {FG}"),
        ),
        border_style=PURPLE, box=box.ROUNDED))
    ans = con.input(f"  [{GREEN}]permission granted? [y/N] > [/]").strip().lower()
    if ans != "y":
        con.print(f"  [{RED}]No affirmation. Exiting.[/]")
        log("SESSION DENIED — user answered N")
        sys.exit(0)
    log("SESSION START — user affirmed authorization")
    con.print(f"  [{GREEN}]logged. let's work.[/]\n")

def need_binary():
    if not STATE["elf"]:
        con.print(f"  [{RED}]no binary loaded — use option 1 first[/]\n"); return False
    return True

# ---- modules ----------------------------------------------------------
def m_load():
    p = con.input(f"  [{CYAN}]path to binary > [/]").strip()
    if not os.path.isfile(p):
        con.print(f"  [{RED}]not a file: {p}[/]\n"); return
    if not HAVE_PWN:
        con.print(f"  [{RED}]pwntools not installed[/]\n"); return
    try:
        STATE["elf"] = ELF(p); STATE["binary"] = os.path.abspath(p)
        log(f"LOADED {STATE['binary']}")
        con.print(f"  [{GREEN}]loaded[/] {p}\n")
    except Exception as e:
        con.print(f"  [{RED}]failed: {e}[/]\n")

def m_recon():
    if not need_binary(): return
    e = STATE["elf"]
    t = Table(title="recon", border_style=PURPLE, box=box.ROUNDED, title_style=f"bold {PURPLE}")
    t.add_column("property", style=CYAN); t.add_column("value", style=FG)
    mit = lambda ok_good, val: f"[{GREEN}]{val}[/]" if ok_good else f"[{RED}]{val}[/]"
    t.add_row("arch", f"{e.arch} / {e.bits}-bit / {e.endian}")
    t.add_row("Canary", mit(not e.canary, e.canary))   # no canary = easier = "green" for attacker
    t.add_row("NX", mit(not e.nx, e.nx))
    t.add_row("PIE", mit(not e.pie, e.pie))
    t.add_row("RELRO", str(e.relro))
    t.add_row("symbols", str(len(e.symbols)))
    con.print(t); con.print()

def m_juicy():
    if not need_binary(): return
    e = STATE["elf"]
    con.print(Panel("juicy — where to look", border_style=ORANGE, box=box.ROUNDED, style=f"bold {ORANGE}"))
    # dangerous imports
    found = [(n,d) for n,d in DANGER.items() if n in e.symbols or n in getattr(e,'plt',{}) or n in getattr(e,'got',{})]
    if found:
        t = Table(title="dangerous functions present", border_style=RED, box=box.SIMPLE)
        t.add_column("func", style=f"bold {RED}"); t.add_column("why", style=FG)
        for n,d in found: t.add_row(n, d)
        con.print(t)
    # win-like symbols
    wins = [s for s in e.symbols if any(h in s.lower() for h in WIN_HINTS)]
    if wins:
        con.print(f"  [{GREEN}]win-like symbols:[/] " + ", ".join(f"[{GREEN}]{w}[/]@{hex(e.symbols[w])}" for w in wins[:8]))
    # /bin/sh
    try:
        sh = list(e.search(b"/bin/sh"))
        if sh: con.print(f"  [{PINK}]/bin/sh string @[/] {hex(sh[0])}")
    except Exception: pass
    # suggested actions
    sugg = []
    if not e.canary and not e.pie: sugg.append("no canary + no PIE -> classic ret2win / ret2libc")
    elif e.canary and not e.pie:   sugg.append("canary present -> need a leak (leak-and-replay)")
    if e.pie:                       sugg.append("PIE on -> need an address leak to defeat ASLR")
    if e.nx:                        sugg.append("NX on -> reuse code (ret2libc/ROP), not shellcode")
    if "system" in e.symbols or "system" in getattr(e,'plt',{}): sugg.append("system() available -> ret2system")
    if sugg:
        con.print(f"\n  [{YELLOW}]suggested direction:[/]")
        for s in sugg: con.print(f"    [{YELLOW}]•[/] {s}")
    con.print()

def m_gadgets():
    if not need_binary(): return
    e = STATE["elf"]
    try:
        rop = ROP(e)
        wants = {"ret":["ret"], "pop rdi":["pop rdi","ret"], "pop rsi":["pop rsi","ret"],
                 "pop rax":["pop rax","ret"], "syscall":["syscall"], "leave":["leave","ret"]}
        t = Table(title="ROP gadgets", border_style=PURPLE, box=box.ROUNDED)
        t.add_column("gadget", style=CYAN); t.add_column("addr", style=GREEN)
        for name, seq in wants.items():
            try:
                g = rop.find_gadget(seq)
                t.add_row(name, hex(g[0]) if g else "[dim]—[/]")
            except Exception:
                t.add_row(name, "[dim]—[/]")
        con.print(t); con.print()
    except Exception as ex:
        con.print(f"  [{RED}]gadget search failed: {ex}[/]\n")

def m_grep():
    d = con.input(f"  [{CYAN}]source dir (blank = cwd) > [/]").strip() or "."
    if not os.path.isdir(d):
        con.print(f"  [{RED}]not a dir[/]\n"); return
    pats = list(DANGER.keys()) + ["malloc","free","alloca","format"]
    rx = re.compile(r"\b(" + "|".join(pats) + r")\b")
    hits = []
    for root,_,files in os.walk(d):
        for fn in files:
            if fn.endswith((".c",".cc",".cpp",".h",".py")):
                fp = os.path.join(root,fn)
                try:
                    for i,line in enumerate(open(fp,errors="ignore"),1):
                        if rx.search(line):
                            hits.append((fp,i,line.strip()[:70]))
                except Exception: pass
    if not hits:
        con.print(f"  [{GREEN}]no risky patterns found[/]\n"); return
    t = Table(title=f"risky patterns in {d}", border_style=ORANGE, box=box.SIMPLE)
    t.add_column("file:line", style=CYAN); t.add_column("code", style=FG)
    for fp,i,code in hits[:40]:
        t.add_row(f"{os.path.relpath(fp,d)}:{i}", code)
    con.print(t); con.print(f"  [{COMMENT}]{len(hits)} hit(s)[/]\n")

def m_scaffold():
    if not need_binary(): return
    e = STATE["elf"]
    out = os.path.join(os.path.dirname(STATE["binary"]), "exploit_skeleton.py")
    win = next((s for s in e.symbols if any(h in s.lower() for h in WIN_HINTS)), None)
    tmpl = f'''#!/usr/bin/env python3
# SKELETON — generated by grimoire. REVIEW before running. Local target only.
from pwn import *
context.binary = elf = ELF({STATE["binary"]!r})
context.log_level = "info"

# --- local process only. no remote target is wired in on purpose. ---
p = process(elf.path)

OFFSET = None   # TODO: find with grimoire option 5 (cyclic offset)
assert OFFSET is not None, "set OFFSET first"

ret = ROP(elf).find_gadget(["ret"])[0]   # movaps alignment
payload  = b"A"*OFFSET
{"payload += p64(ret); payload += p64(elf.symbols[%r])  # ret2win" % win if win and not e.pie else "# TODO: build your chain (leak? ret2libc? see grimoire suggestions)"}

# REVIEW the payload above before sending. Nothing fires automatically.
input("[review payload, press enter to send to LOCAL process] ")
p.sendline(payload)
p.interactive()
'''
    with open(out,"w") as f: f.write(tmpl)
    log(f"SCAFFOLD written {out}")
    con.print(f"  [{GREEN}]wrote reviewable skeleton:[/] {out}")
    con.print(f"  [{COMMENT}]it targets a LOCAL process and pauses for your review before sending[/]\n")

def m_lite():
    """Emit the standalone, dependency-free recon parser for paste-in on locked-down boxes."""
    here = os.path.dirname(os.path.abspath(__file__))
    src = os.path.join(here, "grimoire_lite.py")
    if os.path.isfile(src):
        con.print(f"  [{GREEN}]portable recon lives at:[/] {src}")
        con.print(f"  [{COMMENT}]scp it to a wargame box, or `cat` + paste it. Zero deps, stdlib only.[/]")
        con.print(f"  [{COMMENT}]on the box:[/] [{CYAN}]python3 grimoire_lite.py <challenge_binary>[/]\n")
    else:
        con.print(f"  [{RED}]grimoire_lite.py not found next to grimoire.py[/]\n")

def m_offset():
    if not need_binary(): return
    import resource
    binpath = STATE["binary"]
    con.print(Panel(
        Text.assemble(
            ("cyclic offset finder\n\n", f"bold {CYAN}"),
            ("Runs YOUR binary locally with a De Bruijn pattern, reads the crash,\n", FG),
            ("computes the offset to the saved return address, and verifies it.\n", FG),
            ("Reports confidence honestly — a candidate is a hypothesis, not gospel.", COMMENT),
        ), border_style=CYAN, box=box.ROUNDED))
    length = con.input(f"  [{CYAN}]pattern length [800] > [/]").strip()
    length = int(length) if length.isdigit() else 800
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    except Exception:
        con.print(f"  [{ORANGE}]note: couldn't raise core limit; finder may need a core dump enabled[/]")
    try:
        from pwn import process, cyclic, cyclic_find, p64, context
        context.binary = STATE["elf"]
        p = process(binpath); p.send(cyclic(length, n=8)); p.wait(timeout=6)
        core = p.corefile
        cands = []
        try:
            o = cyclic_find(core.rip & 0xffffffffffffffff, n=8)
            if o >= 0: cands.append(("RIP", o))
        except Exception: pass
        for d in (-8, 0, 8, 16):
            try:
                o = cyclic_find(core.read(core.rsp + d, 8), n=8)
                if o >= 0: cands.append((f"RSP{d:+d}", o))
            except Exception: pass
        if not cands:
            con.print(f"  [{RED}]no offset resolved — inspect corefile (RSP={hex(core.rsp)} RIP={hex(core.rip)})[/]\n")
            return
        off = min(c[1] for c in cands)
        # honest verification: jump to a canonical-unmapped addr, confirm it lands in RIP
        verified = False
        try:
            p2 = process(binpath); p2.send(b"A"*off + p64(0x4142434445)); p2.wait(timeout=6)
            verified = (p2.corefile.rip == 0x4142434445)
        except Exception:
            verified = None
        t = Table(title="offset finder", border_style=CYAN, box=box.ROUNDED)
        t.add_column("source", style=COMMENT); t.add_column("offset", style=GREEN)
        for name, o in cands: t.add_row(name, str(o))
        con.print(t)
        if verified is True:
            con.print(f"  [{GREEN}]offset = {off}  [VERIFIED ✓ — controls RIP][/]")
            con.print(f"  [{GREEN}]payload:[/] b'A'*{off} + p64(target)\n")
            log(f"OFFSET {binpath} = {off} VERIFIED")
        else:
            tag = "unverified" if verified is False else "verify errored"
            con.print(f"  [{YELLOW}]offset candidate = {off}  [{tag} — inspect on your box][/]")
            con.print(f"  [{COMMENT}]messy crash dynamics (frame writes, non-clean ret) can mask control.[/]\n")
            log(f"OFFSET {binpath} = {off} UNVERIFIED")
    except Exception as ex:
        con.print(f"  [{RED}]finder error: {ex}[/]\n")

MENU = [
    ("load binary", m_load), ("recon (mitigations)", m_recon),
    ("juicy (where to look)", m_juicy), ("ROP gadgets", m_gadgets),
    ("cyclic offset finder", m_offset), ("grep source for risk", m_grep),
    ("scaffold PoC skeleton", m_scaffold),
    ("export portable recon (grimoire-lite)", m_lite),
]

def menu():
    while True:
        tgt = STATE["binary"] or "none"
        con.print(f"  [{COMMENT}]target:[/] [{CYAN}]{tgt}[/]")
        for i,(name,_) in enumerate(MENU,1):
            con.print(f"    [{PURPLE}]{i}[/]  {name}")
        con.print(f"    [{RED}]0[/]  quit")
        c = con.input(f"\n  [{GREEN}]grimoire > [/]").strip()
        if c == "0":
            log("SESSION END"); con.print(f"  [{PURPLE}]stay curious.[/]"); return
        if c.isdigit() and 1 <= int(c) <= len(MENU):
            con.print()
            try: MENU[int(c)-1][1]()
            except Exception as ex: con.print(f"  [{RED}]error: {ex}[/]\n")
        else:
            con.print(f"  [{RED}]?[/]\n")

if __name__ == "__main__":
    if not HAVE_PWN:
        con.print(f"[{YELLOW}]warning: pwntools missing — analysis limited. pip install pwntools --break-system-packages[/]")
    gate(); menu()
