# grimoire - sig.merlin's binex setup

A recon & triage **cockpit** for binary exploitation. Not a monolith, an
opinionated front-end that orchestrates the good tools and encodes a point of
view. Local-only by design: it analyzes binaries on THIS machine, never reaches
off-box, never autofires. Suggests and scaffolds; you review and pull the trigger.

## Install
    pip install rich pwntools --break-system-packages

## Run
    python3 grimoire.py

Boots with a static-resolve intro, asks for authorization (logged), then a
numbered menu:

    1  load binary
    2  recon (mitigations)          canary / NX / PIE / RELRO, attacker-colored
    3  juicy (where to look)        dangerous funcs, win-symbols, /bin/sh, DIRECTION
    4  ROP gadgets                  ret / pop rdi / syscall / leave ...
    5  cyclic offset finder         runs target locally, finds + VERIFIES offset,
                                    reports confidence honestly
    6  grep source for risk         scan .c/.py for risky patterns
    7  scaffold PoC skeleton        reviewable exploit template (local, pauses to review)
    8  export portable recon        -> grimoire-lite for locked-down boxes

## grimoire-lite  (the wargame paste-in)
Zero dependencies. Stdlib only. Parses ELF mitigations from raw bytes.
For OverTheWire / pwnable.kr / any locked-down box with just python3:

    scp grimoire_lite.py user@wargame:/tmp/     # or cat + paste it
    python3 grimoire_lite.py <challenge_binary>

Gives the same mitigation read + suggested direction as full grimoire,
needing nothing installed.

## Notes for the OTW workflow
- Most pwn challenges: pull the binary local (scp) and use full grimoire.
- Locked-down boxes where you can't install: use grimoire-lite in place.
- The offset finder needs core dumps (`ulimit -c unlimited`, which it sets).
  It reports VERIFIED vs candidate honestly, a candidate is a hypothesis;
  confirm it before building on it. Messy crash dynamics (frame writes,
  non-clean ret) can mask control even when the offset is right.

## Ethos
Analyze, suggest, scaffold, never autofire, never off-box. The brake is the
point. This is a setup that respects the tools it orchestrates and the person
running it.

it's Modelo time somewhere.
