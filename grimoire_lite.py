#!/usr/bin/env python3
# grimoire-lite  --  portable ELF recon, ZERO dependencies (stdlib only).
# Paste onto any box (wargames, locked-down hosts) that has python3.
# Reads mitigations + juicy functions straight from raw ELF bytes.
#   usage:  python3 grimoire_lite.py <binary>
#      or:  paste this whole thing into a python3 REPL and call recon("<path>")
import sys, struct

DANGER = {"gets","strcpy","strcat","sprintf","scanf","system","execve",
          "read","printf","memcpy","gets_s","realpath","getwd"}

def recon(path):
    with open(path,"rb") as f: d = f.read()
    if d[:4] != b"\x7fELF":
        print("not an ELF"); return
    is64 = d[4] == 2
    le   = d[5] == 1
    end  = "<" if le else ">"
    e_type = struct.unpack_from(end+"H", d, 16)[0]      # 2=EXEC(no PIE) 3=DYN(PIE/so)
    e_mach = struct.unpack_from(end+"H", d, 18)[0]      # 0x3e=x86-64 0x03=x86
    arch = {0x3e:"x86-64",0x03:"x86",0xb7:"aarch64",0x28:"arm"}.get(e_mach,hex(e_mach))

    # program headers -> NX (GNU_STACK) and RELRO (GNU_RELRO)
    if is64:
        e_phoff = struct.unpack_from(end+"Q", d, 32)[0]
        e_phentsize = struct.unpack_from(end+"H", d, 54)[0]
        e_phnum = struct.unpack_from(end+"H", d, 56)[0]
    else:
        e_phoff = struct.unpack_from(end+"I", d, 28)[0]
        e_phentsize = struct.unpack_from(end+"H", d, 42)[0]
        e_phnum = struct.unpack_from(end+"H", d, 44)[0]

    PT_GNU_STACK=0x6474e551; PT_GNU_RELRO=0x6474e552; PT_DYNAMIC=2
    nx=True; relro="No"; dyn_off=dyn_sz=0
    for i in range(e_phnum):
        off = e_phoff + i*e_phentsize
        p_type = struct.unpack_from(end+"I", d, off)[0]
        if is64:
            p_flags = struct.unpack_from(end+"I", d, off+4)[0]
            p_off   = struct.unpack_from(end+"Q", d, off+8)[0]
            p_filesz= struct.unpack_from(end+"Q", d, off+32)[0]
        else:
            p_off   = struct.unpack_from(end+"I", d, off+4)[0]
            p_flags = struct.unpack_from(end+"I", d, off+24)[0]
            p_filesz= struct.unpack_from(end+"I", d, off+16)[0]
        if p_type == PT_GNU_STACK:
            nx = not (p_flags & 0x1)         # X bit set => stack executable => NX off
        elif p_type == PT_GNU_RELRO:
            relro = "Partial"
        elif p_type == PT_DYNAMIC:
            dyn_off, dyn_sz = p_off, p_filesz

    # dynamic section -> BIND_NOW => Full RELRO ; also scan for canary/juicy via strings
    DT_BIND_NOW=24; DT_FLAGS=30; DT_FLAGS_1=0x6ffffffb; DF_BIND_NOW=0x8; DF_1_NOW=0x1
    bind_now=False
    if dyn_off:
        entsz = 16 if is64 else 8
        for o in range(dyn_off, dyn_off+dyn_sz, entsz):
            if is64:
                tag,val = struct.unpack_from(end+"qQ", d, o)
            else:
                tag,val = struct.unpack_from(end+"iI", d, o)
            if tag==0: break
            if tag==DT_BIND_NOW: bind_now=True
            if tag==DT_FLAGS and (val&DF_BIND_NOW): bind_now=True
            if tag==DT_FLAGS_1 and (val&DF_1_NOW): bind_now=True
    if relro=="Partial" and bind_now: relro="Full"

    # canary + juicy: scan the raw bytes for symbol names (crude but dependency-free)
    canary = b"__stack_chk_fail" in d
    juicy = sorted({n for n in DANGER if (b"\x00"+n.encode()+b"\x00") in d})

    # ---- report ----
    g="\033[92m"; r="\033[91m"; c="\033[96m"; y="\033[93m"; p="\033[95m"; x="\033[0m"
    pie = (e_type==3)
    def mark(attacker_good, label): return f"{g}{label}{x}" if attacker_good else f"{r}{label}{x}"
    print(f"{p}== grimoire-lite :: {path} =={x}")
    print(f"  arch    : {c}{arch} {'64' if is64 else '32'}-bit{x}")
    print(f"  Canary  : {mark(not canary, canary)}")
    print(f"  NX      : {mark(not nx, nx)}")
    print(f"  PIE     : {mark(not pie, pie)}")
    print(f"  RELRO   : {relro}")
    if juicy: print(f"  {y}juicy   : {', '.join(juicy)}{x}")
    # suggested direction (same brain as full grimoire)
    s=[]
    if not canary and not pie: s.append("no canary + no PIE -> classic ret2win / ret2libc")
    elif canary and not pie:   s.append("canary -> need a leak (leak-and-replay)")
    if pie: s.append("PIE -> need an address leak")
    if nx:  s.append("NX -> reuse code (ret2libc/ROP), not shellcode")
    if "system" in juicy: s.append("system() present -> ret2system")
    if s:
        print(f"  {y}direction:{x}")
        for i in s: print(f"    - {i}")

if __name__=="__main__":
    if len(sys.argv)<2: print("usage: python3 grimoire_lite.py <binary>"); sys.exit(1)
    recon(sys.argv[1])
