#!/usr/bin/env python3
"""
ir2fwir - convert a Flipper Zero .ir remote into a FreeWili 1 (OG) .fwir database.

The .fwir format was reverse-engineered and validated end-to-end on hardware
(stock Display v67):
  line 1 : "# fwili IR database v 1\n"
  entry  : "<name>=<signed-decimal-int>\n"
where the int is the 4-byte NEC air-frame, little-endian:
  byte0 = address low
  byte1 = address high      (NECext) | ~address low (plain NEC)
  byte2 = command
  byte3 = command 2nd byte  (NECext) | ~command    (plain NEC)
written with printf "%d" (signed).

Only NEC / NECext signals convert - the OG hardware speaks NEC timing only.
Everything else (Samsung32, RC5/6, SIRC, Kaseikyo, Pioneer, RCA, NEC42, raw...)
is skipped and reported.
"""
import argparse, os, re, sys

FWIR_HEADER = "# fwili IR database v 1\n"

# Keys that legitimately appear before the first signal block.
FILE_HEADER_KEYS = {"Filetype", "Version"}


# Whole-name fallbacks for buttons named entirely in symbols (DTMF/transport
# keys are common in real remotes: 129x '*', 96x '#', 62x '>>' in Flipper-IRDB)
SYMBOL_NAMES = {
    "*": "star", "#": "hash", "<<": "rew", ">>": "ffwd",
    "<": "left", ">": "right", "?": "help", "/": "slash", "°": "deg",
}


def sanitize(name, maxlen):
    # On-device name rules are undocumented for FW1. Baseline: FW2's picker
    # accepts letters, digits, '-' and '_'; FW1's own keypad also offers '+',
    # and dropping it merges real Vol+/Vol- style pairs (623 collisions across
    # Flipper-IRDB), so '+' is kept. '#' stays banned - the .fwir header line
    # itself starts with '#'.
    name = name.strip()
    name = re.sub(r"[\s/]+", "_", name)  # 'Play/Pause' reads best as Play_Pause
    name = re.sub(r"[^A-Za-z0-9_+-]", "", name)
    name = re.sub(r"_{2,}", "_", name)
    return name[:maxlen] if maxlen else name


def printable(s, cap=32):
    # skip-report strings come straight from the input file; don't let a
    # crafted file put control bytes (ANSI escapes) on the operator's terminal
    return re.sub(r"[^\x20-\x7e]", "", s)[:cap]


def parse_ir(path):
    """Yield a dict per signal block in a Flipper .ir file.

    Tolerates both field orders inside a '#'-separated block (canonical
    Flipper writes 'name:' first; some converted files put it last).  A block
    with fields but no 'name:' yields {"_nameless_block": True} so it can be
    reported instead of silently vanishing - or worse, bleeding its fields
    into a neighbouring signal.
    """
    fields, named = {}, False

    def flush():
        nonlocal fields, named
        out = None
        if named:
            out = fields
        elif fields and not (fields.keys() <= FILE_HEADER_KEYS):
            out = {"_nameless_block": True}
        fields, named = {}, False
        return out

    # utf-8-sig: real Flipper-IRDB files occasionally carry a UTF-8 BOM,
    # which would otherwise glue itself onto the first key ("﻿Filetype")
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if line == "#":  # bare '#' is the canonical block separator
                out = flush()
                if out:
                    yield out
                continue
            if line.startswith("#"):  # '# text' is a comment - stay in block
                continue
            if ":" not in line:
                continue
            key, _, val = line.partition(":")
            key, val = key.strip(), val.strip()
            if key == "name":
                if named:  # consecutive signals with no '#' between them
                    yield fields
                    fields = {}
                fields["name"] = val
                named = True
            else:
                fields[key] = val
    out = flush()
    if out:
        yield out


def hexbytes(field):
    return [int(x, 16) for x in field.split()]


def to_fwir_code(sig):
    """Return (signed_int, None) on success or (None, reason) if unconvertible."""
    if sig.get("type") != "parsed":
        return None, sig.get("type", "no-type")
    proto = sig.get("protocol", "")
    if proto not in ("NEC", "NECext"):
        return None, proto or "no-protocol"
    try:
        addr = hexbytes(sig["address"])
        cmd = hexbytes(sig["command"])
    except (KeyError, ValueError):
        return None, "malformed"
    # Flipper writes each field as 4 hex bytes; accept fewer, but every byte
    # must be a byte - int(x, 16) happily returns 511 for "1FF" and -5 for
    # "-5", either of which would silently corrupt the packed code.
    if not addr or not cmd or any(not 0 <= b <= 0xFF for b in addr + cmd):
        return None, "malformed"
    a0, c0 = addr[0], cmd[0]
    if proto == "NECext":
        # byte1 is the real address high byte - it cannot be inferred
        if len(addr) < 2 or any(addr[2:]) or any(cmd[2:]):
            return None, "malformed"
        a1 = addr[1]
        c1 = cmd[1] if len(cmd) > 1 else (~c0 & 0xFF)  # byte3 is usually ~command
    else:  # plain 8-bit NEC: one meaningful byte per field, rest must be zero
        if any(addr[1:]) or any(cmd[1:]):
            return None, "malformed"
        a1 = ~a0 & 0xFF
        c1 = ~c0 & 0xFF
    u = a0 | (a1 << 8) | (c0 << 16) | (c1 << 24)
    return (u - (1 << 32) if u >= (1 << 31) else u), None


def convert(path, maxlen=24):
    entries, skipped = [], {}  # skipped: reason -> [signal names]
    seen = set()
    for sig in parse_ir(path):
        if "_nameless_block" in sig:
            skipped.setdefault("nameless-block", []).append("?")
            continue
        code, reason = to_fwir_code(sig)
        if code is None:
            skipped.setdefault(reason, []).append(sig.get("name", "?"))
            continue
        name = (sanitize(sig["name"], maxlen)
                or SYMBOL_NAMES.get(sig["name"].strip()) or "code")
        base, n = name, 1
        while name in seen:  # de-dup names within one database
            n += 1
            suffix = f"_{n}"
            room = (maxlen - len(suffix)) if maxlen else len(base)
            # suffix must fit under maxlen; collapse '__' so the result is a
            # fixed point of sanitize() (keeps ir->fwir->ir round-trips stable)
            name = re.sub(r"_{2,}", "_", base[: max(0, room)] + suffix)
        seen.add(name)
        entries.append((name, code))
    return entries, skipped


def render(entries):
    out = [FWIR_HEADER]
    out += [f"{name}={code}\n" for name, code in entries]
    return "".join(out)


def atomic_write(out, text):
    """Write via temp + rename: an ENOSPC surprise mid-write must never leave
    a truncated file where a good one stood. Returns success."""
    tmp = f"{out}.tmp{os.getpid()}"
    try:
        with open(tmp, "w", newline="", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, out)
        return True
    except OSError as e:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        print(f"error: cannot write {out!r}: {e.strerror or e}", file=sys.stderr)
        return False


def report_skips(skipped, file=sys.stdout):
    for reason, names in sorted(skipped.items(), key=lambda kv: -len(kv[1])):
        shown = ", ".join(printable(n) for n in names[:6])
        if len(names) > 6:
            shown += ", ..."
        print(f"    skipped {len(names):4d}  ({printable(reason)}): {shown}", file=file)


def name_cap(text):
    v = int(text)
    if v != 0 and v < 4:
        raise argparse.ArgumentTypeError("must be 0 (unlimited) or >= 4")
    return v


def main(argv=None):
    ap = argparse.ArgumentParser(description="Convert Flipper .ir to FreeWili .fwir")
    ap.add_argument("input", help="input .ir file")
    ap.add_argument("-o", "--output", help="output .fwir (default: alongside input)")
    ap.add_argument("--maxlen", type=name_cap, default=24,
                    help="max name length, 0 = unlimited (default 24)")
    ap.add_argument("-f", "--force", action="store_true",
                    help="overwrite an existing output file")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args(argv)

    out = args.output or os.path.splitext(args.input)[0] + ".fwir"
    same = os.path.abspath(out) == os.path.abspath(args.input) or (
        os.path.exists(out) and os.path.exists(args.input)
        and os.path.samefile(out, args.input)
    )
    if same:  # never truncate the input, --force included
        print(f"error: output {out!r} is the input file; pick another with -o",
              file=sys.stderr)
        return 1
    if os.path.isdir(out):
        print(f"error: {out!r} is a directory", file=sys.stderr)
        return 1
    if os.path.exists(out) and not args.force:
        print(f"error: {out!r} exists; use --force to overwrite", file=sys.stderr)
        return 1

    try:
        entries, skipped = convert(args.input, args.maxlen)
    except OSError as e:
        print(f"error: cannot read {args.input!r}: {e.strerror or e}", file=sys.stderr)
        return 1

    nskip = sum(len(v) for v in skipped.values())
    if not entries:
        print(f"error: no convertible NEC/NECext signals in {args.input!r} "
              f"({nskip} skipped); nothing written", file=sys.stderr)
        report_skips(skipped, file=sys.stderr)
        return 1

    if not atomic_write(out, render(entries)):
        return 1

    if not args.quiet:
        print(f"{out}: {len(entries)} codes converted, {nskip} skipped")
        report_skips(skipped)
    return 0


if __name__ == "__main__":
    sys.exit(main())
