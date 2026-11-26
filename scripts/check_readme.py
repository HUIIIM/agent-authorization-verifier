"""Run every command printed in README.md, literally, in a clean clone (W7).

Every fenced ``bash`` or ``python`` block in README.md is a command the
README promises works. Each one must be preceded by an annotation comment
(invisible on GitHub) stating what the text claims::

    <!-- readme-check: exit=0 expect="verdict: ACCEPT" -->

``exit`` is the required exit status; each ``expect`` (repeatable) is a
string that must appear in the block's combined stdout/stderr. A bash or
python block without an annotation fails the check, so no printed command
can go untested. Other fences (json, text) are not commands and are not
run.

The clean environment is a fresh ``git clone`` of this repository's HEAD
(plus the working tree's uncommitted changes to tracked files, so the
check can run before a commit), with no ``.venv``, no ``build/`` and no
inherited virtualenv on PATH. The blocks run in README order in one bash
session from the clone's root, so ``. .venv/bin/activate`` carries over
to later blocks, exactly as for a reader typing them. Python blocks are
written to a file outside the clone and run with ``python FILE`` from the
clone's root.

Usage (repository root):  python scripts/check_readme.py [--keep | --list]
Exit 0 when every block meets its annotation, 1 otherwise.
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FENCE = re.compile(r"^```([A-Za-z0-9_-]*)\s*$")
ANNOT = re.compile(r"^<!--\s*readme-check:(.*?)-->\s*$")
RUNNABLE = {"bash": "bash", "sh": "bash", "console": "bash", "shell": "bash", "python": "python"}


def parse_blocks(text: str) -> list[dict]:
    lines = text.splitlines()
    blocks: list[dict] = []
    i = 0
    while i < len(lines):
        m = FENCE.match(lines[i])
        if not m:
            i += 1
            continue
        lang, start = m.group(1).lower(), i
        j = i + 1
        while j < len(lines) and lines[j].rstrip() != "```":
            j += 1
        body = "\n".join(lines[i + 1 : j]) + "\n"
        k = start - 1
        while k >= 0 and not lines[k].strip():
            k -= 1
        annot = ANNOT.match(lines[k]) if k >= 0 else None
        blocks.append({"lang": lang, "line": start + 1, "body": body, "annot": annot})
        i = j + 1
    return blocks


def parse_annotation(raw: str) -> tuple[int, list[str]]:
    want_exit, expects = None, []
    for tok in shlex.split(raw):
        key, _, val = tok.partition("=")
        if key == "exit":
            want_exit = int(val)
        elif key == "expect":
            expects.append(val)
        else:
            raise ValueError(f"unknown annotation key {key!r}")
    if want_exit is None:
        raise ValueError("annotation needs exit=N")
    return want_exit, expects


def clean_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PYTHON", "VIRTUAL_ENV"))}
    venv = os.environ.get("VIRTUAL_ENV")
    exe_dir = str(Path(sys.executable).parent)
    keep = []
    for p in env.get("PATH", "").split(os.pathsep):
        in_venv = (venv and p.startswith(venv)) or (
            p == exe_dir and Path(sys.prefix) != Path(sys.base_prefix)
        )
        if p and not in_venv:
            keep.append(p)
    env["PATH"] = os.pathsep.join(keep)
    env["AAV_README_CHECK_NESTED"] = "1"  # selftest.sh skips this check when nested
    return env


def make_clone(dest: Path) -> str:
    subprocess.run(["git", "clone", "-q", "--no-local", str(ROOT), str(dest)], check=True)
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()
    changed = subprocess.run(
        ["git", "diff", "--name-only", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.split()
    for rel in changed:
        src, dst = ROOT / rel, dest / rel
        if src.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        elif dst.exists():
            dst.unlink()
    note = f" + {len(changed)} uncommitted tracked change(s)" if changed else ""
    return head[:12] + note


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--keep", action="store_true", help="keep the clean clone and logs")
    ap.add_argument("--list", action="store_true", help="list the annotated blocks; run nothing")
    args = ap.parse_args(argv)

    blocks = parse_blocks((ROOT / "README.md").read_text(encoding="utf-8"))
    runnable = [b for b in blocks if b["lang"] in RUNNABLE]
    errors = []
    for b in runnable:
        if b["annot"] is None:
            errors.append(
                f"README.md:{b['line']}: {b['lang']} block has no readme-check annotation"
            )
            continue
        try:
            b["exit"], b["expect"] = parse_annotation(b["annot"].group(1))
        except ValueError as exc:
            errors.append(f"README.md:{b['line']}: {exc}")
    if errors:
        print("\n".join(errors))
        return 1
    if args.list:
        for b in runnable:
            first = b["body"].strip().splitlines()[0]
            want = "; ".join(repr(e) for e in b["expect"]) or "(exit status only)"
            print(
                f"README.md:{b['line']} [{b['lang']}] exit={b['exit']} expect {want}: {first[:80]}"
            )
        print(f"{len(runnable)} blocks annotated, 0 unannotated")
        return 0

    work = Path(tempfile.mkdtemp(prefix="aav-readme-check-"))
    clone, logs = work / "clone", work / "logs"
    logs.mkdir()
    print(f"clean clone of {make_clone(clone)} at {clone}")
    driver = ["cd " + shlex.quote(str(clone))]
    for n, b in enumerate(runnable, 1):
        out = logs / f"{n:02d}.out"
        if b["lang"] == "python":
            script = logs / f"{n:02d}.py"
            script.write_text(b["body"], encoding="utf-8")
            run = f"python {shlex.quote(str(script))}"
        else:
            script = logs / f"{n:02d}.sh"
            script.write_text(b["body"], encoding="utf-8")
            run = f"source {shlex.quote(str(script))}"
        driver.append(f"{{ {run} ; }} >{shlex.quote(str(out))} 2>&1; echo $? >{out}.rc")
    proc = subprocess.run(["bash", "-c", "\n".join(driver)], env=clean_env(), check=False)
    if proc.returncode != 0:
        print(f"driver exited {proc.returncode}")

    failed = 0
    for n, b in enumerate(runnable, 1):
        out = logs / f"{n:02d}.out"
        text = out.read_text(encoding="utf-8", errors="replace") if out.exists() else ""
        rc_file = Path(f"{out}.rc")
        rc = int(rc_file.read_text()) if rc_file.exists() else None
        missing = [e for e in b["expect"] if e not in text]
        ok = rc == b["exit"] and not missing
        failed += not ok
        first = b["body"].strip().splitlines()[0]
        print(
            f"{'ok  ' if ok else 'FAIL'} README.md:{b['line']} [{b['lang']}] exit {rc} "
            f"(want {b['exit']}); expect {len(b['expect']) - len(missing)}/{len(b['expect'])}: "
            f"{first[:90]}"
        )
        if not ok:
            for e in missing:
                print(f"     missing in output: {e!r}")
            print("     --- output tail ---")
            print("\n".join("     " + ln for ln in text.splitlines()[-25:]))
    print(f"README check: {len(runnable) - failed}/{len(runnable)} blocks as stated")
    if args.keep or failed:
        print(f"clone and logs kept at {work}")
    else:
        shutil.rmtree(work, ignore_errors=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
