"""S-01 W5 self-check runner (outside the judgment path, design section 4.6).

One command runs the three acceptance checks and the verifier-side
five-item self-check list, then writes a dated, versioned report into
selfcheck/reports/:

  (a) derived public keys match the JWK set fully
  (b) positive examples + the N-15 signature regeneration are byte-identical
  (c) the four old-base signatures all FAIL on the corrected base and all
      PASS on the old base (anti-mixing fixtures)

  1. python -m pytest -q
  2. ruff check src tests
  3. ruff format --check src tests
  4. ast.parse sweep over every tracked .py file
  5. CLI run-vectors against tests/fixtures/vectors.json

plus the section 4.6 boundary check (no code under src/ imports selfcheck).

This file may import agent_auth_verifier; nothing under src/ may import it.
It only reads repository data and writes its report; it changes no vector,
baseline or verifier file.

Usage (from the repository root):  python selfcheck/run_selfcheck.py
"""

from __future__ import annotations

import argparse
import ast
import base64
import datetime as dt
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256

from agent_auth_verifier.components import build_signature_base
from agent_auth_verifier.crypto import (
    b64u_encode,
    jwk_to_public_key,
    verify_signature,
)
from agent_auth_verifier.httpmsg import parse_message
from agent_auth_verifier.sf import SFBytes, SFInnerList, SFItem, parse_dictionary
from agent_auth_verifier.vectors import VectorSet

VECTORS = ROOT / "tests" / "fixtures" / "vectors.json"
ANTI_MIXING_FILE = ROOT / "selfcheck" / "fixtures" / "anti-mixing" / "old-base-signatures.json"
ANTI_MIXING_SOURCE_REPO = "HUIIIM/wimse-http-signature-test-vectors"
ANTI_MIXING_SOURCE_PATH = "selfcheck/anti-mixing/old-base-signatures.json"
ANTI_MIXING_SOURCE_MD5 = "a9ff2f3a31c7e2cf64fe44328cab0646"
REPORTS = ROOT / "selfcheck" / "reports"
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
LABEL_PREFIX = "s01-validation-vectors:"

# Readings recorded by earlier waves (selfcheck.md, W3 delta). A live
# reading that differs is flagged DIVERGENT in the report, never overwritten.
EXPECTED_SUITE = {"matched": 22, "mismatched": 1, "not_judgeable": 6}
EXPECTED_N09 = "attribution-only"
EXPECTED_N09B = "MATCH"


@dataclass
class Check:
    key: str
    name: str
    command: str
    status: str = "NOT RUN"  # PASS / FAIL / BLOCKED
    result: str = ""
    details: list[str] = field(default_factory=list)


def _env() -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(SRC), env.get("PYTHONPATH", "")]))
    return env


def _run(cmd: list[str]) -> tuple[int, str]:
    proc = subprocess.run(cmd, cwd=ROOT, env=_env(), capture_output=True, text=True, check=False)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


# -- (a) key derivation ----------------------------------------------------
def _derive_public_jwk(name: str, alg: str) -> tuple[dict, str]:
    seed = hashlib.sha256((LABEL_PREFIX + name).encode("ascii")).digest()
    if alg == "Ed25519":
        pub = Ed25519PrivateKey.from_private_bytes(seed).public_key()
        raw = pub.public_bytes_raw()
        return {"kty": "OKP", "crv": "Ed25519", "x": b64u_encode(raw)}, b64u_encode(seed)
    if alg == "ES256":
        scalar = int.from_bytes(seed, "big") % (P256_N - 1) + 1
        priv = ec.derive_private_key(scalar, ec.SECP256R1())
        nums = priv.public_key().public_numbers()
        jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": b64u_encode(nums.x.to_bytes(32, "big")),
            "y": b64u_encode(nums.y.to_bytes(32, "big")),
        }
        return jwk, b64u_encode(scalar.to_bytes(32, "big"))
    raise ValueError(alg)


def check_a(data: dict) -> Check:
    c = Check("a", "Derived public keys match the JWK set", "derive per materials.key_derivation")
    materials = data["materials"]
    ok = True
    compared = 0
    jwk_set: list[tuple[str, dict]] = []
    for key in materials["keys"]:
        jwk_set.append((f"materials.keys[{key['name']}].public_jwk", key["public_jwk"]))
    jwk_set.append(
        ("trusted_config.issuer_anchor_jwk", materials["trusted_config"]["issuer_anchor_jwk"])
    )
    for wid, wit in materials["wits"].items():
        jwk_set.append((f"wits[{wid}].claims.cnf.jwk", wit["claims"]["cnf"]["jwk"]))
    by_kid = {k["kid"]: k for k in materials["keys"]}
    for key in materials["keys"]:
        derived, derived_d = _derive_public_jwk(key["name"], key["alg"])
        published = key["public_jwk"]
        diffs = [m for m in derived if published.get(m) != derived[m]]
        extra = set(published) - set(derived) - {"alg", "kid"}
        if published.get("alg") != key["alg"] or published.get("kid") != key["kid"]:
            diffs.append("alg/kid")
        if key["private_d"] != derived_d:
            diffs.append("private_d")
        if extra:
            diffs.append(f"unexpected members {sorted(extra)}")
        compared += 1
        ok &= not diffs
        c.details.append(
            f"{key['name']} ({key['alg']}, kid {key['kid']}): "
            + (
                "all members equal (" + ", ".join(sorted(derived)) + ", private_d)"
                if not diffs
                else "MISMATCH in " + ", ".join(diffs)
            )
        )
    for where, jwk in jwk_set[len(materials["keys"]) :]:
        src = by_kid.get(jwk.get("kid"))
        same = src is not None and src["public_jwk"] == jwk
        ok &= same
        compared += 1
        c.details.append(
            f"{where} (kid {jwk.get('kid')}): "
            + ("identical to the derived key's JWK" if same else "MISMATCH")
        )
    c.status = "PASS" if ok else "FAIL"
    c.result = f"{compared}/{compared} JWKs equal" if ok else "mismatch, see details"
    return c


# -- (b) regeneration byte-identity ---------------------------------------
def _sign_det(alg: str, name: str, data: bytes) -> bytes:
    seed = hashlib.sha256((LABEL_PREFIX + name).encode("ascii")).digest()
    if alg == "Ed25519":
        return Ed25519PrivateKey.from_private_bytes(seed).sign(data)
    scalar = int.from_bytes(seed, "big") % (P256_N - 1) + 1
    priv = ec.derive_private_key(scalar, ec.SECP256R1())
    der = priv.sign(data, ec.ECDSA(SHA256(), deterministic_signing=True))  # RFC 6979
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _signer_for(vs: VectorSet, data: dict, member: SFInnerList, raw: str, vid: str) -> dict:
    keys = {k["kid"]: k for k in data["materials"]["keys"]}
    keyid = member.params.get("keyid")
    if keyid is not None:
        return keys[keyid.value]
    if vid == "N-15":  # literal ES256 by svcC (mutation note); WIT-A binds svcA
        return next(k for k in data["materials"]["keys"] if k["name"] == "svcC")
    token = parse_message(raw).header("workload-identity-token") or ""
    wit = next(w for w in data["materials"]["wits"].values() if w["jws"] == token)
    return keys[wit["claims"]["cnf"]["jwk"]["kid"]]


def check_b(vs: VectorSet, data: dict) -> Check:
    c = Check(
        "b",
        "Positive examples + N-15 regeneration byte-identical",
        "rebuild base, re-sign (Ed25519; ES256 RFC 6979), compare bytes",
    )
    ids = [v["id"] for v in data["vectors"] if v["kind"] == "positive"] + ["N-15"]
    total = good = 0
    for vid in ids:
        vec = vs.vectors[vid]
        raw = vs.base_message_raw(vid)
        message = parse_message(raw)
        paired = None
        if vec.get("paired_request_ref"):
            paired = parse_message(vs.base_message_raw(vec["paired_request_ref"]))
        sig_input = parse_dictionary(message.header("signature-input") or "")
        sigs = parse_dictionary(message.header("signature") or "")
        provided = vec.get("signature_base_provided") or {}
        for label, member in sig_input.items():
            assert isinstance(member, SFInnerList)
            total += 1
            base = build_signature_base(message, member, paired)
            sig_item = sigs[label]
            assert isinstance(sig_item, SFItem) and isinstance(sig_item.value, SFBytes)
            literal = sig_item.value.value
            key = _signer_for(vs, data, member, raw, vid)
            regen = _sign_det(key["alg"], key["name"], base.encode("ascii"))
            base_eq = provided.get(label) == base if label in provided else None
            sig_eq = regen == literal
            verifies = verify_signature(
                key["alg"], jwk_to_public_key(key["public_jwk"]), literal, base.encode("ascii")
            )
            row_ok = sig_eq and base_eq is not False
            good += row_ok
            c.details.append(
                f"{vid} {label} ({key['alg']}, {key['kid']}): base vs provided "
                f"{'identical' if base_eq else ('n/a' if base_eq is None else 'DIFFERENT')}; "
                f"regenerated signature {'byte-identical' if sig_eq else 'DIFFERENT'} "
                f"({len(literal)} bytes, sha256 {hashlib.sha256(literal).hexdigest()[:16]}); "
                f"literal verifies over rebuilt base: {verifies}"
            )
    c.status = "PASS" if good == total else "FAIL"
    c.result = f"{good}/{total} signatures byte-identical (bases identical where provided)"
    return c


def check_b_regen(vs: VectorSet, data: dict) -> Check:
    c = Check(
        "b+",
        "Regen negatives reproducible (supplement)",
        "construct each negative-message vector twice",
    )
    ids = [v["id"] for v in data["vectors"] if v["kind"] == "negative-message"]
    same = 0
    for vid in ids:
        a = vs.construct(vid)
        b = VectorSet.load(VECTORS).construct(vid)
        eq = (a.message_raw, a.paired_raw) == (b.message_raw, b.paired_raw)
        same += eq
        src = vs.vectors[vid].get("signature_source")
        c.details.append(f"{vid} ({src}): {'byte-identical' if eq else 'DIFFERENT'}")
    c.status = "PASS" if same == len(ids) else "FAIL"
    c.result = f"{same}/{len(ids)} negative-message vectors byte-identical across two constructions"
    return c


# -- (c) anti-mixing -------------------------------------------------------
def _verdict(ok: bool) -> str:
    return "PASS" if ok else "FAIL"


def check_c(vs: VectorSet, data: dict) -> Check:
    rel = ANTI_MIXING_FILE.relative_to(ROOT)
    c = Check(
        "c",
        "Old-base signatures: FAIL on corrected base, PASS on old base",
        f"verify each entry of {rel} against old_base and corrected_base",
    )
    if not ANTI_MIXING_FILE.is_file():
        c.status = "BLOCKED"
        c.result = f"{rel} not present; not run"
        return c
    raw = ANTI_MIXING_FILE.read_bytes()
    md5 = hashlib.md5(raw).hexdigest()
    md5_ok = md5 == ANTI_MIXING_SOURCE_MD5
    c.details.append(
        f"Vendored copy MD5 `{md5}` vs source MD5 `{ANTI_MIXING_SOURCE_MD5}` "
        f"({ANTI_MIXING_SOURCE_REPO}:{ANTI_MIXING_SOURCE_PATH}): "
        + ("**identical**" if md5_ok else "**DIFFERENT**")
    )
    fx = json.loads(raw)
    keys = {k["name"]: k for k in data["materials"]["keys"]}
    entries = fx.get("entries", [])
    good = 0
    pending = 0
    for e in entries:
        key = keys[e["signer"]]
        pub = jwk_to_public_key(key["public_jwk"])
        sig = base64.b64decode(e["old_signature"])
        on_old = _verdict(verify_signature(e["alg"], pub, sig, e["old_base"].encode("utf-8")))
        on_new = _verdict(verify_signature(e["alg"], pub, sig, e["corrected_base"].encode("utf-8")))
        exp_old, exp_new = e.get("old_base_verdict"), e.get("corrected_base_verdict")
        # The W5 acceptance requirement: PASS on the old base, FAIL on the corrected base.
        req_ok = on_old == "PASS" and on_new == "FAIL" and key["alg"] == e["alg"]
        # The fixture's own expectations; null means not asserted by the fixture.
        fx_old_ok = exp_old is None or exp_old == on_old
        fx_new_ok = exp_new is None or exp_new == on_new
        pending += exp_new is None
        ok = req_ok and fx_old_ok and fx_new_ok
        good += ok
        provided = (vs.vectors[e["vector"]].get("signature_base_provided") or {}).get(e["label"])
        c.details.append(
            f"{e['vector']} {e['label']} ({e['alg']}, signer {e['signer']}): "
            f"old base {on_old} (fixture expects {exp_old}); "
            f"corrected base {on_new} (fixture expects "
            + ("null, pending U4" if exp_new is None else str(exp_new))
            + "); corrected_base == suite signature_base_provided: "
            + str(provided == e["corrected_base"])
            + (" -> as required" if ok else " -> VIOLATION")
        )
    n = len(entries)
    c.status = "PASS" if good == n == 4 and md5_ok else "FAIL"
    c.result = f"{good}/{n} entries PASS on old base and FAIL on corrected base; vendored MD5 " + (
        "identical to source" if md5_ok else "DIFFERS from source"
    )
    if n != 4:
        c.result += f" (expected 4 entries, found {n})"
    if pending:
        c.result += (
            f"; fixture corrected_base_verdict null (pending U4) for {pending}/{n}, "
            "so the corrected-base leg is judged against the W5 requirement only"
        )
    return c


# -- five-item self-check list ---------------------------------------------
def _tracked_py() -> list[Path]:
    _, out = _run(["git", "ls-files", "*.py"])
    return [ROOT / p for p in out.splitlines() if p]


def five_items() -> tuple[list[Check], dict]:
    checks: list[Check] = []
    code, out = _run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"])
    last = out.splitlines()[-1] if out else ""
    checks.append(
        Check(
            "1",
            "Unit + suite tests",
            "python -m pytest -q",
            "PASS" if code == 0 else "FAIL",
            last.strip("= "),
        )
    )
    code, out = _run(["ruff", "check", "--no-cache", "src", "tests"])
    checks.append(
        Check(
            "2",
            "Lint",
            "ruff check src tests",
            "PASS" if code == 0 else "FAIL",
            out.splitlines()[-1] if out else "",
        )
    )
    code, out = _run(["ruff", "format", "--no-cache", "--check", "src", "tests"])
    checks.append(
        Check(
            "3",
            "Format",
            "ruff format --check src tests",
            "PASS" if code == 0 else "FAIL",
            out.splitlines()[-1] if out else "",
        )
    )
    files = _tracked_py()
    bad = []
    for p in files:
        try:
            ast.parse(p.read_text(), filename=str(p))
        except SyntaxError as exc:
            bad.append(f"{p.relative_to(ROOT)}: {exc}")
    checks.append(
        Check(
            "4",
            "Syntax sweep",
            "ast.parse over every tracked .py file",
            "PASS" if not bad else "FAIL",
            f"{len(files)} files, {len(files) - len(bad)} parse",
            bad,
        )
    )
    code, out = _run(
        [
            sys.executable,
            "-m",
            "agent_auth_verifier.cli",
            "run-vectors",
            "--set",
            "tests/fixtures/vectors.json",
        ]
    )
    summary = next((ln for ln in out.splitlines() if ln.startswith("summary:")), "")
    m = re.search(r"(\d+) matched, (\d+) mismatched, (\d+) not judgeable", summary)
    counts = (
        dict(zip(["matched", "mismatched", "not_judgeable"], map(int, m.groups()))) if m else {}
    )
    rows = {}
    current = None
    for ln in out.splitlines():
        head = re.match(r"^(\S+)\s+(MATCH|MISMATCH|NOT_JUDGEABLE)", ln)
        if head:
            current = head.group(1)
            rows[current] = {"status": head.group(2), "legs": []}
        elif current and ln.strip().startswith("t="):
            rows[current]["legs"].append(ln.strip())
    suite = {"exit": code, "summary": summary, "counts": counts, "rows": rows}
    status = "PASS" if counts == EXPECTED_SUITE and code == 1 else "FAIL"
    checks.append(
        Check(
            "5",
            "Suite run (CLI)",
            "python -m agent_auth_verifier.cli run-vectors --set tests/fixtures/vectors.json",
            status,
            f"{summary.removeprefix('summary: ')}; exit {code}",
        )
    )
    return checks, suite


def classify_n09(rows: dict) -> tuple[str, str]:
    row = rows.get("N-09")
    if not row:
        return "missing", "N-09 not in run output"
    if row["status"] == "MATCH":
        return "none (now MATCH)", row["legs"][0] if row["legs"] else ""
    leg = row["legs"][0] if row["legs"] else ""
    m = re.search(r"expected (\w+)/(\w+)/(\w+), got (\w+)/(\w+)/(\w+)", leg)
    if m and m.group(1) == m.group(4) and m.group(2) != m.group(5):
        return "attribution-only", leg
    return "verdict divergence", leg


def boundary_check() -> Check:
    c = Check(
        "4.6",
        "Selfcheck outside the judgment path",
        "AST scan of src/**/*.py for imports of selfcheck",
    )
    offenders = []
    for p in sorted(SRC.rglob("*.py")):
        tree = ast.parse(p.read_text())
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""] + [a.name for a in node.names]
            elif isinstance(node, ast.Call) and getattr(node.func, "id", "") == "__import__":
                names = [getattr(a, "value", "") for a in node.args if isinstance(a, ast.Constant)]
            if any(str(n).split(".")[0] in {"selfcheck", "run_selfcheck"} for n in names):
                offenders.append(f"{p.relative_to(ROOT)}:{node.lineno}")
    c.status = "PASS" if not offenders else "FAIL"
    c.result = "no src/ module imports or references selfcheck" if not offenders else "violation"
    c.details = offenders
    return c


# -- report ----------------------------------------------------------------
def _git(*args: str) -> str:
    return _run(["git", *args])[1]


def _next_report_path(date: str) -> tuple[Path, int]:
    REPORTS.mkdir(parents=True, exist_ok=True)
    n = 1
    while (REPORTS / f"selfcheck-{date}-r{n}.md").exists():
        n += 1
    return REPORTS / f"selfcheck-{date}-r{n}.md", n


def _table(checks: list[Check]) -> list[str]:
    out = ["| Check | Command | Status | Result |", "| --- | --- | --- | --- |"]
    for c in checks:
        out.append(f"| ({c.key}) {c.name} | `{c.command}` | **{c.status}** | {c.result} |")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--date", help="report date (default: today, UTC)")
    args = ap.parse_args(argv)
    date = args.date or dt.datetime.now(dt.UTC).date().isoformat()

    data = json.loads(VECTORS.read_text())
    vs = VectorSet.load(VECTORS)
    acceptance = [check_a(data), check_b(vs, data), check_b_regen(vs, data), check_c(vs, data)]
    items, suite = five_items()
    boundary = boundary_check()
    n09_class, n09_leg = classify_n09(suite["rows"])
    n09b = suite["rows"].get("N-09b", {}).get("status", "missing")

    readings = [
        ("matched count", str(EXPECTED_SUITE["matched"]), str(suite["counts"].get("matched"))),
        ("N-09 divergence classification", EXPECTED_N09, n09_class),
        ("N-09b", EXPECTED_N09B, n09b),
    ]
    divergent = [r for r in readings if r[1] != r[2]]

    path, rev = _next_report_path(date)
    head = _git("rev-parse", "HEAD")
    dirty = bool(_git("status", "--porcelain", "--", "src", "tests", "vectors"))
    import cryptography

    _, ruff_v = _run(["ruff", "--version"])
    _, pytest_v = _run([sys.executable, "-m", "pytest", "--version"])
    lines = [
        f"# Self-check report {date} r{rev}",
        "",
        (
            f"Date: {date}. Revision r{rev} of this date. Produced by "
            "`python selfcheck/run_selfcheck.py`; every reading below was taken live by that run."
        ),
        "",
        f"Code under test: commit `{head}`"
        + (" (working tree has uncommitted changes under src/tests/vectors)" if dirty else "")
        + f". Vector set: `{VECTORS.relative_to(ROOT)}` (MD5 "
        f"`{hashlib.md5(VECTORS.read_bytes()).hexdigest()}`).",
        "",
        (
            f"Toolchain: Python {platform.python_version()}, "
            f"cryptography {cryptography.__version__}, "
            f"{pytest_v.splitlines()[0] if pytest_v else 'pytest ?'}, {ruff_v}."
        ),
        "",
        "## Acceptance checks (a)-(c)",
        "",
        *_table(acceptance),
        "",
    ]
    for c in acceptance:
        lines += [f"### ({c.key}) {c.name}", "", *[f"- {d}" for d in c.details], ""]
    lines += [
        "## Five-item self-check list",
        "",
        *_table(items),
        "",
        "## Suite readings vs recorded expectations",
        "",
        "| Reading | Expected (recorded) | Live | Status |",
        "| --- | --- | --- | --- |",
        *[
            f"| {n} | {e} | {lv} | {'match' if e == lv else '**DIVERGENT**'} |"
            for n, e, lv in readings
        ],
        "",
        f"N-09 leg: `{n09_leg}`",
        "",
        "N-09b legs: "
        + "; ".join(f"`{x}`" for x in suite["rows"].get("N-09b", {}).get("legs", [])),
        "",
        "Divergences from recorded expectations: "
        + (
            "none."
            if not divergent
            else "; ".join(f"{n}: expected {e}, live {lv}" for n, e, lv in divergent)
        ),
        "",
        "## Boundary (design section 4.6)",
        "",
        *_table([boundary]),
        *[f"- {d}" for d in boundary.details],
        "",
    ]
    all_checks = acceptance + items + [boundary]
    failed = [c for c in all_checks if c.status == "FAIL"]
    blocked = [c for c in all_checks if c.status == "BLOCKED"]
    overall = "FAIL" if failed or divergent else ("INCOMPLETE" if blocked else "PASS")
    lines += [
        "## Overall",
        "",
        f"**{overall}** -- {sum(c.status == 'PASS' for c in all_checks)} pass, "
        f"{len(failed)} fail, {len(blocked)} blocked"
        + (f" ({', '.join('(' + c.key + ')' for c in blocked)})" if blocked else "")
        + f"; {len(divergent)} divergent reading(s).",
        "",
    ]
    path.write_text("\n".join(lines))
    print(f"report: {path.relative_to(ROOT)}")
    print(f"overall: {overall}")
    for c in all_checks:
        print(f"  ({c.key}) {c.status}: {c.result}")
    return {"PASS": 0, "INCOMPLETE": 2}.get(overall, 1)


if __name__ == "__main__":
    raise SystemExit(main())
