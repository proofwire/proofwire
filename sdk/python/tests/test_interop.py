"""Interoperability with the JavaScript implementation, run for real.

These drive the repository's own CLI and core with Node, so they are skipped
when this package is tested outside the repository or without Node.
"""

import json
import os
import random
import shutil
import subprocess
from pathlib import Path

import pytest

from deedwrit import ProofLog, Recorder, canonical_bytes, cosign, generate_identity, verify_bundle

REPO = Path(__file__).resolve().parents[3]
PW = REPO / "packages" / "cli" / "src" / "bin.js"
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(
    not NODE or not PW.exists() or not (REPO / "node_modules").exists(),
    reason="needs Node and the deedwrit repository with its workspace installed",
)


def node(script: str) -> str:
    """Run an ES module in the repository, so @deedwrit/core resolves."""
    r = subprocess.run([NODE, "--input-type=module", "-e", script], cwd=REPO, capture_output=True, text=True, encoding="utf-8")
    assert r.returncode == 0, r.stderr
    return r.stdout


def pw(*args: str, home: Path) -> subprocess.CompletedProcess:
    env = {**os.environ, "NO_COLOR": "1", "HOME": str(home), "USERPROFILE": str(home)}
    return subprocess.run([NODE, str(PW), *args], cwd=home, capture_output=True, text=True, encoding="utf-8", env=env)


def test_canonical_bytes_match_javascript_on_a_corpus_of_awkward_values(tmp_path):
    rng = random.Random(1234)
    floats = [rng.uniform(-1e6, 1e6) for _ in range(200)]
    floats += [rng.uniform(0, 1) * 10 ** rng.randint(-30, 30) for _ in range(200)]
    floats += [0.1, 0.2, 0.30000000000000004, 1e21, 1e-7, 9.999999999999999e20, 2**53 - 1, 2**53 + 2, 5e-324, 1.7976931348623157e308, -1e-7, 123e-20]
    strings = ["", "plain", "é☃", "\U0001F600 emoji", "\x00\x01\x1f\x7f", "tab\tnew\nline\r", 'quote" back\\slash', "  ", "ﬁ", "😀"]
    objects = [
        {"b": 1, "a": 2, "A": 3, "1": 4, "é": 5, "\U0001F600": 6, "ﬁ": 7, "": 8},
        {"nested": {"z": [1, 2.5, None, True, False, {"k": "v"}], "a": []}, "empty": {}},
    ]
    corpus = floats + strings + objects + [[s, f] for s, f in zip(strings, floats)]
    text = json.dumps(corpus)
    (tmp_path / "corpus.json").write_text(text, encoding="utf-8")
    out = node(
        "import fs from 'node:fs'; import { canonicalBytes } from '@deedwrit/core';"
        f"const c = JSON.parse(fs.readFileSync({json.dumps(str(tmp_path / 'corpus.json'))}, 'utf8'));"
        "process.stdout.write(JSON.stringify(c.map((v) => canonicalBytes(v).toString('hex'))));"
    )
    theirs = json.loads(out)
    ours = [canonical_bytes(v).hex() for v in json.loads(text)]
    mismatches = [(i, json.loads(text)[i]) for i, (a, b) in enumerate(zip(ours, theirs)) if a != b]
    assert not mismatches, mismatches[:5]
    assert len(ours) == len(theirs)


def test_a_log_written_in_python_passes_pw_verify_and_pw_check(tmp_path):
    log = ProofLog.create(tmp_path / ".deedwrit")
    rec = Recorder(log, agent="support-bot", principal="ops@acme.test", namespace="crm")

    @rec.tool("refund", metrics=lambda order, cents: {"amount_usd": cents / 100})
    def refund(order, cents):
        return {"ok": True, "note": "remboursé ✓"}

    for i in range(5):
        refund(f"ord_{i}", 1234 + i)
    cp = log.checkpoint()
    witness, _ = generate_identity()
    log.trust_key(witness.kid, witness.public_key)
    log.add_signature(cp["body"]["size"], next(s for s in cosign(cp, witness)["sigs"] if s["role"] == "witness"))

    verified = pw("verify", "--log", str(log.dir), home=tmp_path)
    assert verified.returncode == 0, verified.stdout + verified.stderr

    (tmp_path / "evidence.json").write_text(json.dumps(log.bundle()), encoding="utf-8")
    checked = pw("check", "evidence.json", "--witnesses", "1", "--witness-key", f"{witness.kid}={witness.public_key}", home=tmp_path)
    assert checked.returncode == 0, checked.stdout + checked.stderr
    assert "Verified" in checked.stdout

    # And the JS reporting tools read it too.
    listed = pw("log", "--log", str(log.dir), "--json", home=tmp_path)
    assert [r["action"]["target"] for r in json.loads(listed.stdout)][:2] == ["crm.refund", "crm.refund"]


def test_a_log_written_by_javascript_verifies_in_python_and_can_be_continued(tmp_path):
    d = tmp_path / "js-log"
    pin = node(
        "import { ProofLog, generateIdentity, cosign } from '@deedwrit/core';"
        f"const log = ProofLog.create({json.dumps(str(d))});"
        "const actor = { agent: 'claude', runtime: 'js', session: 's', principal: 'dana@acme.test' };"
        "const a = (target, params, extra = {}) => log.append({ actor, action: { kind: 'tool_call', target, params, metrics: { amount_usd: 12.75 } }, decision: { outcome: 'allow', policy: 'p', rules: [] }, ...extra });"
        "a('stripe.refund', { order: 'o1', key: 'sk-ant-api03-Xk92mQvT1pLs8fR4nB6yH0jW', note: 'ünïcödé 😀' });"
        "log.append({ actor, action: { kind: 'tool_call', target: 'mail.send', params: {} }, decision: { outcome: 'deny', policy: 'p', rules: ['r'], reason: 'no', declined: { by: 'slack:U1 (dana)', at: new Date().toISOString() } } });"
        "a('db.drop', {}, { phase: 'intent', decision: { outcome: 'allow', policy: 'p', rules: ['no-drop'], enforced: false, wouldBe: 'deny' } });"
        "const cp = log.checkpoint();"
        "const w = generateIdentity().identity; log.trustKey(w.kid, w.publicKey);"
        "log.addSignature(cp.body.size, cosign(cp, w).sigs.find((s) => s.role === 'witness'));"
        "process.stdout.write(JSON.stringify({ kid: w.kid, pub: w.publicKey }));"
    )
    witness = json.loads(pin)

    ro = ProofLog.open(d, read_only=True)
    assert ro.size == 3
    assert ro.audit()["ok"], ro.audit()["issues"]
    bundle = json.loads(json.dumps(ro.bundle()))
    assert verify_bundle(bundle, min_witnesses=1, trusted_witnesses={witness["kid"]: witness["pub"]})["ok"]

    # Python picks up where JavaScript left off, and the CLI accepts the result.
    rw = ProofLog.open(d)
    with Recorder(rw, agent="py", principal="ops@acme.test").call("crm.note", {"text": "from python"}) as c:
        c.result = "done"
    rw.checkpoint()
    both = pw("verify", "--log", str(d), home=tmp_path)
    assert both.returncode == 0, both.stdout + both.stderr

    # A bundle JavaScript exported, tampered with, fails here too.
    bundle["entries"][0]["receipt"]["action"]["target"] = "stripe.charge"
    assert not verify_bundle(bundle)["ok"]


def test_both_sides_agree_on_which_calls_never_finished(tmp_path):
    from deedwrit import entry_hash, find_unfinished

    actor = {"agent": "claude", "runtime": "test", "session": "s", "principal": "p@acme.test"}
    allow = {"outcome": "allow", "policy": "p", "rules": []}
    log = ProofLog.create(tmp_path / ".deedwrit")
    old = "2026-01-01T00:00:00.000Z"
    done = log.append(ts=old, phase="intent", actor=actor, action={"kind": "tool_call", "target": "crm.query", "params": {}}, decision=allow)
    log.append(ts=old, phase="outcome", ref=entry_hash(done), actor=actor, action={"kind": "tool_call", "target": "crm.query", "params": {}}, decision=allow, result={"status": "ok", "payload": None})
    log.append(ts=old, phase="intent", actor=actor, action={"kind": "tool_call", "target": "stripe.refund", "params": {}}, decision=allow)
    cut = log.append(ts=old, phase="intent", actor=actor, action={"kind": "tool_call", "target": "db.migrate", "params": {}}, decision=allow)
    log.append(ts=old, phase="outcome", ref=entry_hash(cut), actor=actor, action={"kind": "tool_call", "target": "db.migrate", "params": {}}, decision=allow, result={"status": "error", "code": "unfinished", "payload": None})

    theirs = json.loads(node(
        "import { ProofLog, findUnfinished } from '@deedwrit/core';"
        f"const log = ProofLog.open({json.dumps(str(tmp_path / '.deedwrit'))}, {{ readOnly: true }});"
        "process.stdout.write(JSON.stringify(findUnfinished(log.entries)));"
    ))
    ours = find_unfinished(log.entries)
    assert ours == theirs
    assert [u["target"] for u in ours["unfinished"]] == ["stripe.refund"]

    res = pw("verify", "--fail-on-unfinished", home=tmp_path)
    assert res.returncode == 3, res.stdout + res.stderr
    assert "stripe.refund" in res.stdout
