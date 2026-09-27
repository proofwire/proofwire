# proof-wire (Python)

Tamper-evident receipts for what your AI agents do, from Python. This is the
Python SDK for [Proofwire](https://github.com/proofwire/proofwire), and it
writes exactly the format the `proofwire` CLI reads:

- a log written here passes `pw verify`;
- a bundle exported here passes `pw check`;
- logs and bundles written by the JavaScript side open and verify here.

CI runs both directions against the real CLI on every commit.

```bash
pip install "proof-wire @ git+https://github.com/proofwire/proofwire#subdirectory=sdk/python"
```

That installs straight from this repository. The package is not on PyPI yet;
once it is, `pip install proof-wire` will do the same.

Python 3.9+. The one dependency is `cryptography`, for Ed25519.

## Record an agent's tool calls

```python
from proof_wire import ProofLog, Recorder

log = ProofLog.open_or_create(".proofwire")
rec = Recorder(log, agent="support-bot", principal="ops@acme.com", namespace="stripe")

@rec.tool("refund", metrics=lambda order_id, amount_cents: {"amount_usd": amount_cents / 100})
def refund(order_id: str, amount_cents: int):
    return stripe.Refund.create(payment_intent=order_id, amount=amount_cents)

refund("pi_123", 4200)
```

Each call leaves two signed receipts:

1. **An intent receipt, before the call runs.** A crash mid-call still leaves
   evidence it was attempted.
2. **An outcome receipt, when it returns or raises**, linked to the intent.

Async functions work the same. So does a context manager:

```python
with rec.call("crm.update", params={"id": 42}) as call:
    call.result = crm.update(42)
```

Arguments and results are **committed to, not stored**. A receipt holds a
salted hash plus a preview with secrets and personal data masked (API keys,
card numbers, emails and so on). The salts stay in the log's private
`salts.jsonl`, so you can later prove what a value was:
`log.reveal(seq, "params", value)`. Or you can destroy the salts, and the value
becomes unprovable forever while the receipt still verifies:
`log.shred(predicate)`.

### Check calls before they run

```python
def decide(target, params):
    if target.endswith(".delete"):
        return {"outcome": "deny", "rules": ["no-deletes"], "reason": "agents may not delete"}
    return {"outcome": "allow", "policy": "v3"}

rec = Recorder(log, agent="support-bot", principal="ops@acme.com", decide=decide)
```

A refused call never runs. It gets one receipt, and `PolicyDenied` is raised.
An `escalate` outcome is a denial here, recorded as `policy:no-approver`,
because nobody in the process can approve it.

The full policy language (budgets, rate limits, escalation to a person, Slack
approvals, monitor mode) lives in the `pw proxy` MCP proxy. For an agent that
uses MCP, wrap its servers with that instead. A Python port of the policy
engine is planned.

## Hand over evidence

```python
import json
from proof_wire import verify_bundle

log.checkpoint()                                   # sign the current state
open("evidence.json", "w").write(json.dumps(log.bundle()))

# Anyone can verify it, here or with `pw check evidence.json`:
verify_bundle(json.load(open("evidence.json")))
# -> {"ok": True, "issues": [], "checked": 12}
```

To require an independent witness, pin its key. Get the key from somewhere the
bundle can't influence:

```python
verify_bundle(bundle, min_witnesses=1, trusted_witnesses={"pw1…": "<public key>"})
```

`pw report` (from the npm CLI) turns a log written here into an evidence pack
for auditors.

## Ship to a hub

```python
from proof_wire import push

push(log, "https://hub.acme.com", token=os.environ["PROOFWIRE_TOKEN"], name="support-bot")
```

It sends whatever the hub doesn't have yet, and is safe to call again. Plain
`http://` is refused unless the hub is on this machine, so the API key never
crosses a network unencrypted.

## What's here

| Module | |
| --- | --- |
| `canonical` | RFC 8785 canonical JSON: UTF-16 key order, ECMAScript number formatting |
| `merkle` | RFC 6962 trees, inclusion and consistency proofs |
| `keys` | Ed25519 identities, canonical base64url |
| `receipt` | Build, seal, sign and verify receipts |
| `checkpoint` | Signed tree heads, witness countersignatures |
| `log` | `ProofLog`, the on-disk log the CLI shares, and `verify_bundle` |
| `record` | `Recorder`, for Python agents |
| `remote` | `push` to a hub |

Tested against the RFC 6962 Certificate Transparency reference tree and the
RFC 8032 Ed25519 vectors, plus byte-level canonicalization parity with the
JavaScript implementation over hundreds of awkward values.

License: Apache-2.0.
