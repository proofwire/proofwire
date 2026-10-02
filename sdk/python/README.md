# deedwrit (Python)

Tamper-evident receipts for what your AI agents do, from Python. This is the
Python SDK for [Deedwrit](https://github.com/deedwrit/deedwrit), and it
writes exactly the format the `deedwrit` CLI reads:

- a log written here passes `dw verify`;
- a bundle exported here passes `dw check`;
- logs and bundles written by the JavaScript side open and verify here.

CI runs both directions against the real CLI on every commit.

```bash
pip install "deedwrit @ git+https://github.com/deedwrit/deedwrit#subdirectory=sdk/python"
```

That installs straight from this repository. The package is not on PyPI yet;
once it is, `pip install deedwrit` will do the same.

Python 3.9+. The one dependency is `cryptography`, for Ed25519.

## Record an agent's tool calls

```python
from deedwrit import ProofLog, Recorder

log = ProofLog.open_or_create(".deedwrit")
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
approvals, monitor mode) lives in the `dw proxy` MCP proxy and in the
JavaScript `Recorder` in `@deedwrit/core`. For an agent that uses MCP, wrap
its servers with the proxy instead. A Python port of the policy engine is
planned.

### Use it with LangChain or the OpenAI Agents SDK

Wrap the agent's tools once; use the wrapped ones in their place. Each call is
checked with `decide`, recorded as intent and outcome, and a refused call
never runs: the model is told why in the tool's reply, as the MCP proxy does,
instead of the agent crashing.

```python
from deedwrit.integrations.langchain import record_tools        # pip install "deedwrit[langchain]"
agent = create_react_agent(model, record_tools(rec, [search, refund]))

from deedwrit.integrations.openai_agents import record_tools    # pip install "deedwrit[openai-agents]"
agent = Agent(name="Support", tools=record_tools(rec, [lookup_order, refund]))
```

Hosted OpenAI tools (web search and the like) run on OpenAI's side, so they
are passed through unrecorded. Both adapters need Python 3.10+, and are tested
in CI against the real packages.

### Find calls that never finished

Each call's intent is on disk before the tool runs. If the process is killed
while a call is out, the intent has no outcome, and that is worth knowing:

```python
from deedwrit import find_unfinished

found = find_unfinished(log.entries)
for u in found["unfinished"]:
    print(u["seq"], u["ts"], u["target"], u["principal"])
```

`inFlight` holds calls from the last five minutes that may still be running,
and `abandoned` the ones a recorder gave up on while shutting down. `dw verify`
reports the same list, and `dw verify --fail-on-unfinished` exits 3 when there
is one.

## Hand over evidence

```python
import json
from deedwrit import verify_bundle

log.checkpoint()                                   # sign the current state
open("evidence.json", "w").write(json.dumps(log.bundle()))

# Anyone can verify it, here or with `dw check evidence.json`:
verify_bundle(json.load(open("evidence.json")))
# -> {"ok": True, "issues": [], "checked": 12}
```

To require an independent witness, pin its key. Get the key from somewhere the
bundle can't influence:

```python
verify_bundle(bundle, min_witnesses=1, trusted_witnesses={"pw1…": "<public key>"})
```

`dw report` (from the npm CLI) turns a log written here into an evidence pack
for auditors.

## Ship to a hub

```python
from deedwrit import push

push(log, "https://hub.acme.com", token=os.environ["DEEDWRIT_TOKEN"], name="support-bot")
```

It sends whatever the hub doesn't have yet, and is safe to call again. Plain
`http://` is refused unless the hub is on this machine, so the API key never
crosses a network unencrypted.

## What's here

| Module | |
| --- | --- |
| `canonical` | RFC 8785 canonical JSON: UTF-16 key order, ECMAScript number formatting |
| `merkle` | RFC 6962 trees, inclusion and consistency proofs |
| `unfinished` | `find_unfinished`: calls sent and never answered |
| `integrations` | `langchain.record_tools`, `openai_agents.record_tools` |
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
