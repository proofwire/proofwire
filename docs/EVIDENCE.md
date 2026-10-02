# Evidence packs for auditors

`vw report` turns a Vouchwell log into a directory you can hand to an auditor,
an assessor or a regulator. The report inside is an index to the evidence, not
a verdict: it shows what your agents did, what the policy decided, who approved
or declined what, and that none of it has been altered. Whether that meets a
particular obligation is the assessor's call, so the report says what the
evidence *supports*, never that you *comply*.

```bash
vw report                                   # the whole log, both frameworks
vw report --since 2026-07-01 --until 2026-09-30 --out q3-evidence
vw report --framework ai-act                # or soc2
vw report --witness-keys witnesses/keys.json   # count witnesses against keys you pinned
```

## What's in the pack

| File | For | What it is |
| --- | --- | --- |
| `report.html` | People | One self-contained page, with no scripts and no network access. It opens the same from an email attachment years from now, and prints cleanly. |
| `evidence.bundle.json` | Verification | The signed receipts with their inclusion proofs, the log's keys and its checkpoints. It holds no payloads and no salts, so it's safe to send. |
| `summary.json` | Tools | The report's facts, for loading into a GRC system or a spreadsheet. |
| `SHA256SUMS` | Custody | Checksums, so a copy can be matched against the original. |

The report covers:

- **Integrity.** Whether every receipt verifies, the Merkle root, checkpoints,
  and witness signatures, including how many verify against the keys you pinned.
- **Activity.** Calls by tool, by principal and by agent, and spend.
- **Human decisions.** Every escalation, and whether a named person approved
  or declined it. An escalation that nobody answered is shown as closed by a
  fallback (`policy:timeout`), never as a person's decision.
- **Refused actions**, with the rule that fired and the reason.
- **Monitor mode.** Calls that ran unenforced, and what would have stopped them.
- **Policies in force.** Each policy version by hash, with when it was first
  and last used.
- **A mapping to the EU AI Act and SOC 2.** See below.
- **What the report can't show.** Actions that bypassed the proxy, payload
  contents, whether a decision was right, and compliance itself.

## For the auditor: checking it without trusting us

The report is produced by the party being audited, so **don't rely on the
HTML**. Verify the evidence directly:

```bash
npm install -g vouchwell
cd q3-evidence
sha256sum -c SHA256SUMS                     # the files are the ones produced
vw check evidence.bundle.json               # every receipt is signed and in the log
```

If the log is witnessed, pin witness keys you got from somewhere other than
the pack, e.g. [`witnesses/keys.json`](../witnesses/keys.json) in this
repository, at a commit you trust:

```bash
vw check evidence.bundle.json --witnesses 1 --witness-keys keys.json
```

Then compare the root that `vw check` prints with the one in `report.html`,
and with any root you received earlier. A root you got earlier that the new log
doesn't extend means history was rewritten.

A pack made with `--since`/`--until` is a **filtered export**. Each receipt in
it is proven to be part of the full log, but the pack alone can't prove that
nothing in the period was left out. For that, ask for the full log, or check
the root against a witness.

## The framework mapping

Each row names a requirement, what in the pack speaks to it, and where in the
pack to find it.

**EU AI Act (Regulation (EU) 2024/1689).** Mapped against:

- Article 12: automatic record-keeping of events over the system's lifetime,
  covering (a) risk, (b) post-market monitoring and (c) deployer monitoring.
- Article 14: human oversight.
- Articles 19 and 26(6): keeping logs for at least six months.

Which of these apply depends on whether the system is high-risk, and on whether
you are its provider or its deployer. Application dates for high-risk
obligations have moved before. Confirm both with counsel.

**SOC 2.** An illustrative mapping to Trust Services Criteria this evidence
commonly supports: CC6.1, CC7.2, CC7.3, CC8.1 and CC4.1. Your auditor decides
which controls it's evidence for.

## What makes this evidence rather than a claim

- Receipts are signed by the agent's key and hash-chained. Altering, removing
  or reordering one breaks verification.
- Every receipt names the policy version that decided it, by hash. A policy
  can't be changed after the fact without that showing.
- Approvals and declines are **inside** the signed receipt, not in a separate
  table someone could edit.
- Witnesses countersign the log's state. After that, even the key holder can't
  rewrite history unnoticed; see [`THREAT-MODEL.md`](THREAT-MODEL.md).
