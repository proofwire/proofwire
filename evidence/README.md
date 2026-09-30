# How Vouchwell was built

Vouchwell makes AI agents accountable, and an AI agent built it. This folder
holds the record of what that agent did.

This repository's Claude Code hooks ([`.claude/settings.json`](../.claude/settings.json))
run [`vw hook`](../docs/CODING-AGENTS.md) around every tool call an agent makes
while working here: every shell command, file read, edit and fetch. Each call
is checked against [the project's policy](../.claude/vouchwell.policy.json)
before it runs and recorded as a signed, hash-chained receipt. Each file here
is one log exported as an evidence bundle, named for the log.

## Check it yourself

```bash
npx vouchwell check evidence/<file>.json
```

Or paste the file into the verifier on [the website](https://vouchwell.github.io/vouchwell/).
CI checks every bundle on every push.

## What a bundle proves

- **Which calls were made, in order.** It shows every tool call made and when,
  which tool it was (`claude-code.Bash`, `claude-code.Edit`, …), what the
  policy decided, whether it succeeded, and how long it took.
- **Nothing was removed.** No receipt has been removed, reordered or changed
  since it was signed. Each receipt commits to the one before it, and the
  checkpoints commit to all of them.
- **Refusals are on record.** Calls the policy refused show up as refusals,
  and calls a person had to approve show who approved them.

## What it does not show

- **What the calls touched.** These logs are recorded with previews off
  (`"previews": "none"` in [the config](../.claude/vouchwell.config.json)). A
  receipt holds a salted commitment to its arguments and output, never the
  command, file or content. So a public record cannot leak anything from the
  machine it was made on. The salts stay on that machine, so the commitments
  cannot be opened by anyone else.
- **Anything done outside Claude Code's tools.** It also cannot show changes
  made by hand. Every commit is still in git history.
- **Who holds the signing key.** Each log is signed by a key made on the
  machine that recorded it. The bundle proves the log is internally
  consistent, and that it matches the key it names. Two things tie that key to
  this project:
  - the bundle arrived by a commit to this repository;
  - once the project runs a witness, the witness's co-signature on the
    checkpoints, which a verifier can pin (`--witness-key`).

## Adding to it

Working in this repository with Claude Code records automatically. Before you
push, write the log out:

```bash
npm run evidence            # checkpoint, then write evidence/<log id>.json
```

Commit the file it writes. The live log, its signing key and its salts stay in
`.claude/vouchwell-log/`, which git ignores.
