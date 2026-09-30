# Coding agents: record and gate Claude Code's own tools

`vw proxy` sees the MCP servers an agent calls. A coding agent does most of its
work without them: it runs shell commands, reads and edits files, and fetches
pages with tools built into the agent. `vw hook` covers those. Claude Code runs
a command before and after every tool call (its
[hooks](https://docs.claude.com/en/docs/claude-code/hooks)), and `vw hook` is
that command.

```bash
npm install -g vouchwell
vw policy template coding-agent shell-safety secrets --out vouchwell.policy.json
vw hook install            # this project: .claude/settings.json
```

The hooks load when a Claude Code session starts. From then on every tool call
is checked against `vouchwell.policy.json` and recorded in `.vouchwell/`. Use
`vw log` to see what the agent did and `vw verify` to prove nothing has been
removed.

## What happens to each call

| Claude Code event | What `vw hook` does |
|---|---|
| `PreToolUse` | The policy decides. **Allowed:** an `intent` receipt, written to disk before the tool runs. Claude Code's own permission prompts still apply as usual. **Refused:** one receipt, and Claude Code is told to deny the call, with the policy's reason. **Escalated:** Claude Code asks its user, who is the approver. |
| `PostToolUse` | An `outcome` receipt, linked to its intent by hash. For an escalated call, the intent is written now, recording that the person approved it. |
| `PostToolUseFailure` | The same, as an error: `tool_error`, or `interrupted`. |
| `PermissionDenied` | Claude Code's permission check refused the call: `permission_denied`. |
| `SessionEnd` | Calls that never reported back are closed as `not_run`, escalations nobody approved are recorded as declined, and the log is checkpointed. |

Tool names are recorded as `claude-code.<Tool>`, e.g. `claude-code.Bash` and
`claude-code.Edit`, so policy rules can match them. Each Claude Code session is
its own `actor.session` (`cc_<session id>`).

## The policy

Every template works here. These three are written for coding agents:

- **`coding-agent`** refuses reading or writing secret files (`.env`, private
  keys, credential files) and touching the agent's own audit log. A person must
  approve shell commands that name a secret file, and skipping git hooks
  (`--no-verify`).
- **`shell-safety`** refuses `rm -rf`, force-pushes, disk formatting and piping
  a download into a shell.
- **`secrets`** refuses any call whose arguments contain a credential.

Check a policy against what the agent has already done before it can block
anything:

```bash
vw hook install --monitor          # record what would be blocked, block nothing
# … a few days of normal work …
vw policy test                     # which past calls the policy would change
vw hook install                    # then enforce
```

## Settings

In `vouchwell.config.json`:

```json
{
  "hook": {
    "principal": "you@example.com",
    "previews": "params",
    "monitor": false
  }
}
```

- **`previews`** sets how much of each call is copied into its receipt, beside
  the commitment that proves what it was:
  - `"params"` (the default) copies the tool's arguments, with secrets masked;
  - `"all"` also copies its output;
  - `"none"` keeps only the commitments.

  Use `"none"` for a log you will publish: it shows which tools ran, when, and
  what the policy decided, and none of what they touched.
- **`principal`** is who the agent works for. Defaults to `actor.principal`.
- **`monitor`**: `true` records what the policy would block without blocking
  it. `--enforce` on the command overrides it.

`vw hook install` flags:
- `--user` writes to `~/.claude/settings.json`, so the hooks apply in every project.
- `--local` writes to `.claude/settings.local.json`, which is not shared.
- `--command` sets the exact command Claude Code runs.

`vw hook uninstall` removes only the entries `vw hook install` added.

## To publish the log

```bash
vw hook evidence            # checkpoint, then write evidence/<log id>.json
vw check evidence/*.json    # what anyone can run against it
```

The bundle holds no payloads and no salts.

## Guarantees and limits

- **When enforcing, a call that cannot be recorded is refused.** If the log
  cannot be written, the call is denied and Claude Code shows why. This is
  deliberate: a gate that opens whenever the log breaks is not a gate. To turn
  recording off, start Claude Code with `VOUCHWELL_HOOK=off`. The agent's own
  shell cannot set this: hooks get the environment Claude Code started with.
- **Parallel tool calls keep one chain.** Claude Code runs the hooks of
  parallel calls at the same time. Each takes a lock on the log first, so the
  chain never forks.
- **A hook sees what Claude Code reports, and nothing else.** A tool that runs
  outside Claude Code's tool calls is not recorded. A subprocess started by a
  recorded shell command is recorded only as that command.
- **A pattern list is not a sandbox.** A shell can reach a file by another
  name. What the policy does guarantee is a signed record of every attempt it
  saw, including the refused ones.
