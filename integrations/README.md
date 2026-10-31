# Agent integrations

| Directory | For | What it adds |
| --- | --- | --- |
| [`claude-code/`](claude-code) | Claude Code | Plugin: the `doppelkey` skill, a SessionStart hook that loads the shims into every Bash command and explains handles, and the MCP server (`doppelkey mcp`) |
| [`skills/doppelkey/`](skills/doppelkey/SKILL.md) | Codex, Gemini CLI, Cursor, Copilot and other [Agent Skills](https://agentskills.io) clients | The same skill in the open SKILL.md format |
| [`codex/`](codex/README.md) | OpenAI Codex | How to add the skill and the MCP server |

All of them need the `doppelkey` CLI on `PATH`.

## Claude Code

```bash
claude plugin marketplace add KaiHongTan/dopplekey
claude plugin install doppelkey@doppelkey
```

or inside a session: `/plugin marketplace add KaiHongTan/dopplekey`, then `/plugin install doppelkey@doppelkey`.

What the plugin does:

- **SessionStart hook** (`scripts/session-start.sh`). In a protected project it appends `doppelkey env` output (`NODE_OPTIONS=--require …`, and `PYTHONPATH` for Python projects) to `CLAUDE_ENV_FILE`, so commands Claude runs directly (`node app.js`, `pytest`) load the shims. It also tells Claude that handles are not broken secrets. In a project with plain secrets in `.env`, it mentions that the skill can help. It never prints values.
- **Skill** (`/doppelkey:doppelkey`): when to propose `npx doppelkey init`, the rules for handles, and what to do with errors.
- **MCP server**: tools `status`, `doctor`, `list_secrets`. They return names and health only.

`doppelkey init` also writes `env.NODE_OPTIONS` into the project's `.claude/settings.json`, so projects work even without the plugin.
