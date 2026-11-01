# Agent integrations

| Directory | For | What it adds |
| --- | --- | --- |
| [`claude-code/`](claude-code) | Claude Code | A plugin with the `doppelkey` skill, a SessionStart hook and the MCP server |
| [`skills/doppelkey/`](skills/doppelkey/SKILL.md) | Codex, Gemini CLI, Cursor, Copilot and other [Agent Skills](https://agentskills.io) clients | The same skill in the open `SKILL.md` format |
| [`codex/`](codex/README.md) | OpenAI Codex | How to add the skill and the MCP server |

All of them need the `doppelkey` CLI on `PATH`.

## Claude Code

```bash
claude plugin marketplace add KaiHongTan/doppelkey
claude plugin install doppelkey@doppelkey
```

Inside a session, the equivalent is `/plugin marketplace add KaiHongTan/doppelkey`, then `/plugin install doppelkey@doppelkey`.

The plugin adds three things:

- **A SessionStart hook.** In a protected project, it appends the output of `doppelkey env` to `CLAUDE_ENV_FILE`, so commands Claude runs directly (`node app.js`, `pytest`, `bin/rails test`) load the shims. It also tells Claude that handles are not broken secrets. In a project that keeps plain secrets in `.env`, it mentions that the skill can help. It never prints a value.
- **A skill** (`/doppelkey:doppelkey`) covering when to suggest `npx doppelkey init`, the rules for handles, and what to do when an error mentions doppelkey.
- **The MCP server**, with tools `status`, `doctor` and `list_secrets`. They return names and health only.

Projects work without the plugin too: `doppelkey init` writes `env.NODE_OPTIONS` into the project's `.claude/settings.json`.
