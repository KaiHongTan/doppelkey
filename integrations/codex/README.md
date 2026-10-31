# doppelkey with OpenAI Codex

1. **Skill:** copy [`../skills/doppelkey`](../skills/doppelkey) into your Codex skills directory (see the Codex skills docs), or into the repository's agent skills folder.
2. **MCP server:** add to `~/.codex/config.toml`:

   ```toml
   [mcp_servers.doppelkey]
   command = "doppelkey"
   args = ["mcp"]
   ```

3. **Shims for commands Codex runs:** `doppelkey init` already writes `.npmrc` (npm/pnpm scripts) and a venv `.pth` (Python). For commands Codex runs directly, start Codex from a shell where you ran `eval "$(doppelkey env)"`, or prefix commands with `doppelkey run --`.

`doppelkey init` also adds a note to `AGENTS.md` explaining that handles are not broken secrets.
