# Agent compatibility

The RouterOS audit skills use the common directory-based Agent Skills pattern:

```
routeros-audit-*/
├── SKILL.md
├── agents/
│   └── openai.yaml
└── references/
```

The authoritative instructions live in `SKILL.md`. Do not fork the instructions per agent.

## Supported hosts

### Claude Code

Use the skill folders under:

- user scope: `~/.claude/skills/`
- project scope: `<repo>/.claude/skills/`

### OpenAI Codex

Codex discovers repository skills under `.agents/skills/` and user skills under `$HOME/.agents/skills/`.

Recommended project layout:

```
<repo>/.agents/skills/routeros-audit-method/
<repo>/.agents/skills/routeros-factory-defaults/
<repo>/.agents/skills/routeros-audit-firewall/
...
```

### Google Antigravity

Antigravity also supports the common `SKILL.md` layout.

- global: `~/.gemini/config/skills/`
- project/workspace: `<repo>/.agents/skills/`

Because Codex and Antigravity both support project skills in `.agents/skills/`, the same project installation can serve both.

### ChatGPT Skills

The common `SKILL.md` remains the source of instructions. `agents/openai.yaml` supplies OpenAI UI metadata such as display name and short description.

## Recommended installation model

Clone this repository once and symlink the required folders instead of copying and editing them independently.

Example on Linux/macOS:

```bash
git clone https://github.com/fabioKoruja00/routeros-security-skills ~/routeros-security-skills

mkdir -p ~/.claude/skills ~/.agents/skills ~/.gemini/config/skills

for d in ~/routeros-security-skills/routeros-*; do
  name="$(basename "$d")"
  ln -sfn "$d" "$HOME/.claude/skills/$name"
  ln -sfn "$d" "$HOME/.agents/skills/$name"
  ln -sfn "$d" "$HOME/.gemini/config/skills/$name"
done
```

On Windows, use directory junctions/symlinks or copy the folders, but keep this repository as the source of truth.

## Shared dependencies

Every domain skill should be installed with:

- `routeros-audit-method`
- `routeros-factory-defaults`

These two provide the common audit method, safety constraints, severity model, output format, version awareness and factory baselines.

## Portability rules

To preserve compatibility across hosts:

- keep YAML frontmatter in `SKILL.md` limited to `name` and `description`;
- keep paths relative and portable;
- keep detailed material under `references/`;
- avoid agent-specific instructions in the core skill unless unavoidable;
- put OpenAI-specific UI metadata only in `agents/openai.yaml`;
- do not require scripts unless deterministic execution is genuinely needed;
- do not assume one agent's proprietary tool names inside RouterOS audit instructions.

