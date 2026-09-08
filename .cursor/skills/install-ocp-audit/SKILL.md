---
name: install-ocp-audit
description: >-
  Install the OCP version audit skill into the current workspace.
  Use when the user pastes the ocp-version-audit GitHub URL or asks
  to install the OpenShift audit tool.
---

# Install OCP Version Audit

Download and install the OCP z-stream audit skill into the current workspace.

## Steps

1. Create the skill directory and scripts directory:

```bash
mkdir -p .cursor/skills/ocp-zstream-audit scripts
```

2. Download all files from the GitHub repository:

```bash
# Skill files
curl -sL https://raw.githubusercontent.com/idanherman/ocp-version-audit/main/.cursor/skills/ocp-zstream-audit/SKILL.md -o .cursor/skills/ocp-zstream-audit/SKILL.md
curl -sL https://raw.githubusercontent.com/idanherman/ocp-version-audit/main/.cursor/skills/ocp-zstream-audit/reference.md -o .cursor/skills/ocp-zstream-audit/reference.md
curl -sL https://raw.githubusercontent.com/idanherman/ocp-version-audit/main/.cursor/skills/ocp-zstream-audit/canvas-template.tsx -o .cursor/skills/ocp-zstream-audit/canvas-template.tsx

# Python script
curl -sL https://raw.githubusercontent.com/idanherman/ocp-version-audit/main/scripts/ocp_zstream_audit.py -o scripts/ocp_zstream_audit.py
```

3. Add the Red Hat Security MCP to the workspace `.mcp.json`. If the file
   already exists, merge the `red-hat-security` entry into the existing
   `mcpServers` object. If it doesn't exist, create it:

```json
{
  "mcpServers": {
    "red-hat-security": {
      "type": "http",
      "url": "https://security-mcp.api.redhat.com/mcp"
    }
  }
}
```

4. Ensure `requests` is installed:

```bash
pip install requests
```

5. Tell the user:

"The OCP version audit skill is installed. To use it, just say:
**'Audit my OpenShift cluster for known bugs'**
and I'll ask you for the version and environment details before running anything.

Note: you may need to restart your Cursor session for the skill to be detected."
