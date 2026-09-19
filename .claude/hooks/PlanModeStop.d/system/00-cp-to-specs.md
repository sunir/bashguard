# Rename Approved Plan in Specs

Story: exitplanmode-copy-to-specs

You have finished planning and the user approved your plan.

Claude Code saves plans to `./specs/` (configured via `plansDirectory`).
The plan file already exists there with a generated name. Rename it now.

**Before starting implementation:**

1. **Rename the plan file** — Give it a descriptive name:
   ```bash
   # Find the plan file (recently modified .md in specs/)
   ls -t specs/*.md | head -3
   # Rename to match the task
   mv specs/<generated-name>.md specs/<task-name>-plan.md
   ```

2. **Add metadata** — Add a YAML front-matter block at the top:
   ```markdown
   ---
   id: PLAN-[TASK-NAME]
   status: approved
   date: YYYY-MM-DD
   ---
   ```

3. **Take the task** — Create or take a task that references the spec:
   ```
   TaskCreate(
     subject: "Implement [feature]",
     description: "Approved plan: specs/[task-name]-plan.md"
   )
   ```

4. **Start work** — Follow FocusMode: TAKE → BRANCH → TEST → CODE → ...

**Why this matters:**
Plans document decisions and rationale. Future sessions reference the
spec instead of re-planning. The specs/ directory is the project memory.
