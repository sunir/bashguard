# Clean Code Worth Preserving

- `bashguard.models:Finding` at `bashguard/models.py:48` is a frozen value object with validation for required identity at `bashguard/models.py:63-65`; findings are evidence values rather than mutable verdict state.
- `bashguard.policy:decide` at `bashguard/policy.py:90` cleanly separates detection from response policy and returns a single `Verdict` without mutating global state.
- `bashguard.project_config:merge_configs` at `bashguard/project_config.py:107` has a clear ratcheting intent and preserves redirect/confirmation metadata when replacing an existing override at `bashguard/project_config.py:147-156`.
- `bashguard.rules.error_nodes:ErrorNodesRule.check` at `bashguard/rules/error_nodes.py:36` treats parse errors as audit-integrity risk instead of ignoring them.
- `bashguard.rules.ci_workflow_inject:CiWorkflowInjectRule.check` at `bashguard/rules/ci_workflow_inject.py:127` is grounded in a real attack chain and catches redirects plus `cp`/`mv`/`tee` destinations.
- `spike/acl_shadow_fs:ACLShadowFS._check_access` at `spike/acl_shadow_fs.py:50` uses `posixpath.normpath` and exact-or-subtree matching, which is the right shape for path containment.
- `bashguard.audit_log:read_log` at `bashguard/audit_log.py:35` tolerates corrupt JSONL lines without breaking the whole log query, which is appropriate for an append-only operational log.
