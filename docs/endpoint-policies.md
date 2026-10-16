# Endpoint policy declarations

Endpoint policies are an optional, explicit trust configuration for routes
that are intentionally public or intentionally limited to named roles. A
matching policy suppresses findings for the covered endpoint and emits a
separate `policy-declared` report entry. It does not create a finding or
change detection rules.

**No `--endpoint-policy` option means no policies.** The default report and
finding behavior is unchanged; the optional `policy_declarations` JSON member
is omitted when no policy matches.

## Configuration file

Pass a JSON file to `charon analyze`:

```bash
charon analyze captures.json \
  --credentials credentials.json \
  --endpoint-policy endpoint-policy.json
```

The file has one top-level `endpoints` array. Each entry has an HTTP method, a
URL path or route template, and an access declaration:

```json
{
  "endpoints": [
    {
      "method": "GET",
      "path": "/status",
      "access": "public",
      "description": "Unauthenticated service status endpoint"
    },
    {
      "method": "DELETE",
      "path": "/users/{user_id}",
      "access": "role-restricted",
      "allowed_roles": ["admin"],
      "description": "Only administrators may delete users"
    }
  ]
}
```

- `method` is matched case-insensitively and normalized to uppercase.
- `path` must be absolute and contain no query string or fragment. A template
  parameter such as `{user_id}` matches one non-empty path segment; static
  segments must match exactly. The most specific matching route wins.
- `access` is either `public` or `role-restricted`. Public policies must not
  list roles. Role-restricted policies must include at least one
  `allowed_roles` value.
- `description` is optional. Duplicate method/path pairs and unknown config
  keys are rejected.

## Behavior and report

A policy is matched by method and path, independent of the host. A matching
captured exchange is always recorded in the policy-declared section, even if
there was no finding to suppress. Any finding whose complete evidence chain is
covered by configured policies is removed from the `findings` list and from
`finding_count`. A cross-endpoint finding remains if any evidence endpoint is
not covered. Suppressed finding IDs, rule IDs, classifications, and their
`classification_scope` are retained under that endpoint's policy entry for
auditability. In report JSON schema version 2, findings and suppressed entries
use `classification` plus `classification_scope`; only official OWASP
classifications also use the `owasp_class` field. Charon-internal heuristics
are labeled separately.

JSON reports include a `policy_declarations` array only when a policy matched.
Each entry has `status: "policy-declared"`, the observed method/path, the
configured path template, access type, declared roles, matched exchange IDs,
and any suppressed finding summaries. Markdown reports present the same
information in a **Policy-declared endpoints** section. These entries are
policy outcomes, not findings.

Role names are descriptive metadata only: Charon does not infer them from
credential labels or verify the application's role enforcement. A matching
policy is an operator-authored suppression decision and can hide genuine
issues if applied too broadly or inaccurately. Keep declarations narrow and
review suppressed finding IDs in the report. A role-restricted entry does not
prove that the endpoint enforces the declared roles.

The same config is available to Python callers through
`PipelineConfig(endpoint_policy=EndpointPolicyConfig(...))`. An empty config is
a no-op.
