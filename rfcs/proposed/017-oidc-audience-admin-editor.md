# RFC 017: OIDC client audience-scoping admin editor

**Status**: Proposed
**ROADMAP**: External UI/UX design update v0.50.1 — page 8 ("OIDC client editor"); closes the v0.50.0 "out-of-scope: admin UI for `oidc_clients.audience`" gap
**ADR**: ADR-014 §Q1 (audience scoping shipped v0.50.0; admin UI was deferred)
**Severity**: **P2 — operator-experience gap; v0.50.0 shipped the schema + gate but operators currently must run direct D1 SQL to use it**
**Estimated scope**: Small/medium — ~150 LOC handler + ~80 LOC template + ~10 tests; no schema change, additive routes only

## Background

v0.50.0 shipped per-client audience scoping
(ADR-014 §Q1 Resolved): a non-NULL value in
`oidc_clients.audience` gates `/introspect` so a
requesting client can only see tokens whose `aud`
matches its configured audience.

The v0.50.0 CHANGELOG and ROADMAP both noted:

> Recommended deployment progression for multi-RS
> deployments:
> 1. Upgrade to v0.50.0. No clients have audience
>    set. Behavior unchanged.
> 2. Identify which resource-server clients
>    should be scoped...
> 3. Set `oidc_clients.audience` for those
>    clients via direct D1 statement
>    (`UPDATE oidc_clients SET audience = ? WHERE
>    id = ?`). **Admin console UI for this is out
>    of v0.50.0 scope.**

In practice this means an operator with a
deployment that *should* scope per-client audience
must:

- Open `wrangler d1 execute` against production.
- Run an UPDATE statement with the client's id
  and the desired audience string.
- Verify the change took effect by re-running a
  SELECT.
- Watch audit logs for
  `IntrospectionAudienceMismatch` events.

This is a **friction wall**: small enough to be
ignorable, big enough to deter operators from
turning the feature on. The deck's page 8 calls
this out directly:

> OIDC client editor | audience scoping は
> resource server 境界を説明。NULL は legacy
> unscoped と表示。

This RFC closes that gap.

## Requirements

1. The tenant admin console MUST surface
   `oidc_clients.audience` as a first-class form
   field on the OIDC client editor page.
2. The form MUST visibly distinguish "legacy
   unscoped" (NULL) from "explicit empty string"
   from "scoped to <value>" — three states with
   distinct semantics.
3. The form MUST explain the audience-scoping
   policy in operator language at the point of
   editing (not buried in deployment chapter).
4. Changing the audience MUST be auditable —
   produce an `OidcClientAudienceChanged` audit
   event with `before` and `after` payload
   fields.
5. The form MUST NOT allow an audience value
   that's already assigned to a different client
   in the same tenant **without an explicit
   override** (operator confirms "I know this
   creates a shared audience"). Two clients
   sharing an audience is a legitimate
   multi-resource-server-fronting-the-same-
   logical-audience pattern but the default
   should be "unique audience per client" with
   the override available.

## Design

### Page placement

The existing tenant admin OIDC client editor is
at `/admin/t/<slug>/oidc-clients/<id>`. Add the
audience field below the existing
`redirect_uri` editor.

If no editor page exists today (the OIDC client
table may currently be read-only or not ship a
detail page), this RFC scopes a minimal editor:
GET → form, POST → update, with the audience
field as the only mutable piece in the v0.50.x
release. Other client fields (name, redirect URIs,
client_secret rotation) get separate editors as
they become needed; this RFC does not block on
them.

### Form shape

```html
<form method="post" action="/admin/t/{slug}/oidc-clients/{id}/audience">
  <fieldset>
    <legend>Introspection audience scope</legend>
    <p class="explainer">
      When set, this client may only introspect
      tokens whose `aud` claim matches this
      audience verbatim. When unset (NULL), the
      client uses pre-v0.50.0 unscoped behavior:
      it can introspect any token cesauth issues.
    </p>

    <div class="field">
      <label>
        <input type="radio" name="mode"
               value="unscoped"
               {checked_unscoped}>
        Unscoped (legacy default — any audience)
      </label>
    </div>

    <div class="field">
      <label>
        <input type="radio" name="mode"
               value="scoped"
               {checked_scoped}>
        Scoped to:
      </label>
      <input type="text" name="audience_value"
             value="{current_audience_esc}"
             aria-label="Audience value"
             placeholder="https://api.example.com">
    </div>

    <details>
      <summary>What goes in this field?</summary>
      <p>
        The audience is the identifier this
        client's resource server uses for its
        own tokens. Cesauth mints access
        tokens with `aud=client.id`, so for
        most deployments the audience equals
        the client's own client_id. For
        deployments where one cesauth fronts
        multiple resource servers, the
        audience is the operator-controlled
        identifier for the specific resource
        server this client represents.
      </p>
    </details>

    <input type="hidden" name="csrf" value="{csrf_token}">
    <button type="submit">Apply</button>
    <a href="...">Cancel</a>
  </fieldset>
</form>

<section class="audit-trail">
  <h3>Recent audience changes</h3>
  {audit_table_for_this_client}
</section>
```

The radio + text-field combo is the **deliberate
representation of three states**:

- `mode=unscoped`, audience_value ignored → DB
  becomes NULL. Pre-v0.50.0 behavior.
- `mode=scoped`, audience_value=`""` → DB stores
  empty string. Distinct from NULL: matches the
  test pin
  `empty_string_audiences_compared_byte_exact`
  from v0.50.0. Operator who wants this must
  understand it's **not** unscoped.
- `mode=scoped`, audience_value="..." → DB
  stores the string.

### Handler

`POST /admin/t/<slug>/oidc-clients/<id>/audience`:

```rust
1. CSRF check (existing pattern).
2. Authorization: caller must be Tenant Admin or
   System Admin for this tenant slug. Use
   existing check_permission helper.
3. Read existing client, capture current
   audience for the audit `before` payload.
4. Parse mode + audience_value; produce the
   target value (None / Some("") / Some("...")).
5. Uniqueness check (per Requirements §5):
   query oidc_clients for any other client in
   the same tenant with this audience. If found
   and the request lacks `?force=1`, render the
   form again with a warning panel:
   "Audience '...' is also configured on
   client '<other_client_id>'. Two clients
   sharing an audience is supported (multi-RS
   fronting one logical audience), but is rare.
   To proceed, click Apply with confirmation
   below."
6. Apply via repository.update_audience(...).
7. Emit OidcClientAudienceChanged audit event
   with payload {before, after, force_override:
   bool}.
8. Redirect (PRG) to the editor with a
   "success.audience_updated" flash.
```

### New audit event kind

`EventKind::OidcClientAudienceChanged`. Snake-case
`oidc_client_audience_changed`. Payload:

```json
{
  "before":          "https://api.old.example.com" | null,
  "after":           "https://api.new.example.com" | null | "",
  "force_override":  false
}
```

The before/after carry **operator-controlled
identifiers, not secret material** — same
audit-payload discipline as
`IntrospectionAudienceMismatch` from RFC 009.
The `force_override` flag is true when the
operator bypassed the uniqueness warning.

### Where the explainer lives

The form's `<details>` element carries the
"what goes in this field" explainer as
**inline-discoverable context**. Operators don't
need to leave the page to know what the
audience field means. The explainer is canonical
for the field — the `docs/src/deployment/`
entry on audience scoping should reference the
admin UI's explainer rather than duplicate it.

### Read view (no edit permission)

Tenant Admin / System Admin see the full form.
Tenant Read-Only Admin sees the same surface but
with the form disabled (radio buttons disabled,
button hidden, `<small>You don't have
permission to edit audience scope.</small>`
appended). The explainer stays visible —
read-only admins benefit from the context
explanation as much as editing admins.

### Audit-trail section

Below the form, a small table shows the recent
`OidcClientAudienceChanged` events for **this
client only**. Source: existing
`AuditEventRepository::search` with
`kind="oidc_client_audience_changed"` and
filtering by client_id. Limit ~5 rows. This
makes "what was this set to last week?" a
one-click visible answer rather than a
cross-reference operation.

## Test plan

### Pure (where applicable)

The form-state computation
(mode-radio + value-field → resolved
`Option<String>`) has a small pure helper that
goes in `cesauth_core::admin::oidc_clients`:

```rust
pub enum AudienceFormMode { Unscoped, Scoped }

pub fn resolve_audience_target(
    mode:  AudienceFormMode,
    value: &str,
) -> Option<String> {
    match mode {
        AudienceFormMode::Unscoped => None,
        AudienceFormMode::Scoped   => Some(value.to_string()),
    }
}
```

(Distinguishing `Some("")` from `None` from
`Some("...")` is the explicit point.)

Tests:

1. `unscoped_mode_yields_none`
2. `scoped_mode_with_empty_value_yields_some_empty_string`
3. `scoped_mode_with_value_yields_some_value`
4. `scoped_mode_strips_no_whitespace` — pin: the
   audience matcher in v0.50.0 is byte-exact, so
   the form does not trim. Operators get exactly
   what they typed.

### Worker handler tests

5. `post_audience_unscoped_writes_null_to_db`
6. `post_audience_scoped_with_value_writes_value`
7. `post_audience_emits_audit_event_with_before_after`
8. `post_audience_uniqueness_collision_renders_warning_form`
9. `post_audience_uniqueness_collision_with_force_proceeds`
10. `post_audience_csrf_required`
11. `post_audience_requires_tenant_admin_or_system_admin`
12. `audit_trail_section_renders_recent_changes_for_this_client_only`

### UI rendering

13. `editor_renders_form_with_radio_for_unscoped_legacy_default`
14. `editor_renders_form_with_scoped_when_audience_set`
15. `editor_renders_disabled_form_for_read_only_admin`

## Security considerations

**Uniqueness as default**. v0.50.0's audience
gate doesn't itself enforce uniqueness — two
clients can share an audience and both
introspect tokens carrying that audience. This
is a legitimate pattern for multi-RS-fronting-
one-logical-audience deployments. The default-
unique-with-override-on-confirm behavior makes
the *common* case (one audience per client) the
quiet path, and the *unusual* case (intentional
sharing) explicit. An operator who shares
without realizing it loses defense-in-depth.

**Empty-string audience**. Setting audience to
`""` is distinct from NULL in v0.50.0's gate
(byte-exact comparison). Cesauth mints tokens
with `aud=client.id`; a client.id is never the
empty string (UUIDs/randomly-generated). So
audience `""` matches **no token**, effectively
disabling introspection for the client without
removing scoping. This is a **legitimate
operator move** (a temporary lockdown without
losing the scoping config); the form supports
it explicitly. Documented in the explainer
text indirectly via "matches verbatim" wording.

**Audit before/after with operator IDs**. The
audit event carries audience strings (operator-
controlled identifiers). Same privacy posture
as v0.50.0's `IntrospectionAudienceMismatch`:
audiences are not secret material, so audit
exposure is fine.

**Ill-typed audience values**. RFC 7519 §4.1.3
makes `aud` a string or array of strings. RFC
009 pins string-only. The form's text input
allows any UTF-8; the audience matcher in
v0.50.0 does byte-equality. Validation: refuse
audiences containing newlines or NUL bytes
(cosmetic, prevents accidental copy-paste of
multi-line text); otherwise allow anything.

**Cross-tenant audience reuse**. Two clients in
different tenants can have the same audience —
the gate is per-client, not global. The
uniqueness check in §Design is **per-tenant
only** to support cross-tenant separation
correctly.

**Race with /introspect calls**. Audience
change → next introspect call by this client
sees the new value. There's no atomic-rotation
concern (unlike refresh-token families): the
audience is read fresh per request from D1.
Existing in-flight introspections (already past
the lookup) complete with the old value;
subsequent ones use the new value. Document in
the form: "Change takes effect immediately for
new requests. In-flight requests complete with
the old setting."

## Open questions

**Should the form support setting audience for
multiple clients in one go?** No — bulk-edit
patterns invite mistakes that single-client
edit doesn't. Operators with N clients to scope
do N small edits. The audit trail makes the
sequence reviewable.

**Should there be a "test audience" button that
runs a synthetic introspection request before
saving?** Out of v0.50.x scope. A test-mode
endpoint that constructs a stub token and shows
the gate's verdict would be a real UX upgrade
but is its own substantial feature (synthetic
token-mint surface, scoped audit, dry-run gate
integration). Defer until operator demand
surfaces.

**Should we expose audience scoping for refresh
introspection?** RFC 009 pinned this as
out-of-scope for v0.50.x (refresh families
don't record an audience). Same here — the
form pertains to access-token introspection
audience scoping. If refresh-side scoping is
ever added, the form gains a separate
sub-section.

## Implementation order

1. **PR 1** — Pure helper
   `resolve_audience_target` + 4 unit tests.
   Compiles standalone. ~30 LOC.
2. **PR 2** — Handler + GET form + POST submit
   + uniqueness check + audit emission.
   ~150 LOC + 8 tests.
3. **PR 3** — UI rendering tests for all three
   form states (unscoped legacy, scoped, read-
   only). ~30 LOC + 3 tests.
4. **PR 4** — Audit-trail section below form
   (search + render). ~50 LOC + 1 test.
5. **PR 5** — `MessageKey` variants for the
   form labels (EN + JA). ~20 LOC.
6. **PR 6** — CHANGELOG + release.

## Notes for the implementer

- This RFC's pure-helper PR lands first and is
  the safest review. The handler PR depends on
  it.
- Coordinate with RFC 009: that RFC's
  amendment to ADR-014 §Q1 is a good place to
  note that the admin UI gap closed in this RFC.
  Cross-link the two ADR amendments.
- The `<details>` HTML element (collapsible)
  is keyboard-navigable by default in modern
  browsers and screen-reader-announced as
  "summary". Don't replace it with custom JS.
- Coordinate with RFC 015: the audit event
  emitted here gets the `request_id` cross-link
  so operator can trace "who changed this?" by
  request_id ↔ user session ↔ later actions.
- For tenant admins: this is a **tenant-scoped
  admin operation** by design. System admins
  retain the ability via the same surface (a
  System Admin can navigate to any tenant). No
  separate system-admin-only path needed.
