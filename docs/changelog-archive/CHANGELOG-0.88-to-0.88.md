# cesauth — CHANGELOG (archive: v0.88–v0.88)

> This file is part of the changelog archive.
> Current releases are in the root [`CHANGELOG.md`](../../CHANGELOG.md).

## [0.88.1] - 2026-10-29

### Twenty-nine unreachable handlers removed, and a guard against more — RFC 157

### Removed

- **Twenty-nine request handlers that no route pointed at.** Each was a `.json`
  companion sitting beside a registered form handler, with no registration of
  its own, reachable by nothing, fetched by nothing, and — for all but a few —
  not even exercised by a test. They had accumulated because nothing failed
  when one was added: the router does not notice a handler it was never told
  about.

  Deleting them was a decision, not a default. Every client-rendered admin page
  was read first to establish whether any of them fetches the endpoint in
  question; two such pages do fetch a form companion, and both of those
  companions are registered and were left alone.

### Added

- **`unused_imports` and `unused_variables` are now build errors in the Worker
  crate**, as a crate-level attribute rather than a CI flag — so a local build
  enforces exactly what CI does, and the setting travels with the source rather
  than living in a workflow file. A deliberately narrow pair: the wider
  "deny all warnings" remains rejected, because it would make every future
  toolchain's new lint a release-blocking failure.

### Fixed

- The import leftovers the previous cycles' work had made redundant. These had
  been kept on purpose: while the pages they belonged to were still broken,
  the compiler's complaints about them were the clearest evidence of what was
  wrong. That evidence stopped being needed when the pages were fixed in
  v0.86.1 and v0.86.2, and the reason for keeping them had outlived the rule.

---

## [0.88.0] - 2026-10-29

### An invitation now grants what it offers — RFC 153

### Added

- **Accepting an invitation places you in the tenant that invited you, with
  the role it named.** Neither had ever happened. An invitation recorded an
  email, a tenant and a role, sent a link, and applied none of it: the
  invitation was marked accepted *before* any account existed, with a
  placeholder in place of a user id; the identifier meant to carry the
  invitation forward was read nowhere; the role was read exactly once, into an
  audit message; and registration always placed the new user in the default
  tenant. The flow now creates the user in the invitation's tenant, grants the
  membership with the invitation's role, records the real user id, and emits
  the audit event — **in that order**, so a failure at any step leaves the
  invitation usable instead of consuming it.
- **A user who abandons the flow is no longer locked out of their own
  invitation.** Previously the first submission consumed it, so returning later
  produced *"Already accepted. Please sign in"* to someone with no account, and
  only a fresh invitation from an administrator could recover it.
- **Invitations can be revoked.** `POST /admin/t/:slug/invitations/:id/revoke`,
  with the invitations page listing what is pending and a per-row control. The
  revoked state has been described by the schema since invitations shipped and
  nothing could produce it.
- An invited email that **already has an account** now gains the membership and
  role too, rather than signing in and silently receiving neither. Their own
  home tenant is left as it was.

### Fixed

- **The page that begins acceptance redirected to a URL that does not answer.**
  It sent the browser to a `GET` of an endpoint registered only for `POST`, so
  the invitee landed on a 404 — the flow was dead one step earlier than its
  own design described. It now renders the next step directly.
- Two administrative forms — add a member, grant a user-scoped role — returned
  403 for every tenant but one, because they require the target user to belong
  to the tenant and nothing could place a user in one. They succeed for an
  invited user now.
- Values interpolated into the invitation-acceptance page are escaped. The
  page's own policy already prevented scripts from running, so this was markup
  injection rather than a scripting hole, available only to someone who can
  already issue invitations.

---

