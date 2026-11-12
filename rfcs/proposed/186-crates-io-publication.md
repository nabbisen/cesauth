# RFC 186 — crates.io publication: reserve the names now, publish later

**Status**: Proposed, 2026-11-12. **Needs the owner's authorization**, and the
first half is an irreversible outward action I will not take without it.
**Trigger**: the owner, 2026-11-12 — *"it may be better for us to consider
publishment on crates.io when reasonable."*

---

## 1. What is already true, measured

`cesauth` **is registered**: version `0.0.0`, created **2026-09-10**, 14
downloads. That matches the comment every member `Cargo.toml` already carries —
*"Not published to crates.io. Only the name `cesauth` is reserved (0.0.0
placeholder, 2026-09-10). Flip this to `true` deliberately, per crate, if this
one is ever genuinely published — never by leaving it unset."* So the owner has
already made this decision once, in this form, and the discipline is written
down.

**Every member name is unregistered**, checked against the crates.io API
2026-11-12:

| name | status |
|---|---|
| `cesauth` | **registered**, 0.0.0, 2026-09-10 |
| `cesauth-core` | **available** |
| `cesauth-adapter-cloudflare` | **available** |
| `cesauth-adapter-test` | **available** |
| `cesauth-migrate` | **available** |
| `cesauth-frontend` | **available** |
| `cesauth-backend` | **available** |

**crates.io has no namespace reservation.** Owning `cesauth` confers nothing
over `cesauth-core` — the registry is flat and first-come. There is no prefix
claim, no organisation scope, and no mechanism to reclaim a name someone else
takes first.

## 2. The one part that is lost by waiting

Everything about *publishing* can wait indefinitely at no cost. **Name
availability cannot.** It is the only element of this question with a
first-come property, and it is closable for the price of six placeholder
publishes — the identical move already made for `cesauth` on 2026-09-10.

**§5.1 proposes exactly that and nothing more.**

## 3. Prerequisites already satisfied

Checked, not assumed:

- **Inter-member dependencies are already in publishable form.**
  `Cargo.toml:39-42` declares each as `{ version = "0", path = "crates/..." }`
  — the version is what crates.io needs, the path is what local builds use. A
  path-only dependency would have blocked publication outright; none exists.
- **Workspace metadata is present**: `license = "Apache-2.0"`, `repository`,
  `authors`, `edition`, `rust-version`, and `cesauth-core` carries its own
  `description`.
- **`publish = false` is explicit on all seven members**, with a comment
  requiring a deliberate per-crate flip. Nothing publishes by accident.

## 4. Prerequisites NOT satisfied — the honest list

These are why *real* publication is not being proposed today.

1. **`cesauth-core`'s public API has no external consumer and has never been
   read as one.** Every caller is in-workspace. Publishing a library invites
   people to depend on a surface nobody has reviewed from outside.
2. **The documentation others would read is known-wrong in places.**
   `route-contracts.md`'s audit-kind column names **15 of 42** strings the code
   does not produce. That is tracked, and it is the sort of thing a published
   crate's readers rely on.
3. **The 0.x semver contract needs stating for strangers.** `CHANGELOG.md` says
   the public surface "may change between minor versions" — correct and legal
   at 0.x, where a minor *is* the breaking slot. In-workspace that costs
   nothing; for an external dependent every minor is a potential break, and
   they should be told in the crate's own README, not only in a CHANGELOG
   preamble.
4. **`cargo publish --dry-run` has never been run.** Until it has, "we could
   publish" is a belief. It also needs checking that the package contains no
   `.dev.vars` or other local configuration — a packaging question, not a git
   question.
5. **Which crates should ever publish is undecided.** My reading:
   `cesauth-core` is the only plausible library; `cesauth-adapter-cloudflare`
   is arguable; `backend`, `frontend`, `migrate`, `adapter-test` and
   `migrate-test` are an application, a binary and two test harnesses, and I
   would not publish them beyond a placeholder. **That is a recommendation, not
   a decision.**

**This is deliberately not tied to 1.0.** Publishing at 0.x is ordinary and
widespread; 1.0 remains undeclared, unscoped and the owner's alone, and nothing
here should be read as a step toward it or a requirement of it.

## 5. Proposal

**§5.1 — Reserve the six names now.** Six `0.0.0` placeholder publishes, same
shape as `cesauth`'s. This is **irreversible**: a published version can be
yanked but never deleted, and the names become permanently associated with this
project. **It needs the owner's explicit authorization and I will not do it
otherwise.** My recommendation is to do it, because the cost is one afternoon's
irreversibility against a name that cannot be recovered if taken.

**§5.2 — Write down what "reasonable" means**, as criteria rather than a date,
in `docs/src/expert/contributing.md` beside the existing publish discipline:
`cargo publish --dry-run` clean and inspected for stray local configuration;
`cesauth-core`'s public surface reviewed from the outside at least once; the
0.x breaking-change contract stated in the crate's own README; and the
known-wrong documentation on the published surface corrected.

**§5.3 — Then publish `cesauth-core` alone**, as its own cut, with its own
review, once §5.2's criteria are met. Not bundled with feature work.

## 6. What I am not proposing

- **No real publication now.** §4 is not cleared.
- **No publishing the application crates** beyond placeholders.
- **No change to any `publish = false` flag in this RFC.** The flags are the
  safety mechanism; they get flipped one crate at a time, deliberately, as the
  comment already requires.
- **No coupling to 1.0.**

## 7. Risk I want on the record

A placeholder publish is **not** free of judgement: it makes the project's
existence and name permanent on a public registry, and the repository is
already public, so this adds reach rather than disclosure. If the owner would
rather the project stay unlisted for now, **the cost of that choice is the
possibility of losing `cesauth-core`**, and that is a legitimate trade to
decline. I am not treating "reserve it" as the obviously correct answer, only
as the one I would pick.
