# `prompt` & `max_age` handling

OIDC Core §3.1.2.1 defines four values for `prompt`:

| Value             | cesauth support    | Outcome when used              |
|-------------------|--------------------|--------------------------------|
| `none`            | ✅ supported       | Short-circuit if session valid, else `login_required` |
| `login`           | ✅ supported       | Force re-authentication         |
| `consent`         | ❌ rejected        | `invalid_request` error        |
| `select_account`  | ❌ rejected        | `invalid_request` error        |

The two rejected values are rejected at validation time rather than
silently ignored. A client that relies on them cannot fail open.

## `prompt=none`

The client asserts it has a logged-in user and wants to skip the
login page. Three cases:

- **Session valid (ActiveSessionStore says `Active`, passes
  max_age):** mint an auth code and 302 to the client's
  `redirect_uri`. No UI.
- **Session invalid:** 302 to `redirect_uri?error=login_required`.
  Never show the login page when `prompt=none` is set.
- **Session partially valid (e.g., account disabled):** map to the
  appropriate OIDC error (`login_required`, `interaction_required`,
  `account_selection_required`). Never swallow.

This is the SSO path for return visits. If the user has a valid
session they see an instant redirect; if not, the client knows to
start a non-silent flow.

## `prompt=login`

The client asserts that fresh authentication is required, regardless
of any existing session. cesauth skips the session short-circuit and
always renders the login page. After successful auth,
`post_auth::complete_auth` runs as usual. The existing session is
NOT invalidated — `prompt=login` is about the current flow, not
about ending the session globally.

## `max_age`

`max_age` is an integer in seconds. If provided, cesauth treats any
session older than `now - max_age` as inadequate for the current AR
— even though the session is still valid for other purposes.

The check happens at the same point as the session short-circuit:

```rust
fn session_satisfies_max_age(session: &ActiveSession,
                             max_age: Option<i64>,
                             now: i64) -> bool {
    match max_age {
        None    => true,
        Some(m) => session.authenticated_at + m >= now,
    }
}
```

A failed `max_age` check goes down the same path as a missing
session: if `prompt=none` is also set, return `login_required`;
otherwise render the login page.

The `authenticated_at` field is written by `post_auth::complete_auth`
on each successful auth (not by `touch`, which only extends
inactivity timeouts). So `max_age` measures time since the user
actually proved identity — re-proving via the login page resets it.

## `auth_time` claim

When a client sends `max_age` or requests the `auth_time` claim via
`claims` parameter (not yet supported), the resulting ID token MUST
include `auth_time`. cesauth always includes it regardless, taken
from `session.authenticated_at`, because it is a small integer and
clients that don't need it ignore it.
