//! UI routes.
//!
//! Exactly one endpoint right now: `GET /` and `GET /login`, which both
//! render the login page. Kept in its own module so that adding more
//! pages later (error, post-verify landing, admin console) is a matter
//! of dropping a new handler here rather than touching route plumbing.
//!
//! ## `next` handling (v0.31.0 P1-A)
//!
//! When a `/me/*` page redirects an unauthenticated user here, it
//! attaches `?next=<base64url(target)>`. We validate (reusing
//! `me::auth::decode_and_validate_next`) and on success stash the
//! encoded value in `__Host-cesauth_login_next`. After the user
//! signs in, `complete_auth_post_gate` reads the cookie and lands
//! them at the validated target.

use worker::{Request, Response, Result, RouteContext};

use crate::config::Config;
use crate::csrf;
use crate::log::{self, Category, Level};
use crate::routes::me::auth as me_auth;

/// `GET /` and `GET /login` — Leptos shell for the login page.
///
/// No session check; the login page is always public.  The Leptos
/// `Login` component renders the email form and the passkey button.
pub async fn login<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    crate::routes::leptos_shell::leptos_html_shell(
        &req, &ctx.env, "Sign in — cesauth", "en",
    ).await
}
