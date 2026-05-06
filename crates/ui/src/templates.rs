//! HTML templates.
//!
//! Shape contract: every page is a full HTML5 document. The worker
//! crate wraps each string below in a `Response` with the correct
//! `Content-Type` and CSP headers. Style is inline-scoped to the page
//! to avoid shipping a separate CSS file for a handful of rules.

use crate::escape;

/// A small stylesheet common to every page. Deliberately modest:
/// system font stack, high contrast, no vendor CSS reset.
const BASE_CSS: &str = r#"
:root {
  color-scheme: light dark;
  --bg: Canvas;
  --fg: CanvasText;
  --muted: GrayText;
  --accent: #2753c8;
  --err: #a6261d;
}
* { box-sizing: border-box; }
html, body {
  margin: 0;
  padding: 0;
  background: var(--bg);
  color: var(--fg);
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  line-height: 1.5;
}
main {
  max-width: 28rem;
  margin: 3rem auto;
  padding: 1.5rem;
}
h1 { font-size: 1.5rem; margin: 0 0 1rem; }
p  { margin: 0 0 1rem; }
label { display: block; margin: 1rem 0 0.25rem; font-weight: 600; }
input[type="email"],
input[type="text"] {
  width: 100%;
  padding: 0.5rem 0.75rem;
  border: 1px solid var(--muted);
  border-radius: 0.25rem;
  font: inherit;
  background: var(--bg);
  color: var(--fg);
}
input:focus { outline: 2px solid var(--accent); outline-offset: 2px; }
button {
  margin-top: 1rem;
  padding: 0.5rem 1rem;
  border: 1px solid var(--accent);
  background: var(--accent);
  color: white;
  font: inherit;
  border-radius: 0.25rem;
  cursor: pointer;
}
button.secondary {
  background: var(--bg);
  color: var(--accent);
}
button:focus { outline: 2px solid var(--accent); outline-offset: 2px; }
.error {
  color: var(--err);
  border-left: 3px solid var(--err);
  padding: 0.5rem 0.75rem;
  margin: 1rem 0;
}
.muted { color: var(--muted); font-size: 0.9em; }
footer { margin-top: 3rem; color: var(--muted); font-size: 0.8em; text-align: center; }
"#;

fn frame(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{title}</title>
  <style>{css}</style>
</head>
<body>
<main>
{body}
</main>
<footer>cesauth</footer>
</body>
</html>
"#,
        title = escape(title),
        css   = BASE_CSS,
        body  = body,
    )
}

/// The initial login page. Passkey attempt runs first on load
/// (progressive enhancement); the email fallback form is always in the
/// DOM so users without JS can still proceed.
///
/// `turnstile_sitekey` is the public site-key for Cloudflare Turnstile.
/// When `Some`, the Turnstile loader script is included and a widget
/// is inserted in the email form - the widget writes a hidden
/// `cf-turnstile-response` field that `/magic-link/request` validates
/// server-side. When `None`, the page is Turnstile-free (no script is
/// loaded, no `data-sitekey` attribute with an empty value is emitted;
/// both would be error cases at the widget level).
pub fn login_page(
    csrf_token:        &str,
    error:             Option<&str>,
    turnstile_sitekey: Option<&str>,
) -> String {
    let err_region = match error {
        Some(msg) => format!(
            r#"<div class="error" role="alert" aria-live="assertive">{}</div>"#,
            escape(msg),
        ),
        None => String::from(
            r#"<div class="error" role="alert" aria-live="assertive" hidden></div>"#,
        ),
    };

    // Only emit the Turnstile bits when we actually have a sitekey.
    // An empty `data-sitekey=""` renders a broken widget.
    let (turnstile_script, turnstile_widget) = match turnstile_sitekey {
        Some(sk) if !sk.is_empty() => (
            String::from(
                r#"<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>"#,
            ),
            format!(
                r#"<div class="cf-turnstile" data-sitekey="{}"></div>"#,
                escape(sk),
            ),
        ),
        _ => (String::new(), String::new()),
    };

    // The inline script is tiny and purely progressive: the form works
    // without it. We still set `defer` so it runs after the DOM exists.
    let body = format!(r#"
<h1>Sign in</h1>
<p>Use your passkey if you have one. Otherwise, enter your email and we'll send you a one-time code.</p>

{turnstile_script}

{err_region}

<noscript>
  <p class="muted">Passkey sign-in requires JavaScript. Use the email option below.</p>
</noscript>

<section aria-labelledby="passkey-heading">
  <h2 id="passkey-heading" class="muted">Passkey</h2>
  <button id="passkey-btn" type="button">Sign in with a passkey</button>
</section>

<form method="POST" action="/magic-link/request" aria-labelledby="mail-heading">
  <h2 id="mail-heading" class="muted">Or email me a code</h2>
  <input type="hidden" name="csrf" value="{csrf}">
  <label for="email">Email address</label>
  <input id="email" name="email" type="email" required autocomplete="email"
         inputmode="email" spellcheck="false">
  {turnstile_widget}
  <button type="submit" class="secondary">Email me a code</button>
</form>

<script defer>
(async () => {{
  const btn = document.getElementById("passkey-btn");
  const err = document.querySelector(".error[role='alert']");
  if (!window.PublicKeyCredential) {{
    btn.disabled = true;
    return;
  }}
  btn.addEventListener("click", async () => {{
    err.hidden = true;
    try {{
      const r = await fetch("/webauthn/authenticate/start", {{ method: "POST" }});
      if (!r.ok) throw new Error("could not start");
      const opts = await r.json();
      // navigator.credentials.get() expects ArrayBuffer values; convert.
      const cred = await navigator.credentials.get({{ publicKey: decode(opts.publicKey) }});
      const f = await fetch("/webauthn/authenticate/finish", {{
        method: "POST",
        headers: {{ "content-type": "application/json" }},
        body: JSON.stringify(encode(cred)),
      }});
      if (!f.ok) throw new Error("authentication failed");
      window.location.href = "/";
    }} catch (e) {{
      err.textContent = "Passkey sign-in didn't work. Try the email option.";
      err.hidden = false;
    }}
  }});

  // Minimal base64url <-> ArrayBuffer helpers. Intentionally inlined
  // to keep the page dependency-free.
  function b64urlToBuf(s) {{
    const p = s.length % 4 === 0 ? "" : "=".repeat(4 - s.length % 4);
    const b = atob((s + p).replace(/-/g, "+").replace(/_/g, "/"));
    const u = new Uint8Array(b.length);
    for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
    return u.buffer;
  }}
  function bufToB64url(b) {{
    const u = new Uint8Array(b);
    let s = "";
    for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }}
  function decode(opts) {{
    const o = {{ ...opts }};
    o.challenge = b64urlToBuf(o.challenge);
    if (o.allowCredentials) o.allowCredentials = o.allowCredentials.map(c => (
      {{ ...c, id: b64urlToBuf(c.id) }}
    ));
    return o;
  }}
  function encode(cred) {{
    return {{
      id:     cred.id,
      rawId:  bufToB64url(cred.rawId),
      type:   cred.type,
      response: {{
        clientDataJSON:    bufToB64url(cred.response.clientDataJSON),
        authenticatorData: bufToB64url(cred.response.authenticatorData),
        signature:         bufToB64url(cred.response.signature),
        userHandle:        cred.response.userHandle ? bufToB64url(cred.response.userHandle) : null,
      }},
    }};
  }}
}})();
</script>
"#,
        err_region       = err_region,
        csrf             = escape(csrf_token),
        turnstile_script = turnstile_script,
        turnstile_widget = turnstile_widget,
    );

    frame("Sign in - cesauth", &body)
}

/// Page shown after a Magic Link has been sent. Does not reveal whether
/// the email existed (account enumeration mitigation).
///
/// `handle` is the AuthChallenge handle from the prior `/magic-link/request`
/// step. The verify endpoint needs it to look up the challenge.
/// `csrf_token` is the CSRF token (matching the
/// `__Host-cesauth-csrf` cookie) required by `/magic-link/verify`'s
/// form-encoded path. Both fields land as hidden inputs so the
/// browser carries them on submission.
///
/// Pre-v0.25.0 this template took no arguments and rendered a form
/// missing both fields, which made the form-flow path unusable in
/// browsers (the verify handler returns 400 on empty handle, and
/// the v0.24.0 CSRF gap fill rejects empty csrf). The path was
/// failing closed but invisible-to-users. v0.25.0 fixes the UX and
/// adds an end-to-end form test (see `tests.rs`).
pub fn magic_link_sent_page(handle: &str, csrf_token: &str) -> String {
    let body = format!(
        r#"
<h1>Check your inbox</h1>
<p>If that address is registered, we've just sent a one-time code. It expires in 10 minutes.</p>

<form method="POST" action="/magic-link/verify" aria-labelledby="otp-heading">
  <h2 id="otp-heading" class="muted">Enter the code</h2>
  <input type="hidden" name="handle" value="{handle}">
  <input type="hidden" name="csrf"   value="{csrf}">
  <label for="code">One-time code</label>
  <input id="code" name="code" type="text" required autocomplete="one-time-code"
         inputmode="text" spellcheck="false" pattern="[A-Za-z0-9]{{6,12}}">
  <button type="submit">Continue</button>
</form>
"#,
        handle = escape(handle),
        csrf   = escape(csrf_token),
    );
    frame("Check your inbox - cesauth", &body)
}

/// Generic error page. The worker layer maps specific errors to strings
/// (we do not leak internal detail here).
pub fn error_page(title: &str, detail: &str) -> String {
    let body = format!(
        r#"<h1>{title}</h1>
<div class="error" role="alert" aria-live="assertive">{detail}</div>
<p><a href="/">Back to sign in</a></p>"#,
        title  = escape(title),
        detail = escape(detail),
    );
    frame(title, &body)
}

// =====================================================================
// TOTP enrollment + verify pages (v0.28.0)
// =====================================================================

/// TOTP enrollment page. Shown by `GET /me/security/totp/enroll`
/// after a fresh secret has been minted and an unconfirmed
/// `totp_authenticators` row parked.
///
/// The user scans `qr_svg` with their authenticator app (or
/// types `secret_b32` manually if they can't scan), then enters
/// the displayed code into the form which POSTs to
/// `/me/security/totp/enroll/confirm`.
///
/// The QR code is server-rendered SVG (no JavaScript dependency,
/// no third-party CDN). `qr_svg` is the raw `<svg>...</svg>`
/// payload which we inline into the page (it's already trusted
/// — generated by our own code, not user input — but we still
/// avoid escaping it so the SVG renders).
///
/// `csrf_token` matches the `__Host-cesauth-csrf` cookie value
/// for the POST guard.
pub fn totp_enroll_page(qr_svg: &str, secret_b32: &str, csrf_token: &str) -> String {
    let body = format!(
        r#"<h1>Set up an authenticator</h1>
<p>Scan this QR code with Google Authenticator, Authy, 1Password,
or any other RFC 6238 TOTP app:</p>

<figure class="qr-figure" aria-label="QR code containing your TOTP secret">
{qr_svg}
</figure>

<details>
  <summary>Can't scan? Enter the key manually:</summary>
  <p class="muted">Algorithm: SHA-1 · Digits: 6 · Period: 30 seconds</p>
  <pre class="totp-secret"><code>{secret}</code></pre>
</details>

<form method="POST" action="/me/security/totp/enroll/confirm" aria-labelledby="confirm-heading">
  <h2 id="confirm-heading">Confirm with a code</h2>
  <p>After scanning, your app will display a 6-digit code that
  changes every 30 seconds. Enter the current code to finish setup.</p>
  <input type="hidden" name="csrf" value="{csrf}">
  <label for="code">Current code</label>
  <input id="code" name="code" type="text" required autocomplete="one-time-code"
         inputmode="numeric" pattern="[0-9]{{6}}" maxlength="6"
         spellcheck="false">
  <button type="submit">Confirm and enable</button>
</form>

<p class="muted"><a href="/">Cancel and go back</a></p>"#,
        qr_svg = qr_svg, // pre-validated SVG, intentionally NOT escaped
        secret = escape(secret_b32),
        csrf   = escape(csrf_token),
    );
    frame("Set up an authenticator - cesauth", &body)
}

/// Recovery-codes display page. Shown ONCE after successful
/// enrollment confirmation. `codes` are the plaintext recovery
/// codes minted in this enrollment; this is the only time the
/// user will ever see them.
///
/// The page emphasizes this with strong visual treatment and a
/// confirm checkbox. There is no "show again" path — that's the
/// whole point of the at-rest hash. If the user navigates away
/// before saving, they have to disable TOTP and re-enroll to
/// get fresh codes.
pub fn totp_recovery_codes_page(codes: &[String]) -> String {
    let codes_html: String = codes.iter()
        .map(|c| format!("<li><code>{}</code></li>", escape(c)))
        .collect::<Vec<_>>()
        .join("\n");

    let body = format!(
        r#"<h1>Save your recovery codes</h1>
<div class="warning" role="alert" aria-live="assertive">
  <strong>This is the only time these codes will be shown.</strong>
  Save them somewhere safe (a password manager, a printed copy in a
  drawer). Each code can be used once if you lose access to your
  authenticator.
</div>

<ul class="totp-recovery-codes">
{codes}
</ul>

<p>You'll need a recovery code to sign in if your authenticator is
unavailable. Once a code is used, it can't be reused.</p>

<p><a href="/">I've saved them — continue</a></p>"#,
        codes = codes_html,
    );
    frame("Save your recovery codes - cesauth", &body)
}

/// TOTP verify page. Shown by `GET /me/security/totp/verify`
/// when the post-MagicLink gate has parked a `PendingTotp`
/// challenge. The user enters their current 6-digit code, the
/// form POSTs to the same path, and on success the original
/// authentication flow resumes (session start, AR redirect).
///
/// `csrf_token` matches the `__Host-cesauth-csrf` cookie. The
/// pending TOTP handle is carried in the `__Host-cesauth_totp`
/// cookie set by `complete_auth`, NOT in the form (it's
/// session state, not user input).
///
/// `error` is `None` for the initial page render; `Some(message)`
/// when the previous attempt's code was invalid (so the page
/// can show the error inline). Pre-empted attempts (cookie
/// missing / challenge expired) redirect to `/login` rather
/// than re-render this page.
pub fn totp_verify_page(csrf_token: &str, error: Option<&str>) -> String {
    let error_block = match error {
        Some(msg) => format!(
            r#"<div class="error" role="alert" aria-live="assertive">{}</div>"#,
            escape(msg)
        ),
        None => String::new(),
    };

    let body = format!(
        r#"<h1>Enter your code</h1>
<p>For added security, your account is protected by an
authenticator app. Enter the 6-digit code your app shows now.</p>

{error_block}

<form method="POST" action="/me/security/totp/verify" aria-labelledby="verify-heading">
  <h2 id="verify-heading" class="muted">Authenticator code</h2>
  <input type="hidden" name="csrf" value="{csrf}">
  <label for="code">6-digit code</label>
  <input id="code" name="code" type="text" required autocomplete="one-time-code"
         inputmode="numeric" pattern="[0-9]{{6}}" maxlength="6"
         spellcheck="false" autofocus>
  <button type="submit">Continue</button>
</form>

<details class="muted">
  <summary>Lost your authenticator?</summary>
  <p>Use a recovery code from your enrollment instead:</p>
  <form method="POST" action="/me/security/totp/recover" aria-labelledby="recover-heading">
    <span id="recover-heading" class="visually-hidden">Recover with a one-time code</span>
    <input type="hidden" name="csrf" value="{csrf}">
    <label for="recovery-code">Recovery code</label>
    <input id="recovery-code" name="code" type="text" required
           autocomplete="off" inputmode="text"
           pattern="[A-Za-z0-9 \-]+"
           maxlength="13"
           spellcheck="false">
    <button type="submit">Use recovery code</button>
  </form>
</details>"#,
        error_block = error_block,
        csrf        = escape(csrf_token),
    );
    frame("Enter your code - cesauth", &body)
}

#[cfg(test)]
mod tests;
