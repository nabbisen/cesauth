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

  /* v0.31.0: state tokens. Used by .flash--*, .badge--*, button.danger,
   * button.warning. Color values are derived from the v0.31.0 UI/UX
   * review materials (PNG #2 / #11) and tested for WCAG AA contrast
   * against --bg. Each foreground token is paired with a soft
   * background variant for flash/banner regions.
   *
   * IMPORTANT: never rely on color alone — every state has a
   * companion icon and text label per WCAG 1.4.1 (Use of Color).
   * The .flash and .badge templates emit these. */
  --success:    #1f9d55;
  --success-bg: #e8f5e9;
  --warning:    #b76e00;
  --warning-bg: #fff7e6;
  --danger:     #c92a2a;
  --danger-bg:  #fdecea;
  --info:       #1864ab;
  --info-bg:    #e7f5ff;
}

/* Dark-mode overrides. Light bg variants would wash out on a dark
 * canvas, so we shift to muted dark tints with the same hue family.
 * Foreground tokens get a brightness boost for contrast against the
 * dark canvas. Tested informally against macOS Dark Mode and Firefox
 * dark theme; if the deployment renders against an unusual canvas
 * (e.g., true #000), the legibility floor is still acceptable
 * because each state pairs color with text + icon. */
@media (prefers-color-scheme: dark) {
  :root {
    --success:    #4ade80;
    --success-bg: #14532d;
    --warning:    #fbbf24;
    --warning-bg: #78350f;
    --danger:     #f87171;
    --danger-bg:  #7f1d1d;
    --info:       #60a5fa;
    --info-bg:    #1e3a8a;
  }
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
/* v0.31.0: explicit danger / warning button states. The disable-TOTP
 * confirmation page uses button.danger for the confirm action; future
 * destructive flows should reuse it rather than inlining colors. */
button.danger {
  border-color: var(--danger);
  background:   var(--danger);
  color:        white;
}
button.danger:focus  { outline: 2px solid var(--danger); outline-offset: 2px; }
button.warning {
  border-color: var(--warning);
  background:   var(--bg);
  color:        var(--warning);
}
button.warning:focus { outline: 2px solid var(--warning); outline-offset: 2px; }
button:focus { outline: 2px solid var(--accent); outline-offset: 2px; }

.error {
  color: var(--err);
  border-left: 3px solid var(--err);
  padding: 0.5rem 0.75rem;
  margin: 1rem 0;
}

/* v0.31.0: flash banners. One-shot notifications rendered from the
 * __Host-cesauth_flash cookie (see crates/worker/src/flash.rs). The
 * .flash root carries role + aria-live so screen readers announce
 * without a focus-grab; level-specific styling lives on the
 * modifier classes. Each flash MUST include an icon + text label
 * (the template enforces this) so the message is legible without
 * color perception. */
.flash {
  display: flex;
  align-items: flex-start;
  gap: 0.6rem;
  padding: 0.75rem 1rem;
  margin: 1rem 0;
  border-left: 4px solid var(--muted);
  border-radius: 0.25rem;
  background: var(--bg);
}
.flash--success { border-left-color: var(--success); background: var(--success-bg); color: var(--success); }
.flash--warning { border-left-color: var(--warning); background: var(--warning-bg); color: var(--warning); }
.flash--danger  { border-left-color: var(--danger);  background: var(--danger-bg);  color: var(--danger);  }
.flash--info    { border-left-color: var(--info);    background: var(--info-bg);    color: var(--info);    }
.flash__icon  { font-weight: bold; flex-shrink: 0; }
.flash__text  { flex: 1; }

/* v0.31.0: state badges. Used by the Security Center to label
 * TOTP enabled/disabled state and recovery code remaining count.
 * Same icon-plus-text rule as .flash. */
.badge {
  display: inline-flex;
  align-items: center;
  gap: 0.3rem;
  padding: 0.15rem 0.55rem;
  border-radius: 999px;
  font-size: 0.85em;
  font-weight: 600;
  border: 1px solid currentColor;
  background: var(--bg);
}
.badge--success { color: var(--success); }
.badge--warning { color: var(--warning); }
.badge--danger  { color: var(--danger);  }
.badge--info    { color: var(--info);    }

.muted { color: var(--muted); font-size: 0.9em; }
footer { margin-top: 3rem; color: var(--muted); font-size: 0.8em; text-align: center; }

/* Shared utility for screen-reader-only text. Used to attach an
 * accessible label to icons that visually convey state (the icon is
 * decorative, the text is the source of truth for assistive tech). */
.visually-hidden {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}
"#;

/// View model for [`flash_block`]. Carries the level + display
/// text + icon needed to render a flash banner. The struct is
/// constructed by the worker's `flash` module via its public API
/// — `cesauth-ui` does not depend on the worker, so the worker
/// builds the FlashView from its own [`Flash`] before handing it
/// to the renderer.
///
/// The `text` is a `&'static str` because the worker emits it
/// from a closed token table (see `cesauth_worker::flash::FlashKey`),
/// not from user-supplied input. The renderer therefore does NOT
/// escape it; pinned by tests in this module.
///
/// `aria_live` is `"polite"` or `"assertive"`. `css_modifier` is
/// `"flash--success"` etc. `icon` is a single Unicode glyph.
#[derive(Debug, Clone, Copy)]
pub struct FlashView {
    pub aria_live:    &'static str,
    pub css_modifier: &'static str,
    pub icon:         &'static str,
    pub text:         &'static str,
}

/// Render a one-shot flash banner. Returns the empty string when
/// `view` is `None` so the caller can splice it into a body
/// unconditionally.
///
/// HTML shape:
///
/// ```html
/// <div class="flash flash--success" role="status" aria-live="polite">
///   <span class="flash__icon" aria-hidden="true">✓</span>
///   <span class="flash__text">TOTP を有効にしました。</span>
/// </div>
/// ```
///
/// Icon carries `aria-hidden="true"` because it's decorative —
/// screen readers announce the text. The accessibility floor is:
/// (a) a screen reader hears the text via aria-live, (b) a
/// sighted color-blind user reads the icon + text together with
/// the level conveyed by the colored border. Color is never the
/// sole carrier (WCAG 1.4.1).
pub fn flash_block(view: Option<FlashView>) -> String {
    let Some(v) = view else { return String::new(); };

    // role: alert for assertive, status for polite. Matches WAI-ARIA
    // best practice (role="alert" implies aria-live=assertive +
    // aria-atomic=true; we explicitly set aria-live anyway for
    // older AT compatibility).
    let role = if v.aria_live == "assertive" { "alert" } else { "status" };

    format!(
        r#"<div class="flash {modifier}" role="{role}" aria-live="{live}">
  <span class="flash__icon" aria-hidden="true">{icon}</span>
  <span class="flash__text">{text}</span>
</div>"#,
        modifier = v.css_modifier,
        role     = role,
        live     = v.aria_live,
        icon     = v.icon,
        text     = v.text,
    )
}

fn frame(title: &str, body: &str) -> String {
    frame_with_flash(title, "", body)
}

/// Like [`frame`] but allows the caller to splice a flash banner
/// at the top of `<main>`. `flash_html` should typically come from
/// [`flash_block`]; an empty string yields a flash-less page.
fn frame_with_flash(title: &str, flash_html: &str, body: &str) -> String {
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
{flash}
{body}
</main>
<footer>cesauth</footer>
</body>
</html>
"#,
        title = escape(title),
        css   = BASE_CSS,
        flash = flash_html,
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
///
/// `error`: optional inline error rendered above the confirm form.
/// Set to `Some(msg)` when the previous confirm POST failed (wrong
/// code or replay-protection rejection); `None` for the initial
/// render. Mirrors the `totp_verify_page` shape so handlers across
/// the TOTP flow have a uniform error surface.
///
/// When `error` is `Some`, the code input keeps `autofocus` so the
/// user lands on the form field after the page re-renders. Pin
/// reasoning: a wrong code mid-enrollment means the user already
/// has the authenticator app open; sending them back to the QR
/// code is wasted motion. Focus on the input invites the next
/// fresh code.
pub fn totp_enroll_page(
    qr_svg:     &str,
    secret_b32: &str,
    csrf_token: &str,
    error:      Option<&str>,
) -> String {
    let err_block = match error {
        Some(msg) => format!(
            r#"<div class="error" role="alert" aria-live="assertive">{}</div>"#,
            escape(msg),
        ),
        None => String::new(),
    };

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

{err_block}

<form method="POST" action="/me/security/totp/enroll/confirm" aria-labelledby="confirm-heading">
  <h2 id="confirm-heading">Confirm with a code</h2>
  <p>After scanning, your app will display a 6-digit code that
  changes every 30 seconds. Enter the current code to finish setup.</p>
  <input type="hidden" name="csrf" value="{csrf}">
  <label for="code">Current code</label>
  <input id="code" name="code" type="text" required autocomplete="one-time-code"
         inputmode="numeric" pattern="[0-9]{{6}}" maxlength="6"
         spellcheck="false" autofocus>
  <button type="submit">Confirm and enable</button>
</form>

<p class="muted"><a href="/">Cancel and go back</a></p>"#,
        qr_svg    = qr_svg, // pre-validated SVG, intentionally NOT escaped
        secret    = escape(secret_b32),
        err_block = err_block,
        csrf      = escape(csrf_token),
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

<p><a href="/me/security">I've saved them — continue</a></p>"#,
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

/// TOTP disable confirmation page. Shown by `GET /me/security/totp/disable`
/// when the user requests TOTP removal. The form POSTs to the same
/// path; on success the worker deletes the user's TOTP authenticators
/// + recovery codes and redirects with a success notice.
///
/// Disabling TOTP is destructive in the sense that the user loses
/// MFA on their account, and any unredeemed recovery codes are
/// also wiped. The page emphasizes both consequences and requires
/// an explicit confirm click — no "are you sure" double-prompt
/// (one click is enough; the consequences are clearly stated and
/// re-enrolling takes one minute).
///
/// `csrf_token` matches the `__Host-cesauth-csrf` cookie value
/// for the POST guard. v0.30.0 surface.
pub fn totp_disable_confirm_page(csrf_token: &str) -> String {
    let body = format!(
        r#"<h1>Disable two-factor authentication?</h1>
<div class="warning" role="alert" aria-live="polite">
  <strong>This will turn off TOTP for your account.</strong>
  Your authenticator app's entry will stop working, and any unused
  recovery codes will also be deleted. You can re-enable TOTP
  later by enrolling a new authenticator.
</div>

<p>If you've lost access to your authenticator, you can recover
with a one-time code from your enrollment instead — that path is
on the sign-in screen, not here.</p>

<form method="POST" action="/me/security/totp/disable" aria-labelledby="disable-heading">
  <h2 id="disable-heading" class="muted">Confirm</h2>
  <input type="hidden" name="csrf" value="{csrf}">
  <button type="submit" class="danger">Yes, disable TOTP</button>
</form>

<p class="muted"><a href="/">Cancel and go back</a></p>"#,
        csrf = escape(csrf_token),
    );
    frame("Disable TOTP - cesauth", &body)
}

// =====================================================================
// /me/security — Security Center index page (v0.31.0 P0-A)
// =====================================================================

/// Primary authentication method for the current session — used
/// by the Security Center to label "how you sign in". Surfaces
/// only as display copy; no security decision rides on this
/// value. Set by the worker from the session record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimaryAuthMethod {
    /// WebAuthn / Passkey. Already MFA-strong (device possession
    /// + on-device user verification), so TOTP is bypassed in
    /// `complete_auth`.
    Passkey,
    /// Magic Link via email. TOTP gate applies on top of this.
    MagicLink,
    /// Anonymous trial principal. Cannot enroll TOTP; the page
    /// renders without TOTP controls.
    Anonymous,
}

impl PrimaryAuthMethod {
    fn label(self) -> &'static str {
        match self {
            Self::Passkey   => "パスキー",
            Self::MagicLink => "メールリンク",
            Self::Anonymous => "匿名トライアル",
        }
    }
}

/// View state for [`security_center_page`]. Built by the worker
/// handler from the session + TOTP repo lookups; the template is
/// a pure projection of this struct.
///
/// `recovery_codes_remaining` is the result of
/// `RecoveryRepo::count_remaining` for the current user. Only
/// meaningful when `totp_enabled` is `true` — the rendering
/// suppresses the recovery section when TOTP is off, since
/// unconfirmed users have no codes.
#[derive(Debug, Clone, Copy)]
pub struct SecurityCenterState {
    pub primary_method:           PrimaryAuthMethod,
    pub totp_enabled:             bool,
    pub recovery_codes_remaining: u32,
}

/// Render the Security Center index page.
///
/// Design rules (plan v2 §3.1 P0-A):
///
/// - **Single task per page**: this page only displays state and
///   links to specialized actions (`/me/security/totp/enroll`,
///   `/me/security/totp/disable`). No enrollment, disable, or
///   recovery flow runs from here directly.
/// - **State as text + icon + color** (WCAG 1.4.1): every badge
///   carries an icon glyph + label, never color alone.
/// - **Recovery threshold**: N=10 / 2-9 → info; N=1 → warning;
///   N=0 → danger. The threshold rationale is in plan §3.1 P0-A.
///   No early "you should re-enroll" pressure because the
///   re-enrollment path is heavy.
/// - **Anonymous users**: the TOTP section is hidden; they see
///   only their primary-method label + a hint that TOTP becomes
///   available after promotion.
pub fn security_center_page(state: &SecurityCenterState) -> String {
    security_center_page_with_flash(state, "")
}

/// Same as [`security_center_page`] but allows the caller to
/// splice a flash banner above the page content. The Security
/// Center handler builds the banner from
/// `__Host-cesauth_flash`; other callers can pass `""` to get
/// the flash-less rendering (matching the legacy entry point).
pub fn security_center_page_with_flash(
    state:      &SecurityCenterState,
    flash_html: &str,
) -> String {
    let primary_row = format!(
        r#"<section class="security-row" aria-labelledby="primary-heading">
  <h2 id="primary-heading">サインイン方法</h2>
  <p>{label}</p>
</section>"#,
        label = escape(state.primary_method.label()),
    );

    let totp_section = match state.primary_method {
        PrimaryAuthMethod::Anonymous => format!(
            r#"<section class="security-row" aria-labelledby="totp-heading">
  <h2 id="totp-heading">二段階認証 (TOTP)</h2>
  <p class="muted">匿名トライアルでは TOTP を有効化できません。
  通常アカウントへの promote 後に有効化できます。</p>
</section>"#,
        ),
        _ => totp_section_html(state.totp_enabled, state.recovery_codes_remaining),
    };

    let body = format!(
        r#"<h1>セキュリティ</h1>
<p class="muted">サインインと二段階認証の状態を確認します。</p>

{primary_row}

{totp_section}

<section class="security-row" aria-labelledby="sessions-heading">
  <h2 id="sessions-heading">アクティブなセッション</h2>
  <p>サインイン中の端末/ブラウザを一覧表示し、不要なセッションを取り消せます。</p>
  <p><a href="/me/security/sessions">セッションを確認する</a></p>
</section>

<p class="muted"><a href="/">トップへ戻る</a></p>"#,
        primary_row = primary_row,
        totp_section = totp_section,
    );
    frame_with_flash("セキュリティ - cesauth", flash_html, &body)
}

/// TOTP subsection of the Security Center. Branches on
/// `enabled`; when enabled, also renders the recovery-codes
/// status row with the 4-tier threshold treatment from plan
/// §3.1 P0-A.
fn totp_section_html(enabled: bool, recovery_remaining: u32) -> String {
    if !enabled {
        return r#"<section class="security-row" aria-labelledby="totp-heading">
  <h2 id="totp-heading">二段階認証 (TOTP)</h2>
  <p>
    <span class="badge badge--info">
      <span aria-hidden="true">ⓘ</span>
      <span>無効</span>
    </span>
  </p>
  <p>Authenticator アプリで生成する 6 桁コードによる二段階認証を有効にできます。
  パスキーをお使いの場合は既に強力な認証が有効なので、TOTP は任意です。</p>
  <p><a href="/me/security/totp/enroll">TOTP を有効化する</a></p>
</section>"#.to_owned();
    }

    let recovery_row = recovery_status_html(recovery_remaining);

    format!(
        r#"<section class="security-row" aria-labelledby="totp-heading">
  <h2 id="totp-heading">二段階認証 (TOTP)</h2>
  <p>
    <span class="badge badge--success">
      <span aria-hidden="true">✓</span>
      <span>有効</span>
    </span>
  </p>
  {recovery_row}
  <p><a href="/me/security/totp/disable">TOTP を無効化する</a></p>
</section>"#,
        recovery_row = recovery_row,
    )
}

/// Recovery-codes status block. Four-tier rendering per plan
/// §3.1 P0-A:
///
/// - N=10 → info badge, no supporting text (initial state).
/// - N=2–9 → info badge with the count, no supporting text.
/// - N=1 → warning badge + supporting text encouraging
///   re-enrollment. This is the first tier where the action
///   ("re-enroll") is truly justified.
/// - N=0 → danger badge + clear "operator contact required"
///   message.
fn recovery_status_html(n: u32) -> String {
    match n {
        0 => r#"<div class="flash flash--danger" role="alert" aria-live="assertive">
    <span class="flash__icon" aria-hidden="true">⛔</span>
    <span class="flash__text">
      <strong>リカバリーコード残なし。</strong>
      authenticator を失うと管理者連絡が必要です。
    </span>
  </div>"#.to_owned(),

        1 => r#"<div class="flash flash--warning" role="alert" aria-live="assertive">
    <span class="flash__icon" aria-hidden="true">⚠</span>
    <span class="flash__text">
      <strong>リカバリーコード: 残り 1 個。</strong>
      次に authenticator を失うと管理者連絡が必要になります。
      TOTP を一度無効化して再 enroll すると 10 個に戻せます。
    </span>
  </div>"#.to_owned(),

        n => format!(
            r#"<p>
    <span class="badge badge--info">
      <span aria-hidden="true">ⓘ</span>
      <span>リカバリーコード: {n} 個有効</span>
    </span>
  </p>"#,
        ),
    }
}


// =====================================================================
// v0.35.0 — /me/security/sessions page
// =====================================================================

/// One row in the active-sessions list. The handler builds these
/// from `SessionState` rows returned by
/// `ActiveSessionStore::list_for_user`. Kept here (vs. importing
/// `SessionState` directly) so the template's contract is
/// surface-stable: future changes to `SessionState` shape won't
/// silently change what the user sees.
#[derive(Debug, Clone)]
pub struct SessionListItem {
    pub session_id:    String,
    pub auth_method:   String,   // "passkey" | "magic_link" | "admin"
    pub client_id:     String,   // displayed; empty string is fine
    pub created_at:    i64,      // Unix seconds
    pub last_seen_at:  i64,      // Unix seconds; matches created_at on D1-projected rows
    /// `true` if this row is the session that's currently
    /// rendering the page. Surfaced as a "this device" badge
    /// and disables the row's revoke button (revoking your
    /// current session would just log you out — handle that
    /// via the regular logout flow).
    pub is_current:    bool,
}

pub fn sessions_page(
    items:      &[SessionListItem],
    csrf_token: &str,
    flash_html: &str,
) -> String {
    let rows = if items.is_empty() {
        r##"<p class="muted">アクティブなセッションはありません。</p>"##.to_owned()
    } else {
        items.iter().map(|s| render_session_row(s, csrf_token)).collect::<Vec<_>>().join("\n")
    };

    let body = format!(
        r##"<h1>アクティブなセッション</h1>
<p class="muted">サインイン中の端末/ブラウザの一覧です。心当たりのないセッションは右側のボタンで取り消してください。</p>

<section class="security-section" aria-label="Active sessions">
  {rows}
</section>

<p class="muted">
  <a href="/me/security">← セキュリティ センターへ戻る</a>
</p>"##,
        rows  = rows,
    );

    frame_with_flash("アクティブなセッション - cesauth", flash_html, &body)
}

fn render_session_row(s: &SessionListItem, csrf_token: &str) -> String {
    let method_label = match s.auth_method.as_str() {
        "passkey"    => "パスキー",
        "magic_link" => "Magic Link",
        "admin"      => "管理者ログイン",
        _            => "不明",
    };
    let created = format_unix_local(s.created_at);
    let last    = format_unix_local(s.last_seen_at);

    let badge = if s.is_current {
        r##"<span class="badge badge--current" aria-label="この端末">この端末</span>"##
    } else {
        ""
    };

    // Current session's revoke button is disabled — the user
    // should log out via the normal flow instead. If we let
    // them revoke their own session, the next request would
    // redirect to /login and the action would feel
    // self-defeating; logout-via-known-button is better UX.
    let action = if s.is_current {
        r##"<button type="button" class="muted" disabled aria-disabled="true" title="このセッションは現在使用中です。ログアウトはトップページからどうぞ。">使用中</button>"##.to_owned()
    } else {
        format!(
            r##"<form method="post" action="/me/security/sessions/{sid}/revoke" class="inline-form">
  <input type="hidden" name="csrf" value="{csrf}">
  <button type="submit" class="warning">取り消す</button>
</form>"##,
            sid  = escape(&s.session_id),
            csrf = escape(csrf_token),
        )
    };

    format!(
        r##"<article class="session-card" aria-label="セッション {sid}">
  <header>
    <strong>{method}</strong> {badge}
  </header>
  <dl class="session-meta">
    <dt>サインイン</dt><dd>{created}</dd>
    <dt>最終アクセス</dt><dd>{last}</dd>
    <dt>クライアント</dt><dd><code>{client}</code></dd>
    <dt>セッション ID</dt><dd><code>{sid_short}</code></dd>
  </dl>
  <footer>{action}</footer>
</article>"##,
        sid       = escape(&s.session_id),
        sid_short = escape(&shorten_id(&s.session_id)),
        method    = method_label,
        badge     = badge,
        created   = escape(&created),
        last      = escape(&last),
        client    = escape(&s.client_id),
        action    = action,
    )
}

/// Format a Unix-seconds timestamp as ISO-8601 UTC. The user
/// page is otherwise localized JA, but timestamp formatting
/// stays UTC because cesauth has no per-user timezone yet —
/// see ROADMAP i18n track for that future work.
fn format_unix_local(unix: i64) -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|d| d.format(&Rfc3339).ok())
        .unwrap_or_else(|| unix.to_string())
}

/// Truncate a UUID-shaped session_id to the first 8 chars for
/// display. The full id is in the form action's URL; the
/// shortened version is just visual chrome.
fn shorten_id(id: &str) -> String {
    let mut out: String = id.chars().take(8).collect();
    if id.chars().count() > 8 { out.push('…'); }
    out
}

#[cfg(test)]
mod tests;

