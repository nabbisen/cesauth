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
pub fn magic_link_sent_page() -> String {
    let body = r#"
<h1>Check your inbox</h1>
<p>If that address is registered, we've just sent a one-time code. It expires in 10 minutes.</p>

<form method="POST" action="/magic-link/verify" aria-labelledby="otp-heading">
  <h2 id="otp-heading" class="muted">Enter the code</h2>
  <label for="code">One-time code</label>
  <input id="code" name="code" type="text" required autocomplete="one-time-code"
         inputmode="text" spellcheck="false" pattern="[A-Za-z0-9]{6,12}">
  <button type="submit">Continue</button>
</form>
"#;
    frame("Check your inbox - cesauth", body)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_page_contains_aria_live_region() {
        let html = login_page("t", None, None);
        assert!(html.contains("aria-live=\"assertive\""));
    }

    #[test]
    fn login_page_escapes_csrf_token() {
        let html = login_page("a\"b", None, None);
        assert!(html.contains(r#"value="a&quot;b""#));
        assert!(!html.contains(r#"value="a"b""#));
    }

    #[test]
    fn error_page_escapes_detail() {
        let html = error_page("oops", "<script>");
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<script>"));
    }
}
