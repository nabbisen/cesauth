/**
 * cesauth WebAuthn helper — crates/frontend/static/webauthn.js
 *
 * Provides `cesauthPasskeyAuthenticate()` for the Leptos login component.
 * Loaded as a module in the HTML shell's CSP-nonced bootstrap <script>.
 *
 * ## Security
 * - Loaded via `<script type="module" nonce="…">` — satisfies strict
 *   `script-src 'nonce-…'` CSP.
 * - No eval, no dynamic imports beyond the wasm bundle.
 * - Exposes one function on `window.__cesauth` (set by the shell script);
 *   the Rust/WASM component calls it via js_sys reflection.
 *
 * ## Serialisation note
 * The webauthn-rs `AuthenticationResponse` expects camelCase JSON with
 * base64url-no-pad encoded binary fields.  `b64url()` below produces that
 * encoding.  The `response` sub-object mirrors the `PublicKeyCredential
 * .response` shape exactly as the browser exposes it.
 */

const b64url = buf =>
    btoa(String.fromCharCode(...new Uint8Array(buf)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

const fromB64url = s =>
    Uint8Array.from(
        atob(s.replace(/-/g, '+').replace(/_/g, '/')),
        c => c.charCodeAt(0),
    );

/**
 * Complete passkey authentication flow:
 *   1. POST /webauthn/authenticate/start   → challenge + handle
 *   2. navigator.credentials.get()         → browser shows passkey picker
 *   3. POST /webauthn/authenticate/finish  → session cookie set
 *   4. Navigate to finish.url              → proper OIDC redirect or /me/security
 *
 * @throws {Error} with a user-readable message on any failure.
 */
export async function cesauthPasskeyAuthenticate() {
    // ── Step 1: get challenge from server ─────────────────────────────────
    const startResp = await fetch('/webauthn/authenticate/start', {
        method:  'POST',
        headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
        body:    '{}',
    });
    if (!startResp.ok) {
        const e = await startResp.json().catch(() => ({ error: 'server_error' }));
        throw new Error(e.error || 'passkey_start_failed');
    }
    const { handle, public_key: pkOptions } = await startResp.json();

    // Decode binary fields from base64url before passing to the browser.
    pkOptions.challenge = fromB64url(pkOptions.challenge);
    if (pkOptions.allowCredentials) {
        pkOptions.allowCredentials = pkOptions.allowCredentials.map(c => ({
            ...c,
            id: fromB64url(c.id),
        }));
    }

    // ── Step 2: browser passkey picker ───────────────────────────────────
    let credential;
    try {
        credential = await navigator.credentials.get({ publicKey: pkOptions });
    } catch (err) {
        // User cancelled, no passkeys available, or security key error.
        if (err.name === 'NotAllowedError') throw new Error('passkey_cancelled');
        if (err.name === 'NotSupportedError') throw new Error('passkey_unsupported');
        throw new Error('passkey_error');
    }

    // ── Step 3: finish authentication ────────────────────────────────────
    const body = {
        handle,
        id:     credential.id,
        rawId:  b64url(credential.rawId),
        type:   credential.type,
        response: {
            clientDataJSON:    b64url(credential.response.clientDataJSON),
            authenticatorData: b64url(credential.response.authenticatorData),
            signature:         b64url(credential.response.signature),
            userHandle:        credential.response.userHandle
                ? b64url(credential.response.userHandle)
                : null,
        },
    };

    const finishResp = await fetch('/webauthn/authenticate/finish', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(body),
        // fetch follows 302 automatically; finishResp.url is the final URL.
    });

    if (!finishResp.ok) {
        const e = await finishResp.json().catch(() => ({ error: 'auth_failed' }));
        throw new Error(e.error || 'passkey_finish_failed');
    }

    // finishResp.url is the URL after following any redirect — either
    // /me/security (direct login) or redirect_uri?code=… (OIDC flow).
    window.location.replace(finishResp.url || '/me/security');
}
