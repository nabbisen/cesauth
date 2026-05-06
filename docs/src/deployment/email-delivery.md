# Email delivery (Magic Link)

Magic Link is cesauth's fallback authentication method when a user has no
registered Passkey. Delivering the one-time code requires an email provider.
This chapter describes how to configure delivery, what adapters are available,
and how to monitor the delivery pipeline.

---

## Adapter selection

cesauth picks a mail adapter from the runtime environment in this priority order:

| Priority | Condition | Adapter |
|---|---|---|
| 1 | `WRANGLER_LOCAL=1` | `DevConsoleMailer` — logs handle to console |
| 2 | `MAGIC_LINK_MAILER` service binding present | `ServiceBindingMailer` |
| 3 | `MAILER_PROVIDER_URL` is set | `HttpsProviderMailer` |
| 4 | Nothing configured | `UnconfiguredMailer` — audits misconfig on first use |

You can confirm which adapter is active by issuing a test Magic Link request
in staging and checking the audit log for `magic_link_delivered` or
`magic_link_delivery_failed`.

---

## Option A: Cloudflare service binding (recommended)

A service binding keeps the OTP delivery path entirely within Cloudflare's
network (no outbound HTTPS call). You deploy a small mail worker that receives
cesauth's JSON envelope and calls your SMTP or email API.

### wrangler.toml

```toml
[[services]]
binding     = "MAGIC_LINK_MAILER"
service     = "your-mail-worker"
environment = "production"
```

### Envelope received by your mail worker

```json
{
  "recipient":  "user@example.com",
  "handle":     "challenge-handle-abc",
  "code":       "ABCD1234",
  "locale":     "ja",
  "tenant_id":  "tenant_xyz",
  "reason":     "initial_auth"
}
```

`reason` is one of `initial_auth`, `returning_user_auth`, `anonymous_promote`.

Your mail worker renders the email body and sends it. cesauth considers
delivery successful when the worker returns HTTP 2xx.

### Security note

Your mail worker receives `code` in plaintext. Ensure:
- The worker does NOT log `code` to any persistent store.
- The worker uses `wrangler secret put` for SMTP credentials, not
  `[vars]` in `wrangler.toml`.
- TLS is enforced on the SMTP connection.

---

## Option B: HTTPS provider

For providers that accept an authenticated JSON POST (SendGrid, Resend,
Postmark, Mailgun, SES via API Gateway), set:

```sh
wrangler secret put MAILER_PROVIDER_URL
# e.g.: https://api.sendgrid.com/v3/mail/send

wrangler secret put MAILER_PROVIDER_AUTH_HEADER
# e.g.: Bearer SG.xxxxxx

wrangler secret put MAILER_PROVIDER_FROM_ADDRESS
# e.g.: noreply@example.com

# Optional:
wrangler secret put MAILER_PROVIDER_FROM_NAME
# e.g.: Example App
```

cesauth sends a SendGrid v3-compatible JSON body. For providers with a
different shape, deploy a thin translation proxy or use the service binding
adapter instead.

### Timing note

Provider latency varies. For maximum user experience, consider using
`waitUntil` in your request handler to fire the mailer call after the
HTTP response is already sent. cesauth's current implementation sends
inline; this is a known trade-off tracked under ADR-015 §Q7.

---

## Option C: Defer (unconfigured)

If you don't configure any provider, cesauth uses `UnconfiguredMailer`.
Every Magic Link issuance will be audited as:

```json
{"kind": "magic_link_delivery_failed", "reason": "handle=... kind=not_configured"}
```

Users will see the normal "check your inbox" page but never receive a code.
This is the correct default for deployments that use only Passkey auth and
don't need Magic Link.

---

## Local development

In `wrangler dev` (`WRANGLER_LOCAL=1`), the `DevConsoleMailer` is active.
It logs the challenge `handle` to the console but **never the OTP code**.

To retrieve the OTP during development:

```sh
wrangler d1 execute cesauth-db --local \
  --command "SELECT code_hash FROM auth_challenges WHERE handle = '<handle>'"
```

The `code_hash` is a base64url SHA-256 of the plaintext code. For dev
convenience, you can brute-force the 8-character code against the known
alphabet (`ABCDEFGHJKMNPQRSTUVWXYZ23456789`) with a small script, or
patch your dev flow to read the code from the challenge store directly.

---

## Monitoring

Add these panels to your audit dashboard:

| Event kind | Signal |
|---|---|
| `magic_link_delivery_failed kind=not_configured` | No mailer configured |
| `magic_link_delivery_failed kind=permanent` | Provider rejected address or config |
| `magic_link_delivery_failed kind=transient` | Provider hiccup (monitor rate) |
| `magic_link_delivered` | Successful delivery |

Compute the delivery success rate as:

```
magic_link_delivered / (magic_link_delivered + magic_link_delivery_failed)
```

A rate below 0.99 warrants investigation unless you have an intentional
`not_configured` deployment.

---

## Security considerations

### Enumeration prevention

cesauth returns the same "check your inbox" HTTP 200 response whether
delivery succeeds or fails. This prevents an attacker from using the
differential response to enumerate valid email addresses.

### Provider-side responsibility

Once the OTP leaves cesauth via `send()`, your mail provider's storage and
pipeline become the trust boundary. Due diligence:

- Use a provider that enforces TLS for SMTP relay.
- Enable at-rest encryption for stored messages if your provider offers it.
- Set a short message retention policy (OTPs expire in minutes; stored
  OTPs beyond that are a liability).
- Review your provider's handling of `X-Message-Id` and bounce webhooks.

### Bounce handling

cesauth does not currently process bounce notifications. A user with an
invalid email address will be issued codes that are never delivered.
This is not a security issue (the OTP is useless without the email), but
it is an operational concern. Future work: a bounce adapter that flips
`users.email_verified = false` or suppresses further sends.
