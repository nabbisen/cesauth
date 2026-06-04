# RFC 031 — MagicLinkMailer enum dispatcher

**Status**: Implemented  
**Priority**: P0 (build blocker)  
**Size**: Medium (~80 LOC change)  
**Depends on**: RFC 030

## Problem

`MagicLinkMailer` uses `async fn` in trait methods. Rust cannot create
`dyn MagicLinkMailer` from such a trait (not object-safe). The current
`adapter-cloudflare/src/mailer.rs` factory returns `Box<dyn MagicLinkMailer>`,
which does not compile.

## Decision

Replace the `Box<dyn MagicLinkMailer>` factory with a concrete
`CloudflareMagicLinkMailer` enum that dispatches to the four backend variants
(`Dev`, `Https`, `ServiceBinding`, `Unconfigured`) via a match.

The `MagicLinkMailer` trait keeps `async fn send(...)` — no change to the
trait or to individual provider impls. Only the factory and the worker handler's
type annotation change.

## Implementation

```rust
pub enum CloudflareMagicLinkMailer {
    Dev(DevConsoleMailer),
    Https(HttpsProviderMailer),
    ServiceBinding(ServiceBindingMailer),
    Unconfigured(UnconfiguredMailer),
}

impl MagicLinkMailer for CloudflareMagicLinkMailer {
    async fn send(&self, payload: &MagicLinkPayload<'_>) -> Result<MailerReceipt, MailerError> {
        match self {
            Self::Dev(m)            => m.send(payload).await,
            Self::Https(m)          => m.send(payload).await,
            Self::ServiceBinding(m) => m.send(payload).await,
            Self::Unconfigured(m)   => m.send(payload).await,
        }
    }
}
```

Worker handler receives `CloudflareMagicLinkMailer` (concrete type), not `Box<dyn>`.
