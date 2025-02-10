# Project Initiation

```console
$ cargo init
    Creating binary (application) package
note: see more `Cargo.toml` keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html

$ cargo add axum
(...)
      Adding axum v0.8.1 to dependencies
             Features:
             + form
             + http1
             + json
             + matched-path
             + original-uri
             + query
             + tokio
             + tower-log
             + tracing
             - __private
             - __private_docs
             - http2
             - macros
             - multipart
             - ws
(...)
$ cargo add tokio -F full
(...)
      Adding tokio v1.43.0 to dependencies
             Features:
             + bytes
             + fs
             + full
             + io-std
             + io-util
             + libc
             + macros
             + net
             + parking_lot
             + process
             + rt
             + rt-multi-thread
             + signal
             + signal-hook-registry
             + socket2
             + sync
             + time
             + tokio-macros
             - mio
             - test-util
             - tracing
             - windows-sys
(...)
```