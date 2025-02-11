# Project startup

```console
$ cargo init
    Creating binary (application) package
note: see more `Cargo.toml` keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html
```

```console
$ cargo install loco

$ # use database
$ cargo install sea-orm-cli
```

```console
$ loco new
✔ ❯ App name? · cesauth
✔ ❯ What would you like to build? · Saas App with server side rendering
✔ ❯ Select a DB Provider · Sqlite # (or PostgreSQL)
✔ ❯ Select your background worker type · Async (in-process tokio async tasks)

🚂 Loco app generated successfully in:
/(...)/cesauth

```
