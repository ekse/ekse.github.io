+++
title = "Dependency cooldowns in rust"
date = "2026-10-05"
slug = "rust-dependency-cooldowns"

[taxonomies]
categories = ["Posts"]
tags = ["rust", "cooldowns"]

+++

Rust is adding dependency cooldowns in version 1.100. Cooldowns have emerged as a defense against supply chain attacks ([cooldowns.dev](https://cooldowns.dev/)). The concept is simple but effective: Let's wait a couple days before installing newly published versions of packages. See [We should all be using dependency cooldowns](https://blog.yossarian.net/2025/11/21/) for arguments in favor of them.

Cooldowns are configured with the `min-publish-age` option in `.cargo/config.toml`. The [cargo configuration](https://doc.rust-lang.org/cargo/reference/config.html#hierarchical-structure) is resolved from multiple locations which brings a lot of flexibility, cooldowns can be configured globally in the user home folder, or in the project folder to apply for all contributors.

```toml
[registry]
global-min-publish-age = "7 days"
```

When adding a package, cargo will install the latest package that meets the cooldown period. The cooldown is also applied to indirect dependencies. In the example below we are adding `console`, the cooldown is also applied to `libc` which is not a direct dependency of the project.

```
$ cargo +nightly add console
    Updating crates.io index
      Adding console v0.16.4 to dependencies
    Updating crates.io index
     Locking 6 packages to highest Rust 1.101.0-nightly compatible versions as of 25 days ago
      Adding console v0.16.4 (available: v0.16.6, published 24 days ago)
      Adding encode_unicode v1.0.0
      Adding libc v0.2.189 (available: v0.2.190, published 28 hours ago)
      Adding unicode-width v0.2.2
      Adding windows-link v0.2.1
      Adding windows-sys v0.61.2
```

If we attempt to add a version that is too recent, either with `cargo add` or by editing Cargo.toml, the project fails to build. 

```
$ cargo +nightly add console@0.16.6
    Updating crates.io index
      Adding console v0.16.6 to dependencies
    Updating crates.io index
error: failed to select a version for the requirement `console = "^0.16.6"`
  version 0.16.6 is too new (published 24 days ago, minimum age 25 days)
location searched: crates.io index
required by package `cooldown_test v0.1.0 (/home/ekse/cooldown_test)`
help: to preserve the min-publish-age, downgrade the requirement to "0.16.4"
help: to use too-new packages anyways, re-resolve with `CARGO_RESOLVER_INCOMPATIBLE_PUBLISH_AGE=allow`
```

As explained in the error message we can force the installation with `CARGO_RESOLVER_INCOMPATIBLE_PUBLISH_AGE=allow`. The version is written to the Cargo.lock and will be installed without error from that point on.

```
$ CARGO_RESOLVER_INCOMPATIBLE_PUBLISH_AGE=allow cargo +nightly build
    Updating crates.io index
     Locking 6 packages to highest Rust 1.101.0-nightly compatible versions
      Adding console v0.16.6 (published 24 days ago, minimum age 25 days)
      Adding libc v0.2.190 (published 30 hours ago, minimum age 25 days)
   Compiling libc v0.2.190
   Compiling console v0.16.6
   Compiling cooldown_test v0.1.0 (/home/ekse/cooldown_test)
```

When using a version of cargo older than 1.100, cargo displays a warning and installs the package without respecting the cooldown.

```
$ cargo build
warning: ignoring `registry.global-min-publish-age` without `-Zmin-publish-age`
   Compiling libc v0.2.190
   Compiling unicode-width v0.2.2
   Compiling console v0.16.6
   Compiling cooldown_test v0.1.0 (/home/ekse/cooldown_test)
```

Documentation:

- [https://doc.rust-lang.org/nightly/cargo/reference/config.html#registryglobal-min-publish-age](https://doc.rust-lang.org/nightly/cargo/reference/config.html#registryglobal-min-publish-age)
- [https://doc.rust-lang.org/nightly/cargo/reference/unstable.html#min-publish-age](https://doc.rust-lang.org/nightly/cargo/reference/unstable.html#min-publish-age)
- [https://github.com/rust-lang/rfcs/blob/main/text/3923-cargo-min-publish-age.md](https://github.com/rust-lang/rfcs/blob/main/text/3923-cargo-min-publish-age.md)

