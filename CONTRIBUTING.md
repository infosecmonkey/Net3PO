# Contributing

Thanks for helping. A few rules keep the project healthy:

- Open an issue first for new tools or large changes, so we can agree on scope.
- Each tool has pure, unit-tested logic in `src-tauri/src/tools/<tool>/core.rs`
  and Tauri commands in `commands.rs`, plus a Svelte panel in
  `src/lib/tools/<Tool>/`.
- Treat all network input as hostile: bounded buffers, validated parsers, a
  timeout on every socket. Never panic on bad input.
- Dependencies must be MIT, Apache-2.0, BSD, ISC, Zlib or MPL-2.0. CI enforces
  this with `cargo deny check` and `pnpm licenses:check`. After changing
  dependencies, run `pnpm notices` and commit the updated notices file.
- No telemetry, and nothing from real customer networks (names, IPs, configs)
  in code, tests or fixtures.
- Before opening a PR, run fmt, clippy (`-D warnings`), the tests and
  `pnpm check`.

By submitting a contribution you agree that it is licensed under the Apache
License 2.0, as described in section 5 of the license.
