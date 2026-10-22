# Contributing

Thanks for helping. A few principles keep Vigía useful:

- **Zero runtime dependencies.** It should run anywhere Node 20+ runs, with nothing to install and no supply chain to audit. Use the Node standard library.
- **Quiet by default.** Every new check must say what makes it P1, P2 or P3. A check that pages people for noise will get Vigía muted.
- **Pure logic goes in `lib.mjs`, with tests.** Matching, prioritisation and parsing must be unit-testable without network access.
- **Every alert text goes in both languages** in `i18n.mjs`. A test checks that both have the same keys.

```bash
npm test
node server.mjs   # with VIGIA_INV / VIGIA_STATE pointing at scratch files if you like
```

Open an issue before starting a large change, such as a new data source or channel.
