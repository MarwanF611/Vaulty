# Kickoff — how to start with Claude Code

## 1. Open the project

```
cd ~/Documents/personalProjects/Vaulty
claude
```

## 2. Paste this as the first message

> Read CLAUDE.md, docs/SPEC.md, docs/SECURITY.md and docs/PHASES.md in full before doing
> anything else.
>
> We are starting Phase 0: the crypto core, no UI. Before you write code, tell me:
> the crate layout you plan, the vault header byte format, and the exact crypto crates and
> versions you will use. I want to approve that before any implementation.
>
> Once I approve, work through the Phase 0 checklist one item at a time. After each item run
> `cargo test` and `cargo clippy -- -D warnings`, and tell me what you verified. Do not move
> to Phase 1 until every Phase 0 exit criterion is met.

## 3. Rhythm for every session after that

Start with:

> Read CLAUDE.md and docs/PHASES.md. We are on Phase N, item "X". Restate what done means for
> that item, then implement it.

End with:

> Run cargo test and cargo clippy. Summarise what changed, what you verified, and tick the
> boxes in docs/PHASES.md.

## 4. Things worth interrupting Claude Code about

- Any suggestion to invent a crypto construction, or to skip authentication of associated data
- Any plaintext secret being passed to the frontend outside `reveal_secret` / `copy_secret`
- Any `unwrap()` in a path that handles key material
- Any dependency that wants network access
- "We can add the format version later" — no, it goes in from commit one

## 5. Before phase 3

Buy the Apple Developer account and get a signed build working with the keychain entitlement.
Biometrics does not work in an unsigned app, and discovering that late costs a week.

## 6. Keep the docs alive

When a decision changes, update `docs/SPEC.md` or `docs/SECURITY.md` in the same commit.
Claude Code re-reads them every session; stale docs quietly become wrong instructions.
