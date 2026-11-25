# 06: a seller Worker protected by Aethel Verify

A Cloudflare Worker that checks, for each request, who an AI agent acts for and what its owner allowed, and pays the
Aethel Verify service per check in test USDC. **Base Sepolia testnet only**: no SLA, state may be reset, test funds have no value.
AI-reviewed, fuzzed, scanned; not a third-party audit.

## Run it

```bash
cp -r 06-seller-starter my-seller && cd my-seller
npm install
npx aethel-verify keygen --out seed.txt          # your seller identity (prints the public key only)
npx aethel-verify wallet new --out wallet.key    # a test wallet (prints the address and the faucet)
npx aethel-verify wallet balance --address 0x... # fund it with test USDC from the faucet it printed
cp .dev.vars.example .dev.vars                   # paste the two file contents into it
npx aethel-verify setup --seed seed.txt --audience https://my-seller.example/api
npm run dev
```

Edit `AUDIENCE` and `OWNER_KEYS` in `wrangler.toml`. `OWNER_KEYS` is the list of owner public keys you accept; empty
accepts nobody. A delegation an agent signs for itself names the agent's own key as the owner, so decide who your owners are.

## Two routes

- `/free`: any approved agent. `/paid`: the agent's delegation must also allow the amount in the `aethel-amount` header.

## Switch to require

`MODE = "log"` serves every request and reports the decision in an `aethel-verify` header. Once the decisions look right,
set `MODE = "require"` in `wrangler.toml`: a request the check does not approve then gets 401, 403, 429 or 503.

## What CI here covers

This repository's CI cannot reach the testnet. It runs only `node --check` and the offline tests in `test/`, which read the
template's configuration. A real paid check needs the funded wallet and the live service: run it yourself as above.
