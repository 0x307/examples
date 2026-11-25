// A seller Worker protected by Aethel Verify, on Base Sepolia (testnet).
//   /free   any agent the check approves; costs one paid check
//   /paid   the same, and the agent's delegation must allow the amount in the `aethel-amount` header
// Everything else passes through untouched.

import { createAethelVerify } from "@0x307/aethel-verify";
import { durableStores, SellerState } from "@0x307/aethel-verify/durable";
import { payingFetch, SellerPayer } from "@0x307/aethel-verify/pay";

// Both classes must be exported from the Worker's entry file: Cloudflare finds them here.
export { SellerState, SellerPayer };

const ROUTES = {
  "/free": { action: "query" },
  "/paid": { action: "purchase", spend: true, amountHeader: "aethel-amount" },
};

async function api(request, env, ctx, decision) {
  return Response.json({ hello: "agent", path: new URL(request.url).pathname, decision });
}

let handler;
function build(env) {
  if (env.MODE !== "log" && env.MODE !== "require") {
    // A typo must not quietly mean "log", which never refuses anything.
    throw new Error('MODE must be "log" or "require"');
  }
  const owners = new Set((env.OWNER_KEYS ?? "").split(",").map((s) => s.trim()).filter(Boolean));
  return createAethelVerify({
    network: "sepolia",
    audience: env.AUDIENCE,
    rpSeed: env.RP_SEED,
    mode: env.MODE,
    // Who may grant your agents authority. This accepts only the owner keys you list.
    ownerPolicy: (principalKey) => owners.has(principalKey),
    stores: durableStores(env.SELLER_STATE, env.AUDIENCE),
    fetch: payingFetch(env), // pays the service per check from PAYER_PRIVATE_KEY
    timeoutMs: 10000, // the first paid check includes a deposit and takes a few seconds
  }).wrap(ROUTES, api);
}

export default {
  async fetch(request, env, ctx) {
    handler ??= build(env);
    return handler(request, env, ctx);
  },
};
