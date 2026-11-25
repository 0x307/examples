// Offline checks only (this repo's CI cannot reach the testnet): the template's config and wiring read as intended.
// Run: npm test
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";

const read = (p) => readFileSync(new URL(`../${p}`, import.meta.url), "utf8");
const toml = read("wrangler.toml");
const src = read("src/index.js");

test("both Durable Objects are bound and migrated, and the Worker exports both classes", () => {
  for (const cls of ["SellerState", "SellerPayer"]) {
    assert.match(toml, new RegExp(`class_name = "${cls}"`));
    assert.ok(toml.includes(`new_sqlite_classes = ["${cls}"]`));
    assert.match(src, /export \{ SellerState, SellerPayer \}/);
  }
});

test("the template starts in log mode, accepts no owner, and holds no secret", () => {
  assert.match(toml, /^MODE = "log"$/m);
  assert.match(toml, /^OWNER_KEYS = ""$/m);
  assert.doesNotMatch(toml, /^(RP_SEED|PAYER_PRIVATE_KEY)\s*=/m);
  assert.ok(!existsSync(new URL("../.dev.vars", import.meta.url)), ".dev.vars must not be committed");
  assert.match(read(".gitignore"), /\.dev\.vars/);
});

test("a mistyped MODE is refused, never read as log (control: both valid values are named)", () => {
  assert.match(src, /env\.MODE !== "log" && env\.MODE !== "require"/);
  assert.match(src, /mode: env\.MODE/);
});

test("it is testnet only", () => {
  assert.match(src, /network: "sepolia"/);
  assert.doesNotMatch(src, /mainnet/);
});
