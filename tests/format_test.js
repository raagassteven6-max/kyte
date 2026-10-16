// Tests for the pure helpers in static/format.js. Run: node format_test.js <path>
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const sandbox = {};
vm.runInNewContext(fs.readFileSync(process.argv[2], "utf8"), sandbox);
const F = sandbox.KyteFormat;
assert.ok(F, "format.js must define KyteFormat on the global object");

const NOW = Date.UTC(2026, 9, 13, 15, 0, 0); // 13 Oct 2026 15:00 UTC (TZ=UTC)
const iso = (ms) => new Date(ms).toISOString();
const MIN = 60_000, HOUR = 3_600_000, DAY = 86_400_000;

// formatWhen
assert.equal(F.formatWhen(null, NOW), "Date unknown");
assert.equal(F.formatWhen("garbage", NOW), "Date unknown");
assert.equal(F.formatWhen(iso(NOW - 20_000), NOW), "just now");
assert.equal(F.formatWhen(iso(NOW + 5 * MIN), NOW), "just now"); // clock skew
assert.equal(F.formatWhen(iso(NOW - 12 * MIN), NOW), "12 min ago");
assert.equal(F.formatWhen(iso(NOW - 3 * HOUR), NOW), "3 h ago");
assert.equal(F.formatWhen(iso(Date.UTC(2026, 9, 13, 0, 5)), NOW), "14 h ago"); // 14h55m
assert.equal(F.formatWhen(iso(Date.UTC(2026, 9, 12, 23, 0)), NOW), "Yesterday");
const older = F.formatWhen(iso(NOW - 3 * DAY), NOW);
assert.ok(older && older !== "Yesterday" && !older.includes("ago"), older);

// senderInitial
assert.equal(F.senderInitial("Priya Nair"), "P");
assert.equal(F.senderInitial("  ana"), "A");
assert.equal(F.senderInitial("Jo \u{1F388} Park"), "J");
assert.equal(F.senderInitial("\u{1F388}\u{1F388}"), "?");
assert.equal(F.senderInitial("evil@scam.example"), "E");
assert.equal(F.senderInitial("\u00c9mile"), "\u00c9");
assert.equal(F.senderInitial(""), "?");
assert.equal(F.senderInitial(null), "?");

// swatchIndex
assert.equal(F.swatchIndex("ada@example.com", 5), F.swatchIndex("ADA@example.com", 5));
for (const a of ["a@x.com", "b@x.com", "", "\u{1F388}", "z".repeat(500)]) {
  const i = F.swatchIndex(a, 5);
  assert.ok(Number.isInteger(i) && i >= 0 && i < 5, `${a} -> ${i}`);
}
assert.notEqual(
  new Set(["a@x.com", "b@x.com", "c@x.com", "d@x.com", "e@x.com", "f@x.com"]
    .map((a) => F.swatchIndex(a, 5))).size, 1);

// safeGmailUrl
assert.equal(F.safeGmailUrl("https://mail.google.com/mail/?authuser=a#all/1"),
  "https://mail.google.com/mail/?authuser=a#all/1");
for (const bad of ["javascript:alert(1)", "http://mail.google.com/", "https://evil.example/",
                   "https://mail.google.com.evil.example/", "", null, undefined, 42]) {
  assert.equal(F.safeGmailUrl(bad), null, String(bad));
}

// countLabel
assert.equal(F.countLabel(0), "No emails");
assert.equal(F.countLabel(1), "1 email");
assert.equal(F.countLabel(5), "5 emails");

console.log("format helpers ok");
