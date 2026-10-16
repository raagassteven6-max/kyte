/* Pure display helpers. No DOM access, so they can be tested in Node. */
(function (root) {
  "use strict";

  const MINUTE = 60000;
  const HOUR = 3600000;

  function sameDay(a, b) {
    return a.getFullYear() === b.getFullYear()
      && a.getMonth() === b.getMonth()
      && a.getDate() === b.getDate();
  }

  /** "12 min ago", "3 h ago", "Yesterday", or a short date. */
  function formatWhen(iso, nowMs) {
    const then = typeof iso === "string" ? Date.parse(iso) : NaN;
    if (Number.isNaN(then)) return "Date unknown";
    const diff = nowMs - then;
    if (diff < MINUTE) return "just now"; // includes small clock skew
    if (diff < HOUR) return Math.floor(diff / MINUTE) + " min ago";
    const thenDate = new Date(then);
    const now = new Date(nowMs);
    if (sameDay(thenDate, now)) return Math.floor(diff / HOUR) + " h ago";
    const yesterday = new Date(nowMs);
    yesterday.setDate(yesterday.getDate() - 1);
    if (sameDay(thenDate, yesterday)) return "Yesterday";
    return thenDate.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  }

  /** First letter or digit of a sender label, upper-cased; "?" if none. */
  function senderInitial(label) {
    const match = String(label == null ? "" : label).match(/[\p{L}\p{N}]/u);
    return match ? match[0].toLocaleUpperCase() : "?";
  }

  /** Stable index in [0, n) so a sender always gets the same colour. */
  function swatchIndex(address, n) {
    let hash = 5381;
    for (const ch of String(address == null ? "" : address).toLowerCase()) {
      hash = ((hash << 5) + hash + ch.codePointAt(0)) >>> 0;
    }
    return hash % n;
  }

  /** Only ever link to Gmail over https; anything else is dropped. */
  function safeGmailUrl(url) {
    const prefix = "https://mail.google.com/";
    return typeof url === "string" && url.startsWith(prefix) ? url : null;
  }

  function countLabel(n) {
    if (n === 0) return "No emails";
    return n === 1 ? "1 email" : n + " emails";
  }

  root.KyteFormat = { formatWhen, senderInitial, swatchIndex, safeGmailUrl, countLabel };
})(typeof globalThis !== "undefined" ? globalThis : this);
