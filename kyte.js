/* Kyte dashboard. All text goes in with textContent, never as HTML. */
(function () {
  "use strict";

  const F = globalThis.KyteFormat;
  const $ = (id) => document.getElementById(id);
  const els = {
    list: $("cards"), loading: $("loading"), empty: $("empty"), emptyText: $("empty-text"),
    error: $("error"), status: $("status"), template: $("card-template"),
    refresh: $("refresh"), retry: $("retry"), heading: $("inbox-heading"),
  };
  const FILTER_NAMES = { all: "All", unread: "Unread", today: "Today" };
  const EMPTY_TEXT = {
    all: "Your inbox is empty. Nice and quiet.",
    unread: "No unread mail. The sky is clear.",
    today: "Nothing has arrived today yet.",
  };
  const TINTS = 5;

  let filter = "all";
  let latest = 0; // guards against out-of-order responses

  function show(state) {
    els.loading.hidden = state !== "loading";
    els.empty.hidden = state !== "empty";
    els.error.hidden = state !== "error";
    els.list.hidden = state !== "ready";
  }

  function announce(count) {
    els.status.textContent = F.countLabel(count) + " · " + FILTER_NAMES[filter];
  }

  function buildCard(card) {
    const item = els.template.content.firstElementChild.cloneNode(true);
    const article = item.querySelector(".card");
    const subject = item.querySelector(".subject");
    subject.id = "s-" + card.id;
    article.setAttribute("aria-labelledby", subject.id);
    subject.textContent = card.subject;
    item.querySelector(".sender").textContent = card.sender;
    item.querySelector(".snippet").textContent = card.snippet;
    const avatar = item.querySelector(".avatar");
    avatar.textContent = F.senderInitial(card.sender);
    avatar.classList.add("tint-" + (F.swatchIndex(card.sender_address || card.sender, TINTS) + 1));
    const time = item.querySelector("time");
    time.textContent = F.formatWhen(card.received_at, Date.now());
    if (card.received_at) time.dateTime = card.received_at;
    if (card.unread) item.classList.add("is-unread");

    const link = item.querySelector(".link");
    const url = F.safeGmailUrl(card.gmail_url);
    if (url) {
      link.href = url;
      link.setAttribute("aria-label", "Open in Gmail: " + card.subject + " (opens in a new tab)");
    } else {
      link.remove();
    }
    const dismiss = item.querySelector(".dismiss");
    dismiss.setAttribute("aria-label", "Dismiss: " + card.subject);
    dismiss.addEventListener("click", () => dismissCard(card.id, item));
    return item;
  }

  function render(cards) {
    els.list.replaceChildren(...cards.map(buildCard));
    if (cards.length === 0) {
      els.emptyText.textContent = EMPTY_TEXT[filter];
      show("empty");
    } else {
      show("ready");
    }
    announce(cards.length);
  }

  async function load() {
    const ticket = ++latest;
    show("loading");
    els.status.textContent = "Loading…";
    try {
      const response = await fetch("/api/emails?filter=" + encodeURIComponent(filter), {
        headers: { Accept: "application/json" },
        credentials: "same-origin",
      });
      if (!response.ok) throw new Error("HTTP " + response.status);
      const cards = await response.json();
      if (ticket === latest) render(cards);
    } catch (err) {
      console.error("Kyte: could not load emails", err);
      if (ticket === latest) {
        show("error");
        els.status.textContent = "Couldn’t load emails.";
      }
    }
  }

  async function dismissCard(id, item) {
    try {
      const response = await fetch("/api/emails/" + encodeURIComponent(id) + "/dismiss", {
        method: "POST",
        credentials: "same-origin",
      });
      if (response.status !== 204) throw new Error("HTTP " + response.status);
    } catch (err) {
      console.error("Kyte: could not dismiss", err);
      els.status.textContent = "Couldn’t dismiss that email. Try again.";
      return;
    }
    const neighbour = item.nextElementSibling || item.previousElementSibling;
    item.remove();
    const remaining = els.list.children.length;
    if (remaining === 0) {
      els.emptyText.textContent = EMPTY_TEXT[filter];
      show("empty");
      els.heading.tabIndex = -1;
      els.heading.focus();
    } else {
      neighbour.querySelector(".dismiss").focus();
    }
    els.status.textContent = "Dismissed. " + F.countLabel(remaining) + " · " + FILTER_NAMES[filter];
  }

  document.querySelectorAll(".chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      filter = chip.dataset.filter;
      document.querySelectorAll(".chip").forEach((other) => {
        other.setAttribute("aria-pressed", String(other === chip));
      });
      load();
    });
  });
  els.refresh.addEventListener("click", load);
  els.retry.addEventListener("click", load);

  load();
})();
