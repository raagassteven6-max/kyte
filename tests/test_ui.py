"""Task 5 tests: the dashboard UI (markup, styling rules, safety, helpers).

No browser is available, so these check what can be checked from the files:
WCAG contrast of the design tokens, semantic markup, XSS-safety rules and,
when Node is installed, the pure JavaScript helpers.
"""

import os
import re
import shutil
import subprocess
import unittest
from html.parser import HTMLParser
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "src" / "kyte" / "static"
JS_TESTS = Path(__file__).resolve().parent / "js"


def read(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


def luminance(hex_color: str) -> float:
    r, g, b = (int(hex_color[i : i + 2], 16) / 255 for i in (1, 3, 5))

    def lin(c: float) -> float:
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)


def contrast(a: str, b: str) -> float:
    hi, lo = sorted((luminance(a), luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def tokens() -> dict[str, str]:
    css = read("kyte.css")
    return dict(re.findall(r"--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})\s*;", css))


class ContrastTests(unittest.TestCase):
    def setUp(self) -> None:
        self.t = tokens()

    def ratio(self, fg: str, bg: str) -> float:
        return contrast(self.t[fg], self.t[bg])

    def test_required_tokens_exist(self) -> None:
        needed = {"ground", "surface", "ink", "muted", "accent", "accent-ink",
                  "signal", "tint-1", "tint-2", "tint-3", "tint-4", "tint-5"}
        self.assertLessEqual(needed, set(self.t))

    def test_body_text_meets_aaa(self) -> None:
        self.assertGreaterEqual(self.ratio("ink", "ground"), 7.0)
        self.assertGreaterEqual(self.ratio("ink", "surface"), 7.0)

    def test_secondary_text_meets_aa(self) -> None:
        self.assertGreaterEqual(self.ratio("muted", "ground"), 4.5)
        self.assertGreaterEqual(self.ratio("muted", "surface"), 4.5)

    def test_accent_text_and_buttons_meet_aa(self) -> None:
        self.assertGreaterEqual(self.ratio("accent", "ground"), 4.5)
        self.assertGreaterEqual(self.ratio("accent", "surface"), 4.5)
        self.assertGreaterEqual(self.ratio("accent-ink", "accent"), 4.5)

    def test_unread_marker_meets_non_text_contrast(self) -> None:
        self.assertGreaterEqual(self.ratio("signal", "surface"), 3.0)

    def test_avatar_tints_carry_white_initials(self) -> None:
        for n in range(1, 6):
            self.assertGreaterEqual(
                contrast("#ffffff", self.t[f"tint-{n}"]), 4.5, f"tint-{n}"
            )


class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))


class MarkupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.html = read("index.html")
        c = _Collector()
        c.feed(self.html)
        self.tags = c.tags

    def count(self, tag: str) -> int:
        return sum(1 for t, _ in self.tags if t == tag)

    def attrs(self, tag: str) -> list[dict[str, str | None]]:
        return [a for t, a in self.tags if t == tag]

    def test_document_basics(self) -> None:
        self.assertTrue(self.html.lstrip().lower().startswith("<!doctype html>"))
        self.assertTrue(self.attrs("html")[0].get("lang"))
        self.assertIn("Kyte", re.search(r"<title>(.*?)</title>", self.html).group(1))
        viewport = [a for a in self.attrs("meta") if a.get("name") == "viewport"]
        self.assertTrue(viewport)
        self.assertIn("width=device-width", viewport[0]["content"] or "")

    def test_landmarks_and_headings(self) -> None:
        self.assertEqual(self.count("main"), 1)
        self.assertEqual(self.count("header"), 1)
        self.assertEqual(self.count("h1"), 1)
        self.assertGreaterEqual(self.count("h2"), 1)

    def test_skip_link_targets_main(self) -> None:
        skip = [a for a in self.attrs("a") if a.get("href") == "#main"]
        self.assertTrue(skip)
        main = self.attrs("main")[0]
        self.assertEqual(main.get("id"), "main")

    def test_filter_buttons_expose_pressed_state(self) -> None:
        pressed = [a for a in self.attrs("button") if "aria-pressed" in a]
        self.assertEqual(
            sorted(a.get("data-filter") or "" for a in pressed),
            ["all", "today", "unread"],
        )
        self.assertEqual(sum(a["aria-pressed"] == "true" for a in pressed), 1)

    def test_buttons_are_real_buttons_with_type(self) -> None:
        for a in self.attrs("button"):
            self.assertEqual(a.get("type"), "button")

    def test_status_live_region_and_error_alert(self) -> None:
        roles = [a.get("role") for _, a in self.tags]
        self.assertIn("status", roles)
        self.assertIn("alert", roles)

    def test_card_template_present(self) -> None:
        self.assertEqual(self.count("template"), 1)
        self.assertEqual(self.count("article"), 1)

    def test_ids_are_unique(self) -> None:
        ids = [a["id"] for _, a in self.tags if a.get("id")]
        self.assertEqual(len(ids), len(set(ids)))

    def test_no_inline_handlers_or_styles_or_positive_tabindex(self) -> None:
        for _, a in self.tags:
            for name, value in a.items():
                self.assertFalse(name.startswith("on"), name)
                self.assertNotEqual(name, "style")
                if name == "tabindex":
                    self.assertLessEqual(int(value or 0), 0)

    def test_scripts_are_external_and_local(self) -> None:
        scripts = self.attrs("script")
        self.assertTrue(scripts)
        for a in scripts:
            self.assertTrue((a.get("src") or "").startswith("/static/"), a)


class StyleAndSafetyTests(unittest.TestCase):
    def test_css_has_focus_and_reduced_motion_rules(self) -> None:
        css = read("kyte.css")
        self.assertIn(":focus-visible", css)
        self.assertIn("prefers-reduced-motion", css)
        self.assertNotRegex(css, r"outline:\s*none")

    def test_tap_targets_are_at_least_44px(self) -> None:
        css = read("kyte.css")
        for selector in (r"\.btn", r"\.chip", r"\.link", r"\.dismiss"):
            rule = re.search(selector + r"\s*\{([^}]*)\}", css)
            self.assertIsNotNone(rule, selector)
            self.assertIn("min-height: 2.75rem", rule.group(1), selector)

    def test_css_has_fallback_font_stacks(self) -> None:
        css = read("kyte.css")
        for family in ("Fraunces", "IBM Plex Sans", "IBM Plex Mono"):
            self.assertRegex(css, rf"{family}[^;]*,[^;]*(serif|sans-serif|monospace)")

    def test_js_never_writes_html(self) -> None:
        banned = (r"innerHTML|outerHTML|insertAdjacentHTML|document\.write"
                  r"|eval\(|new Function")
        for name in ("format.js", "kyte.js"):
            self.assertNotRegex(read(name), banned, name)


NODE = shutil.which("node")


@unittest.skipUnless(NODE, "node is not installed")
class JavaScriptTests(unittest.TestCase):
    def test_syntax(self) -> None:
        for name in ("format.js", "kyte.js"):
            r = subprocess.run([NODE, "--check", str(STATIC / name)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)

    def test_format_helpers(self) -> None:
        env = {**os.environ, "TZ": "UTC"}
        cmd = [NODE, str(JS_TESTS / "format_test.js"), str(STATIC / "format.js")]
        r = subprocess.run(cmd, capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
