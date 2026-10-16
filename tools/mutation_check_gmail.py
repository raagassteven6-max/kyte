"""Break the Gmail source on purpose; every mutation should make a test fail.

Each run has a timeout so a mutation that causes an endless retry loop counts
as caught instead of hanging.  Run: python tools/mutation_check_gmail.py
"""
import pathlib, shutil, subprocess, sys, tempfile
SRC = pathlib.Path(__file__).resolve().parent.parent
G = "src/kyte/gmail.py"
MUTATIONS = [
  ("fetches full messages, not metadata", G, '"format": "metadata"', '"format": "full"'),
  ("unread flag trusted from cached message", G, "replace(self._cache[i], unread=i in unread)", "self._cache[i]"),
  ("retry budget ignored", G, "if attempt >= self._max_retries:", "if attempt >= 99:"),
  ("second 401 retried forever", G, "                if refreshed:\n", "                if False:\n"),
  ("invalid_grant not mapped to reconnect", G, 'if exc.code == "invalid_grant":', "if False:"),
  ("Retry-After not capped", G, "return min(max(float(retry_after), 0.0), MAX_RETRY_WAIT)", "return max(float(retry_after), 0.0)"),
  ("backoff not exponential", G, "self._base_delay * 2**attempt * jitter", "self._base_delay * jitter"),
  ("permission 403 not a reconnect", G, "if status == 403 and reason in _PERMISSION_REASONS:", "if False:"),
  ("token used until the last second", G, "cached.expires_at - TOKEN_SAFETY_MARGIN > self._clock()", "cached.expires_at > self._clock()"),
  ("deleted message fails everything", G, "                raise _MessageGone\n", "                raise MailUnavailable('x')\n"),
  ("messages refetched every time", G, "missing = [i for i in ids if i not in self._cache]", "missing = list(ids)"),
  ("wrong-id reply accepted", G, "return email if email.id == message_id else None", "return email"),
  ("rate-limit 403 not retried", G, "rate_limited = status == 403 and reason in _RATE_LIMIT_REASONS", "rate_limited = False"),
  ("network failure not retried", G, "_RETRYABLE_STATUSES = {0, 429,", "_RETRYABLE_STATUSES = {429,"),
  ("unread list ignored", G, "unread = set(self._list_ids(unread_only=True))", "unread = set()"),
  ("paging cap ignored", G, "return ids[: self._max_messages]", "return ids"),
  # Expected to SURVIVE: the id filter and URL quoting each protect the path.
  ("id filter removed (quote() still protects)", G, "isinstance(message_id, str) and _VALID_ID.fullmatch(message_id)", "isinstance(message_id, str)"),
]
EXPECTED_SURVIVORS = {"id filter removed (quote() still protects)"}
bad = []
for name, rel, old, new in MUTATIONS:
    work = pathlib.Path(tempfile.mkdtemp())
    shutil.copytree(SRC, work / "k", ignore=shutil.ignore_patterns("__pycache__", "*.db", "tools"))
    f = work / "k" / rel; s = f.read_text()
    assert s.count(old) == 1, (name, s.count(old))
    f.write_text(s.replace(old, new))
    try:
        r = subprocess.run([sys.executable, "-m", "unittest", "tests.test_gmail"], cwd=work / "k",
                           env={"PYTHONPATH": "src", "PATH": "/usr/bin:/bin"}, capture_output=True, text=True, timeout=90)
        killed = r.returncode != 0
    except subprocess.TimeoutExpired:
        killed = True
    shutil.rmtree(work, ignore_errors=True)
    expected = name in EXPECTED_SURVIVORS
    print(("KILLED   " if killed else "SURVIVED ") + name + ("  (expected)" if expected and not killed else ""))
    if killed == expected: bad.append(name)
print(f"\n{len(MUTATIONS)-len(bad)}/{len(MUTATIONS)} as expected")
sys.exit(1 if bad else 0)
