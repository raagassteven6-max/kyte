import pathlib, shutil, subprocess, sys
SRC = pathlib.Path("/home/claude/kyte")
MUTATIONS = [
  ("owner check disabled", "src/kyte/oauth.py", "if email.strip().lower() != owner_email.strip().lower():", "if False:"),
  ("state (CSRF) check disabled", "src/kyte/oauth.py", "if not hmac.compare_digest(given.encode(), flow.state.encode()):", "if False:"),
  ("refresh token stored in plaintext", "src/kyte/credentials.py", "self._vault.encrypt(refresh_token),", "refresh_token.encode(),"),
  ("ID token expiry ignored", "src/kyte/oauth.py", "if exp <= now:", "if False:"),
  ("stranger's grant not revoked", "src/kyte/auth.py", "self._google.revoke(grant)  # don't leave a stranger's grant behind", "pass"),
  ("cookie purpose binding removed", "src/kyte/security.py", 'key = derive_key(secret, f"cookie/{purpose}").hex()', 'key = derive_key(secret, "cookie").hex()'),
  ("cookie salt removed", "src/kyte/security.py", 'salt=f"kyte-{purpose}"', 'salt="kyte"'),
  ("origin check always true", "src/kyte/auth.py", 'return origin == f"{parsed.scheme}://{parsed.netloc}"', "return True"),
  ("gmail scope not required", "src/kyte/auth.py", "if GMAIL_SCOPE not in tokens.scope.split():", "if False:"),
  ("session not tied to owner", "src/kyte/auth.py", "email == self._settings.owner_email", "True"),
  ("nonce check disabled", "src/kyte/oauth.py", "if not isinstance(token_nonce, str) or not hmac.compare_digest(", "if False and not hmac.compare_digest("),
  ("email_verified ignored", "src/kyte/oauth.py", 'if claims.get("email_verified") not in (True, "true"):', "if False:"),
  ("PKCE challenge wrong", "src/kyte/oauth.py", 'return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()', 'return verifier'),
  ("missing refresh token accepted", "src/kyte/auth.py", "if not tokens.refresh_token:", "if False:"),
  ("disconnect keeps local token", "src/kyte/auth.py", "        self._creds.clear()\n        return revoked", "        return revoked"),
]
survived = []
for name, rel, old, new in MUTATIONS:
    work = pathlib.Path("/tmp/mut"); shutil.rmtree(work, ignore_errors=True)
    shutil.copytree(SRC, work, ignore=shutil.ignore_patterns("__pycache__", "*.db"))
    f = work / rel; s = f.read_text()
    assert s.count(old) == 1, (name, s.count(old))
    f.write_text(s.replace(old, new))
    r = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", "."],
                       cwd=work, env={"PYTHONPATH": "src", "PATH": "/usr/bin:/bin"}, capture_output=True, text=True)
    killed = r.returncode != 0
    print(("KILLED   " if killed else "SURVIVED ") + name)
    if not killed: survived.append(name)
print(f"\n{len(MUTATIONS)-len(survived)}/{len(MUTATIONS)} mutations caught")
sys.exit(1 if survived else 0)
