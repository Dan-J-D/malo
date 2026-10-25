"""Drives the real Malo desktop app through WebDriver: local server setup, destination, account,
live backup ("Newly found"), safe viewer, attachment save and lock."""
import imaplib
import os
import ssl
import sys
import time
import uuid

from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException, StaleElementReferenceException
from selenium.webdriver.common.by import By
from selenium.webdriver.common.options import ArgOptions

IMAP_USER = f"gui-{uuid.uuid4().hex[:8]}"
SHOTS = "/tmp/saved"


def seed():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    m = imaplib.IMAP4_SSL("localhost", 10993, ssl_context=ctx)
    m.login(IMAP_USER, "pass")
    plain = b"From: Alice <alice@example.com>\r\nTo: me@example.com\r\nSubject: Plain hello\r\nDate: Mon, 1 Jan 2024 10:00:00 +0000\r\n\r\nHello from the GUI test https://example.org/path\r\n"
    html = (b"From: \"Bank paypal.com\" <evil@phish.example>\r\nTo: me@example.com\r\nSubject: HTML trap\r\nMIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/html\r\n\r\n"
            b"<p onclick=x()>Click <a href=\"https://evil.example/login\">here</a><script>alert(1)</script>"
            b"<img src=\"https://tracker.example/p.gif\"></p>\r\n--b\r\nContent-Type: application/pdf; name=\"invoice.pdf.exe\"\r\n"
            b"Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\nContent-Transfer-Encoding: base64\r\n\r\nTVqQAAMAAAAEAAAA\r\n--b--\r\n")
    rlo = "\u202e"
    zw = "\u200b"
    tricky = (f"From: =?UTF-8?Q?Pay{zw}Pal?= <x@xn--pypal-4ve.com>\r\nTo: me@example.com\r\n"
              f"Subject: Invoice {rlo}gnp.exe\r\nMIME-Version: 1.0\r\n"
              "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nÜber 日本 😀\r\n"
              f"--b\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename*=UTF-8''invoice%E2%80%AEfdp.exe\r\n"
              "Content-Transfer-Encoding: base64\r\n\r\nTVqQAAMAAAAEAAAA\r\n--b--\r\n").encode("utf-8")
    for msg in (plain, html, tricky):
        m.append("INBOX", None, None, msg)
    m.logout()


ISSUER = "http://localhost:18080/default"
OAUTH_USER = os.environ.get("MALO_E2E_OAUTH_USER", "")


def oauth_access_token(username):
    """Authorization code + PKCE against the mock provider, as the mailbox owner would do."""
    import base64, hashlib, json, urllib.parse, urllib.request

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    verifier = uuid.uuid4().hex + uuid.uuid4().hex
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    redirect = "http://127.0.0.1:5555/callback"
    q = urllib.parse.urlencode({"response_type": "code", "client_id": "malo-test", "redirect_uri": redirect,
                                "scope": "openid", "state": "s", "code_challenge": challenge, "code_challenge_method": "S256"})
    opener = urllib.request.build_opener(NoRedirect)
    try:
        opener.open(f"{ISSUER}/authorize?{q}", data=urllib.parse.urlencode({"username": username}).encode())
        raise AssertionError("expected a redirect")
    except urllib.error.HTTPError as e:
        location = e.headers["Location"]
    code = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)["code"][0]
    body = urllib.parse.urlencode({"grant_type": "authorization_code", "code": code, "redirect_uri": redirect,
                                   "client_id": "malo-test", "code_verifier": verifier}).encode()
    return json.load(urllib.request.urlopen(f"{ISSUER}/token", data=body))["access_token"]


def seed_oauth():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    m = imaplib.IMAP4_SSL("localhost", 12993, ssl_context=ctx)
    token = oauth_access_token(OAUTH_USER)
    m.authenticate("XOAUTH2", lambda _: f"user={OAUTH_USER}\x01auth=Bearer {token}\x01\x01".encode())
    m.append("INBOX", None, None, b"From: Carol <carol@example.com>\r\nTo: me@example.com\r\nSubject: Via OAuth\r\n\r\nSigned in with XOAUTH2\r\n")
    m.logout()


def driver():
    opts = ArgOptions()
    opts.set_capability("browserName", "wry")
    opts.set_capability("tauri:options", {"application": "/app/malo"})
    return webdriver.Remote(command_executor="http://127.0.0.1:4444", options=opts)


def wait(fn, timeout=60, what="condition"):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            r = fn()
            if r:
                return r
        except (NoSuchElementException, StaleElementReferenceException) as e:
            last = e
        time.sleep(0.3)
    raise AssertionError(f"timed out waiting for {what} ({last})")


def xp(d, path):
    return d.find_element(By.XPATH, path)


def button(d, text):
    return wait(lambda: xp(d, f"//button[normalize-space()='{text}' or contains(normalize-space(), '{text}')][not(@disabled)]"), what=f"button {text}")


def field(d, label, exact=False):
    cond = f"normalize-space(text()[1])='{label}'" if exact else f"contains(normalize-space(), '{label}')"
    return wait(lambda: xp(d, f"//label[{cond}]//*[self::input or self::select or self::textarea]"), what=f"field {label}")


def fill(d, label, value, exact=False):
    for _ in range(3):
        el = field(d, label, exact)
        el.clear()
        el.send_keys(value)
        if el.get_attribute("value") == value:
            return
        time.sleep(0.3)
    raise AssertionError(f"could not type into {label!r} (value is {el.get_attribute('value')!r})")


def settings(d):
    """Open Settings and wait until its async content has rendered (the layout shifts until then)."""
    d.execute_script("location.hash = '#/settings'")
    wait(lambda: "Auto-lock after" in text(d) and "Delete my account" in text(d), what="settings loaded")
    time.sleep(0.5)


def text(d):
    return d.find_element(By.TAG_NAME, "body").text


def shot(d, name):
    d.save_screenshot(os.path.join(SHOTS, f"{name}.png"))


def main():
    seed()
    seed_oauth()
    d = driver()
    try:
        d.set_window_size(1400, 900)
        wait(lambda: "Connect to a Malo server" in text(d), what="connect screen")
        shot(d, "01-connect")
        button(d, "Use local server").click()

        # First start: the setup token from the bundled server is pre-filled.
        wait(lambda: "Create the administrator" in text(d), what="setup screen")
        assert field(d, "Setup token").get_attribute("value"), "setup token not prefilled"
        fill(d, "Username", "owner")
        fill(d, "Password", "owner-password-1", exact=True)
        fill(d, "Repeat password", "owner-password-1")
        shot(d, "02-setup")
        button(d, "Create").click()

        # The recovery kit must be exported before continuing.
        wait(lambda: "Save your recovery kit" in text(d), timeout=90, what="recovery kit screen")
        cont = xp(d, "//button[contains(., 'continue')]")
        assert not cont.is_enabled(), "continue must be disabled before saving the kit"
        button(d, "Save recovery kit").click()
        wait(lambda: os.path.exists(f"{SHOTS}/malo-recovery-kit-owner.json"), what="kit file")
        button(d, "continue").click()
        wait(lambda: "Dashboard" in text(d) and "Auto-lock in" in text(d), what="dashboard")
        shot(d, "03-dashboard")

        # Destination: a plain folder in the user's private area.
        d.execute_script("location.hash = '#/destinations'")
        button(d, "Add destination").click()
        fill(d, "Name", "Local folder")
        fill(d, "Folder", "gui-backups")
        button(d, "Test").click()
        wait(lambda: "Write/read/delete OK" in text(d), what="destination test")
        button(d, "Save").click()
        wait(lambda: "Local folder" in text(d) and "Add destination" in text(d), what="destination saved")

        # Account wizard: preset → sign-in → test → save.
        d.execute_script("location.hash = '#/accounts/new'")
        button(d, "Other IMAP server").click()
        fill(d, "Name", "GUI test mail")
        fill(d, "Email / username", IMAP_USER)
        fill(d, "IMAP host", "localhost")
        fill(d, "Port", "10993")
        field(d, "Accept invalid server certificates").click()
        fill(d, "Password", "pass", exact=True)
        button(d, "Test connection").click()
        wait(lambda: "Connected." in text(d), what="connection test")
        shot(d, "04-account-test")
        button(d, "Add account").click()
        wait(lambda: "GUI test mail" in text(d) and "Step 2 of 3" not in text(d), what="account list")

        # The first scheduled backup starts right away; watch the live "Newly found" list.
        d.execute_script("location.hash = '#/activity'")
        wait(lambda: "Plain hello" in text(d) and "HTML trap" in text(d), timeout=90, what="newly found rows")
        wait(lambda: len(d.find_elements(By.XPATH, "//span[contains(@class,'pill') and normalize-space()='verified']")) >= 3, timeout=90, what="verified pills")
        shot(d, "05-activity")

        # Hidden Unicode is shown, not obeyed: the RLO subject can't pose as ".png".
        wait(lambda: "Invoice ⟨U+202E⟩gnp.exe" in text(d), timeout=90, what="revealed RLO in subject")
        xp(d, "//tr[contains(., 'U+202E')]/td[2]").click()
        wait(lambda: "text-direction characters" in text(d), what="hidden-character warnings")
        body = text(d)
        assert "invoice⟨U+202E⟩fdp.exe" in body, "attachment name not revealed"
        assert "imitate other domains" in body, "punycode sender not flagged"
        assert "Über 日本 😀" in body, "normal Unicode must render unchanged"
        d.execute_script("window.confirm = () => true")
        button(d, "Save as").click()
        wait(lambda: os.path.exists(f"{SHOTS}/invoicefdp.exe"), what="saved without the RLO")
        shot(d, "06a-unicode")
        d.execute_script("history.back()")

        # Safe viewer: plain text by default, sanitized HTML in a sandboxed iframe on request.
        xp(d, "//tr[contains(., 'HTML trap')]/td[2]").click()
        wait(lambda: "Display name" in text(d), what="phishing warning")
        body = text(d)
        assert "Executable" in body and "invoice.pdf.exe" in body, "attachment warnings missing"
        field(d, "Show HTML").click()
        frame = wait(lambda: xp(d, "//iframe[@title='Message content']"), what="iframe")
        assert frame.get_attribute("sandbox") == "", f"iframe sandbox is {frame.get_attribute('sandbox')!r}"
        srcdoc = frame.get_attribute("srcdoc") or ""
        assert "<script" not in srcdoc.lower() and "onclick" not in srcdoc.lower(), "unsanitized HTML reached the viewer"
        assert "tracker.example" not in srcdoc, "remote image URL inside the iframe"
        assert "href=" not in srcdoc.lower(), "live link inside the iframe (links are only opened via confirmation)"
        assert "default-src 'none'" in srcdoc, "inner CSP missing"
        assert "remote image(s) blocked" in text(d)
        xp(d, "//summary[contains(., 'Links in this message')]").click()
        assert "https://evil.example/login" in text(d), "real link target not shown"
        shot(d, "06-viewer")
        d.execute_script("window.confirm = () => true")
        button(d, "Save as").click()
        wait(lambda: os.path.exists(f"{SHOTS}/invoice.pdf.exe"), what="attachment saved")
        with open(f"{SHOTS}/invoice.pdf.exe", "rb") as f:
            assert f.read(2) == b"MZ"

        # OAuth2 account: browser sign-in (PKCE on a loopback listener) → refresh token to the server
        # → XOAUTH2 against the OAuth-only Dovecot → backup.
        d.execute_script("location.hash = '#/accounts/new'")
        button(d, "Other IMAP server").click()
        fill(d, "Name", "GUI OAuth mail")
        fill(d, "Email / username", OAUTH_USER)
        fill(d, "IMAP host", "localhost")
        fill(d, "Port", "12993")
        field(d, "Accept invalid server certificates").click()
        field(d, "OAuth2 (your own client ID)").click()
        fill(d, "Client ID", "malo-test")
        fill(d, "Authorization URL", f"{ISSUER}/authorize")
        fill(d, "Token URL", f"{ISSUER}/token")
        fill(d, "Scopes", "openid offline_access")
        button(d, "Sign in with browser").click()
        wait(lambda: xp(d, "//span[contains(@class,'pill') and normalize-space()='authorized']"), timeout=60, what="OAuth authorized")
        button(d, "Test connection").click()
        wait(lambda: "Connected." in text(d), what="OAuth connection test")
        shot(d, "06b-oauth-account")
        button(d, "Add account").click()
        wait(lambda: "GUI OAuth mail" in text(d) and "Step 2 of 3" not in text(d), what="oauth account list")
        d.execute_script("location.hash = '#/activity'")
        wait(lambda: "Via OAuth" in text(d), timeout=90, what="oauth message discovered")
        wait(lambda: xp(d, "//tr[contains(., 'Via OAuth')]//span[contains(@class,'pill') and normalize-space()='verified']"), timeout=90, what="oauth message verified")

        # Browse shows both, new-since-last-visit filter works.
        d.execute_script("location.hash = '#/browse'")
        wait(lambda: "Plain hello" in text(d), what="browse list")

        # Lock now: keys wiped, back to the login screen.
        button(d, "Lock now").click()
        wait(lambda: "Log in to unlock" in text(d) and "Locked" in text(d), what="locked login screen")
        shot(d, "07-locked")
        fill(d, "Password", "owner-password-1", exact=True)
        button(d, "Unlock").click()
        wait(lambda: "Dashboard" in text(d), what="dashboard after unlock")

        # Deleting your own account takes two steps; the last administrator is refused.
        settings(d)
        button(d, "Delete my account").click()
        cont = wait(lambda: xp(d, "//button[normalize-space()='Continue']"), what="step 1")
        assert not cont.is_enabled(), "step 1 must require acknowledging"
        field(d, "I understand this cannot be undone").click()
        button(d, "Continue").click()
        wait(lambda: "Step 2 of 2" in text(d), what="step 2")
        final = xp(d, "//button[normalize-space()='Delete my account' and @type='submit']")
        fill(d, "to confirm", "delete owner?")
        fill(d, "Your password", "owner-password-1")
        assert not final.is_enabled(), "wrong phrase must keep the button disabled"
        fill(d, "to confirm", "delete owner")
        final.click()
        wait(lambda: "last administrator" in text(d), what="last-admin refusal")
        button(d, "Back").click()
        button(d, "Cancel").click()

        # Remote mode: switch to the Docker server, confirm its fingerprint (TOFU), set it up.
        settings(d)
        button(d, "Switch server").click()
        wait(lambda: "Connect to a Malo server" in text(d), what="connect screen again")
        fill(d, "Server URL", os.environ["MALO_REMOTE_URL"])
        button(d, "Check server").click()
        wait(lambda: "First connection" in text(d), what="fingerprint prompt")
        assert os.environ["MALO_REMOTE_FP"] in text(d), "shown fingerprint differs from the server's"
        shot(d, "08-remote-fingerprint")
        button(d, "Trust and connect").click()
        wait(lambda: "Create the administrator" in text(d), what="remote setup screen")
        fill(d, "Setup token", os.environ["MALO_REMOTE_TOKEN"])
        fill(d, "Username", "remote-admin")
        fill(d, "Password", "remote-password-1", exact=True)
        fill(d, "Repeat password", "remote-password-1")
        button(d, "Create").click()
        wait(lambda: "Save your recovery kit" in text(d), timeout=90, what="remote recovery kit")
        button(d, "Save recovery kit").click()
        button(d, "continue").click()
        wait(lambda: "Dashboard" in text(d) and "127.0.0.1:18443" in text(d), what="remote dashboard")
        shot(d, "09-remote-dashboard")

        # Invite a second user, register through the GUI, then let them delete their own account.
        d.execute_script("location.hash = '#/admin'")
        button(d, "Create invite code").click()
        code = wait(lambda: xp(d, "//p[contains(., 'Invite code')]/span[contains(@class,'mono')]").text, what="invite code")
        button(d, "Log out").click()
        wait(lambda: "Log in to unlock" in text(d), what="login after logout")
        button(d, "Create account").click()
        fill(d, "Username", "leaver")
        fill(d, "Password", "leaver-password-1", exact=True)
        fill(d, "Repeat password", "leaver-password-1")
        fill(d, "Invite code", code)
        button(d, "Create").click()
        wait(lambda: "Save your recovery kit" in text(d), timeout=90, what="leaver kit")
        button(d, "Save recovery kit").click()
        button(d, "continue").click()
        wait(lambda: "leaver" in text(d) and "Dashboard" in text(d), what="leaver dashboard")
        settings(d)
        button(d, "Delete my account").click()
        field(d, "I understand this cannot be undone").click()
        button(d, "Continue").click()
        fill(d, "Your password", "leaver-password-1")
        fill(d, "to confirm", "delete leaver")
        xp(d, "//button[normalize-space()='Delete my account' and @type='submit']").click()
        wait(lambda: 'The account "leaver" was deleted' in text(d), what="deleted notice on login screen")
        fill(d, "Username", "leaver")
        fill(d, "Password", "leaver-password-1", exact=True)
        button(d, "Unlock").click()
        wait(lambda: "invalid username or password" in text(d), what="deleted user can't log in")
        shot(d, "10-account-deleted")

        # Reset the local server (two steps), then the bundled server starts from scratch.
        button(d, "Change server").click()
        wait(lambda: "Reset local server" in text(d), what="local data panel")
        button(d, "Reset local server").click()
        field(d, "I understand this cannot be undone").click()
        button(d, "Continue").click()
        fill(d, "to confirm", "DELETE")
        button(d, "Delete local server data").click()
        wait(lambda: "No local server data yet" in text(d), what="local data gone")
        shot(d, "11-local-reset")
        button(d, "Use local server").click()
        wait(lambda: "Create the administrator" in text(d), timeout=60, what="fresh local setup")
        print("GUI end-to-end test passed")
    except Exception:
        shot(d, "failure")
        print(text(d)[:3000], file=sys.stderr)
        raise
    finally:
        d.quit()


if __name__ == "__main__":
    main()
