"""Assertions and fixtures the scrubber test files share.

``check`` is the two-direction assertion every rule is tested with: the text
scrubs to exactly what is expected, the scanner is silent on that output, and
the raw text is flagged exactly when something was removed.

The secret-shaped values are assembled here at runtime from obviously
invented parts. A literal Stripe, SendGrid, Google, GitLab, Shopify, GitHub,
Telegram or PEM key in the source reads to a credential scanner (and to
GitHub push protection) as a leaked key, so no such shape may appear in a
source file; joined at import time, each constant still has the exact shape
the rule under test must catch.
"""

import time

# --- the two-direction assertion ---------------------------------------------------------


def check(scrub, scanner, text, expected, kind=None):
    """``text`` scrubs to ``expected``; the scanner is silent on that output;
    the raw text is flagged when, and only when, something was removed, with
    ``kind`` among the leak kinds if one is named."""
    out = scrub(text)
    assert out == expected, (text, out)
    assert not scanner.scan(out), (out, scanner.scan(out))
    if out == text:
        assert not scanner.scan(text), (text, scanner.scan(text))
    else:
        kinds = {leak.kind for leak in scanner.scan(text)}
        assert kinds, text
        assert kind is None or kind in kinds, (text, kinds)


# --- timing ------------------------------------------------------------------------------

SCRUB_BUDGET = 2.0  # seconds


def assert_cost_ratio(small, large, factor, label="", rounds=5):
    """``large`` costs less than ``factor`` times ``small``, for two calls on
    inputs of a known size ratio.

    Each round times the two calls back to back and the smallest ratio of the
    rounds is the answer. Contention hits both halves of a round alike, so a
    loaded machine can only understate the ratio, never overstate it: this
    assertion misses a regression on a busy machine rather than failing on a
    healthy one. Comparing two wall-clock measurements taken minutes apart
    does neither."""
    best = float("inf")
    for _ in range(rounds):
        started = time.perf_counter()
        small()
        between = time.perf_counter()
        large()
        ended = time.perf_counter()
        best = min(best, (ended - between) / max(between - started, 1e-6))
    assert best < factor, (label, best, factor)


def assert_fast(call, budget=SCRUB_BUDGET, label=""):
    """``call`` stays under ``budget`` seconds, measured on its quickest of up
    to three runs.

    The budget is deliberately generous, and the repeats happen only after a
    run misses it: these tests guard against catastrophic backtracking, which
    costs seconds on every run and on every machine, while a tight budget
    would mostly report the load on the machine running the suite."""
    best = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        call()
        best = min(best, time.perf_counter() - started)
        if best < budget:
            return
    raise AssertionError((label, best))


# --- secret shapes, assembled from invented parts ------------------------------------------

STRIPE_LIVE = "sk_" + "live_" + "Ab12Cd34Ef56Gh78Jk90Lm12"           # sk_live_ + 24 characters
STRIPE_LIVE_SHORT = "sk_" + "live_" + "Ab12Cd34Ef56Gh78"             # cut short by the person pasting it
STRIPE_LIVE_LONG = STRIPE_LIVE + "Np34Qr56St78Uv90Wx12"              # a longer key of the same shape
STRIPE_WEBHOOK = "whs" + "ec_" + "Ab12Cd34Ef56Gh78Jk90Lm12Np34Qr56"
SENDGRID = "S" + "G." + "Ab12Cd34Ef56Gh78Jk90Lm" + "." + "Np34Qr56St78Uv90Wx12Yz34Ab56Cd78Ef90Gh12Jk3"
GOOGLE_API_KEY = "AI" + "za" + "Sy" + "Ab12Cd34Ef56Gh78Jk90Lm12Np34Qr56S"   # AIza + 35 characters
GITLAB_PAT = "gl" + "pat-" + "Ab12Cd34Ef56Gh78Jk90"
SHOPIFY_TOKEN = "shp" + "at_" + "ab12cd34ef56ab78cd90ef12ab34cd56"
GITHUB_PAT = "gh" + "p_" + "Ab12Cd34Ef56Gh78Jk90Lm12Np34Qr56St78"
AWS_ACCESS_KEY = "AK" + "IA" + "AB12CD34EF56GH78"
OPENAI_KEY = "sk-" + "proj-" + "Ab12Cd34Ef56Gh78Jk90Lm12Np34Qr56St78Uv90Wx12Yz34Ab56Cd78Ef90Gh"
TWILIO_KEY = "S" + "K" + "ab12cd34ef56ab78cd90ef12ab34cd56"
DISCORD_TOKEN = "MTIzNDU2Nzg5MDEyMzQ1Njc4" + "." + "GhIjKl" + "." + "Ab12Cd34Ef56Gh78Jk90Lm12Np34Qr56St78Uv"
BOT_SECRET = "AA" + "Ab12Cd34Ef56Gh78Jk90Lm12Np34Qr56S"               # the 35 characters after the colon
BOT_TOKEN = "123456789" + ":" + BOT_SECRET
BOT_TOKEN_DASH = BOT_TOKEN[:-1] + "-"                                # a token whose last character is a dash
BOT_TOKEN_ID_LIKE = "3012340476" + ":" + BOT_SECRET                  # a bot id that passes the RNOKPP checksum
JWT = ("ey" + "JhbGciOiJIUzI1NiJ9" + "." + "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0"
       + "." + "Ab12Cd34Ef56Gh78Jk90Lm12Np34Qr56St78Uv90Wx1")
PEM_BODY = "xmtrv6ijdsf4mZebD0SvhjEArkzPZto865jQK95TcfvEbIOYAjk17ZpF2OHCK3Ba"  # 64 characters of base64
PEM_TAIL = "MIIEvQIBADANBg=="                                                  # a short last line

_DASHES = "-" * 5


def pem_begin(label="PRIVATE KEY"):
    """The opening line of a PEM block ("PRIVATE KEY", "RSA PRIVATE KEY",
    "PGP PRIVATE KEY BLOCK")."""
    return f"{_DASHES}BEGIN {label}{_DASHES}"


def pem_end(label="PRIVATE KEY"):
    """The closing line that matches ``pem_begin(label)``."""
    return f"{_DASHES}END {label}{_DASHES}"


def pem_block(body=PEM_BODY, tail=PEM_TAIL, label="PRIVATE KEY", sep="\n"):
    """A whole PEM block: header, body lines and footer, joined with ``sep``
    (a literal ``\\n`` inside a JSON string, for instance)."""
    lines = [pem_begin(label), body] + ([tail] if tail else []) + [pem_end(label)]
    return sep.join(lines)
