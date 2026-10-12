#!/usr/bin/env python3
"""Re-pin the Content-Security-Policy script hashes in index.html.

Any edit to the inline <script id="vs-bundle"> or <script id="vs-app"> changes
its SHA-256, and the browser then refuses to run it until the CSP pin is
updated. Run this after editing either script:

    python3 update-csp.py            # rewrites index.html in place
    python3 update-csp.py --check    # exit 1 if the pins are stale

It also checks the crypto bundle against the reproducible-build hash recorded
in PROVENANCE.md / verify.sh, so an accidental bundle edit is caught here too.
"""
import base64, hashlib, re, sys

HTML = "index.html"
BUNDLE_EXPECTED_HEX = "2029930d2807bd3b37d5d4718194b77dd086ba7d420a18176cbdc616960c9eb2"


def script_body(doc: bytes, sid: bytes) -> bytes:
    i = doc.index(b'<script id="' + sid + b'">')
    gt = doc.index(b">", i) + 1
    return doc[gt:doc.index(b"</script>", gt)]


def pin(body: bytes) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(body).digest()).decode()


def main() -> int:
    check = "--check" in sys.argv[1:]
    doc = open(HTML, "rb").read()
    bundle, app = script_body(doc, b"vs-bundle"), script_body(doc, b"vs-app")
    if hashlib.sha256(bundle).hexdigest() != BUNDLE_EXPECTED_HEX:
        print("error: vs-bundle no longer matches the reproducible build; refusing to pin it")
        return 1
    want = "script-src '{}' '{}'".format(pin(bundle), pin(app))
    csp = re.compile(rb"script-src(?: &#39;[^;]*?&#39;)+")
    m = csp.search(doc)
    if not m:
        print("error: script-src directive not found in the CSP meta tag")
        return 1
    have = m.group(0).decode().replace("&#39;", "'")
    if have == want:
        print("CSP pins are current:", pin(app))
        return 0
    if check:
        print("CSP pins are stale.\n  have:", have, "\n  want:", want)
        return 1
    doc = doc[:m.start()] + want.replace("'", "&#39;").encode() + doc[m.end():]
    open(HTML, "wb").write(doc)
    print("Updated CSP:", want)
    return 0


if __name__ == "__main__":
    sys.exit(main())
