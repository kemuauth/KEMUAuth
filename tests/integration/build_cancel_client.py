#!/usr/bin/env python3
"""Generate a disposable, test-only SSH client variant from local sources.

The production sshconnect2.c and ./ssh are never modified. To force a
mid-Challenge cancellation, the variant emits a second USERAUTH_REQUEST
(method "none") in the same encrypted session instead of KEM_RESPONSE.
"""
import re
import sys
from pathlib import Path


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: build_cancel_client.py INPUT_SSHCONNECT2_C OUTPUT_C")
    src = Path(sys.argv[1]).read_text(encoding="utf-8")
    start = src.index("\ninput_userauth_kem_info_req(")
    end = src.index("\nstatic int\nuserauth_passwd(", start)
    body = src[start:end]
    # Locate the normal Challenge parsing tail inside this one handler.
    pat = (r'(\tif \(\(r = sshpkt_get_cstring\(ssh, &alg, NULL\)\).*?'
           r'\(r = sshpkt_get_end\(ssh\)\) != 0\)\n\t\tgoto out;\n)')
    matches = list(re.finditer(pat, body, re.S))
    if len(matches) != 1:
        raise SystemExit("source layout changed: cannot safely locate the KEM Challenge parser")
    insertion = r'''
    /* Test-only behavior, compiled into a disposable client executable. */
    if (getenv("KEMUAUTH_TEST_CANCEL_AFTER_CHALLENGE") != NULL) {
        debug("KEMUAUTH_CANCEL_TEST_REQUEST_SENT");
        if ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
            (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
            (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
            (r = sshpkt_put_cstring(ssh, "none")) != 0 ||
            (r = sshpkt_send(ssh)) != 0)
            goto out;
        r = 0;
        goto out;
    }
'''
    body = body[:matches[0].end()] + insertion + body[matches[0].end():]
    dst = src[:start] + body + src[end:]
    Path(sys.argv[2]).write_text(dst, encoding="utf-8")


if __name__ == "__main__":
    main()
