# Tianwen Property ERP - Unauthenticated File Upload

**CVE:** Pending responsible disclosure

Single-target proof-of-concept for an unauthenticated arbitrary file upload
in the **`/HM/M_Main/AjaxUpload.aspx`** endpoint of **Tianwen Property
Management ERP (天问物业ERP系统)**, a Chinese ASP.NET WebForms enterprise
application.

> This PoC uploads a **harmless `.txt` marker** only. It contains no
> webshell, executes no commands, and must be used **only against systems you
> own or are authorized to test**. This is a research/defensive disclosure
> project, not an exploitation toolkit.

---

## Summary

| Field | Value |
|-------|-------|
| **Product** | Tianwen Property Management ERP (天问物业ERP系统) |
| **Endpoint** | `POST /HM/M_Main/AjaxUpload.aspx` |
| **Upload dir** | `/HM/M_Main/UploadFiles/` |
| **CWE** | CWE-434 - Unrestricted Upload of File with Dangerous Type |
| **CVSS** | ~9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) - pending final calc |
| **Auth** | None (unauthenticated) |
| **Impact** | Arbitrary file upload → ASPX webshell → RCE |
| **Platform** | Microsoft Windows + IIS (.NET Framework / ASP.NET WebForms) |

---

## How It Works

The `AjaxUpload.aspx` handler accepts a `multipart/form-data` upload on the
`UpFileData` field and stores the file under `/HM/M_Main/UploadFiles/` **with
no extension whitelist**. The response body echoes back the relative path of
the uploaded file.

Attack flow (theoretical, for authorized red-team use):

1. `POST` the upload endpoint with a `UpFileData` part.
2. Server stores the file and returns its path, e.g. `/HM/M_Main/UploadFiles/<name>.aspx`.
3. Because `.aspx` is accepted, a malicious `.aspx` page is executed by IIS
   the moment it is requested → remote code execution.

The PoC in this repository only demonstrates the **upload primitive** with a
benign text file, proving the lack of extension validation without
compromising the host.

### Why Windows / IIS is always the target platform

The application is built on **ASP.NET WebForms** (`.aspx` pages backed by a
compiled `M_Main.dll`). WebForms relies on `System.Web`, which is a
**Windows-only** framework - there is no cross-platform WebForms runtime. On
top of that, a functional webshell for this product needs `cmd.exe` through
`System.Diagnostics.Process`, a Windows API. So every vulnerable instance is,
by construction, **Microsoft Windows + Internet Information Services (IIS)**.

### Why deployments are concentrated in China

Tianwen Property Management ERP is a domestic Chinese product aimed at
mainland property-management companies. Its target market, language, sales
channels, and typical hosting (Chinese ISPs, `.cn` domains) mean the affected
population is overwhelmingly on Chinese infrastructure. This is a market
distribution, not a technical one - the bug itself is not geographically
specific.

---

## Usage

```
python3 poc.py --url http://target/ --verify
```

| Option | Description |
|--------|-------------|
| `--url` | Base URL of the target (required) |
| `--timeout` | Request timeout in seconds (default 15) |
| `--output` | Write evidence (target, path, URLs) to a directory |
| `--verify` | Fetch the uploaded marker to confirm it is reachable |

Example:

```bash
# Single target, verify the marker is reachable, save evidence
python3 poc.py --url http://192.0.2.10 --verify --output ./evidence
```

The uploaded marker is a plain text file containing a PoC banner. **Delete it
from the server after the test.**

---

## Interactive Demo (TUI)

A terminal dashboard that walks the full attack chain step by step - module
enumeration, multipart forging, upload, response parsing, and reachability
verification.

```
python3 demo.py              # simulated run (no target needed)
python3 demo.py --url http://target/   # live run against an authorized target
```

The simulated mode is safe to run anywhere and is useful for recordings and
demos. Live mode performs a real benign marker upload, so use it only against
systems you own or are authorized to test.

---

## Related Issues in the Same Product

Other unauthenticated issues exist under the same `/HM/M_Main/` namespace,
suggesting weak input validation across the module:

- `GET /HM/M_Main/InformationManage/AreaAvatarDownLoad.aspx?AreaAvatar=../web.config` - path traversal / arbitrary file read
- `GET /HM/M_Main/InformationManage/ContractDownLoad.aspx?ContractFile=../web.config` - path traversal
- `GET /HM/M_Main/WorkGeneral/docfileDownLoad.aspx?AdjunctFile=../web.config` - path traversal

Together these give an unauthenticated attacker both arbitrary read and
arbitrary write on the web server.

---

## Responsible Disclosure

This research is disclosed under the following process:

1. Identify the vendor and obtain a security contact for Tianwen Property ERP.
2. Send a technical advisory (see `advisory.md`) with the affected endpoint,
   reproduction steps, and recommended fix - **without** a working webshell.
3. Offer a 90-day disclosure window.
4. Only after the window closes (or the vendor fixes/acknowledges) publish
   the full writeup.

**Do not** run this against hosts you do not own or lack written permission
to test. Unauthorized access to computer systems is illegal in most
jurisdictions (e.g. Malaysia Computer Crimes Act 1997).

---

## Recommended Fix (for the vendor)

1. **Whitelist allowed extensions** server-side (e.g. only images/docs), never
   rely on the client-supplied filename or MIME type.
2. **Randomize stored filenames** and strip the original extension entirely.
3. Store uploads **outside the web root** and serve them through a handler
   that forces `Content-Disposition: attachment`.
4. Validate file content (magic bytes) against the allowed type.
5. Apply the same input-validation review to the `DownLoad.aspx` pages listed
   above (path traversal).

---

## License

MIT - provided for defensive security research and education only.

## Disclaimer

The author is not responsible for misuse of this research. Use only against
systems you own or are explicitly authorized to test.
