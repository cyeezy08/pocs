# Finding 3: WebView Subdomain Allowlist Bypass
## Severity: MEDIUM | CVSS: 6.1 (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N) | Type: Allowlist Bypass / Potential XSS

### Summary

WhatsApp's in-app browser (`WaInAppBrowsingActivity`) uses a URL allowlist via `SecureWebView`. The host matcher (`LX/8Cz`) uses `host.endsWith("." + allowedHost)` - substring matching that allows subdomain bypass. If an attacker can take over a subdomain of an allowed host, they can load arbitrary content in WhatsApp's trusted WebView context.

### URL Validation Chain

```
Intent("webview_url") → WaInAppBrowsingActivity.onCreate()
  → SecureWebView.loadUrl(url)
    → LX/9GU.A01(url)  [allowlist check]
      → LX/8Cz.A01(uri)  [host matcher]
        → host.equals(allowedHost) || host.endsWith("." + allowedHost)
```

### The Bug

```java
// LX/8Cz.smali - host matcher
// This is equivalent to:
if (host.equals("whatsapp.com") || host.endsWith(".whatsapp.com")) {
    return ALLOW;
}
```

`host.endsWith(".whatsapp.com")` allows:
- `evil.whatsapp.com` ✓ (attacker content)
- `a.b.c.whatsapp.com` ✓ (deep subdomain)

### Attack Vector: Subdomain Takeover

1. Find a dangling DNS record for a WhatsApp subdomain (e.g., `old.whatsapp.com` → expired CNAME)
2. Register the subdomain with your own hosting
3. Host malicious content that mimics WhatsApp's UI
4. Craft a deep link: `https://old.whatsapp.com/phishing`
5. WhatsApp's WebView loads the attacker's content with WhatsApp's trusted context

### Additional Controls Found

| Control | Status |
|---------|--------|
| File access | Disabled (`setAllowFileAccess(false)`) |
| Content access | Disabled (`setAllowContentAccess(false)`) |
| JS bridge | None (`addJavascriptInterface` not found) |
| HTTPS enforcement | Active (HTTP auto-upgraded to HTTPS) |
| Cross-origin blocking | Opt-in (`webview_avoid_external`, default false) |

### Files

- `/home/kali/2stage/findings/native_analysis/webview_smali/ui/WaInAppBrowsingActivity.smali` (8681 lines)
- `SecureWebView.smali` - Security wrapper
- `LX/9GU.smali` - Allowlist validator
- `LX/8Cz.smali` - Host matcher (the buggy class)

### Recommended Fix

Change from substring matching to exact host matching:
```java
// Before (vulnerable):
host.endsWith("." + allowedHost)

// After (secure):
host.equals(allowedHost)
```
