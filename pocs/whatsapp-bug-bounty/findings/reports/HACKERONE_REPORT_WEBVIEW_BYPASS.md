# HackerOne Report: WebView Subdomain Allowlist Bypass in Host Matcher

## Title
In-app browser URL validator uses insecure substring matching (`endsWith`), allowing host bypass and arbitrary URL loading via subdomain takeover

## Summary
WhatsApp's in-app browser (`WaInAppBrowsingActivity`) enforces a URL allowlist to ensure users only browse trusted domains (such as `*.whatsapp.com`). However, the host matcher logic in class `LX/8Cz` relies on substring matching using the `.endsWith("." + allowedHost)` method. 

If an attacker can take over or point any subdomain of an allowed host (e.g. a dangling CNAME record on a WhatsApp subdomain like `expired-service.whatsapp.com`), they can bypass the filter entirely and load arbitrary external content inside WhatsApp's trusted `SecureWebView` context.

## Severity
Medium (URL Validation Bypass / Phishing / Potential XSS)

---

## Root Cause Analysis
The validation chain operates as follows:
1. An incoming URL is intercepted by `SecureWebView.loadUrl(url)`.
2. The validator `LX/9GU` checks if the URL is allowed.
3. The host matcher `LX/8Cz` extracts the host name from the URI and performs:
```java
if (host.equals(allowedHost) || host.endsWith("." + allowedHost)) {
    return ALLOW;
}
```
In `LX/8Cz.smali`:
```smali
# Insecure endsWith check allowing deep subdomains
invoke-virtual {v5, v0}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z
```

While this correctly matches `www.whatsapp.com`, it also matches **any arbitrary subdomain** (e.g. `anything.whatsapp.com`). If a single subdomain is vulnerable to subdomain takeover (e.g. pointing to a cloud provider with an expired subscription/record), the attacker can serve malicious content that passes WhatsApp's internal validation check.

---

## Steps to Reproduce (Conceptual Scenario)
1. An attacker identifies a dangling CNAME record for a WhatsApp subdomain (e.g., `temp-marketing.whatsapp.com` pointing to a deleted AWS S3 bucket or GitHub Pages repository).
2. The attacker registers the corresponding endpoint on the third-party service to host a custom webpage (e.g., mimicking WhatsApp's login or verification page).
3. The attacker constructs a deep link to load this URL:
```
https://temp-marketing.whatsapp.com/phish.html
```
4. WhatsApp's in-app browser opens the link, matches the host using `endsWith(".whatsapp.com")`, accepts it as safe, and renders the attacker's phishing page within WhatsApp's trusted application frame.

---

## Impact
* **Phishing/Spoofing:** Users trust the in-app browser context as it is spawned directly within WhatsApp and carries the WhatsApp logo/branding. Loading malicious pages under an allowed domain structure makes phishing highly effective.
* **Security Control Bypass:** Circumvents intent-based restrictions preventing external link rendering inside private webview components.

---

## Suggested Fix
1. Modify `LX/8Cz` to perform strict, non-wildcard domain checks where possible, or restrict the allowed subdomain depth.
2. Ensure there is a mechanism to audit and immediately remove dangling DNS records of internal subdomains to mitigate subdomain takeover risks.
3. Use a robust URI host parser that separates subdomains properly before matching against the list of authorized hosts.
