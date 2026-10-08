# Finding 4: QuickSends Nonce Replay Risk
## Severity: LOW-MEDIUM | CVSS: 3.7 (AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N) | Type: Server-Dependent Crypto Issue

### Summary

The `QuickSendsContactsProvider` is exported with no manifest permission. It validates callers via `getCallingPackage()` (correct - not spoofable) and a server-side nonce check. However, the nonce is validated but never consumed/invalidated locally, creating a replay risk if the server doesn't invalidate it either.

### Provider Details

- **Authority:** `com.whatsapp.qs.contacts`
- **Exported:** true (no manifest permission)
- **Columns exposed:** `obfuscated_chat_id`, `display_name`, `profile_photo_uri`, `photo_key`

### Validation Chain

1. Feature flag check (`0x67e1` server config)
2. Account linking state must be ACTIVE
3. `getCallingPackage()` → must be whitelisted Meta app (Facebook, Instagram, FB Lite, IG Lite)
4. Nonce validated via Waffle API (`action: "waffle_2_nonce"`)
5. **No local nonce consumption after validation**

### Whitelisted Packages

| Package | App |
|---------|-----|
| `com.facebook.katana` | Facebook |
| `com.facebook.wakizashi` | Facebook (variant) |
| `com.instagram.android` | Instagram |
| `com.facebook.lite` | Facebook Lite |
| `com.instagram.lite` | Instagram Lite |
| `com.facebook.stella` | Meta AI (REJECTED) |

### Attack Scenario (Requires Prerequisites)

1. Obtain valid nonce from OAuth flow in a whitelisted Meta app
2. Find vulnerability in whitelisted app that allows arbitrary ContentProvider calls
3. Call QuickSendsContactsProvider through the compromised app
4. Extract contact data with unbounded `max_contacts` parameter

### Why Not Higher Severity

- `getCallingPackage()` cannot be spoofed (kernel-enforced)
- Requires pre-existing vulnerability in a whitelisted Meta app
- Nonce validation is server-side (unknown if server invalidates)

### Files

- `/home/kali/2stage/findings/native_analysis/otpmessage_smali/../../../accountlinking/ipc/handler/quicksends/QuickSendsContactsProvider.smali`
- `LX/15n.smali` - Nonce validation runner
- `LX/EEH.smali` - Package whitelist checker
- `LX/DzZ.smali` - Waffle API client
