# Finding 1: UPI Payment Signature Not Verified
## Severity: MEDIUM | CVSS: 5.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N) | Type: Cryptographic Bypass

### Summary

WhatsApp's UPI payment deep link handler (`upi://pay`) extracts a `sign` parameter from the URI but never cryptographically verifies it. The signature is passed through to the payment intent as a string without any validation against HMAC, RSA, or any other cryptographic primitive.

### Root Cause

In `C7m.smali` (UPI parameter parser):
- Line 896: `const-string v6, "sign"` - extracts "sign" from URI query
- Line 1275: `iput-object v10, v0, LX/C7m;->A0M:Ljava/lang/String;` - stores as field

In `C77.smali` (UPI validation):
- Line 618: `const-string v1, "extra_new_mandate_sign"` - passes to intent
- Line 622: `iget-object v0, p1, LX/C7m;->A0M:Ljava/lang/String;` - reads sign
- **NO** Mac, Hmac, Signature, Cipher, or MessageDigest calls exist in the payment flow

### Proof of Concept

```bash
# Craft a UPI deep link with arbitrary sign parameter
# The sign "fakesignature" is accepted without verification
adb shell am start -a android.intent.action.VIEW \
  -d "upi://pay?pa=attacker@upi&pn=Amazon+Shopping&am=50000&cu=INR&tn=Order+Payment&sign=fakesignature"
```

The payment confirmation screen will show:
- Payee: Amazon Shopping (attacker-controlled `pn`)
- Amount: ₹50,000 (attacker-controlled `am`)
- Note: Order Payment (attacker-controlled `tn`)
- Sign: fakesignature (accepted without verification)

### Impact

1. **Payment Parameter Spoofing:** Attacker can set any recipient name, amount, and transaction note
2. **Phishing:** Deep link can present a convincing fake payment confirmation
3. **UPI Spec Violation:** UPI mandates cryptographic signature verification on payment intents

### Mitigating Factors

- User must manually confirm the payment (tap "Pay")
- User must enter UPI PIN (external to WhatsApp)
- Amount limits may apply based on `THIRD_PARTY_DEEP_LINK` vs `DEEP_LINK` source type

### Files

- `C7m.smali` - UPI parameter parser (sign extraction at line 896)
- `C77.smali` - UPI validation (sign passthrough at line 618)
- `IndiaUpiPayIntentReceiverActivity.smali` - Deep link entry point
- `AndroidManifest.xml` - `IndiaUpiPayIntentReceiverActivity` declaration

### Verifier

Ask WhatsApp: "Do you verify the UPI `sign` parameter cryptographically before displaying the payment confirmation screen?" The answer is no - it's extracted and displayed without verification.
