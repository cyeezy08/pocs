# HackerOne Report: UPI Payment Signature Not Verified in Deep Link Handler

## Title
UPI payment `sign` parameter extracted but not cryptographically verified, allowing payment parameter spoofing via deep links

## Summary
WhatsApp's UPI payment deep link handler (`upi://pay`) extracts a `sign` parameter from the URI query string and passes it through to the payment confirmation screen without any cryptographic verification. The signature is displayed as-is, allowing an attacker to craft deep links with arbitrary payment parameters (recipient, amount, name) and a meaningless signature that is accepted by the client.

## Severity
Medium - Requires user interaction (confirm payment + enter UPI PIN), but violates UPI specification requirements for signature verification.

## Steps to Reproduce

1. Craft a UPI deep link with arbitrary parameters:
```
upi://pay?pa=attacker@upi&pn=Amazon+Shopping&am=50000&cu=INR&tn=Refund+Claim&sign=fakesignature123
```

2. Open this deep link on a device with WhatsApp installed:
```bash
adb shell am start -a android.intent.action.VIEW \
  -d "upi://pay?pa=attacker@upi&pn=Amazon+Shopping&am=50000&cu=INR&tn=Refund+Claim&sign=fakesignature123"
```

3. WhatsApp opens the payment confirmation screen showing:
   - Payee: "Amazon Shopping" (spoofed from `pn` parameter)
   - Amount: ₹50,000 (set by attacker via `am` parameter)
   - Note: "Refund Claim" (set by attacker via `tn` parameter)
   - Recipient VPA: `attacker@upi` (set by attacker via `pa` parameter)
   - Sign: "fakesignature123" (accepted without verification)

4. The `sign` parameter is accepted and displayed without any cryptographic validation.

## Root Cause

In `C7m.smali` (UPI parameter parser), the `sign` parameter is extracted from the URI at line 896 and stored as field `A0M` at line 1275. In `C77.smali` (validation), it is passed to the payment intent as `extra_new_mandate_sign` at line 618-622. No cryptographic verification (HMAC, RSA, or otherwise) is performed anywhere in the payment flow.

## Impact

1. **Payment Parameter Spoofing:** Attacker controls recipient name (`pn`), amount (`am`), transaction note (`tn`), and recipient VPA (`pa`)
2. **Phishing:** Deep link presents a convincing fake payment confirmation that could trick users into paying the attacker
3. **UPI Specification Violation:** UPI mandates cryptographic signature verification on payment intents; WhatsApp skips this entirely

## Mitigating Factors

- User must manually tap "Pay" to confirm the payment
- User must enter their UPI PIN (external to WhatsApp)
- Amount limits may differ for `THIRD_PARTY_DEEP_LINK` vs `DEEP_LINK` source types

## Suggested Fix

Verify the `sign` parameter cryptographically before displaying the payment confirmation screen. The UPI specification requires signature validation to ensure payment parameters have not been tampered with.

## Attachments

- `C7m.smali` - UPI parameter parser (sign extraction at line 896)
- `C77.smali` - UPI validation (sign passthrough at line 618, no verification)
- `IndiaUpiPayIntentReceiverActivity.smali` - Entry point for deep link handling
