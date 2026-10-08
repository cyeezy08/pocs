# Finding 6: Exported Services Without Permission
## Severity: LOW | CVSS: 3.3 (AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N) | Type: Defense-in-Depth Gap

### Summary

Multiple WhatsApp services are `exported=true` with no `android:permission` attribute in the manifest. While these services are designed for cross-app communication (Android Auto, Wear OS, etc.), the lack of permission protection means any installed app can bind to them.

### Exported Services (No Permission)

| Service | Purpose | Risk |
|---------|---------|------|
| `BackupNowService` | Trigger backup | Trigger backup without auth |
| `BackupStateService` | Read backup state | Leak backup metadata |
| `WaAccountsCenterService` | Account linking IPC | Access account linking APIs |
| `WhatsAppCarAppService` | Android Auto | Bind from any app |
| `WearOsListenerService` | Wear OS | Bind from any app |
| `GarminBindingServiceShim` | Garmin | Bind from any app |
| `TetheredService` | Tethered mode | Bind from any app |
| `InstrumentationService` | Analytics | Bind from any app |
| `ContactsSyncAdapterService` | Contact sync | Trigger contact sync |
| `InstrumentationFGService` | Foreground instrumentation | Bind from any app |

### Services with Permission (Good)

| Service | Permission |
|---------|-----------|
| `SelfManagedConnectionService` | `android.permission.BIND_TELECOM_CONNECTION_SERVICE` |
| `ChooserTargetServiceCompat` | `android.permission.BIND_CHOOSER_TARGET_SERVICE` |
| `AlarmService` | `android.permission.BIND_JOB_SERVICE` |
| `MediaDownloadJobService` | `android.permission.BIND_JOB_SERVICE` |

### Impact

Most of these are low-risk because they only expose limited functionality. However:
- `WaAccountsCenterService` could be interesting for account linking abuse
- `InstrumentationService` could leak analytics data
- Services without permission are potential confused-deputy targets

### Files

- Android manifest analysis (see `00_OVERVIEW.md`)
