# Intel UHD 620 Driver Guard

PowerShell guard for preventing Windows Update from replacing a newer Intel UHD Graphics 620 driver with older OEM/Windows Update packages.

This repository documents a real case involving a Lenovo notebook with:

```text
PCI\VEN_8086&DEV_5917&SUBSYS_39B017AA
Intel(R) UHD Graphics 620
```

The machine was running a newer Intel driver:

```text
31.0.101.2141
```

but Windows Update repeatedly offered older packages such as:

```text
Intel Corporation - Extension - 25.20.100.6519
Intel Corporation - Display   - 25.20.100.6519
Intel Corporation - Display   - 24.20.100.6292
```

Even after DDU cleanup, disabling automatic driver acquisition, and other common Windows Update workarounds, the older OEM candidates continued to reappear.

## What the script does

`Protect-IntelUHD620.ps1`:

- Detects the currently installed Intel UHD Graphics 620 driver.
- Uses the installed driver version as the minimum allowed version.
- Refuses to continue if the installed driver is older than `31.0.101.2141`.
- Applies best-effort Windows Update / driver-search registry settings.
- Queries the Windows Update Agent directly through the WUA COM API.
- Hides Intel Display updates older than the currently installed driver.
- Hides specific known-bad update IDs discovered during troubleshooting.
- Repeats the scan so that older fallback candidates revealed after hiding a newer one are also caught.
- Performs a final verification.
- Installs a scheduled task that runs at logon and daily to keep the protection active.

## Intended workflow after reinstalling Windows

1. Install Windows normally.
2. Run Windows Update and finish the normal OS updates.
3. Install the latest official Intel graphics driver you want to keep.
4. Reboot.
5. Run PowerShell as Administrator.
6. Execute:

```powershell
powershell.exe -ExecutionPolicy Bypass -File ".\Protect-IntelUHD620.ps1"
```

If the file is in Downloads:

```powershell
powershell.exe -ExecutionPolicy Bypass -File "$env:USERPROFILE\Downloads\Protect-IntelUHD620.ps1"
```

## Protection model

The script does **not** permanently pin one hard-coded Intel driver version.

Instead, it reads the currently installed version and treats that as the floor:

```text
Current Intel driver
        |
        v
Use installed version as minimum
        |
        v
Windows Update scan
        |
        +-- newer Intel Display -> leave alone
        +-- same version        -> leave alone
        `-- older Intel Display -> hide
```

This means that if a newer Intel driver is installed in the future, running the script again automatically raises the protected minimum version.

## Known problematic Windows Update packages

The following packages were observed during troubleshooting and are explicitly blocked by update ID:

| Type | Version | Update ID |
|---|---|---|
| Intel Extension | 25.20.100.6519 | `c70302e4-5b08-4fc3-8a5a-0c95e3653da0` |
| Intel Display | 25.20.100.6519 | `686c0dca-66a5-4605-9943-88a84ff81304` |
| Intel Display | 24.20.100.6292 | `391cb60e-95e0-4655-8b00-ca2a79d43627` |

The script also dynamically hides future Intel Display offers whose parsed version is older than the installed driver.

## Why multiple scans are necessary

Windows Update may reveal an older fallback candidate only after a newer candidate has been hidden.

Observed behavior:

```text
25.20.100.6519
        |
        v hide
24.20.100.6292 appears
        |
        v hide
no older visible candidate
```

For this reason, the script opens new Windows Update Agent sessions and repeats the scan until no additional downgrade candidate is found.

## Scheduled protection

On a normal run, the script copies itself to:

```text
C:\ProgramData\IntelDriverGuard\Protect-IntelUHD620.ps1
```

and creates the scheduled task:

```text
Intel UHD 620 Driver Guard
```

The task runs:

- at user logon;
- once per day at 12:00;
- as `SYSTEM`;
- with highest privileges.

Logs are written to:

```text
C:\ProgramData\IntelDriverGuard\IntelDriverGuard.log
```

## Run without creating a scheduled task

```powershell
powershell.exe -ExecutionPolicy Bypass -File ".\Protect-IntelUHD620.ps1" -NoScheduledTask
```

## Run only the guard scan

This is normally used internally by the scheduled task:

```powershell
powershell.exe -ExecutionPolicy Bypass -File ".\Protect-IntelUHD620.ps1" -GuardOnly
```

## Remove persistent protection

```powershell
powershell.exe -ExecutionPolicy Bypass -File "C:\ProgramData\IntelDriverGuard\Protect-IntelUHD620.ps1" -UninstallGuard
```

This removes the scheduled task and persistent copy of the script.

It does **not** automatically unhide Windows Update packages that were previously marked as hidden.

## Important notes

- Run the script as Administrator.
- Install the Intel driver you actually want to keep **before** running the script.
- Do not use DDU or reset `SoftwareDistribution` after the guard is working unless you are intentionally troubleshooting Windows Update again, because doing so can alter update state.
- Some Windows Update policy registry values are only officially supported by Microsoft on Pro/Enterprise/Education editions. On Windows Home, they should be considered best-effort. The main protection mechanism here is hiding applicable downgrade packages through the Windows Update Agent API.
- This script is intentionally scoped to the Intel UHD Graphics 620 configuration identified above. Review the hardware ID and minimum driver assumptions before adapting it to another machine.

## Requirements

- Windows 10/11
- Windows PowerShell 5.1
- Administrator privileges
- Intel UHD Graphics 620
- Windows Update Agent available

## Disclaimer

Use at your own risk. Driver and Windows Update behavior can change between Windows builds, OEM images, and Intel driver branches. Review the script before running it on hardware other than the configuration documented here.
