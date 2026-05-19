# VulnerableDriverScanner

Passive helper for finding drivers that are likely affected by Microsoft's vulnerable driver blocklist.

## Workflow

1. Run an elevated baseline scan:

   ```bat
   VulnerableDriverScanner.exe snapshot list1
   ```

2. Enable Microsoft's vulnerable driver blocklist in Windows Security, restart the PC, then run:

   ```bat
   VulnerableDriverScanner.exe snapshot list2
   ```

3. Compare the snapshots:

   ```bat
   VulnerableDriverScanner.exe compare list1 list2
   ```

The comparison report treats drivers that existed in `list1` but are missing from `list2` as blocklist candidates. That is a strong hint, not proof, because drivers can also disappear if hardware, services, or startup conditions changed between boots.

## What It Checks

- Currently loaded kernel drivers via `EnumDeviceDrivers`.
- Driver service metadata from the Service Control Manager.
- SHA-256 hashes and version-resource fields.
- Static IOCTL/device-control indicators from PE imports and embedded strings.
- DOS device symbolic links from `QueryDosDevice`.

The scanner does not load drivers, unload drivers, fuzz IOCTLs, or call `DeviceIoControl` against arbitrary device objects.

## Output Location

Snapshots and comparison reports are saved locally under:

```text
%LOCALAPPDATA%\Aegis\VulnerableDriverScanner
```

