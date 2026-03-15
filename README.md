# scripts
various scripts

## Get-BootShutdownEvents
```
PS C:\> Get-BootShutdownEvents |ft

Level Time         Kind                       Description
----- ----         ----                       -----------
Info  15/3 6:00:47 WindowsUpdatesInstallStart Installation Started: Windows has started installing the following update: 2026-03 Cumulative Update for Microsoft ...
Info  15/3 6:19:54 WindowsUpdatesRestart      The process C:\WINDOWS\system32\shutdown.exe (SRV2) has initiated the restart of computer SRV2 ...
Info  15/3 6:22:06 NormalShutdown             The Event log service was stopped. (id 6006 from EventLog)
Info  15/3 6:22:12 NormalShutdown             The operating system is shutting down at system time  2026 - 03 - 15T04:22:12.144072600Z. (id 13 from Microsoft-Windows-Kernel-General)
Info  15/3 6:22:14 Boot                       The operating system started at system time  2026 - 03 - 15T04:22:14.500000000Z. (id 12 from Microsoft-Windows-Kernel-General)
Info  15/3 6:22:22 Boot                       The Event log service was started. (id 6005 from EventLog)
Info  15/3 6:22:44 WindowsUpdatesRestart      The process C:\WINDOWS\servicing\TrustedInstaller.exe (SRV2) has initiated the restart of computer SRV2...
Info  15/3 6:22:45 NormalShutdown             The Event log service was stopped. (id 6006 from EventLog)
Info  15/3 6:22:51 NormalShutdown             The operating system is shutting down at system time  2026 - 03 - 15T04:22:51.294803800Z. (id 13 from Microsoft-Windows-Kernel-General)
Info  15/3 6:22:53 Boot                       The operating system started at system time  2026 - 03 - 15T04:22:53.500000000Z. (id 12 from Microsoft-Windows-Kernel-General)
Info  15/3 6:22:59 Boot                       The Event log service was started. (id 6005 from EventLog)
Info  15/3 6:23:20 WindowsUpdatesInstallCompl Installation Successful: Windows successfully installed the following update: 2026-03 Cumulative Update for Microsoft ...

```
