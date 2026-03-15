# scripts
various scripts

## Get-BootShutdownEvents
```
PS C:\> Get-BootShutdownEvents |ft

Level       Time                 Kind                           Description
-----       ----                 ----                           -----------
Information 15/3/2026 6:00:47 πμ WindowsUpdatesInstallStarted   Installation Started: Windows has started installing the following update: 2026-03 Cumulative Update for Microsoft server operating system vers...
Information 15/3/2026 6:19:54 πμ WindowsUpdatesRestart          The process C:\WINDOWS\system32\shutdown.exe (SRV2) has initiated the restart of computer SRV2 on behalf of user NT AUTHORITY\SYSTEM for th...
Information 15/3/2026 6:22:06 πμ NormalShutdown                 The Event log service was stopped. (id 6006 from EventLog)
Information 15/3/2026 6:22:12 πμ NormalShutdown                 The operating system is shutting down at system time  2026 - 03 - 15T04:22:12.144072600Z. (id 13 from Microsoft-Windows-Kernel-General)
Information 15/3/2026 6:22:14 πμ Boot                           The operating system started at system time  2026 - 03 - 15T04:22:14.500000000Z. (id 12 from Microsoft-Windows-Kernel-General)
Information 15/3/2026 6:22:22 πμ Boot                           The Event log service was started. (id 6005 from EventLog)
Information 15/3/2026 6:22:44 πμ WindowsUpdatesRestart          The process C:\WINDOWS\servicing\TrustedInstaller.exe (SRV2) has initiated the restart of computer SRV2 on behalf of user NT AUTHORITY\SYST...
Information 15/3/2026 6:22:45 πμ NormalShutdown                 The Event log service was stopped. (id 6006 from EventLog)
Information 15/3/2026 6:22:51 πμ NormalShutdown                 The operating system is shutting down at system time  2026 - 03 - 15T04:22:51.294803800Z. (id 13 from Microsoft-Windows-Kernel-General)
Information 15/3/2026 6:22:53 πμ Boot                           The operating system started at system time  2026 - 03 - 15T04:22:53.500000000Z. (id 12 from Microsoft-Windows-Kernel-General)
Information 15/3/2026 6:22:59 πμ Boot                           The Event log service was started. (id 6005 from EventLog)
Information 15/3/2026 6:23:20 πμ WindowsUpdatesInstallCompleted Installation Successful: Windows successfully installed the following update: 2026-03 Cumulative Update for Microsoft server operating system v...

```
