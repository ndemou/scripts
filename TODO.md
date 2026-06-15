# Test-NetConnectivityToHost: description for host and port meaning

Besides the current syntax:
```
Test-NetConnectivityToHost -Host 10.1.2.3 -OpenPorts 3389,22001
```
Also support this new syntax:
```
Test-NetConnectivityToHost -Host @{'10.1.2.3'='VM-SRV-1'} -OpenPorts @{3389='RDP'; 22001='SoftOne'}
```
In order for the messages to be more explanatory: `Port 22001(SoftOne) of 10.1.2.3(VM-SRV-1) is not open`

# WindowsUpdateHelper.ps1

It creates a scheduled task named "WindowsUpdateHelper-ForcedReboot". This task should have a consisse description explaining who created it (the path to the script), why it was created, that it's normal to have missed its schedule and that it's ok to delete it.

# Rearange files

 - Move scripts to a subdir.
 - Move python code and templates for index.html to a subdir.
