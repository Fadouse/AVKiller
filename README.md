# AVKiller

A simple tool designed to restrict the capabilities of core antivirus processes by dropping privileges.

## Overview

AVKiller is a utility that allows you to limit the effectiveness of antivirus software by:
- Removing all privileges from target processes
- Setting their integrity level to Low (S-1-16-4096)
- Effectively restricting their ability to perform system operations

## Features

- Target processes by PID, process name, or executable image name
- List all matching processes with detailed information
- Elevate to SYSTEM context for maximum effectiveness
- Run with minimal dependencies (Windows API only)

## Requirements

- Windows operating system
- Administrator privileges (required for SeDebugPrivilege)
- Visual Studio or compatible C++ compiler

## Usage

```
AVKiller.exe --pid <PID>
AVKiller.exe --pname <process name>
AVKiller.exe --image <exe file name>
```

### Examples

```
AVKiller.exe --pid 1234
```
Immediately drops privileges for process with ID 1234.

```
AVKiller.exe --pname HipsDaemon.exe
```
Lists all running processes named "HipsDaemon.exe" (Huorong) and allows you to select which one to modify.

```
AVKiller.exe --image avp.exe
```
Lists all running processes with the executable name "avp.exe" (Kaspersky) and allows you to select which one to modify.

## How It Works

AVKiller operates by:

1. Elevating itself with SeDebugPrivilege and SeImpersonatePrivilege
2. Impersonating the SYSTEM account to gain high-level access
3. Opening a handle to the target process
4. Modifying the process token to:
   - Remove all privileges
   - Set integrity level to Low
5. This prevents the target process from performing privileged actions

## Build Instructions

1. Clone this repository
2. Open in Visual Studio
3. Run with Administrator privileges

## Security Notice

This tool is designed for educational purposes and security research. Use of this tool to disable security software could:
- Leave your system vulnerable to malware
- Violate terms of service agreements
- Potentially be illegal in certain contexts

## Disclaimer

This software is provided for educational purposes only. The author is not responsible for any misuse or damage caused by this program. Users are responsible for ensuring they have proper authorization before using this tool on any system.

## License

[MIT License](LICENSE)
