# SugiotAV

This project has been a challenging but rewarding experience. Below is an overview of the main components and functionalities of the SugiotAV system.

## Introduction

The SugiotAV system comprises three main components:
1. A **user-mode console application**.
2. A **device driver** (DeviceControl).
3. A **mini-filter driver** (FileDriver).

These components work together to implement a security system that can:
- Block specific files and processes.
- Manage whitelists and blacklists.
- Perform memory dumps.

This document provides an overview of the key functionalities and techniques used in each component.

---

## Components and Features

### 1. User Console Application

The **user console application** interacts with the SugiotAV device driver and provides a user interface for:
- Adding files to blacklists or whitelists.
- Blocking access to specific files.
- Dumping memory from a process.
- Killing processes.

**Key Features:**
- **Command Parsing:** Parses command-line arguments to determine the requested action (e.g., `-blacklist`, `-whitelist`, `-block`, `-dump`, `-kill`, `-init`).
- **IOCTL Communication:** Uses `DeviceIoControl` to send IOCTL (Input Output Control) commands to the driver.
- **Memory Management:** Dynamically allocates memory for file paths (e.g., prepending `\Device\HarddiskVolume3` to file paths before sending them to the driver).

---

### 2. Device Driver (DeviceControl)

The **DeviceControl driver** processes IOCTL commands sent by the user console application. It manages core security functions, including process termination and memory dumps.

**Key Techniques:**
- **Driver Initialization:** Registers the driver, creates a device, and establishes a symbolic link for communication.
- **IOCTL Handling:** Processes commands like:
  - `IOCTL_BLACKLIST`
  - `IOCTL_WHITELIST`
  - `IOCTL_BLOCK`
  - `IOCTL_DUMP`
  - `IOCTL_KILL`
- **Process and Memory Management:** 
  - Reads process memory using `KeReadProcessMemory`.
  - Terminates processes with `ZwTerminateProcess`.
  - Copies memory safely using `MmCopyVirtualMemory`.

---

### 3. Mini-Filter Driver (FileDriver)

The **mini-filter driver** monitors file and process operations, enforcing security policies based on blacklists and whitelists.

**Key Techniques:**
- **Filter Registration:** Registers with the system via `FilterDriverEntry` and sets up callbacks for file and process operations.
- **Process Creation Notification:** Uses `PsSetCreateProcessNotifyRoutine` to register a callback (`ProcessCreateNotify`) that:
  - Checks the image file name of new processes.
  - Blocks processes based on whitelist/blacklist rules.
- **File Operation Filtering:** Intercepts file operations with `PreCreateOperation`, blocking access to protected file paths.
- **Process Information Querying:** Uses `ZwQueryInformationProcess` to retrieve process details for enforcing policies.

---

## Summary

The SugiotAV system effectively combines **user-mode** and **kernel-mode** components to create a robust security solution. 

1. The **user console application** allows easy management of blacklists, whitelists, and file protections.  
2. The **device driver** facilitates communication and performs critical tasks like process termination and memory dumps.  
3. The **mini-filter driver** adds security by monitoring and controlling file and process operations.

Together, these components showcase advanced techniques in IOCTL communication, memory management, and kernel-mode driver development, resulting in a comprehensive security tool.

---
