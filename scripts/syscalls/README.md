# Syscall LSM Hook Checker

This Python script analyzes all system calls (syscalls) on a Linux system to check for Linux Security Module (LSM) hooks in their execution path. It uses the `trace-cmd` tool to capture function graphs for each syscall and then searches for LSM-related function calls.

## Purpose

The main purposes of this script are:

1. To provide a comprehensive overview of which syscalls have LSM hooks in their execution path.
2. To help in understanding the security implications of various syscalls.
3. To assist in debugging or auditing LSM implementations.

## Dependencies

This script requires the following:

1. Python 3.6 or later
2. `trace-cmd` tool
3. `ausyscall` command (part of the `auditd` package)

To install the dependencies on a Debian-based system (like Ubuntu), you can use:

```
sudo apt-get update
sudo apt-get install trace-cmd auditd
```

For other Linux distributions, please use the appropriate package manager.

## Usage

1. Save the script to a file, e.g., `syscall_lsm_checker.py`
2. Make the script executable:
   ```
   chmod +x syscall_lsm_checker.py
   ```
3. Run the script with sudo privileges:
   ```
   sudo ./syscall_lsm_checker.py
   ```

Note: The script needs to be run with sudo privileges because it uses `trace-cmd`, which requires root access to trace kernel functions.

## Output

The script will:

1. Print progress to the console as it analyzes each syscall.
2. Create a summary file named `lsm_hooks_summary_YYYYMMDD_HHMMSS.txt` in the same directory as the script.
3. Print a summary to the console after completing the analysis.

The summary will show, for each syscall, whether any LSM hooks were found and if so, which ones.

## Caution

This script executes all syscalls on your system. While it's designed to be safe, it's recommended to run it in a controlled environment, particularly if you're working on a production system.

## Customization

You can modify the `lsm_patterns` list in the `check_for_lsm_hooks` function to search for different or additional patterns if needed.

## Contributing

Contributions to improve the script are welcome. Please ensure that you maintain or improve code quality, including keeping the type hints up to date.
